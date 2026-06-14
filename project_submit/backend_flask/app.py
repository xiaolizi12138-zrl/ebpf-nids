
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS

import sqlite3
import logging
import requests
import socket
import json
import threading
import time
import os

# ===================== 基础配置 =====================

DB_PATH = "db.sqlite3"
LOG_FILE = "alarm.log"

# XDP Loader loader 创建的 Unix Socket
# 注意：这是同一台 Linux 虚拟机内部通信，不是给前端连的
XDP_SOCKET_PATH = "/tmp/xdp_loader.sock"

logging.basicConfig(
    filename=LOG_FILE,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

app = Flask(__name__)
CORS(app)

app.config["JSON_AS_ASCII"] = False
app.json.ensure_ascii = False

# 允许前端跨主机连接 WebSocket
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ===================== 数据库 =====================

def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dst_ip TEXT,
        alert_type TEXT,
        attack_type TEXT,
        src_loc TEXT,
        timestamp_ns INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS flow_rates(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        pps INTEGER,
        bytes_per_sec INTEGER,
        total_pkts INTEGER,
        total_bytes INTEGER,
        timestamp INTEGER
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ===================== 工具函数 =====================

def get_ip_loc(ip):
    private_prefixes = ("127.", "192.168.", "10.", "172.16.")

    for prefix in private_prefixes:
        if ip.startswith(prefix):
            return "内网-局域网"

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=3)
        js = res.json()
        if js.get("status") == "success":
            return f'{js.get("country", "")}-{js.get("regionName", "")}-{js.get("city", "")}'
        return "未知地址"
    except Exception:
        return "获取失败"


def build_features_for_model(msg):
    """
    构造模型输入特征。

    inference.py 需要 15 个特征：
    Flow Duration, Total Fwd Packets, Total Backward Packets,
    Total Length of Fwd Packets, Total Length of Bwd Packets,
    Fwd Packet Length Max, Fwd Packet Length Min,
    Bwd Packet Length Max, Bwd Packet Length Min,
    Flow Bytes/s, Flow Packets/s,
    Fwd IAT Mean, Bwd IAT Mean,
    SYN Flag Count, ACK Flag Count。

    当前 loader 发来的 XDP 告警字段较少，因此这里先做联调适配：
    1. 如果 msg 里已有 features 且长度为 15，则直接使用；
    2. 如果没有完整 features，则根据 alert_type 构造一组基础特征。
    """
    if isinstance(msg.get("features"), list) and len(msg.get("features")) == 15:
        return msg.get("features")

    try:
        alert_type = int(msg.get("alert_type", 0))
    except Exception:
        alert_type = 0

    flow_duration = float(msg.get("flow_duration", 10000))
    total_fwd_packets = float(msg.get("total_fwd_packets", 10))
    total_bwd_packets = float(msg.get("total_backward_packets", 0))
    total_len_fwd = float(msg.get("total_length_fwd", 600))
    total_len_bwd = float(msg.get("total_length_bwd", 0))
    fwd_len_max = float(msg.get("fwd_packet_length_max", 60))
    fwd_len_min = float(msg.get("fwd_packet_length_min", 40))
    bwd_len_max = float(msg.get("bwd_packet_length_max", 0))
    bwd_len_min = float(msg.get("bwd_packet_length_min", 0))
    flow_bytes_s = float(msg.get("bytes_per_sec", msg.get("flow_bytes_s", 0)))
    flow_packets_s = float(msg.get("pps", msg.get("flow_packets_s", 0)))
    fwd_iat_mean = float(msg.get("fwd_iat_mean", 1000))
    bwd_iat_mean = float(msg.get("bwd_iat_mean", 0))
    syn_flag_count = float(msg.get("syn_flag_count", 0))
    ack_flag_count = float(msg.get("ack_flag_count", 0))

    if alert_type == 1:
        # SYN Flood：大量 SYN，无 ACK
        total_fwd_packets = max(total_fwd_packets, 120)
        total_len_fwd = max(total_len_fwd, 7200)
        flow_packets_s = max(flow_packets_s, 100)
        syn_flag_count = max(syn_flag_count, 120)
        ack_flag_count = 0

    elif alert_type == 2:
        # 端口扫描：多个端口 SYN 探测
        total_fwd_packets = max(total_fwd_packets, 30)
        total_len_fwd = max(total_len_fwd, 1800)
        flow_packets_s = max(flow_packets_s, 30)
        syn_flag_count = max(syn_flag_count, 30)
        ack_flag_count = 0

    return [
        flow_duration,
        total_fwd_packets,
        total_bwd_packets,
        total_len_fwd,
        total_len_bwd,
        fwd_len_max,
        fwd_len_min,
        bwd_len_max,
        bwd_len_min,
        flow_bytes_s,
        flow_packets_s,
        fwd_iat_mean,
        bwd_iat_mean,
        syn_flag_count,
        ack_flag_count
    ]


def call_inference(msg):
    """
    调用算法同学提供的 inference.py。

    注意：
    当前 XDP 已经完成 syn_flood / port_scan 的规则检测。
    模型 inference.py 只返回：
        0 = 正常
        1 = 攻击
    它不细分 syn_flood 或 port_scan。

    因此：
    1. 如果消息来自 XDP alert，并且带有 alert_name，则最终 attack_type 使用 alert_name；
    2. 模型仍然会被调用，用于满足后端调用模型的流程；
    3. 如果模型返回 normal，但 XDP 已经产生告警，不覆盖 XDP 的告警类型。
    """
    try:
        from inference import predict

        features = build_features_for_model(msg)
        model_result = predict(features)

        # XDP 已经产生告警时，以 XDP 的告警名称为准
        if msg.get("alert_name"):
            return msg.get("alert_name")

        try:
            alert_type = int(msg.get("alert_type", 0))
        except Exception:
            alert_type = 0

        if alert_type == 1:
            return "syn_flood"

        if alert_type == 2:
            return "port_scan"

        # 如果不是 XDP 告警，再参考模型结果
        if model_result == 0:
            return "normal"

        if model_result == 1:
            return "attack"

        return f"attack_{model_result}"

    except Exception as e:
        logging.error(f"模型调用失败：{str(e)}")

        # 模型异常时，仍然保证 XDP 联调链路正常
        if msg.get("alert_name"):
            return msg.get("alert_name")

        try:
            alert_type = int(msg.get("alert_type", 0))
        except Exception:
            alert_type = 0

        if alert_type == 1:
            return "syn_flood"

        if alert_type == 2:
            return "port_scan"

        return "unknown"


def save_alert(msg):
    src_ip = msg.get("src_ip", "")
    dst_ip = msg.get("dst_ip", "")
    alert_type = str(msg.get("alert_type", ""))
    timestamp_ns = int(msg.get("timestamp_ns", msg.get("timestamp", 0)))

    # 按分工表：收到告警后调用 inference.py
    attack_type = call_inference(msg)

    src_loc = get_ip_loc(src_ip)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts(src_ip, dst_ip, alert_type, attack_type, src_loc, timestamp_ns)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (src_ip, dst_ip, alert_type, attack_type, src_loc, timestamp_ns)
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    data = {
        "id": new_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "alert_type": alert_type,
        "attack_type": attack_type,
        "src_loc": src_loc,
        "timestamp_ns": timestamp_ns
    }

    logging.info(f"新增告警：{src_ip} -> {dst_ip}, type={attack_type}, loc={src_loc}")
    print("📥 收到 XDP 告警并写入数据库：", data)

    # 推送给前端
    socketio.emit("new_alarm", data)

    return data


def save_flow_rate(msg):
    ip = msg.get("ip", "")
    pps = int(msg.get("pps", 0))
    bytes_per_sec = int(msg.get("bytes_per_sec", 0))
    total_pkts = int(msg.get("total_pkts", 0))
    total_bytes = int(msg.get("total_bytes", 0))
    timestamp = int(msg.get("timestamp", time.time()))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO flow_rates(ip, pps, bytes_per_sec, total_pkts, total_bytes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ip, pps, bytes_per_sec, total_pkts, total_bytes, timestamp)
    )
    conn.commit()
    conn.close()

    data = {
        "ip": ip,
        "pps": pps,
        "bytes_per_sec": bytes_per_sec,
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "timestamp": timestamp
    }

    logging.info(f"流速统计：{data}")

    # 推送给前端
    socketio.emit("flow_rate", data)

    return data


def handle_xdp_msg(msg):
    msg_type = msg.get("type", "")

    if msg_type == "alert":
        return save_alert(msg)

    if msg_type == "flow_rate":
        return save_flow_rate(msg)

    logging.warning(f"未知消息类型：{msg}")
    print("⚠️ 未知 XDP 消息：", msg)
    return None


# ===================== 连接XDP Loader loader 的 Unix Socket 客户端 =====================

def xdp_socket_client_loop():
    """
    后端作为 Unix Socket 客户端，
    主动连接XDP Loader loader 创建的 /tmp/xdp_loader.sock。

    loader 发送 JSON Lines：
    一行一个 JSON。
    """
    while True:
        client = None

        try:
            if not os.path.exists(XDP_SOCKET_PATH):
                print(f"等待XDP Loader loader 启动：{XDP_SOCKET_PATH}")
                time.sleep(2)
                continue

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(XDP_SOCKET_PATH)

            print(f"✅ 后端已连接XDP Loader loader：{XDP_SOCKET_PATH}")
            logging.info(f"已连接 XDP loader socket: {XDP_SOCKET_PATH}")

            buffer = ""

            while True:
                chunk = client.recv(4096)

                if not chunk:
                    print("⚠️ loader 连接断开，准备重连")
                    logging.warning("XDP loader socket disconnected")
                    break

                buffer += chunk.decode("utf-8", errors="ignore")

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        msg = json.loads(line)
                        handle_xdp_msg(msg)
                    except json.JSONDecodeError:
                        print("❌ JSON 解析失败：", line)
                        logging.error(f"JSON parse failed: {line}")

        except PermissionError:
            print("❌ 权限不足，无法连接 XDP Socket")
            print("请执行：sudo chmod 666 /tmp/xdp_loader.sock")
            logging.error("Permission denied when connecting XDP socket")
            time.sleep(3)

        except ConnectionRefusedError:
            print("⚠️ XDP Socket 拒绝连接，等待重试")
            time.sleep(2)

        except Exception as e:
            print("❌ Unix Socket 客户端异常：", str(e))
            logging.error(f"Unix Socket client error: {str(e)}")
            time.sleep(3)

        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass


# ===================== WebSocket =====================

@socketio.on("connect")
def handle_connect():
    print("✅ 前端 WebSocket 已连接")


@socketio.on("disconnect")
def handle_disconnect():
    print("❌ 前端 WebSocket 已断开")


# ===================== 首页路由（托管 Dashboard） =====================

# dashboard.html 位于项目根目录：libbpf-bootstrap/dashboard.html
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@app.route("/")
def index():
    from flask import send_from_directory
    return send_from_directory(DASHBOARD_DIR, "dashboard.html")


# ===================== HTTP API =====================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/alert", methods=["POST"])
def add_alert():
    """
    保留 HTTP 告警接口，方便 Postman/curl 单独测试。
    真正联调时，告警主要来自 /tmp/xdp_loader.sock。
    """
    try:
        msg = request.get_json() or {}
        data = save_alert(msg)
        return jsonify({"code": 200, "msg": "success", "data": data})
    except Exception as e:
        logging.error(f"新增告警失败：{str(e)}")
        return jsonify({"code": 500, "msg": "新增失败", "error": str(e)}), 500


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, src_ip, dst_ip, alert_type, attack_type, src_loc, timestamp_ns
            FROM alerts
            ORDER BY id DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        conn.close()

        data = []
        for r in rows:
            data.append({
                "id": r[0],
                "src_ip": r[1],
                "dst_ip": r[2],
                "alert_type": r[3],
                "attack_type": r[4],
                "src_loc": r[5],
                "timestamp_ns": r[6]
            })

        return jsonify({"code": 200, "data": data})

    except Exception as e:
        return jsonify({"code": 500, "msg": "查询失败", "error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cur.fetchone()[0]

        cur.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
        type_count = dict(cur.fetchall())

        cur.execute("""
            SELECT ip, pps, bytes_per_sec, total_pkts, total_bytes, timestamp
            FROM flow_rates
            ORDER BY id DESC
            LIMIT 10
        """)
        flow_rows = cur.fetchall()

        conn.close()

        latest_flows = []
        for r in flow_rows:
            latest_flows.append({
                "ip": r[0],
                "pps": r[1],
                "bytes_per_sec": r[2],
                "total_pkts": r[3],
                "total_bytes": r[4],
                "timestamp": r[5]
            })

        return jsonify({
            "code": 200,
            "total_alerts": total_alerts,
            "type_count": type_count,
            "latest_flows": latest_flows
        })

    except Exception as e:
        return jsonify({"code": 500, "msg": "统计失败", "error": str(e)}), 500


@app.route("/api/alert/clear", methods=["DELETE"])
def clear_all():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM alerts")
        cur.execute("DELETE FROM flow_rates")
        conn.commit()
        conn.close()

        return jsonify({"code": 200, "msg": "已清空"})
    except Exception as e:
        return jsonify({"code": 500, "msg": "清空失败", "error": str(e)}), 500



def get_local_ip():
    """
    获取当前虚拟机局域网 IP，用于提示前端访问地址。
    如果获取失败，则返回 127.0.0.1。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ===================== 启动入口 =====================

if __name__ == "__main__":
    t = threading.Thread(target=xdp_socket_client_loop, daemon=True)
    t.start()

    print("=" * 60)
    print("✅ Flask 告警后端已启动")
    print("✅ HTTP API: http://0.0.0.0:5000")
    local_ip = get_local_ip()
    print(f"✅ 前端跨主机访问地址: http://{local_ip}:5000")
    print(f"✅ WebSocket 地址: http://{local_ip}:5000")
    print(f"✅ Unix Socket 客户端目标: {XDP_SOCKET_PATH}")
    print("=" * 60)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )
