#!/usr/bin/env python3
"""
eBPF 网络攻击检测系统 - 后端 API 服务
提供数据接口 + WebSocket 实时推送
"""

import json
import time
import random
import threading
import sqlite3
import os
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ebpf-dashboard-secret'
CORS(app)

# SocketIO 初始化（支持 WebSocket）
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# ================================================================
#  数据库初始化（SQLite）
# ================================================================

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'alerts.db')

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            dst_ip TEXT,
            attack_type TEXT,
            src_loc TEXT DEFAULT '未知',
            timestamp REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ================================================================
#  模拟数据生成（无后端时页面也能有数据）
# ================================================================

ATTACK_TYPES = ['syn_flood', 'port_scan', 'ssh_brute', 'dns_amp', 'other']
PROVINCES = ['北京', '上海', '广州', '深圳', '杭州', '成都', '武汉', '南京',
             '西安', '重庆', '长沙', '郑州', '济南', '沈阳', '昆明']
CITIES = {
    '北京': '北京', '上海': '上海', '广州': '广东', '深圳': '广东',
    '杭州': '浙江', '成都': '四川', '武汉': '湖北', '南京': '江苏',
    '西安': '陕西', '重庆': '重庆', '长沙': '湖南', '郑州': '河南',
    '济南': '山东', '沈阳': '辽宁', '昆明': '云南'
}

# 模拟流量数据
sim_flows = []
sim_total_alerts = 0
sim_alerts = []
sim_lock = threading.Lock()

def random_ip():
    return f"{random.randint(10, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_mock_flow():
    """生成一条模拟流量记录"""
    province = random.choice(PROVINCES)
    return {
        'ip': random_ip(),
        'bytes_per_sec': random.randint(50000, 5000000),
        'total_bytes': random.randint(100000, 50000000),
        'pps': random.randint(10, 2000),
        'timestamp': time.time(),
        'src_loc': f"{CITIES[province]} {province}",
    }

def generate_mock_alert():
    """生成一条模拟告警"""
    attack_type = random.choice(ATTACK_TYPES)
    province = random.choice(PROVINCES)
    return {
        'src_ip': random_ip(),
        'dst_ip': random_ip(),
        'attack_type': attack_type,
        'src_loc': f"{CITIES[province]} {province}",
        'timestamp_ns': int(time.time() * 1000),
    }

def background_data_generator():
    """后台线程：定期生成模拟数据"""
    global sim_total_alerts
    while True:
        time.sleep(3)
        with sim_lock:
            # 更新流量数据（保持3-8条）
            sim_flows.append(generate_mock_flow())
            if len(sim_flows) > 8:
                sim_flows.pop(0)

            # 随机生成告警（30%概率）
            if random.random() < 0.3:
                alert = generate_mock_alert()
                sim_alerts.append(alert)
                sim_total_alerts += 1
                if len(sim_alerts) > 50:
                    sim_alerts.pop(0)

                # 通过 WebSocket 实时推送
                try:
                    socketio.emit('alert', json.dumps(alert))
                except:
                    pass

# ================================================================
#  API 路由
# ================================================================

@app.route('/api/health')
def health():
    """健康检查"""
    return jsonify({'status': 'ok', 'timestamp': time.time()})

@app.route('/api/stats')
def stats():
    """获取实时统计数据"""
    with sim_lock:
        # 攻击类型统计
        type_count = {}
        for a in sim_alerts:
            t = a['attack_type']
            type_count[t] = type_count.get(t, 0) + 1

        return jsonify({
            'latest_flows': sim_flows[-10:] if sim_flows else [],
            'total_alerts': sim_total_alerts,
            'type_count': type_count,
        })

@app.route('/api/alerts')
def alerts():
    """获取告警历史"""
    limit = request.args.get('limit', 20, type=int)
    with sim_lock:
        data = sim_alerts[-limit:]
    return jsonify({'data': data})

# ================================================================
#  WebSocket 事件
# ================================================================

@socketio.on('connect')
def handle_connect():
    print(f'[WS] 客户端已连接')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'[WS] 客户端已断开')

# ================================================================
#  启动
# ================================================================

if __name__ == '__main__':
    print('=' * 50)
    print('  eBPF 网络攻击检测系统 - 后端服务')
    print('  API:  http://0.0.0.0:5000')
    print('  WS:   ws://0.0.0.0:5000')
    print('=' * 50)

    # 启动后台数据生成线程
    bg = threading.Thread(target=background_data_generator, daemon=True)
    bg.start()

    # 启动 Flask-SocketIO 服务
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
