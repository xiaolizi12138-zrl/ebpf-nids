# Flask 后端模块使用说明

## 1. 模块负责人

负责人：Backend Team  
模块名称：Flask 后端服务  
模块目录：backend_flask

本模块负责接收XDP Loader loader 发来的告警和流速数据，调用算法模型接口，将结果写入数据库，并通过 HTTP API 和 WebSocket 提供给前端使用。

---

## 2. 模块职责

本模块主要完成以下功能：

1. 提供 Flask HTTP API；
2. 使用 SQLite 存储告警和流速数据；
3. 作为 Unix Socket 客户端连接XDP Loader loader；
4. 从 /tmp/xdp_loader.sock 接收 JSON Lines 数据；
5. 收到 alert 告警后调用 inference.py 模型接口；
6. 将告警识别结果写入 alerts 表；
7. 将流速数据写入 flow_rates 表；
8. 使用 Flask-SocketIO 向前端实时推送告警；
9. 使用 Flask-SocketIO 向前端实时推送流速；
10. 支持 CORS，允许前端跨主机访问；
11. 支持手动 HTTP 告警测试，方便后端独立调试。

---

## 3. 当前支持的告警类型

    alert_type = 1    attack_type = syn_flood
    alert_type = 2    attack_type = port_scan

说明：

    syn_flood
        SYN Flood 攻击告警。

    port_scan
        端口扫描告警。

注意：

    当前模型 inference.py 只判断正常或攻击。
    具体攻击类型 syn_flood 或 port_scan 由 XDP 告警中的 alert_name 字段确定。
    当 XDP 已经产生告警时，后端仍会调用模型，但最终 attack_type 以 XDP 的 alert_name 为准。

---

## 4. 目录结构

建议提交目录结构如下：

    backend_flask/
    ├── app.py
    ├── inference.py
    ├── rf_final.pkl
    ├── web_rules.pkl
    ├── requirements.txt
    ├── README_BACKEND.md
    └── .gitignore

文件说明：

    app.py
        后端主程序，包含 Flask API、Unix Socket 客户端、SQLite 写入和 WebSocket 推送。

    inference.py
        模型调用接口文件，提供 predict(features: list) -> int 函数。

    rf_final.pkl
        随机森林模型文件，必须与 inference.py 放在同一目录下。

    web_rules.pkl
        模型包中附带的规则文件，建议随模型一起保留。

    requirements.txt
        Python 依赖文件。

    README_BACKEND.md
        后端模块使用说明文档。

    .gitignore
        Git 忽略配置文件，用于忽略 venv、日志、数据库、缓存等运行生成文件。

---

## 5. 环境要求

推荐环境：

    Ubuntu 22.04
    Python >= 3.10
    Flask
    Flask-SocketIO
    Flask-CORS
    requests
    simple-websocket
    numpy
    scikit-learn
    pandas

安装依赖：

    cd backend_flask
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

requirements.txt 内容：

    flask
    flask-socketio
    flask-cors
    requests
    simple-websocket
    numpy
    scikit-learn
    pandas

如果网络较慢或解析失败，可以使用国内镜像安装模型依赖：

    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple numpy scikit-learn pandas

---

## 6. 启动前置条件

启动后端前，需要先启动XDP Loader loader，并确保存在：

    /tmp/xdp_loader.sock

如果 loader 未启动，后端会持续输出：

    等待XDP Loader loader 启动：/tmp/xdp_loader.sock

当 loader 启动成功后，后端会自动连接，并输出：

    后端已连接XDP Loader loader：/tmp/xdp_loader.sock

---

## 7. 模型文件准备

后端目录中需要有以下模型相关文件：

    inference.py
    rf_final.pkl
    web_rules.pkl

其中：

    inference.py
        模型调用接口文件。

    rf_final.pkl
        模型文件，inference.py 会加载该文件。

    web_rules.pkl
        模型包附带文件，建议保留。

如果模型压缩包已经放在后端目录，例如：

    模型.zip

可以执行：

    cd backend_flask
    unzip 模型.zip -d model_tmp

然后复制模型文件：

    cp "$(find model_tmp -name 'inference1.py' | head -n 1)" ./inference.py
    cp "$(find model_tmp -name 'rf_final.pkl' | head -n 1)" ./rf_final.pkl
    cp "$(find model_tmp -name 'web_rules.pkl' | head -n 1)" ./web_rules.pkl

确认模型文件存在：

    ls inference.py rf_final.pkl web_rules.pkl

---

## 8. inference.py 模型接口说明

inference.py 是模型调用接口文件。

后端调用方式：

    from inference import predict

函数签名：

    predict(features: list) -> int

当前模型输入为 15 个特征，返回值说明：

    0 = 正常流量
    1 = 攻击流量

当前模型只判断正常或攻击，不直接区分 syn_flood 或 port_scan。

因此：

    1. 后端收到 XDP 告警后，会调用 inference.py；
    2. 如果模型返回 0，表示模型认为该特征更接近正常流量；
    3. 如果模型返回 1，表示模型认为该特征更接近攻击流量；
    4. 当 XDP 已经产生 alert 告警时，最终 attack_type 以 XDP 发来的 alert_name 为准；
    5. 这样可以避免模型把已经由 XDP 规则检测出的 syn_flood 或 port_scan 覆盖成 normal。

测试模型是否能加载：

    cd backend_flask
    source venv/bin/activate

    python3 - <<'PY'
    from inference import FEATURE_LIST, predict

    print("特征数量:", len(FEATURE_LIST))

    test_feat = [
        12000, 8, 6, 500, 300,
        100, 40, 90, 30,
        8000, 70,
        1500, 1400,
        2, 10
    ]

    print("预测结果:", predict(test_feat))
    PY

正常输出应包含：

    特征数量: 15
    预测结果: 0 或 1

---

## 9. 启动后端

进入后端目录：

    cd backend_flask

激活虚拟环境：

    source venv/bin/activate

启动后端：

    python3 app.py

正常输出示例：

    Flask 告警后端已启动
    HTTP API: http://0.0.0.0:5000
    Unix Socket 客户端目标: /tmp/xdp_loader.sock
    后端已连接XDP Loader loader：/tmp/xdp_loader.sock

如果后端一直输出：

    等待XDP Loader loader 启动：/tmp/xdp_loader.sock

说明XDP Loader loader 尚未启动，或者 /tmp/xdp_loader.sock 没有创建成功。

---

## 10. 本机测试

健康检查：

    curl http://127.0.0.1:5000/api/health

正常返回：

    {"status":"ok"}

查询告警：

    curl http://127.0.0.1:5000/api/alerts

查询统计：

    curl http://127.0.0.1:5000/api/stats

清空数据：

    curl -X DELETE http://127.0.0.1:5000/api/alert/clear

---

## 11. 前端跨主机访问

后端监听：

    0.0.0.0:5000

前端访问地址：

    http://后端虚拟机IP:5000

示例：

    http://192.168.43.204:5000

前端不能写：

    http://127.0.0.1:5000

除非前端和后端在同一台机器上运行。

如果前端和后端在不同主机上，需要保证：

    1. 两台设备在同一局域网或同一手机热点下；
    2. 后端虚拟机能被前端主机访问；
    3. Flask 后端 host="0.0.0.0"；
    4. 防火墙放行 5000 端口。

查看后端虚拟机 IP：

    hostname -I

放行 5000 端口：

    sudo ufw allow 5000

---

## 12. HTTP API

### 12.1 健康检查

请求：

    GET /api/health

完整地址：

    http://后端虚拟机IP:5000/api/health

返回：

    {"status":"ok"}

---

### 12.2 查询最近 100 条告警

请求：

    GET /api/alerts

完整地址：

    http://后端虚拟机IP:5000/api/alerts

返回示例：

    {
      "code": 200,
      "data": [
        {
          "id": 1,
          "src_ip": "127.0.0.1",
          "dst_ip": "127.0.0.1",
          "alert_type": "1",
          "attack_type": "syn_flood",
          "src_loc": "内网-局域网",
          "timestamp_ns": 123456789
        },
        {
          "id": 2,
          "src_ip": "127.0.0.1",
          "dst_ip": "127.0.0.1",
          "alert_type": "2",
          "attack_type": "port_scan",
          "src_loc": "内网-局域网",
          "timestamp_ns": 222222222
        }
      ]
    }

字段说明：

    id
        数据库告警 ID。

    src_ip
        源 IP。

    dst_ip
        目的 IP。

    alert_type
        告警类型编号。
        1 表示 SYN Flood。
        2 表示端口扫描。

    attack_type
        攻击类型名称。
        syn_flood 或 port_scan。

    src_loc
        源 IP 属地。

    timestamp_ns
        告警时间戳，单位 ns。

---

### 12.3 查询统计数据

请求：

    GET /api/stats

完整地址：

    http://后端虚拟机IP:5000/api/stats

返回示例：

    {
      "code": 200,
      "total_alerts": 2,
      "type_count": {
        "1": 1,
        "2": 1
      },
      "latest_flows": [
        {
          "ip": "127.0.0.1",
          "pps": 100,
          "bytes_per_sec": 8400,
          "total_pkts": 1000,
          "total_bytes": 84000,
          "timestamp": 1780544095
        }
      ]
    }

字段说明：

    total_alerts
        当前告警总数。

    type_count
        按 alert_type 分组后的告警数量。

    latest_flows
        最近的流速统计数据。

---

### 12.4 手动新增告警测试

请求：

    POST /api/alert

该接口主要用于后端单独测试，不经过 XDP 和 loader。

测试 SYN Flood：

    curl -X POST http://127.0.0.1:5000/api/alert \
      -H "Content-Type: application/json" \
      -d '{"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","alert_type":1,"alert_name":"syn_flood","timestamp_ns":111111111}'

测试端口扫描：

    curl -X POST http://127.0.0.1:5000/api/alert \
      -H "Content-Type: application/json" \
      -d '{"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","alert_type":2,"alert_name":"port_scan","timestamp_ns":222222222}'

成功返回示例：

    {
      "code": 200,
      "msg": "success",
      "data": {
        "id": 1,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "alert_type": "2",
        "attack_type": "port_scan",
        "src_loc": "内网-局域网",
        "timestamp_ns": 222222222
      }
    }

---

### 12.5 清空测试数据

请求：

    DELETE /api/alert/clear

命令：

    curl -X DELETE http://127.0.0.1:5000/api/alert/clear

返回：

    {
      "code": 200,
      "msg": "已清空"
    }

---

## 13. WebSocket 对接说明

后端使用 Flask-SocketIO，前端使用 Socket.IO 客户端连接。

前端连接地址：

    http://后端虚拟机IP:5000

示例：

    const BACKEND = "http://192.168.43.204:5000";
    const socket = io(BACKEND);

连接成功事件：

    socket.on("connect", () => {
        console.log("WebSocket 已连接");
    });

断开事件：

    socket.on("disconnect", () => {
        console.log("WebSocket 已断开");
    });

---

## 14. 实时告警事件

事件名：

    new_alarm

数据示例：

    {
      "id": 1,
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "alert_type": "2",
      "attack_type": "port_scan",
      "src_loc": "内网-局域网",
      "timestamp_ns": 222222222
    }

前端监听示例：

    socket.on("new_alarm", (data) => {
        console.log("收到实时告警：", data);
    });

---

## 15. 实时流速事件

事件名：

    flow_rate

数据示例：

    {
      "ip": "127.0.0.1",
      "pps": 100,
      "bytes_per_sec": 8400,
      "total_pkts": 1000,
      "total_bytes": 84000,
      "timestamp": 1780544095
    }

前端监听示例：

    socket.on("flow_rate", (data) => {
        console.log("收到实时流速：", data);
    });

字段说明：

    ip
        源 IP。

    pps
        每秒包数。

    bytes_per_sec
        每秒字节数。

    total_pkts
        累计包数。

    total_bytes
        累计字节数。

    timestamp
        时间戳。

---
以下命令默认从 project_submit 根目录执行。
## 16. 与XDP Loader loader 联调顺序

终端 1：启动 loader

    cd ebpf_control
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

终端 2：启动后端

    cd backend_flask
    source venv/bin/activate
    python3 app.py

终端 3：测试 SYN Flood

    sudo hping3 -S -p 80 --flood 127.0.0.1

终端 4：测试端口扫描

    sudo nmap -sS -p 1-100 127.0.0.1

成功时：

    loader 终端出现 type=1(syn_flood) 或 type=2(port_scan)
    Flask 后端显示收到 XDP 告警并写入数据库
    前端通过 WebSocket 实时收到 new_alarm
    /api/alerts 能查询到告警记录

---

## 17. 常见问题

### 17.1 curl 127.0.0.1:5000 失败

报错：

    Connection refused

原因：

    Flask 后端没有启动，或者 app.py 启动失败。

解决：

    cd backend_flask
    source venv/bin/activate
    python3 app.py

---

### 17.2 后端一直等待 /tmp/xdp_loader.sock

现象：

    等待XDP Loader loader 启动：/tmp/xdp_loader.sock

原因：

    loader 没有运行，或者 socket 文件没有创建。

解决：

    cd ebpf_control
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

---

### 17.3 模型文件找不到

报错可能包含：

    FileNotFoundError: rf_final.pkl

原因：

    rf_final.pkl 没有放到 backend_flask 目录下。

解决：

    cd backend_flask
    ls rf_final.pkl

如果没有，重新复制模型文件到 backend_flask 目录。

---

### 17.4 numpy、sklearn 或 pandas 缺失

报错可能包含：

    ModuleNotFoundError: No module named 'numpy'
    ModuleNotFoundError: No module named 'sklearn'
    ModuleNotFoundError: No module named 'pandas'

解决：

    cd backend_flask
    source venv/bin/activate
    pip install -r requirements.txt

如果网络不好，可以使用国内镜像：

    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple numpy scikit-learn pandas

---

### 17.5 后端把攻击识别成 normal

如果 loader 已经输出：

    type=1(syn_flood)

但后端写入：

    attack_type: normal

说明模型结果覆盖了 XDP 告警类型。

正确逻辑应为：

    XDP 已经产生 alert 时，以 XDP 的 alert_name 为最终 attack_type。
    模型仍然调用，但不覆盖 XDP 的 syn_flood 或 port_scan。

需要检查 app.py 中的 call_inference 函数。

---



