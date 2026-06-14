# eBPF-NIDS 使用说明文档

## 1. 项目说明

本提交包包含两个主要模块：

    ebpf_control      XDP Loader eBPF 控制面模块
    backend_flask     Flask 后端模块

系统完整运行链路如下：

    XDP 数据面程序
        ↓
    loader 用户态控制面
        ↓
    /tmp/xdp_loader.sock
        ↓
    Flask 后端
        ↓
    SQLite 数据库 / WebSocket 实时推送
        ↓
    前端页面

当前支持的告警类型：

    alert_type = 1    syn_flood
    alert_type = 2    port_scan

其中：

    syn_flood 表示 SYN Flood 攻击
    port_scan 表示端口扫描攻击

---

## 2. 目录结构

    project_submit/
    ├── README.md
    ├── ebpf_control/
    │   ├── src/
    │   │   ├── loader.c
    │   │   └── xdp_blacklist.bpf.c
    │   ├── conf/
    │   │   └── xdp_loader.conf
    │   ├── scripts/
    │   │   └── setup_env.sh
    │   ├── Makefile
    │   └── README_RUN.md
    │
    └── backend_flask/
        ├── app.py
        ├── inference.py
        ├── rf_final.pkl
        ├── web_rules.pkl
        ├── requirements.txt
        ├── README_BACKEND.md
        └── .gitignore

说明：

    ebpf_control/src/loader.c
        XDP Loader用户态控制面核心程序。

    ebpf_control/src/xdp_blacklist.bpf.c
        XDP 数据面程序，用于黑名单过滤、SYN Flood 检测、端口扫描检测、流量统计和 Ring Buffer 告警。

    ebpf_control/conf/xdp_loader.conf
        loader 运行配置文件。

    ebpf_control/scripts/setup_env.sh
        Ubuntu 22.04 环境依赖安装脚本。

    backend_flask/app.py
        Flask 后端主程序。

    backend_flask/inference.py
        模型调用接口文件。

    backend_flask/rf_final.pkl
        随机森林模型文件。

    backend_flask/web_rules.pkl
        模型包附带规则文件，随模型一起保留。

---

## 3. 运行环境要求

推荐环境：

    Ubuntu 22.04
    Linux Kernel >= 5.15
    clang >= 14
    bpftool
    libbpf-dev
    gcc
    make
    python3 >= 3.10
    hping3
    nmap

检查环境：

    uname -r
    clang --version
    bpftool version
    python3 --version

---

## 4. 安装 eBPF 控制面依赖

进入 eBPF 控制面目录：

    cd ebpf_control

执行环境安装脚本：

    chmod +x scripts/setup_env.sh
    ./scripts/setup_env.sh

检查项目环境：

    make check-env

---

## 5. 编译 loader

进入 eBPF 控制面目录：

    cd ebpf_control

编译：

    make clean
    make

编译成功后会生成：

    loader
    xdp_blacklist.bpf.o
    xdp_blacklist.skel.h

---

## 6. 配置 loader

配置文件路径：

    ebpf_control/conf/xdp_loader.conf

推荐本地虚拟机测试配置：

    ifname=lo
    xdp_mode=skb
    socket_path=/tmp/xdp_loader.sock
    log_file=/tmp/xdp_loader.log
    stats_interval_sec=5
    daemon=0

字段说明：

    ifname=lo
        XDP 挂载到本机回环网卡，适合本地测试。

    xdp_mode=skb
        虚拟机或 lo 推荐使用 skb 模式。

    socket_path=/tmp/xdp_loader.sock
        loader 创建的 Unix Socket 路径，Flask 后端会连接该路径。

    stats_interval_sec=5
        每 5 秒统计一次流速。

    daemon=0
        前台运行，方便观察终端输出。

---

## 7. 准备 Flask 后端环境

进入后端目录：

    cd backend_flask

创建并激活虚拟环境：

    python3 -m venv venv
    source venv/bin/activate

安装依赖：

    pip install -r requirements.txt

requirements.txt 中包含：

    flask
    flask-socketio
    flask-cors
    requests
    simple-websocket
    numpy
    scikit-learn
    pandas

如果网络较慢，可以使用国内镜像安装部分依赖：

    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple numpy scikit-learn pandas

---

## 8. 模型文件说明

后端目录中应包含：

    inference.py
    rf_final.pkl
    web_rules.pkl

模型调用方式：

    from inference import predict

函数签名：

    predict(features: list) -> int

当前模型输入为 15 个特征，输出含义：

    0 = 正常流量
    1 = 攻击流量

注意：

    当前模型只判断正常或攻击。
    具体攻击类型 syn_flood 或 port_scan 由 XDP 告警字段 alert_name 决定。
    后端会调用模型，但当 XDP 已经产生告警时，最终 attack_type 以 XDP 的 alert_name 为准。

测试模型是否可用：

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

## 9. 启动 loader

打开终端 1，进入 eBPF 控制面目录：

    cd ebpf_control

启动 loader：

    sudo pkill loader 2>/dev/null
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

正常输出应包含：

    Unix Socket 服务端已启动: /tmp/xdp_loader.sock
    XDP 程序已附加到接口: lo
    Ring Buffer 已就绪
    开始运行：读取 flow_stats、接收 RingBuffer、向后端发送 JSON Lines

该终端不要关闭。

---

## 10. 启动 Flask 后端

打开终端 2，进入后端目录：

    cd backend_flask

启动后端：

    source venv/bin/activate
    python3 app.py

正常输出应包含：

    Flask 告警后端已启动
    HTTP API: http://0.0.0.0:5000
    Unix Socket 客户端目标: /tmp/xdp_loader.sock
    后端已连接XDP Loader loader：/tmp/xdp_loader.sock

如果后端一直显示：

    等待XDP Loader loader 启动：/tmp/xdp_loader.sock

说明 loader 没有启动，或者 /tmp/xdp_loader.sock 没有创建成功。

---

## 11. 测试后端接口

打开终端 3，健康检查：

    curl http://127.0.0.1:5000/api/health

正常返回：

    {"status":"ok"}

查询告警：

    curl http://127.0.0.1:5000/api/alerts

查询统计：

    curl http://127.0.0.1:5000/api/stats

清空测试数据：

    curl -X DELETE http://127.0.0.1:5000/api/alert/clear

---

## 12. SYN Flood 真实链路测试

保持以下两个终端运行：

    终端 1：loader
    终端 2：Flask 后端

打开终端 3，执行：

    sudo hping3 -S -p 80 --flood 127.0.0.1

运行 3 到 5 秒后按：

    Ctrl + C

成功现象：

    loader 终端出现：
    type=1(syn_flood)

    Flask 后端终端出现：
    'alert_type': '1', 'attack_type': 'syn_flood'

查询后端接口：

    curl http://127.0.0.1:5000/api/alerts

应能看到：

    "attack_type":"syn_flood"

---

## 13. 端口扫描真实链路测试

如果未安装 nmap，先执行：

    sudo apt install -y nmap

保持 loader 和 Flask 后端运行，打开终端 3 执行：

    sudo nmap -sS -p 1-100 127.0.0.1

成功现象：

    loader 终端出现：
    type=2(port_scan)

    Flask 后端终端出现：
    'alert_type': '2', 'attack_type': 'port_scan'

查询后端接口：

    curl http://127.0.0.1:5000/api/alerts

应能看到：

    "attack_type":"port_scan"

---

## 14. loader 与后端通信接口

通信方式：

    Unix Domain Socket

Socket 路径：

    /tmp/xdp_loader.sock

通信格式：

    JSON Lines，一行一个 JSON。

### 14.1 告警消息格式

SYN Flood 示例：

    {
      "type": "alert",
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "alert_type": 1,
      "alert_name": "syn_flood",
      "timestamp_ns": 123456789
    }

端口扫描示例：

    {
      "type": "alert",
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "alert_type": 2,
      "alert_name": "port_scan",
      "timestamp_ns": 222222222
    }

字段说明：

    type
        消息类型，告警消息固定为 alert。

    src_ip
        源 IP 地址。

    dst_ip
        目的 IP 地址。

    alert_type
        告警类型编号。

    alert_name
        告警类型名称。

    timestamp_ns
        内核态告警时间戳，单位 ns。

### 14.2 流速消息格式

    {
      "type": "flow_rate",
      "ip": "127.0.0.1",
      "pps": 100,
      "bytes_per_sec": 8400,
      "total_pkts": 1000,
      "total_bytes": 84000,
      "timestamp": 1780544095
    }

字段说明：

    type
        消息类型，流速消息固定为 flow_rate。

    ip
        源 IP 地址。

    pps
        每秒包数。

    bytes_per_sec
        每秒字节数。

    total_pkts
        累计包数。

    total_bytes
        累计字节数。

    timestamp
        用户态统计时间戳。

---

## 15. 后端 HTTP API

后端默认监听：

    0.0.0.0:5000

本机访问：

    http://127.0.0.1:5000

跨主机访问：

    http://后端虚拟机IP:5000

接口列表：

    GET    /api/health
    GET    /api/alerts
    GET    /api/stats
    POST   /api/alert
    DELETE /api/alert/clear

### 15.1 健康检查

请求：

    GET /api/health

示例：

    curl http://127.0.0.1:5000/api/health

返回：

    {"status":"ok"}

### 15.2 查询告警

请求：

    GET /api/alerts

示例：

    curl http://127.0.0.1:5000/api/alerts

### 15.3 查询统计

请求：

    GET /api/stats

示例：

    curl http://127.0.0.1:5000/api/stats

### 15.4 手动新增告警

请求：

    POST /api/alert

测试 SYN Flood：

    curl -X POST http://127.0.0.1:5000/api/alert \
      -H "Content-Type: application/json" \
      -d '{"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","alert_type":1,"alert_name":"syn_flood","timestamp_ns":111111111}'

测试端口扫描：

    curl -X POST http://127.0.0.1:5000/api/alert \
      -H "Content-Type: application/json" \
      -d '{"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","alert_type":2,"alert_name":"port_scan","timestamp_ns":222222222}'

### 15.5 清空数据

请求：

    DELETE /api/alert/clear

示例：

    curl -X DELETE http://127.0.0.1:5000/api/alert/clear

---

## 16. WebSocket 前端对接

后端使用 Flask-SocketIO。

前端连接地址：

    const BACKEND = "http://后端虚拟机IP:5000";
    const socket = io(BACKEND);

如果后端虚拟机 IP 为 192.168.43.204，则写：

    const BACKEND = "http://192.168.43.204:5000";
    const socket = io(BACKEND);

实时告警事件：

    new_alarm

监听示例：

    socket.on("new_alarm", (data) => {
        console.log("收到实时告警：", data);
    });

实时流速事件：

    flow_rate

监听示例：

    socket.on("flow_rate", (data) => {
        console.log("收到实时流速：", data);
    });

注意：

    前端跨主机访问时不要写 127.0.0.1。
    127.0.0.1 只代表前端电脑自己。

---

## 17. 完整联调启动顺序

终端 1：启动 loader

    cd ebpf_control
    make clean
    make
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

终端 2：启动 Flask 后端

    cd backend_flask
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python3 app.py

终端 3：检查后端

    curl http://127.0.0.1:5000/api/health

终端 4：测试攻击

    sudo hping3 -S -p 80 --flood 127.0.0.1

或：

    sudo nmap -sS -p 1-100 127.0.0.1

---

## 18. 常见问题

### 18.1 后端一直等待 /tmp/xdp_loader.sock

现象：

    等待XDP Loader loader 启动：/tmp/xdp_loader.sock

原因：

    loader 没有运行，或者 socket 文件没有创建。

解决：

    cd ebpf_control
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

### 18.2 curl 127.0.0.1:5000 失败

现象：

    Connection refused

原因：

    Flask 后端没有启动，或者 app.py 启动失败。

解决：

    cd backend_flask
    source venv/bin/activate
    python3 app.py

### 18.3 make 编译失败

解决：

    cd ebpf_control
    make check-env
    make clean
    make

如果缺少依赖，重新执行：

    chmod +x scripts/setup_env.sh
    ./scripts/setup_env.sh

### 18.4 模型文件找不到

报错可能包含：

    FileNotFoundError: rf_final.pkl

原因：

    rf_final.pkl 没有放到 backend_flask 目录下。

解决：

    cd backend_flask
    ls rf_final.pkl

应能看到：

    rf_final.pkl

### 18.5 numpy、sklearn 或 pandas 缺失

报错可能包含：

    ModuleNotFoundError: No module named 'numpy'
    ModuleNotFoundError: No module named 'sklearn'
    ModuleNotFoundError: No module named 'pandas'

解决：

    cd backend_flask
    source venv/bin/activate
    pip install -r requirements.txt

### 18.6 前端访问不到后端

检查后端虚拟机 IP：

    hostname -I

检查 Flask 是否监听 5000：

    ss -lntp | grep 5000

应看到：

    0.0.0.0:5000

如果防火墙开启，放行 5000 端口：

    sudo ufw allow 5000

---

## 19. 退出和清理

停止攻击工具：

    Ctrl + C

停止 Flask 后端：

    Ctrl + C

停止 loader：

    Ctrl + C

清理 socket：

    sudo rm -f /tmp/xdp_loader.sock

清空后端测试数据：

    curl -X DELETE http://127.0.0.1:5000/api/alert/clear

---

## 20. 详细模块说明

eBPF 控制面详细说明见：

    ebpf_control/README_RUN.md

Flask 后端详细说明见：

    backend_flask/README_BACKEND.md

