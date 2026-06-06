# eBPF 控制面运行说明

## 1. 功能说明

本模块为 eBPF-NIDS 的用户态控制面模块，用于加载 XDP 数据面程序、读取内核态统计数据、接收 Ring Buffer 告警，并通过 Unix Socket 将告警和流速数据发送给 Flask 后端。

完整运行链路如下：

    XDP 数据面
        ↓
    loader 用户态控制面
        ↓
    /tmp/xdp_loader.sock
        ↓
    Flask 后端
        ↓
    SQLite / WebSocket
        ↓
    前端页面

当前支持的告警类型：

    alert_type = 1    syn_flood
    alert_type = 2    port_scan

---

## 2. 文件说明

本模块目录结构如下：

    ebpf_control/
    ├── src/
    │   ├── loader.c
    │   └── xdp_blacklist.bpf.c
    ├── conf/
    │   └── xdp_loader.conf
    ├── scripts/
    │   └── setup_env.sh
    ├── Makefile
    ├── README_RUN.md
    └── README_EBPF_CONTROL.md

文件说明：

    src/loader.c
        用户态控制面核心程序，负责加载 XDP、读取 Map、接收 Ring Buffer、计算流速并通过 Unix Socket 发送数据。

    src/xdp_blacklist.bpf.c
        XDP 数据面程序，负责黑名单过滤、SYN Flood 检测、端口扫描检测、流量统计和 Ring Buffer 告警。

    conf/xdp_loader.conf
        loader 运行配置文件。

    scripts/setup_env.sh
        Ubuntu 22.04 环境依赖安装脚本。

    Makefile
        编译脚本，用于生成 BPF 目标文件、skeleton 头文件和 loader 可执行程序。

---

## 3. 环境要求

推荐环境：

    Ubuntu 22.04
    Linux Kernel >= 5.15
    clang >= 14
    bpftool 可用
    libbpf-dev
    gcc
    make
    hping3
    nmap
    python3 >= 3.10

检查环境：

    uname -r
    clang --version
    bpftool version
    python3 --version

安装依赖：

    chmod +x scripts/setup_env.sh
    ./scripts/setup_env.sh

检查项目环境：

    make check-env

---

## 4. 编译方法

进入模块目录：

    cd ebpf_control

或者在当前提交包中：

    cd ~/Downloads/project_submit/ebpf_control

执行编译：

    make clean
    make

编译成功后会生成：

    loader
    xdp_blacklist.bpf.o
    xdp_blacklist.skel.h

其中：

    loader
        用户态控制程序。

    xdp_blacklist.bpf.o
        eBPF/XDP 目标文件。

    xdp_blacklist.skel.h
        bpftool 根据 XDP 目标文件生成的 skeleton 头文件。

---

## 5. 配置文件说明

配置文件路径：

    conf/xdp_loader.conf

推荐本地虚拟机测试配置：

    ifname=lo
    xdp_mode=skb
    socket_path=/tmp/xdp_loader.sock
    log_file=/tmp/xdp_loader.log
    stats_interval_sec=5
    daemon=0

字段说明：

    ifname
        XDP 挂载网卡。
        本地测试建议使用 lo。
        如果测试真实网卡，可以改为 ens33、eth0 等。

    xdp_mode
        XDP 模式。
        虚拟机或 lo 测试建议使用 skb。
        真实网卡支持驱动模式时可以改为 drv。

    socket_path
        Unix Domain Socket 路径。
        loader 作为服务端，Flask 后端作为客户端连接该路径。

    log_file
        loader 日志文件路径。

    stats_interval_sec
        流速统计周期，单位为秒。

    daemon
        是否后台运行。
        0 表示前台运行。
        1 表示后台运行。

---

## 6. 启动 loader

进入模块目录：

    cd ~/Downloads/project_submit/ebpf_control

启动 loader：

    sudo pkill loader 2>/dev/null
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

正常输出应包含：

    配置文件: conf/xdp_loader.conf
    Unix Socket 服务端已启动: /tmp/xdp_loader.sock
    XDP 程序已附加到接口: lo
    Ring Buffer 已就绪
    开始运行：读取 flow_stats、接收 RingBuffer、向后端发送 JSON Lines

该终端不要关闭。

停止 loader：

    Ctrl + C

---

## 7. 启动 Flask 后端联调

另开一个终端，进入后端目录：

    cd ~/Downloads/project_submit/backend_flask

创建并激活 Python 虚拟环境：

    python3 -m venv venv
    source venv/bin/activate

安装依赖：

    pip install -r requirements.txt

启动后端：

    python3 app.py

后端正常连接 loader 后，应显示：

    后端已连接占强强 loader：/tmp/xdp_loader.sock

如果后端一直显示：

    等待占强强 loader 启动：/tmp/xdp_loader.sock

说明 loader 没有运行，或者 /tmp/xdp_loader.sock 没有创建成功，需要先启动 loader。

---

## 8. loader 与后端通信格式

loader 通过 Unix Domain Socket 向 Flask 后端发送 JSON Lines。

Socket 路径：

    /tmp/xdp_loader.sock

通信格式：

    一行一个 JSON
    每条 JSON 以换行符结束

### 8.1 告警消息示例

SYN Flood 告警：

    {
      "type": "alert",
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "alert_type": 1,
      "alert_name": "syn_flood",
      "timestamp_ns": 123456789
    }

端口扫描告警：

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
        1 表示 syn_flood。
        2 表示 port_scan。

    alert_name
        告警类型名称。

    timestamp_ns
        内核态告警时间戳，单位 ns。

### 8.2 流速消息示例

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

## 9. SYN Flood 测试

保持以下两个终端运行：

    终端 1：loader
    终端 2：Flask 后端

另开终端执行：

    sudo hping3 -S -p 80 --flood 127.0.0.1

运行 3 到 5 秒后按：

    Ctrl + C

成功时，loader 终端应出现：

    type=1(syn_flood)

后端终端应出现：

    attack_type = syn_flood

或者类似：

    'alert_type': '1', 'attack_type': 'syn_flood'

---

## 10. 端口扫描测试

如果未安装 nmap，先执行：

    sudo apt install -y nmap

保持 loader 和 Flask 后端运行，另开终端执行：

    sudo nmap -sS -p 1-100 127.0.0.1

成功时，loader 终端应出现：

    type=2(port_scan)

后端终端应出现：

    attack_type = port_scan

或者类似：

    'alert_type': '2', 'attack_type': 'port_scan'

---

## 11. 后端接口验证

后端启动后，可以在新终端中测试：

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

## 12. 与前端联调

Flask 后端监听：

    0.0.0.0:5000

查看后端虚拟机 IP：

    hostname -I

假设后端虚拟机 IP 为：

    192.168.43.204

前端访问健康检查：

    http://192.168.43.204:5000/api/health

前端 WebSocket 地址：

    const BACKEND = "http://192.168.43.204:5000";
    const socket = io(BACKEND);

前端监听实时告警：

    socket.on("new_alarm", (data) => {
        console.log("收到实时告警：", data);
    });

前端监听实时流速：

    socket.on("flow_rate", (data) => {
        console.log("收到实时流速：", data);
    });

注意：

    跨主机访问时，前端不要写 127.0.0.1。
    127.0.0.1 只代表前端电脑自己。

---

## 13. 完整联调启动顺序

推荐按以下顺序运行。

终端 1：启动 loader

    cd ~/Downloads/project_submit/ebpf_control
    make clean
    make
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

终端 2：启动 Flask 后端

    cd ~/Downloads/project_submit/backend_flask
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python3 app.py

终端 3：检查后端

    curl http://127.0.0.1:5000/api/health

终端 4：测试 SYN Flood

    sudo hping3 -S -p 80 --flood 127.0.0.1

或测试端口扫描：

    sudo nmap -sS -p 1-100 127.0.0.1

成功链路：

    XDP 数据面
        ↓
    loader 用户态控制面
        ↓
    /tmp/xdp_loader.sock
        ↓
    Flask 后端
        ↓
    SQLite / WebSocket
        ↓
    前端

---

## 14. 常见问题

### 14.1 后端一直等待 /tmp/xdp_loader.sock

现象：

    等待占强强 loader 启动：/tmp/xdp_loader.sock

原因：

    loader 没有运行，或者 socket 文件没有创建。

解决：

    cd ~/Downloads/project_submit/ebpf_control
    sudo rm -f /tmp/xdp_loader.sock
    sudo ./loader -c conf/xdp_loader.conf

### 14.2 curl 127.0.0.1:5000 失败

现象：

    Connection refused

原因：

    Flask 后端没有启动，或者 app.py 启动失败。

解决：

    cd ~/Downloads/project_submit/backend_flask
    source venv/bin/activate
    python3 app.py

### 14.3 make 编译失败

解决：

    make check-env
    make clean
    make

如果缺少依赖，重新执行：

    chmod +x scripts/setup_env.sh
    ./scripts/setup_env.sh

### 14.4 前端访问不到后端

检查后端虚拟机 IP：

    hostname -I

检查 Flask 是否监听 5000：

    ss -lntp | grep 5000

应看到：

    0.0.0.0:5000

如果防火墙开启，放行 5000 端口：

    sudo ufw allow 5000

---

## 15. 停止和清理

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

