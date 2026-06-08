#!/bin/bash
# eBPF-NIDS 一键启动脚本

echo "=========================================="
echo "  eBPF-NIDS 启动脚本"
echo "=========================================="

INTERFACE=${INTERFACE:-lo}

# 1. 启动 XDP 控制面
echo "[1/3] 启动 XDP 控制面..."
cd project_submit/ebpf_control
make
sudo ./loader -c conf/xdp_loader.conf &
LOADER_PID=$!
echo "  ✅ XDP Loader PID: $LOADER_PID"
cd ../..

sleep 2

# 2. 启动后端 Flask
echo "[2/3] 启动后端 Flask 服务..."
cd project_submit/backend_flask
python3 app.py &
FLASK_PID=$!
echo "  ✅ Flask PID: $FLASK_PID"
cd ../..

sleep 3

# 3. 完成
echo "[3/3] 启动完成！"
echo ""
echo "  Dashboard: http://localhost:5000"
echo "  Docker模式: docker-compose up -d"
echo ""
echo "按 Ctrl+C 停止所有服务"

# 等待
wait
