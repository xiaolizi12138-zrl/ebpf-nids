#!/bin/bash
# eBPF-NIDS 停止脚本

echo "停止 eBPF-NIDS..."

# 停止 loader
sudo pkill loader 2>/dev/null && echo "✅ Loader 已停止"

# 停止 Flask
sudo pkill -f "python3 app.py" 2>/dev/null && echo "✅ Flask 已停止"

# 清理 XDP 程序
sudo bpftool net detach xdpgeneric dev lo 2>/dev/null
sudo rm -f /sys/fs/bpf/xdp_blacklist 2>/dev/null

echo "✅ 所有服务已停止"
