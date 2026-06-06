#!/usr/bin/env bash
set -e

echo "== 更新 apt 源 =="
sudo apt update

echo "== 安装基础依赖 =="
sudo apt install -y \
  build-essential git make gcc pkg-config \
  clang llvm \
  libbpf-dev libelf-dev zlib1g-dev \
  linux-headers-$(uname -r) \
  linux-tools-common \
  iproute2 net-tools tcpdump hping3 nmap \
  python3 python3-venv python3-pip \
  valgrind || true

echo "== 检查 bpftool =="
if command -v bpftool >/dev/null 2>&1; then
    bpftool version
else
    echo "未找到 bpftool，尝试安装当前内核 tools..."
    sudo apt install -y linux-tools-$(uname -r) || true

    if command -v bpftool >/dev/null 2>&1; then
        bpftool version
    else
        echo "警告：bpftool 未自动安装成功。"
        echo "Ubuntu 22.04 HWE 内核可能需要手动安装对应 linux-tools 包。"
        echo "可先检查：bpftool version"
    fi
fi

echo "== 环境检查 =="
echo "Kernel:"
uname -r

echo "Clang:"
clang --version | head -n 1 || true

echo "bpftool:"
bpftool version || true

echo "Python:"
python3 --version || true

echo "== 环境安装完成 =="
