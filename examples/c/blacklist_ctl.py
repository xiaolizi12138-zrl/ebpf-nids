#!/usr/bin/env python3
import sys
import struct
import socket
from bcc import BPF

def ip_to_int(ip_str):
    """将 IP 字符串转换为 32 位整数"""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    """将 32 位整数转换为 IP 字符串"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  添加黑名单: python3 blacklist_ctl.py add <IP>")
        print("  删除黑名单: python3 blacklist_ctl.py del <IP>")
        print("  查看黑名单: python3 blacklist_ctl.py list")
        sys.exit(1)

    # 加载 BPF 程序（只为了访问 Map）
    b = BPF(src_file="xdp_blacklist.bpf.c")
    blacklist = b.get_table("blacklist")

    cmd = sys.argv[1]

    if cmd == "add":
        if len(sys.argv) < 3:
            print("请指定要添加的 IP")
            sys.exit(1)
        ip_str = sys.argv[2]
        ip_int = ip_to_int(ip_str)
        blacklist[blacklist.Key(ip_int)] = blacklist.Leaf(1)
        print(f"✅ 已将 {ip_str} 加入黑名单")

    elif cmd == "del":
        if len(sys.argv) < 3:
            print("请指定要删除的 IP")
            sys.exit(1)
        ip_str = sys.argv[2]
        ip_int = ip_to_int(ip_str)
        try:
            del blacklist[blacklist.Key(ip_int)]
            print(f"✅ 已将 {ip_str} 从黑名单移除")
        except KeyError:
            print(f"⚠️ {ip_str} 不在黑名单中")

    elif cmd == "list":
        print("📋 当前黑名单:")
        count = 0
        for key, value in blacklist.items():
            ip_str = int_to_ip(key.value)
            print(f"  ❌ {ip_str}")
            count += 1
        if count == 0:
            print("  (空)")

    else:
        print(f"未知命令: {cmd}")

if __name__ == "__main__":
    main()
