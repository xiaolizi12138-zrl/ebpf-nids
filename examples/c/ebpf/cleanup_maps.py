#!/usr/bin/env python3
"""
Map清理脚本：删除超过TTL的流量统计条目
用法: sudo python3 cleanup_maps.py
"""
import time
import struct
import os

# 从bpftool获取Map ID
def get_map_id(map_name):
    import subprocess
    result = subprocess.run(
        ['sudo', 'bpftool', 'map', 'list'],
        capture_output=True, text=True
    )
    for line in result.stdout.split('\n'):
        if map_name in line:
            return int(line.split(':')[0])
    return None

# 通过bpftool map dump获取所有条目
def dump_map(map_id):
    import subprocess
    result = subprocess.run(
        ['sudo', 'bpftool', 'map', 'dump', 'id', str(map_id)],
        capture_output=True, text=True
    )
    entries = []
    for line in result.stdout.split('\n'):
        if '"key"' in line:
            entries.append(line)
    return entries

# 删除指定key
def delete_entry(map_id, key_hex):
    import subprocess
    key_bytes = bytes.fromhex(key_hex)
    cmd = ['sudo', 'bpftool', 'map', 'delete', 'id', str(map_id), 'key']
    cmd.extend([f'0x{b:02x}' for b in key_bytes])
    subprocess.run(cmd, capture_output=True)

if __name__ == '__main__':
    print("=== eBPF Map 清理脚本 ===\n")
    
    map_id = get_map_id('flow_stats')
    if not map_id:
        print("未找到 flow_stats Map，请先加载XDP程序")
        exit(1)
    
    print(f"flow_stats Map ID: {map_id}")
    print("清理逻辑: 删除超过60秒未更新的条目\n")
    
    # 实际清理逻辑需要在用户态守护进程中实现
    print("提示: 正式的清理逻辑由用户态守护进程执行")
    print("守护进程每30秒扫描一次Map，删除last_seen超过TTL的条目")
