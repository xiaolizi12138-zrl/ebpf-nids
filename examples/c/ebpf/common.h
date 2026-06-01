// common.h - eBPF-NIDS 公共数据结构定义
// 内核态XDP程序和用户态控制程序共享此文件

#ifndef __COMMON_H__
#define __COMMON_H__

// 告警事件结构体
struct alert_event {
    __u32 src_ip;        // 攻击源IP
    __u32 dst_ip;        // 目标IP
    __u8  alert_type;    // 告警类型：1=SYN Flood, 2=端口扫描
    __u64 timestamp;     // 时间戳（纳秒）
};

// 告警类型枚举
enum alert_type {
    ALERT_SYN_FLOOD = 1,
    ALERT_PORT_SCAN = 2,
};

// 流量统计结构体
struct flow_stats {
    __u64 pkt_count;     // 包计数
    __u64 byte_count;    // 字节计数
    __u64 last_seen;     // 最后活跃时间戳
};

// 默认配置参数
#define DEFAULT_SYN_THRESHOLD  100     // SYN Flood阈值（包/秒）
#define DEFAULT_BLACKLIST_SIZE 10000   // 黑名单容量
#define DEFAULT_STATS_SIZE     100000  // 统计Map容量
#define DEFAULT_RINGBUF_SIZE   (256 * 1024)  // Ring Buffer大小

#endif // __COMMON_H__
