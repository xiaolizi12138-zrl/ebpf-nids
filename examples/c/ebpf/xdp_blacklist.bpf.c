// xdp_blacklist.bpf.c - eBPF-NIDS XDP数据面程序 v3.0
// 功能：黑名单过滤 + SYN Flood检测 + 端口扫描检测 + 流量统计 + Ring Buffer告警
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// ==================== 可配置参数 ====================
#define BLACKLIST_SIZE  10000
#define STATS_SIZE      100000
#define SYN_THRESHOLD   100       // SYN Flood阈值
#define PORT_SCAN_THRESHOLD 20    // 端口扫描阈值（访问不同端口数）
#define RINGBUF_SIZE    (256 * 1024)

// ==================== Map 定义 ====================

// 黑名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BLACKLIST_SIZE);
    __type(key, __u32);
    __type(value, __u8);
} blacklist SEC(".maps");

// 流量统计Map
struct flow_stats {
    __u64 pkt_count;
    __u64 byte_count;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, STATS_SIZE);
    __type(key, __u32);
    __type(value, struct flow_stats);
} flow_stats SEC(".maps");

// SYN计数器Map（Per-CPU）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, STATS_SIZE);
    __type(key, __u32);
    __type(value, __u64);
} syn_counter SEC(".maps");

// ★★★ 新增：端口扫描检测Map ★★★
// 记录每个源IP访问过的目的端口（用位图简化实现）
struct port_bitmap {
    __u64 bitmap[16];  // 16×64=1024位，覆盖0-1023端口
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, STATS_SIZE);
    __type(key, __u32);              // 源IP
    __type(value, struct port_bitmap);
} port_scan_map SEC(".maps");

// 告警事件结构体
struct alert_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  alert_type;    // 1=SYN Flood, 2=端口扫描
    __u64 timestamp;
};

// Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} alert_rb SEC(".maps");

// ==================== 内联辅助函数 ====================

// 更新流量统计
static __always_inline void update_flow_stats(__u32 src_ip, __u64 pkt_size)
{
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats, &src_ip);
    if (stats) {
        stats->pkt_count++;
        stats->byte_count += pkt_size;
    } else {
        struct flow_stats new_stats = {1, pkt_size};
        bpf_map_update_elem(&flow_stats, &src_ip, &new_stats, BPF_ANY);
    }
}

// SYN Flood检测
static __always_inline void check_syn_flood(__u32 src_ip, __u32 dst_ip)
{
    __u64 *count = bpf_map_lookup_elem(&syn_counter, &src_ip);
    if (count) {
        (*count)++;
        if (*count > SYN_THRESHOLD) {
            struct alert_event evt = {0};
            evt.src_ip = src_ip;
            evt.dst_ip = dst_ip;
            evt.alert_type = 1;  // SYN Flood
            evt.timestamp = bpf_ktime_get_ns();
            bpf_ringbuf_output(&alert_rb, &evt, sizeof(evt), 0);
            *count = 0;
        }
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&syn_counter, &src_ip, &init, BPF_ANY);
    }
}

// ★★★ 端口扫描检测 ★★★
static __always_inline void check_port_scan(__u32 src_ip, __u32 dst_ip, __u16 dst_port)
{
    struct port_bitmap *bitmap = bpf_map_lookup_elem(&port_scan_map, &src_ip);
    
    if (!bitmap) {
        // 首次出现，初始化位图
        struct port_bitmap new_bitmap = {0};
        bpf_map_update_elem(&port_scan_map, &src_ip, &new_bitmap, BPF_ANY);
        bitmap = bpf_map_lookup_elem(&port_scan_map, &src_ip);
        if (!bitmap) return;
    }
    
    // 只检测0-1023端口（常见服务端口）
    if (dst_port < 1024) {
        int idx = dst_port / 64;
        int bit = dst_port % 64;
        bitmap->bitmap[idx] |= (1ULL << bit);
        
        // 统计已访问的不同端口数
        __u64 total_ports = 0;
        for (int i = 0; i < 16; i++) {
            total_ports += __builtin_popcountll(bitmap->bitmap[i]);
        }
        
        // 超过阈值，触发告警
        if (total_ports > PORT_SCAN_THRESHOLD) {
            struct alert_event evt = {0};
            evt.src_ip = src_ip;
            evt.dst_ip = dst_ip;
            evt.alert_type = 2;  // 端口扫描
            evt.timestamp = bpf_ktime_get_ns();
            bpf_ringbuf_output(&alert_rb, &evt, sizeof(evt), 0);
            
            // 重置位图，防止重复告警
            for (int i = 0; i < 16; i++) {
                bitmap->bitmap[i] = 0;
            }
        }
    }
}

// ==================== XDP 入口 ====================

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // 1. 黑名单检查
    __u8 *blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    // 2. TCP协议检测
    if (ip->protocol == 6) {  // TCP
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);

        // SYN Flood检测
        if (tcp->syn && !tcp->ack)
            check_syn_flood(src_ip, dst_ip);

        // 端口扫描检测
        if (tcp->syn)
            check_port_scan(src_ip, dst_ip, dst_port);
    }

    // 3. 更新流量统计
    update_flow_stats(src_ip, data_end - data);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
