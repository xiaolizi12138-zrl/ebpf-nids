#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 黑名单 Map：key = 源IP，value = 1 表示拦截
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // 源 IP 地址
    __type(value, __u8);     // 1 = 拦截
} blacklist SEC(".maps");

SEC("xdp")
int xdp_blacklist_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // 只处理 IP 包
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    // 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    
    // 查黑名单
    __u8 *blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked && *blocked == 1) {
        bpf_printk("🚫 Blocked packet from IP: %pI4", &src_ip);
        return XDP_DROP;  // 丢弃！
    }
    
    bpf_printk("✅ Allowed packet from IP: %pI4", &src_ip);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
