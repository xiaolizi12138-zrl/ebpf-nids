#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_parse_ip(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 1. 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // 2. 只处理 IP 包
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    // 3. 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // 4. 提取源 IP
    __u32 src_ip = ip->saddr;
    
    // 5. 打印源 IP（调试用）
    bpf_printk("Got packet from IP: %pI4", &src_ip);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
