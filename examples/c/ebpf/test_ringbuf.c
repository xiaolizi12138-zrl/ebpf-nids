#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include "xdp_blacklist.skel.h"

// 手动定义 alert_event（和 XDP 程序里的保持一致）
struct alert_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  alert_type;
    __u64 timestamp;
};

static volatile int running = 1;
void sigint_handler(int sig) { running = 0; }

static int handle_alert(void *ctx, void *data, size_t sz)
{
    struct alert_event *evt = data;
    unsigned char *ip = (unsigned char *)&evt->src_ip;
    printf("🚨 收到告警！源IP: %d.%d.%d.%d  类型: %d  时间戳: %llu\n",
           ip[0], ip[1], ip[2], ip[3], evt->alert_type, evt->timestamp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "用法: %s <网卡名>\n", argv[0]);
        return 1;
    }

    // 1. 打开、加载并自动挂载 BPF 程序
    struct xdp_blacklist_bpf *skel = xdp_blacklist_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载BPF程序失败\n");
        return 1;
    }

    // 2. 设置 ifindex 并挂载 (替代手动 bpf_xdp_attach)
    bpf_program__set_ifindex(skel->progs.xdp_firewall, if_nametoindex(argv[1]));
    int err = xdp_blacklist_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "挂载XDP失败，错误码: %d\n", err);
        xdp_blacklist_bpf__destroy(skel);
        return 1;
    }

    // 3. 设置 Ring Buffer 消费者
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.alert_rb), handle_alert, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "创建Ring Buffer失败\n");
        xdp_blacklist_bpf__detach(skel);
        xdp_blacklist_bpf__destroy(skel);
        return 1;
    }

    printf("✅ 监听告警中... 按 Ctrl+C 退出\n");
    printf("💡 在另一个终端执行: sudo hping3 -S -p 80 --flood 127.0.0.1\n\n");

    signal(SIGINT, sigint_handler);
    while (running) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    xdp_blacklist_bpf__detach(skel);
    xdp_blacklist_bpf__destroy(skel);
    printf("🔄 已卸载\n");
    return 0;
}
