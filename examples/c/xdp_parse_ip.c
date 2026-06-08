#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp_parse_ip.skel.h"

static volatile sig_atomic_t running = 1;

void handle_sigint(int sig) {
    running = 0;
}

int main(int argc, char **argv)
{
    struct xdp_parse_ip_bpf *skel;
    int err;

    if (argc < 2) {
        fprintf(stderr, "用法: %s <网卡名>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "找不到网卡: %s\n", ifname);
        return 1;
    }

    // 打开并加载 BPF 程序
    skel = xdp_parse_ip_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
        return 1;
    }

    // 挂载到网卡（Generic 模式）
    int prog_fd = bpf_program__fd(skel->progs.xdp_parse_ip);
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "挂载 XDP 失败\n");
        goto cleanup;
    }

    printf("✅ XDP 程序已挂载到 %s\n", ifname);
    printf("📌 正在打印经过的 IP 包源地址...\n");
    printf("⏹️  按 Ctrl+C 卸载程序\n\n");
    printf("在另一个终端执行: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    while (running) {
        sleep(1);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("\n🔄 XDP 程序已卸载\n");

cleanup:
    xdp_parse_ip_bpf__destroy(skel);
    return err;
}
