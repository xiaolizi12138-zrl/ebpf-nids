#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp_blacklist.skel.h"

static volatile sig_atomic_t running = 1;

void handle_sigint(int sig) {
    running = 0;
}

int main(int argc, char **argv)
{
    struct xdp_blacklist_bpf *skel;
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

    skel = xdp_blacklist_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "加载 BPF 程序失败\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_blacklist_filter);
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "挂载 XDP 失败\n");
        goto cleanup;
    }

    printf("✅ XDP 黑名单程序已挂载到 %s\n", ifname);
    printf("📌 当前黑名单为空，所有流量放行\n");
    printf("📌 使用 Python 脚本添加黑名单 IP 来测试拦截\n");
    printf("⏹️  按 Ctrl+C 卸载程序\n\n");

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    while (running) {
        sleep(1);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("\n🔄 XDP 程序已卸载\n");

cleanup:
    xdp_blacklist_bpf__destroy(skel);
    return err;
}
