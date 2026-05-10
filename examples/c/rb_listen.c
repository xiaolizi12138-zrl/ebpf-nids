#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

static volatile int running = 1;
void sigint_handler(int sig) { running = 0; }

struct alert_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  alert_type;
    __u64 timestamp;
};

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
    if (argc != 2) {
        fprintf(stderr, "用法: %s <ringbuf_map_id>\n", argv[0]);
        fprintf(stderr, "先用 bpftool map list 找到 alert_rb 的 ID\n");
        return 1;
    }

    int map_id = atoi(argv[1]);
    int map_fd = bpf_map_get_fd_by_id(map_id);
    if (map_fd < 0) {
        perror("bpf_map_get_fd_by_id");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_alert, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "创建 Ring Buffer 失败\n");
        return 1;
    }

    printf("✅ 正在监听 Ring Buffer (Map ID %d)...\n", map_id);
    printf("💡 现在可以在另一个终端发起攻击\n");

    signal(SIGINT, sigint_handler);
    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll 错误: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    printf("🔄 停止监听\n");
    return 0;
}
