// clean_maps.c - eBPF-NIDS Map自动清理守护程序
// 功能：定时清理统计Map和端口扫描Map，防止内存无限增长
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <time.h>

static volatile int running = 1;

void sigint_handler(int sig) { running = 0; }

// 清理指定Map的所有条目
int clean_map(int map_fd, const char *name)
{
    __u32 key = 0, next_key;
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
        count++;
    }

    if (count > 0)
        printf("[%s] 已清理 %s，删除 %d 条记录\n", 
               ctime(&(time_t){time(NULL)}), name, count);

    return count;
}

int main(int argc, char **argv)
{
    int interval = 3600;  // 默认每小时清理一次

    if (argc > 1) interval = atoi(argv[1]);

    printf("Map清理守护进程已启动\n");
    printf("  - 清理间隔: %d 秒\n", interval);
    printf("  - 待清理Map ID: ");
    for (int i = 2; i < argc; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n按 Ctrl+C 退出\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    while (running) {
        sleep(interval);

        // 遍历所有传入的Map ID并清理
        for (int i = 2; i < argc; i++) {
            int fd = bpf_map_get_fd_by_id(atoi(argv[i]));
            if (fd >= 0) {
                clean_map(fd, "map");
                close(fd);
            }
        }
    }

    printf("\n清理守护进程已退出\n");
    return 0;
}
