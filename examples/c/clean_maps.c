#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "用法: %s <map_id>\n", argv[0]);
        return 1;
    }

    int map_fd = bpf_map_get_fd_by_id(atoi(argv[1]));
    if (map_fd < 0) {
        perror("bpf_map_get_fd_by_id 失败");
        return 1;
    }

    while (1) {
        __u32 key = 0, next_key;
        int count = 0;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(map_fd, &next_key);
            key = next_key;
            count++;
        }

        printf("已清理 Map ID %s，删除 %d 条记录\n", argv[1], count);
        sleep(3600);  // 每小时清理一次
    }

    return 0;
}
