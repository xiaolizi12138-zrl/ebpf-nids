// loader.c - 占强强：eBPF 用户态控制面最终版
// 功能：加载/卸载 XDP 程序、读取 flow_stats Map、接收 Ring Buffer 告警、
//      作为 Unix Domain Socket 服务端向后端发送 JSON Lines、支持守护进程、日志、配置文件与 SIGHUP 重载。

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "xdp_blacklist.skel.h"

#define DEFAULT_CONFIG_PATH      "./conf/xdp_loader.conf"
#define DEFAULT_IFNAME           "lo"
#define DEFAULT_SOCKET_PATH      "/tmp/xdp_loader.sock"
#define DEFAULT_LOG_FILE         "/tmp/xdp_loader.log"
#define DEFAULT_STATS_INTERVAL   5
#define MAX_CLIENTS              16

struct flow_stats {
    __u64 pkt_count;
    __u64 byte_count;
};

struct alert_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  alert_type;
    __u64 timestamp;
};

struct app_config {
    char ifname[IF_NAMESIZE];
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char log_file[256];
    int stats_interval_sec;
    int daemon_mode;
    __u32 xdp_flags;
};

struct ip_cache {
    __u32 ip;
    __u64 pkts;
    __u64 bytes;
    struct ip_cache *next;
};

static struct app_config cfg;
static char config_path[256] = DEFAULT_CONFIG_PATH;
static FILE *log_fp = NULL;
static struct xdp_blacklist_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;
static int ifindex = 0;
static bool xdp_attached = false;
static int server_fd = -1;
static int client_fds[MAX_CLIENTS];
static struct ip_cache *cache_head = NULL;
static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t reload_requested = 0;

static void app_log(const char *level, const char *fmt, ...)
{
    char msg[2048];
    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (log_fp) {
        fprintf(log_fp, "[%s] %s\n", level, msg);
        fflush(log_fp);
    }

    if (!cfg.daemon_mode) {
        fprintf(stdout, "[%s] %s\n", level, msg);
        fflush(stdout);
    }

    syslog(strcmp(level, "ERROR") == 0 ? LOG_ERR : LOG_INFO, "[%s] %s", level, msg);
}

static void sig_handler(int sig)
{
    if (sig == SIGHUP) {
        reload_requested = 1;
    } else {
        exiting = 1;
    }
}

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static char *trim(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end-- = '\0';
    }
    return s;
}

static void config_defaults(struct app_config *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->ifname, sizeof(c->ifname), "%s", DEFAULT_IFNAME);
    snprintf(c->socket_path, sizeof(c->socket_path), "%s", DEFAULT_SOCKET_PATH);
    snprintf(c->log_file, sizeof(c->log_file), "%s", DEFAULT_LOG_FILE);
    c->stats_interval_sec = DEFAULT_STATS_INTERVAL;
    c->daemon_mode = 0;
    c->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;  // 默认 generic/skb，虚拟机和 lo 更容易成功
}

static int parse_xdp_mode(const char *value, __u32 *flags)
{
    __u32 base = XDP_FLAGS_UPDATE_IF_NOEXIST;

    if (strcmp(value, "skb") == 0 || strcmp(value, "generic") == 0) {
        *flags = base | XDP_FLAGS_SKB_MODE;
    } else if (strcmp(value, "drv") == 0 || strcmp(value, "native") == 0) {
        *flags = base | XDP_FLAGS_DRV_MODE;
    } else if (strcmp(value, "hw") == 0) {
        *flags = base | XDP_FLAGS_HW_MODE;
    } else if (strcmp(value, "auto") == 0) {
        *flags = base;
    } else {
        return -1;
    }
    return 0;
}

static int load_config_file(const char *path, struct app_config *out)
{
    FILE *fp;
    char line[512];
    int line_no = 0;

    fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) {
            return 0;  // 没有配置文件时使用默认值
        }
        app_log("ERROR", "打开配置文件失败: %s: %s", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key, *value, *eq, *comment;
        line_no++;

        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        key = trim(line);
        if (*key == '\0') {
            continue;
        }

        eq = strchr(key, '=');
        if (!eq) {
            app_log("ERROR", "配置文件第 %d 行格式错误，应为 key=value", line_no);
            fclose(fp);
            return -1;
        }

        *eq = '\0';
        value = trim(eq + 1);
        key = trim(key);

        if (strcmp(key, "ifname") == 0) {
            snprintf(out->ifname, sizeof(out->ifname), "%s", value);
        } else if (strcmp(key, "socket_path") == 0) {
            snprintf(out->socket_path, sizeof(out->socket_path), "%s", value);
        } else if (strcmp(key, "log_file") == 0) {
            snprintf(out->log_file, sizeof(out->log_file), "%s", value);
        } else if (strcmp(key, "stats_interval_sec") == 0) {
            int n = atoi(value);
            if (n <= 0 || n > 3600) {
                app_log("ERROR", "stats_interval_sec 非法: %s", value);
                fclose(fp);
                return -1;
            }
            out->stats_interval_sec = n;
        } else if (strcmp(key, "daemon") == 0) {
            out->daemon_mode = atoi(value) ? 1 : 0;
        } else if (strcmp(key, "xdp_mode") == 0) {
            if (parse_xdp_mode(value, &out->xdp_flags) != 0) {
                app_log("ERROR", "xdp_mode 非法: %s，可选 skb/generic/drv/native/hw/auto", value);
                fclose(fp);
                return -1;
            }
        } else {
            app_log("ERROR", "未知配置项: %s", key);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static int open_log_file(void)
{
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }

    if (cfg.log_file[0] == '\0' || strcmp(cfg.log_file, "syslog") == 0) {
        return 0;
    }

    log_fp = fopen(cfg.log_file, "a");
    if (!log_fp) {
        fprintf(stderr, "打开日志文件失败: %s: %s\n", cfg.log_file, strerror(errno));
        return -1;
    }
    setbuf(log_fp, NULL);
    return 0;
}

static void print_usage(const char *prog)
{
    printf("用法: %s [-c conf/xdp_loader.conf] [-i ifname] [-d] [-h]\n", prog);
    printf("  -c  指定配置文件路径\n");
    printf("  -i  覆盖配置文件中的网卡名，例如 lo、eth0、ens33\n");
    printf("  -d  后台守护进程运行\n");
    printf("  -h  显示帮助\n");
}

static int setup_unix_server(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        app_log("ERROR", "创建 Unix Socket 失败: %s", strerror(errno));
        return -1;
    }

    set_nonblock(fd);
    unlink(path);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        app_log("ERROR", "绑定 Unix Socket 失败: %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    chmod(path, 0666);

    if (listen(fd, MAX_CLIENTS) < 0) {
        app_log("ERROR", "监听 Unix Socket 失败: %s", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    app_log("INFO", "Unix Socket 服务端已启动: %s", path);
    return fd;
}

static void init_clients(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = -1;
    }
}

static void accept_clients(void)
{
    while (1) {
        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            app_log("ERROR", "accept 失败: %s", strerror(errno));
            return;
        }

        set_nonblock(cfd);

        bool stored = false;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_fds[i] < 0) {
                client_fds[i] = cfd;
                stored = true;
                app_log("INFO", "后端客户端已连接，槽位=%d", i);
                break;
            }
        }

        if (!stored) {
            app_log("ERROR", "后端客户端数量超过上限，拒绝连接");
            close(cfd);
        }
    }
}

static void close_client(int idx)
{
    if (client_fds[idx] >= 0) {
        close(client_fds[idx]);
        client_fds[idx] = -1;
    }
}

static void broadcast_json_line(const char *json)
{
    size_t len = strlen(json);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_fds[i] < 0) {
            continue;
        }

        ssize_t n = send(client_fds[i], json, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                app_log("ERROR", "发送给后端失败，关闭客户端槽位=%d: %s", i, strerror(errno));
                close_client(i);
            }
        }
    }
}

static const char *alert_type_to_string(__u8 type)
{
    switch (type) {
    case 1:
        return "syn_flood";
    case 2:
        return "port_scan";
    default:
        return "unknown";
    }
}

static int handle_alert(void *ctx, void *data, size_t data_sz)
{
    struct alert_event *e = data;
    char src[INET_ADDRSTRLEN] = {0};
    char dst[INET_ADDRSTRLEN] = {0};
    char json[512];

    (void)ctx;

    if (!e || data_sz < sizeof(*e)) {
        return 0;
    }

    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));

    app_log("INFO", "告警: %s -> %s, type=%u(%s), timestamp_ns=%" PRIu64,
            src, dst, e->alert_type, alert_type_to_string(e->alert_type), (uint64_t)e->timestamp);

    snprintf(json, sizeof(json),
             "{\"type\":\"alert\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
             "\"alert_type\":%u,\"alert_name\":\"%s\",\"timestamp_ns\":%" PRIu64 "}\n",
             src, dst, e->alert_type, alert_type_to_string(e->alert_type), (uint64_t)e->timestamp);

    broadcast_json_line(json);
    return 0;
}

static struct ip_cache *find_or_create_cache(__u32 ip, __u64 pkts, __u64 bytes, bool *is_new)
{
    struct ip_cache *p = cache_head;

    while (p) {
        if (p->ip == ip) {
            *is_new = false;
            return p;
        }
        p = p->next;
    }

    p = calloc(1, sizeof(*p));
    if (!p) {
        return NULL;
    }

    p->ip = ip;
    p->pkts = pkts;
    p->bytes = bytes;
    p->next = cache_head;
    cache_head = p;
    *is_new = true;
    return p;
}

static void report_flow_rate(__u32 ip, const struct flow_stats *cur)
{
    char ip_str[INET_ADDRSTRLEN] = {0};
    char json[512];
    bool is_new = false;
    struct ip_cache *cache = find_or_create_cache(ip, cur->pkt_count, cur->byte_count, &is_new);
    __u64 dpkts = 0;
    __u64 dbytes = 0;
    __u64 pps = 0;
    __u64 bps = 0;
    time_t now = time(NULL);

    if (!cache) {
        app_log("ERROR", "内存不足，无法维护 IP 统计缓存");
        return;
    }

    if (!is_new) {
        dpkts = cur->pkt_count >= cache->pkts ? cur->pkt_count - cache->pkts : 0;
        dbytes = cur->byte_count >= cache->bytes ? cur->byte_count - cache->bytes : 0;
        pps = dpkts / (cfg.stats_interval_sec > 0 ? cfg.stats_interval_sec : 1);
        bps = dbytes / (cfg.stats_interval_sec > 0 ? cfg.stats_interval_sec : 1);
        cache->pkts = cur->pkt_count;
        cache->bytes = cur->byte_count;
    }

    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    app_log("INFO", "流速: IP=%s, pps=%" PRIu64 ", bytes/s=%" PRIu64 ", total_pkts=%" PRIu64 ", total_bytes=%" PRIu64,
            ip_str, (uint64_t)pps, (uint64_t)bps, (uint64_t)cur->pkt_count, (uint64_t)cur->byte_count);

    snprintf(json, sizeof(json),
             "{\"type\":\"flow_rate\",\"ip\":\"%s\",\"pps\":%" PRIu64 ","
             "\"bytes_per_sec\":%" PRIu64 ",\"total_pkts\":%" PRIu64 ","
             "\"total_bytes\":%" PRIu64 ",\"timestamp\":%ld}\n",
             ip_str, (uint64_t)pps, (uint64_t)bps, (uint64_t)cur->pkt_count,
             (uint64_t)cur->byte_count, (long)now);

    broadcast_json_line(json);
}

static void read_and_report_stats(int stats_fd)
{
    __u32 key;
    __u32 next_key;
    struct flow_stats value;
    int ret;

    ret = bpf_map_get_next_key(stats_fd, NULL, &key);
    if (ret != 0) {
        app_log("INFO", "暂无流量统计，等待数据...");
        return;
    }

    while (1) {
        if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0) {
            report_flow_rate(key, &value);
        }

        ret = bpf_map_get_next_key(stats_fd, &key, &next_key);
        if (ret != 0) {
            break;
        }
        key = next_key;
    }
}

static void cleanup(void)
{
    struct ip_cache *p = cache_head;

    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (xdp_attached && ifindex > 0) {
        __u32 detach_flags = cfg.xdp_flags & ~XDP_FLAGS_UPDATE_IF_NOEXIST;
        int err = bpf_set_link_xdp_fd(ifindex, -1, detach_flags);
        if (err) {
            app_log("ERROR", "卸载 XDP 失败: ifindex=%d, err=%d", ifindex, err);
        } else {
            app_log("INFO", "XDP 程序已卸载: ifindex=%d", ifindex);
        }
        xdp_attached = false;
    }

    if (skel) {
        xdp_blacklist_bpf__destroy(skel);
        skel = NULL;
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        close_client(i);
    }

    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
        unlink(cfg.socket_path);
    }

    while (p) {
        struct ip_cache *next = p->next;
        free(p);
        p = next;
    }
    cache_head = NULL;

    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }

    closelog();
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        app_log("ERROR", "设置 RLIMIT_MEMLOCK 失败: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int load_and_attach_bpf(void)
{
    struct bpf_program *prog;
    int prog_fd;
    int err;

    skel = xdp_blacklist_bpf__open();
    if (!skel) {
        app_log("ERROR", "打开 BPF skeleton 失败");
        return -1;
    }

    err = xdp_blacklist_bpf__load(skel);
    if (err) {
        app_log("ERROR", "加载 BPF 程序失败: %d。可用 sudo dmesg 或 bpftool prog 查看验证器信息", err);
        return -1;
    }

    ifindex = if_nametoindex(cfg.ifname);
    if (ifindex == 0) {
        app_log("ERROR", "找不到网卡接口: %s", cfg.ifname);
        return -1;
    }

    prog = skel->progs.xdp_firewall;
    if (!prog) {
        app_log("ERROR", "skeleton 中找不到 XDP 程序 xdp_firewall");
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        app_log("ERROR", "获取 XDP 程序 fd 失败");
        return -1;
    }

    err = bpf_set_link_xdp_fd(ifindex, prog_fd, cfg.xdp_flags);
    if (err) {
        app_log("ERROR", "附加 XDP 到 %s 失败: err=%d。若 lo/虚拟机测试，建议 xdp_mode=skb", cfg.ifname, err);
        return -1;
    }

    xdp_attached = true;
    app_log("INFO", "XDP 程序已附加到接口: %s(ifindex=%d)", cfg.ifname, ifindex);
    return 0;
}

static int setup_ring_buffer(void)
{
    int alert_fd = bpf_map__fd(skel->maps.alert_rb);

    if (alert_fd < 0) {
        app_log("ERROR", "获取 alert_rb map fd 失败");
        return -1;
    }

    rb = ring_buffer__new(alert_fd, handle_alert, NULL, NULL);
    if (!rb) {
        app_log("ERROR", "Ring Buffer 初始化失败");
        return -1;
    }

    app_log("INFO", "Ring Buffer 已就绪");
    return 0;
}

static int reload_config_runtime(void)
{
    struct app_config new_cfg = cfg;

    if (load_config_file(config_path, &new_cfg) != 0) {
        app_log("ERROR", "配置重载失败，继续使用旧配置");
        return -1;
    }

    // 运行中不自动更换 ifname/xdp_mode，因为这需要先卸载再重新挂载 XDP。
    if (strcmp(new_cfg.ifname, cfg.ifname) != 0 || new_cfg.xdp_flags != cfg.xdp_flags) {
        app_log("ERROR", "运行中不支持热切换 ifname/xdp_mode，请重启程序生效");
        snprintf(new_cfg.ifname, sizeof(new_cfg.ifname), "%s", cfg.ifname);
        new_cfg.xdp_flags = cfg.xdp_flags;
    }

    if (strcmp(new_cfg.socket_path, cfg.socket_path) != 0) {
        app_log("ERROR", "运行中不支持热切换 socket_path，请重启程序生效");
        snprintf(new_cfg.socket_path, sizeof(new_cfg.socket_path), "%s", cfg.socket_path);
    }

    cfg.stats_interval_sec = new_cfg.stats_interval_sec;
    cfg.daemon_mode = new_cfg.daemon_mode;

    if (strcmp(new_cfg.log_file, cfg.log_file) != 0) {
        snprintf(cfg.log_file, sizeof(cfg.log_file), "%s", new_cfg.log_file);
        open_log_file();
    }

    app_log("INFO", "配置已重载: stats_interval_sec=%d, log_file=%s", cfg.stats_interval_sec, cfg.log_file);
    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    int stats_fd;
    time_t last_stats_ts = 0;
    char cli_ifname[IF_NAMESIZE] = {0};
    int cli_daemon = -1;

    config_defaults(&cfg);
    init_clients();
    openlog("xdp_loader", LOG_PID | LOG_CONS, LOG_DAEMON);

    while ((opt = getopt(argc, argv, "c:i:dh")) != -1) {
        switch (opt) {
        case 'c':
            snprintf(config_path, sizeof(config_path), "%s", optarg);
            break;
        case 'i':
            snprintf(cli_ifname, sizeof(cli_ifname), "%s", optarg);
            break;
        case 'd':
            cli_daemon = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (load_config_file(config_path, &cfg) != 0) {
        return 1;
    }
    if (cli_ifname[0]) {
        snprintf(cfg.ifname, sizeof(cfg.ifname), "%s", cli_ifname);
    }
    if (cli_daemon >= 0) {
        cfg.daemon_mode = cli_daemon;
    }

    if (cfg.daemon_mode) {
        if (daemon(0, 0) != 0) {
            perror("daemon");
            return 1;
        }
    }

    if (open_log_file() != 0) {
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    app_log("INFO", "配置文件: %s", config_path);
    app_log("INFO", "启动参数: ifname=%s, socket_path=%s, stats_interval_sec=%d, daemon=%d",
            cfg.ifname, cfg.socket_path, cfg.stats_interval_sec, cfg.daemon_mode);

    bump_memlock_rlimit();

    server_fd = setup_unix_server(cfg.socket_path);
    if (server_fd < 0) {
        cleanup();
        return 1;
    }

    if (load_and_attach_bpf() != 0) {
        cleanup();
        return 1;
    }

    if (setup_ring_buffer() != 0) {
        cleanup();
        return 1;
    }

    stats_fd = bpf_map__fd(skel->maps.flow_stats);
    if (stats_fd < 0) {
        app_log("ERROR", "获取 flow_stats map fd 失败");
        cleanup();
        return 1;
    }

    app_log("INFO", "开始运行：读取 flow_stats、接收 RingBuffer、向后端发送 JSON Lines");

    while (!exiting) {
        time_t now = time(NULL);

        accept_clients();

        if (reload_requested) {
            reload_requested = 0;
            reload_config_runtime();
        }

        if (rb) {
            int err = ring_buffer__poll(rb, 200);  // 200ms，避免影响退出和接收后端连接
            if (err < 0 && err != -EINTR) {
                app_log("ERROR", "Ring Buffer poll 失败: %d", err);
            }
        } else {
            usleep(200 * 1000);
        }

        if (now - last_stats_ts >= cfg.stats_interval_sec) {
            read_and_report_stats(stats_fd);
            last_stats_ts = now;
        }
    }

    app_log("INFO", "收到退出信号，开始清理资源");
    cleanup();
    return 0;
}
