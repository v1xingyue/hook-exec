#include "audit_log.h"
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// 全局配置实例
audit_config_t g_audit_config = {0};

// 初始化审计日志配置
void audit_init(const char *log_dir)
{
    if (!log_dir)
    {
        strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
    }
    else
    {
        strncpy(g_audit_config.log_dir, log_dir, sizeof(g_audit_config.log_dir) - 1);
    }
    g_audit_config.log_dir[sizeof(g_audit_config.log_dir) - 1] = '\0';

    // 确保日志目录存在
    struct stat st = {0};
    if (stat(g_audit_config.log_dir, &st) == -1)
    {
        if (mkdir(g_audit_config.log_dir, 0755) == -1)
        {
            fprintf(stderr, "Failed to create audit log directory %s: %s\n",
                    g_audit_config.log_dir, strerror(errno));
            // 如果创建失败，使用 /tmp
            strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
        }
    }
}

// 获取当前时间字符串
static void get_current_time(char *buffer, size_t size)
{
    time_t now = time(NULL);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", localtime(&now));
}

// 获取进程名称的辅助函数
static void get_process_name(char *buffer, size_t size)
{
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", getpid());

    FILE *cmd_file = fopen(proc_path, "r");
    if (cmd_file)
    {
        size_t len = fread(buffer, 1, size - 1, cmd_file);
        if (len > 0)
        {
            buffer[len] = '\0';
        }
        else
        {
            snprintf(buffer, size, "unknown");
        }
        fclose(cmd_file);
    }
    else
    {
        snprintf(buffer, size, "unknown");
    }
}

// 文件锁辅助函数
static int lock_file(int fd)
{
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0, // 锁定整个文件
    };
    return fcntl(fd, F_SETLKW, &fl);
}

static int unlock_file(int fd)
{
    struct flock fl = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };
    return fcntl(fd, F_SETLK, &fl);
}

// 统一的审计日志函数
void audit_log(audit_type_t type, const char *fmt, ...)
{
    char timestr[64];
    char procname[256];
    char log_path[512];
    char log_buf[4096]; // 临时缓冲区
    size_t log_len = 0;

    get_current_time(timestr, sizeof(timestr));
    get_process_name(procname, sizeof(procname));

    // 构建日志文件路径
    snprintf(log_path, sizeof(log_path), "%s/audit.log", g_audit_config.log_dir);

    // 获取审计类型的字符串表示
    const char *type_str =
        type == AUDIT_EXEC ? "EXEC" : type == AUDIT_SOCKET ? "SOCKET"
                                  : type == AUDIT_NETWORK  ? "NETWORK"
                                  : type == AUDIT_DNS      ? "DNS"
                                  : type == AUDIT_FILE     ? "FILE"
                                  : type == AUDIT_PROCESS  ? "PROCESS"
                                  : type == AUDIT_MEMORY   ? "MEMORY"
                                  : type == AUDIT_SECURITY ? "SECURITY"
                                  : type == AUDIT_SIGNAL   ? "SIGNAL"
                                  : type == AUDIT_ENV      ? "ENV"
                                                           : "UNKNOWN";

    // 首先将所有内容写入缓冲区
    log_len = snprintf(log_buf, sizeof(log_buf),
                       "[%s] [Type=%s(%d)] [pid=%d] [process=%s]\n    ",
                       timestr, type_str, type, getpid(), procname);

    // 添加具体消息到缓冲区
    va_list args;
    va_start(args, fmt);
    log_len += vsnprintf(log_buf + log_len, sizeof(log_buf) - log_len, fmt, args);
    va_end(args);

    // 添加分隔线
    log_len += snprintf(log_buf + log_len, sizeof(log_buf) - log_len,
                        "\n    ------------------------------------------\n");

    // 以追加和同步写入方式打开文件
    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1)
    {
        return;
    }

    // 获取文件锁
    if (lock_file(fd) == -1)
    {
        close(fd);
        return;
    }

    // 原子写入
    write(fd, log_buf, log_len);

    // 确保写入磁盘
    fsync(fd);

    // 释放文件锁
    unlock_file(fd);

    // 关闭文件
    close(fd);
}

// 网络日志辅助函数
void audit_network_addr(const struct sockaddr *addr, char *buf, size_t size)
{
    if (addr->sa_family == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        snprintf(buf, size, "%s:%d", inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port));
    }
    else if (addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        char ipv6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipv6_str, sizeof(ipv6_str));
        snprintf(buf, size, "[%s]:%d", ipv6_str, ntohs(addr_in6->sin6_port));
    }
    else
    {
        snprintf(buf, size, "Unknown address family %d", addr->sa_family);
    }
}