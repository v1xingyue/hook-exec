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
    printf("Initializing audit log with directory: %s\n", log_dir ? log_dir : "NULL");

    if (!log_dir)
    {
        strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
    }
    else
    {
        strncpy(g_audit_config.log_dir, log_dir, sizeof(g_audit_config.log_dir) - 1);
    }
    g_audit_config.log_dir[sizeof(g_audit_config.log_dir) - 1] = '\0';

    printf("Using log directory: %s\n", g_audit_config.log_dir);

    // 确保日志目录存在
    struct stat st = {0};
    if (stat(g_audit_config.log_dir, &st) == -1)
    {
        printf("Log directory does not exist, trying to create it\n");
        if (mkdir(g_audit_config.log_dir, 0755) == -1)
        {
            fprintf(stderr, "Failed to create audit log directory %s: %s\n",
                    g_audit_config.log_dir, strerror(errno));
            printf("Falling back to /tmp directory\n");
            strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
        }
        else
        {
            printf("Successfully created log directory\n");
        }
    }
    else
    {
        printf("Log directory exists, checking permissions\n");
        // 检查目录权限
        if (access(g_audit_config.log_dir, W_OK) == -1)
        {
            fprintf(stderr, "No write permission for directory %s: %s\n",
                    g_audit_config.log_dir, strerror(errno));
            printf("Falling back to /tmp directory\n");
            strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
        }
    }

    // 尝试创建日志文件以验证权限
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/audit.log", g_audit_config.log_dir);
    printf("Testing log file creation: %s\n", log_path);

    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "Failed to create/open log file %s: %s\n",
                log_path, strerror(errno));
    }
    else
    {
        printf("Successfully created/opened log file\n");
        close(fd);
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
    printf("Starting audit_log for type %d\n", type);
    fflush(stdout); // 确保输出立即显示

    char timestr[64];
    char procname[256];
    char log_buf[4096]; // 临时缓冲区
    size_t log_len = 0;

    get_current_time(timestr, sizeof(timestr));
    printf("Got time: %s\n", timestr);
    fflush(stdout);

    get_process_name(procname, sizeof(procname));
    printf("Got process name: %s\n", procname);
    fflush(stdout);

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

    printf("Preparing log message for type: %s\n", type_str);
    fflush(stdout);

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

    // 写入文件
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/audit.log", g_audit_config.log_dir);
    printf("Opening log file: %s\n", log_path);
    fflush(stdout);

    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "Failed to open log file %s: %s\n", log_path, strerror(errno));
        printf("Open failed with errno: %d\n", errno);
        fflush(stdout);
        return;
    }
    printf("Successfully opened log file, fd=%d\n", fd);
    fflush(stdout);

    // 获取文件锁
    if (lock_file(fd) == -1)
    {
        fprintf(stderr, "Failed to lock file %s: %s\n", log_path, strerror(errno));
        printf("Lock failed with errno: %d\n", errno);
        fflush(stdout);
        close(fd);
        return;
    }
    printf("Successfully locked file\n");
    fflush(stdout);

    // 写入日志
    printf("Attempting to write %zu bytes\n", log_len);
    fflush(stdout);

    ssize_t written = write(fd, log_buf, log_len);
    if (written == -1)
    {
        fprintf(stderr, "Failed to write to log file %s: %s\n", log_path, strerror(errno));
        printf("Write failed with errno: %d\n", errno);
        fflush(stdout);
    }
    else if (written < log_len)
    {
        fprintf(stderr, "Partial write to log file %s: %zd of %zu bytes\n",
                log_path, written, log_len);
        printf("Partial write: %zd of %zu bytes\n", written, log_len);
        fflush(stdout);
    }
    else
    {
        printf("Successfully wrote %zd bytes\n", written);
        fflush(stdout);
    }

    if (fsync(fd) == -1)
    {
        fprintf(stderr, "Failed to sync log file %s: %s\n", log_path, strerror(errno));
        printf("Fsync failed with errno: %d\n", errno);
        fflush(stdout);
    }
    else
    {
        printf("Successfully synced file\n");
        fflush(stdout);
    }

    // 释放文件锁
    if (unlock_file(fd) == -1)
    {
        fprintf(stderr, "Failed to unlock file %s: %s\n", log_path, strerror(errno));
        printf("Unlock failed with errno: %d\n", errno);
        fflush(stdout);
    }
    else
    {
        printf("Successfully unlocked file\n");
        fflush(stdout);
    }

    printf("Closing file\n");
    fflush(stdout);
    // 关闭文件
    close(fd);
    printf("File closed\n");
    fflush(stdout);
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