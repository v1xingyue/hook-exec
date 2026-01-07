#include "../include/audit_log.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

// 全局配置实例
audit_config_t g_audit_config = {0};

// 从环境变量获取配置
static void get_config_from_env(void)
{
    // 设置日志级别
    const char *log_level = getenv("AUDIT_LOG_LEVEL");
    if (log_level)
    {
        if (strcmp(log_level, "NONE") == 0)
            g_audit_config.log_level = LOG_NONE;
        else if (strcmp(log_level, "ERROR") == 0)
            g_audit_config.log_level = LOG_ERROR;
        else if (strcmp(log_level, "INFO") == 0)
            g_audit_config.log_level = LOG_INFO;
        else if (strcmp(log_level, "DEBUG") == 0)
            g_audit_config.log_level = LOG_DEBUG;
        else
            g_audit_config.log_level = LOG_INFO; // 默认INFO级别
    }
    else
    {
        g_audit_config.log_level = LOG_INFO;
    }

    // 设置输出目标
    const char *console_output = getenv("AUDIT_CONSOLE_OUTPUT");
    g_audit_config.console_output = console_output && strcmp(console_output, "1") == 0;

    const char *file_output = getenv("AUDIT_FILE_OUTPUT");
    g_audit_config.file_output = !file_output || strcmp(file_output, "0") != 0; // 默认开启文件输出
}

// 输出调试信息
static void debug_print(const char *fmt, ...)
{
    if (g_audit_config.log_level >= LOG_DEBUG && g_audit_config.console_output)
    {
        va_list args;
        va_start(args, fmt);
        fprintf(stdout, "[DEBUG] ");
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
        va_end(args);
        fflush(stdout);
    }
}

// 输出信息
static void info_print(const char *fmt, ...)
{
    if (g_audit_config.log_level >= LOG_INFO && g_audit_config.console_output)
    {
        va_list args;
        va_start(args, fmt);
        fprintf(stdout, "[INFO] ");
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
        va_end(args);
        fflush(stdout);
    }
}

// 输出错误信息
static void error_print(const char *fmt, ...)
{
    if (g_audit_config.log_level >= LOG_ERROR && g_audit_config.console_output)
    {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "[ERROR] ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
        fflush(stderr);
    }
}

// 初始化审计日志配置
void audit_init(const char *log_dir)
{
    // 首先获取环境变量配置
    get_config_from_env();

    info_print("Initializing audit log with directory: %s", log_dir ? log_dir : "NULL");

    if (!log_dir)
    {
        strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
    }
    else
    {
        strncpy(g_audit_config.log_dir, log_dir, sizeof(g_audit_config.log_dir) - 1);
    }
    g_audit_config.log_dir[sizeof(g_audit_config.log_dir) - 1] = '\0';

    info_print("Using log directory: %s", g_audit_config.log_dir);

    if (!g_audit_config.file_output)
    {
        info_print("File output disabled, skipping directory creation");
        return;
    }

    // 确保日志目录存在
    struct stat st = {0};
    if (stat(g_audit_config.log_dir, &st) == -1)
    {
        debug_print("Log directory does not exist, trying to create it");
        if (mkdir(g_audit_config.log_dir, 0755) == -1)
        {
            error_print("Failed to create audit log directory %s: %s",
                        g_audit_config.log_dir, strerror(errno));
            info_print("Falling back to /tmp directory");
            strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
        }
        else
        {
            debug_print("Successfully created log directory");
        }
    }
    else
    {
        debug_print("Log directory exists, checking permissions");
        if (access(g_audit_config.log_dir, W_OK) == -1)
        {
            error_print("No write permission for directory %s: %s",
                        g_audit_config.log_dir, strerror(errno));
            info_print("Falling back to /tmp directory");
            strncpy(g_audit_config.log_dir, "/tmp", sizeof(g_audit_config.log_dir) - 1);
        }
    }

    // 尝试创建日志文件以验证权限
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/audit.log", g_audit_config.log_dir);
    debug_print("Testing log file creation: %s", log_path);

    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1)
    {
        error_print("Failed to create/open log file %s: %s",
                    log_path, strerror(errno));
    }
    else
    {
        debug_print("Successfully created/opened log file");
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
    if (g_audit_config.log_level == LOG_NONE)
        return;

    static int log_fd = -1;
    static int in_audit = 0;

    // 防止递归调用
    if (in_audit)
        return;
    in_audit = 1;

    char timestr[64];
    char procname[256];
    char log_buf[4096];
    size_t log_len = 0;

    get_current_time(timestr, sizeof(timestr));
    get_process_name(procname, sizeof(procname));

    const char *type_str =
        type == AUDIT_EXEC ? "EXEC" : type == AUDIT_FILE   ? "FILE"
                                  : type == AUDIT_PROCESS  ? "PROCESS"
                                  : type == AUDIT_MEMORY   ? "MEMORY"
                                  : type == AUDIT_SECURITY ? "SECURITY"
                                  : type == AUDIT_SIGNAL   ? "SIGNAL"
                                  : type == AUDIT_ENV      ? "ENV"
                                  : type == AUDIT_DNS      ? "DNS"
                                  : type == AUDIT_CONNECT  ? "CONNECT"
                                  : type == AUDIT_LISTEN   ? "LISTEN"
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

    // 输出到控制台
    if (g_audit_config.console_output)
    {
        printf("%s", log_buf);
        fflush(stdout);
    }

    // 输出到文件
    if (g_audit_config.file_output)
    {
        // 如果文件描述符未打开，则打开它
        if (log_fd == -1)
        {
            char log_path[512];
            snprintf(log_path, sizeof(log_path), "%s/audit.log", g_audit_config.log_dir);
            log_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
            if (log_fd == -1)
            {
                error_print("Failed to open log file %s: %s", log_path, strerror(errno));
                in_audit = 0;
                return;
            }
        }

        // 获取文件锁
        if (lock_file(log_fd) == -1)
        {
            error_print("Failed to lock audit log file: %s", strerror(errno));
            in_audit = 0;
            return;
        }

        // 写入日志
        if (write(log_fd, log_buf, log_len) == -1)
        {
            error_print("Failed to write to audit log: %s", strerror(errno));
        }

        // 释放文件锁
        unlock_file(log_fd);
    }

    in_audit = 0;
}

// 网络地址格式化函数
void format_socket_address(const struct sockaddr *addr, char *buf, size_t size)
{
    if (addr == NULL)
    {
        snprintf(buf, size, "NULL");
        return;
    }

    switch (addr->sa_family)
    {
    case AF_INET:
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
        snprintf(buf, size, "%s:%d", ip, ntohs(addr_in->sin_port));
        break;
    }
    case AF_INET6:
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
        snprintf(buf, size, "[%s]:%d", ip, ntohs(addr_in6->sin6_port));
        break;
    }
    case AF_UNIX:
        snprintf(buf, size, "UNIX Domain Socket");
        break;
    default:
        snprintf(buf, size, "Unknown Address Family (%d)", addr->sa_family);
        break;
    }
}