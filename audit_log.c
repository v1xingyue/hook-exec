#include "audit_log.h"
#include <stdarg.h>

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

// 统一的审计日志函数
void audit_log(audit_type_t type, const char *fmt, ...)
{
    char timestr[64];
    char procname[256];
    get_current_time(timestr, sizeof(timestr));
    get_process_name(procname, sizeof(procname));

    FILE *log_file = fopen("/tmp/audit.log", "a");
    if (!log_file)
    {
        return;
    }

    // 写入基本信息
    fprintf(log_file, "[%s] [%s] pid=%d, process=%s\n    ",
            timestr,
            type == AUDIT_EXEC ? "EXEC" : type == AUDIT_SOCKET ? "SOCKET"
                                      : type == AUDIT_NETWORK  ? "NETWORK"
                                      : type == AUDIT_DNS      ? "DNS"
                                      : type == AUDIT_FILE     ? "FILE"
                                      : type == AUDIT_PROCESS  ? "PROCESS"
                                      : type == AUDIT_MEMORY   ? "MEMORY"
                                      : type == AUDIT_SECURITY ? "SECURITY"
                                      : type == AUDIT_SIGNAL   ? "SIGNAL"
                                      : type == AUDIT_ENV      ? "ENV"
                                                               : "UNKNOWN",
            getpid(), procname);

    // 写入具体消息
    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);

    fprintf(log_file, "\n    ------------------------------------------\n");
    fclose(log_file);
}