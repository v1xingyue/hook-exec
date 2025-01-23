#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

// 审计日志类型枚举
typedef enum
{
    AUDIT_EXEC,     // 程序执行
    AUDIT_SOCKET,   // Socket 操作
    AUDIT_NETWORK,  // 网络连接
    AUDIT_DNS,      // DNS 查询
    AUDIT_FILE,     // 文件操作
    AUDIT_PROCESS,  // 进程操作
    AUDIT_MEMORY,   // 内存操作
    AUDIT_SECURITY, // 安全相关
    AUDIT_SIGNAL,   // 信号处理
    AUDIT_ENV       // 环境变量
} audit_type_t;

// 函数声明
void audit_log(audit_type_t type, const char *fmt, ...);

#endif // AUDIT_LOG_H