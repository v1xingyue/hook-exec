#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

// 全局配置结构体
typedef struct
{
    char log_dir[256]; // 审计日志目录
} audit_config_t;

extern audit_config_t g_audit_config;

// 初始化审计日志配置
void audit_init(const char *log_dir);

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

// 网络日志辅助函数
void audit_network_addr(const struct sockaddr *addr, char *buf, size_t size);

#endif // AUDIT_LOG_H