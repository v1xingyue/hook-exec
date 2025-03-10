#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

// 日志级别定义
typedef enum
{
    LOG_NONE = 0,  // 不输出任何日志
    LOG_ERROR = 1, // 只输出错误信息
    LOG_INFO = 2,  // 输出基本信息
    LOG_DEBUG = 3  // 输出所有调试信息
} log_level_t;

// 全局配置结构体
typedef struct
{
    char log_dir[256];     // 审计日志目录
    log_level_t log_level; // 日志级别
    int console_output;    // 是否输出到控制台
    int file_output;       // 是否输出到文件
} audit_config_t;

extern audit_config_t g_audit_config;

// 初始化审计日志配置
void audit_init(const char *log_dir);

// 审计日志类型枚举
typedef enum
{
    AUDIT_EXEC,     // 程序执行
    AUDIT_FILE,     // 文件操作
    AUDIT_PROCESS,  // 进程操作
    AUDIT_MEMORY,   // 内存操作
    AUDIT_SECURITY, // 安全相关
    AUDIT_SIGNAL,   // 信号处理
    AUDIT_ENV,      // 环境变量
    AUDIT_DNS,      // DNS解析
    AUDIT_CONNECT,  // 连接请求
    AUDIT_LISTEN    // 监听请求
} audit_type_t;

// 函数声明
void audit_log(audit_type_t type, const char *fmt, ...);

// 网络地址格式化函数
void format_socket_address(const struct sockaddr *addr, char *buf, size_t size);

#endif // AUDIT_LOG_H