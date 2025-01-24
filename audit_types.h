#ifndef AUDIT_TYPES_H
#define AUDIT_TYPES_H

#include <time.h>
#include <sys/types.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>

// 基础审计记录结构
typedef struct
{
    time_t timestamp;   // 时间戳
    pid_t pid;          // 进程ID
    uid_t uid;          // 用户ID
    char process[256];  // 进程名
    char cwd[PATH_MAX]; // 当前工作目录
} audit_base_t;

// 执行审计记录
typedef struct
{
    audit_base_t base;
    char pathname[PATH_MAX]; // 执行文件路径
    char **argv;             // 参数列表
    char **envp;             // 环境变量
} audit_exec_t;

// 网络连接审计记录
typedef struct
{
    audit_base_t base;
    int sockfd;        // socket文件描述符
    int domain;        // 协议族(AF_INET/AF_INET6)
    int type;          // socket类型(SOCK_STREAM/SOCK_DGRAM)
    char src_ip[46];   // 源IP (IPv6最长45字符)
    uint16_t src_port; // 源端口
    char dst_ip[46];   // 目标IP
    uint16_t dst_port; // 目标端口
} audit_network_t;

// 文件操作审计记录
typedef struct
{
    audit_base_t base;
    char pathname[PATH_MAX]; // 文件路径
    int flags;               // 打开标志
    mode_t mode;             // 文件模式
    off_t size;              // 操作大小
    char operation[32];      // 操作类型(open/read/write/unlink)
} audit_file_t;

// 进程操作审计记录
typedef struct
{
    audit_base_t base;
    pid_t child_pid;    // 子进程ID
    int exit_status;    // 退出状态
    char operation[32]; // 操作类型(fork/exit)
} audit_process_t;

// 内存操作审计记录
typedef struct
{
    audit_base_t base;
    void *addr;         // 内存地址
    size_t length;      // 内存大小
    int prot;           // 保护标志
    int flags;          // 映射标志
    char operation[32]; // 操作类型(mmap/munmap)
} audit_memory_t;

// 安全相关审计记录
typedef struct
{
    audit_base_t base;
    uid_t old_uid;         // 旧用户ID
    uid_t new_uid;         // 新用户ID
    mode_t old_mode;       // 旧权限
    mode_t new_mode;       // 新权限
    char target[PATH_MAX]; // 操作目标
    char operation[32];    // 操作类型(setuid/chmod)
} audit_security_t;

// 全局配置结构
typedef struct
{
    char log_path[PATH_MAX];   // 日志文件路径
    int max_log_size;          // 单个日志文件最大大小
    int max_log_files;         // 最大日志文件数
    int buffer_size;           // 缓冲区大小
    FILE *log_fp;              // 日志文件指针
    pthread_mutex_t log_mutex; // 日志互斥锁
} audit_config_t;

// 声明全局配置变量
extern audit_config_t g_audit_config;

// 格式化函数声明 - 改为使用字符串缓冲区
void audit_exec_to_str(const audit_exec_t *record, char *buf, size_t size);
void audit_network_to_str(const audit_network_t *record, char *buf, size_t size);
void audit_file_to_str(const audit_file_t *record, char *buf, size_t size);
void audit_process_to_str(const audit_process_t *record, char *buf, size_t size);
void audit_memory_to_str(const audit_memory_t *record, char *buf, size_t size);
void audit_security_to_str(const audit_security_t *record, char *buf, size_t size);

// 初始化和清理函数声明
void audit_init(void);
void audit_cleanup(void);

#endif // AUDIT_TYPES_H