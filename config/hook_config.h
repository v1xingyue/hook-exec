#ifndef HOOK_CONFIG_H
#define HOOK_CONFIG_H

// 拦截配置结构体
typedef struct {
    // 系统调用拦截开关
    int enable_execve;    // execve 拦截
    int enable_file;      // 文件操作拦截 (open, write, unlink, rename)
    int enable_process;   // 进程操作拦截 (fork, exit)
    int enable_memory;    // 内存操作拦截 (mmap)
    int enable_security;  // 安全操作拦截 (setuid, chmod)
    int enable_signal;    // 信号处理拦截 (signal)
    int enable_env;       // 环境变量拦截 (putenv)
    int enable_dns;       // DNS 拦截 (gethostbyname, getaddrinfo, sendto, recvfrom)
    int enable_network;   // 网络拦截 (connect, listen)
    
    // 文件操作过滤
    int filter_file_write;  // 是否过滤文件写入（只记录普通文件）
    
    // 路径过滤（可选，用于排除某些路径）
    char exclude_paths[10][256];  // 排除的路径前缀
    int exclude_path_count;
} hook_config_t;

// 全局配置实例
extern hook_config_t g_hook_config;

// 初始化配置（从环境变量或配置文件读取）
void hook_config_init(void);

// 检查某个系统调用是否应该被拦截
int hook_config_is_enabled(int hook_type);

// Hook 类型定义
#define HOOK_TYPE_EXECVE    1
#define HOOK_TYPE_FILE      2
#define HOOK_TYPE_PROCESS   3
#define HOOK_TYPE_MEMORY    4
#define HOOK_TYPE_SECURITY  5
#define HOOK_TYPE_SIGNAL    6
#define HOOK_TYPE_ENV       7
#define HOOK_TYPE_DNS       8
#define HOOK_TYPE_NETWORK   9

#endif // HOOK_CONFIG_H

