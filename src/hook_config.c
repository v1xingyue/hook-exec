#include "../include/hook_config.h"
#include <stdlib.h>
#include <string.h>

// 全局配置实例
hook_config_t g_hook_config = {
    // 默认全部启用
    .enable_execve = 1,
    .enable_file = 1,
    .enable_process = 1,
    .enable_memory = 1,
    .enable_security = 1,
    .enable_signal = 1,
    .enable_env = 1,
    .enable_dns = 1,
    .enable_network = 1,
    .filter_file_write = 1,
    .exclude_path_count = 0
};

// 从环境变量读取配置
static void load_config_from_env(void)
{
    const char *val;
    
    // HOOK_ENABLE_EXECVE
    val = getenv("HOOK_ENABLE_EXECVE");
    if (val) g_hook_config.enable_execve = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_FILE
    val = getenv("HOOK_ENABLE_FILE");
    if (val) g_hook_config.enable_file = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_PROCESS
    val = getenv("HOOK_ENABLE_PROCESS");
    if (val) g_hook_config.enable_process = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_MEMORY
    val = getenv("HOOK_ENABLE_MEMORY");
    if (val) g_hook_config.enable_memory = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_SECURITY
    val = getenv("HOOK_ENABLE_SECURITY");
    if (val) g_hook_config.enable_security = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_SIGNAL
    val = getenv("HOOK_ENABLE_SIGNAL");
    if (val) g_hook_config.enable_signal = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_ENV
    val = getenv("HOOK_ENABLE_ENV");
    if (val) g_hook_config.enable_env = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_DNS
    val = getenv("HOOK_ENABLE_DNS");
    if (val) g_hook_config.enable_dns = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_ENABLE_NETWORK
    val = getenv("HOOK_ENABLE_NETWORK");
    if (val) g_hook_config.enable_network = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
    
    // HOOK_FILTER_FILE_WRITE
    val = getenv("HOOK_FILTER_FILE_WRITE");
    if (val) g_hook_config.filter_file_write = (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
}

// 初始化配置
void hook_config_init(void)
{
    load_config_from_env();
}

// 检查某个系统调用是否应该被拦截
int hook_config_is_enabled(int hook_type)
{
    switch (hook_type) {
        case HOOK_TYPE_EXECVE:
            return g_hook_config.enable_execve;
        case HOOK_TYPE_FILE:
            return g_hook_config.enable_file;
        case HOOK_TYPE_PROCESS:
            return g_hook_config.enable_process;
        case HOOK_TYPE_MEMORY:
            return g_hook_config.enable_memory;
        case HOOK_TYPE_SECURITY:
            return g_hook_config.enable_security;
        case HOOK_TYPE_SIGNAL:
            return g_hook_config.enable_signal;
        case HOOK_TYPE_ENV:
            return g_hook_config.enable_env;
        case HOOK_TYPE_DNS:
            return g_hook_config.enable_dns;
        case HOOK_TYPE_NETWORK:
            return g_hook_config.enable_network;
        default:
            return 0;
    }
}

