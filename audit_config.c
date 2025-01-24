#include "audit_config.h"
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// 定义全局配置变量
audit_config_t g_audit_config = {
    .log_dir = "/var/log/audit",
    .log_file = "/var/log/audit/hook_audit.log",
    .init_log_file = "/tmp/hook_init.log",
    .lock_file = "/tmp/hook_execve.lock",
    .max_log_size = 10 * 1024 * 1024, // 10MB
    .max_log_files = 5,
    .buffer_size = 4096,
    .log_fp = NULL};

// 初始化配置
void audit_config_init(void)
{
    // 初始化互斥锁
    pthread_mutex_init(&g_audit_config.log_mutex, NULL);

    // 确保日志目录存在
    mkdir(g_audit_config.log_dir, 0755);
}

// 清理配置
void audit_config_cleanup(void)
{
    if (g_audit_config.log_fp)
    {
        fclose(g_audit_config.log_fp);
        g_audit_config.log_fp = NULL;
    }
    pthread_mutex_destroy(&g_audit_config.log_mutex);
}

// Getter 函数
const char *get_log_dir(void)
{
    return g_audit_config.log_dir;
}

const char *get_log_file(void)
{
    return g_audit_config.log_file;
}

const char *get_init_log_file(void)
{
    return g_audit_config.init_log_file;
}

const char *get_lock_file(void)
{
    return g_audit_config.lock_file;
}