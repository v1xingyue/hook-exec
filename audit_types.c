#include "audit_types.h"
#include "audit_config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/file.h>

// 定义全局配置变量
audit_config_t g_audit_config = {
    .log_path = "/var/log/audit/hook_audit.log",
    .max_log_size = 10 * 1024 * 1024, // 10MB
    .max_log_files = 5,
    .buffer_size = 4096,
    .log_fp = NULL};

static int is_first_process(void)
{
    static int init_fd = -1;

    // 使用配置中的锁文件路径
    init_fd = open(get_lock_file(), O_RDWR | O_CREAT, 0644);

    if (init_fd != -1)
    {
        if (flock(init_fd, LOCK_EX | LOCK_NB) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// 构造函数 - 在库加载时执行
__attribute__((constructor)) static void init(void)
{
    // 初始化配置
    audit_config_init();

    // 一次性初始化
    if (is_first_process())
    {
        mkdir(get_log_dir(), 0755);
    }

    // 打开日志文件
    g_audit_config.log_fp = fopen(get_log_file(), "a");

    // 添加进程信息到初始化日志
    char proc_name[256];
    get_process_name(proc_name, sizeof(proc_name));

    FILE *debug_log = fopen(get_init_log_file(), "a");
    if (debug_log)
    {
        fprintf(debug_log, "Library initialized in process: %s (PID: %d)\n",
                proc_name, getpid());
        fclose(debug_log);
    }

    // 每个进程都需要执行的初始化代码
    pthread_mutex_init(&g_audit_config.log_mutex, NULL);

    // 写入启动记录
    if (g_audit_config.log_fp)
    {
        time_t now = time(NULL);
        char timestr[64];
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_audit_config.log_fp,
                "=== Audit Hook Library Started at %s ===\n", timestr);
        fflush(g_audit_config.log_fp);
    }
}

// 析构函数 - 在库卸载时执行
__attribute__((destructor)) static void fini(void)
{
    // 写入停止记录
    if (g_audit_config.log_fp)
    {
        time_t now = time(NULL);
        char timestr[64];
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_audit_config.log_fp,
                "=== Audit Hook Library Stopped at %s ===\n", timestr);
        fflush(g_audit_config.log_fp);
        fclose(g_audit_config.log_fp);
    }

    // 销毁互斥锁
    pthread_mutex_destroy(&g_audit_config.log_mutex);

    // 清理配置
    audit_config_cleanup();
}

// 日志写入函数
void write_audit_log(const char *buf)
{
    pthread_mutex_lock(&g_audit_config.log_mutex);

    // 检查日志文件大小
    if (g_audit_config.log_fp)
    {
        fseek(g_audit_config.log_fp, 0, SEEK_END);
        long size = ftell(g_audit_config.log_fp);

        if (size >= g_audit_config.max_log_size)
        {
            // 实现日志轮转
            fclose(g_audit_config.log_fp);

            // 轮转现有日志文件
            char old_name[PATH_MAX], new_name[PATH_MAX];
            for (int i = g_audit_config.max_log_files - 1; i >= 0; i--)
            {
                snprintf(old_name, sizeof(old_name), "%s.%d",
                         g_audit_config.log_path, i);
                snprintf(new_name, sizeof(new_name), "%s.%d",
                         g_audit_config.log_path, i + 1);
                rename(old_name, new_name);
            }

            rename(g_audit_config.log_path, old_name);
            g_audit_config.log_fp = fopen(g_audit_config.log_path, "a");
        }
    }

    // 写入日志
    if (g_audit_config.log_fp)
    {
        fprintf(g_audit_config.log_fp, "%s\n", buf);
        fflush(g_audit_config.log_fp);
    }

    pthread_mutex_unlock(&g_audit_config.log_mutex);
}

// 基础记录格式化
static void base_to_str(const audit_base_t *base, char *buf, size_t size)
{
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&base->timestamp));

    snprintf(buf, size,
             "{\n"
             "  \"timestamp\": \"%s\",\n"
             "  \"pid\": %d,\n"
             "  \"uid\": %d,\n"
             "  \"process\": \"%s\",\n"
             "  \"cwd\": \"%s\"",
             timestr, base->pid, base->uid, base->process, base->cwd);
}

// 执行记录格式化
void audit_exec_to_str(const audit_exec_t *record, char *buf, size_t size)
{
    char base_buf[4096];
    base_to_str(&record->base, base_buf, sizeof(base_buf));

    char argv_buf[2048] = "";
    size_t pos = 0;

    // 构建参数数组
    strcat(argv_buf, "  \"argv\": [");
    for (char **arg = record->argv; arg && *arg; arg++)
    {
        pos = strlen(argv_buf);
        if (arg != record->argv)
        {
            snprintf(argv_buf + pos, sizeof(argv_buf) - pos, ",");
            pos = strlen(argv_buf);
        }
        snprintf(argv_buf + pos, sizeof(argv_buf) - pos, "\n    \"%s\"", *arg);
    }
    strcat(argv_buf, "\n  ]");

    snprintf(buf, size,
             "%s,\n"
             "  \"pathname\": \"%s\",\n"
             "%s\n"
             "}",
             base_buf, record->pathname, argv_buf);
}

// 网络记录格式化
void audit_network_to_str(const audit_network_t *record, char *buf, size_t size)
{
    char base_buf[4096];
    base_to_str(&record->base, base_buf, sizeof(base_buf));

    snprintf(buf, size,
             "%s,\n"
             "  \"sockfd\": %d,\n"
             "  \"domain\": %d,\n"
             "  \"type\": %d,\n"
             "  \"src_ip\": \"%s\",\n"
             "  \"src_port\": %u,\n"
             "  \"dst_ip\": \"%s\",\n"
             "  \"dst_port\": %u\n"
             "}",
             base_buf,
             record->sockfd,
             record->domain,
             record->type,
             record->src_ip,
             record->src_port,
             record->dst_ip,
             record->dst_port);
}

// ... 其他类型的格式化函数实现