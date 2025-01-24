#ifndef AUDIT_CONFIG_H
#define AUDIT_CONFIG_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

// 配置结构体
typedef struct
{
    // 路径配置
    char log_dir[PATH_MAX];       // 日志目录
    char log_file[PATH_MAX];      // 主日志文件
    char init_log_file[PATH_MAX]; // 初始化日志
    char lock_file[PATH_MAX];     // 进程锁文件

    // 日志配置
    int max_log_size;  // 单个日志文件最大大小
    int max_log_files; // 最大日志文件数
    int buffer_size;   // 缓冲区大小

    // 运行时状态
    FILE *log_fp;              // 日志文件指针
    pthread_mutex_t log_mutex; // 日志互斥锁
} audit_config_t;

// 全局配置实例
extern audit_config_t g_audit_config;

// 配置初始化函数
void audit_config_init(void);

// 配置清理函数
void audit_config_cleanup(void);

// 获取配置项的函数
const char *get_log_dir(void);
const char *get_log_file(void);
const char *get_init_log_file(void);
const char *get_lock_file(void);

#endif // AUDIT_CONFIG_H