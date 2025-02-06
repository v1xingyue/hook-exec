#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#define BUFFER_SIZE 4096
static int running = 1;
static int server_fd = -1;

void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM)
    {
        running = 0;
        if (server_fd != -1)
        {
            close(server_fd);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <log_dir>\n", argv[0]);
        return 1;
    }

    const char *log_dir = argv[1];
    char socket_path[256];
    char log_path[256];

    // 确保日志目录存在
    struct stat st = {0};
    if (stat(log_dir, &st) == -1)
    {
        if (mkdir(log_dir, 0755) == -1)
        {
            fprintf(stderr, "Failed to create log directory %s: %s\n",
                    log_dir, strerror(errno));
            return 1;
        }
    }

    // 设置路径
    snprintf(socket_path, sizeof(socket_path), "%s/audit.sock", log_dir);
    snprintf(log_path, sizeof(log_path), "%s/audit.log", log_dir);

    // 删除可能存在的旧socket文件
    unlink(socket_path);

    // 创建服务器socket
    server_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        return 1;
    }

    // 设置服务器地址
    struct sockaddr_un server_addr = {0};
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    // 绑定socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind");
        close(server_fd);
        return 1;
    }

    // 设置权限，让其他用户也能写入
    chmod(socket_path, 0666);

    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Audit log server started. Socket: %s, Log file: %s\n", socket_path, log_path);

    // 打开日志文件
    int log_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (log_fd == -1)
    {
        perror("open log file");
        close(server_fd);
        unlink(socket_path);
        return 1;
    }

    // 主循环
    char buffer[BUFFER_SIZE];
    while (running)
    {
        ssize_t received = recv(server_fd, buffer, sizeof(buffer) - 1, 0);
        if (received > 0)
        {
            buffer[received] = '\0';

            // 写入日志文件
            write(log_fd, buffer, received);
            fsync(log_fd); // 确保写入磁盘
        }
    }

    // 清理
    close(log_fd);
    close(server_fd);
    unlink(socket_path);
    printf("\nAudit log server stopped.\n");

    return 0;
}