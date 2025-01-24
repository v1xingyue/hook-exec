#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h> // 用于 va_list, va_start, va_arg, va_end
#include <limits.h> // 用于 PATH_MAX
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "audit_log.h"

// 定义原始 execve 函数的类型
typedef int (*real_execve_t)(const char *pathname, char *const argv[], char *const envp[]);
typedef int (*real_socket_t)(int domain, int type, int protocol);
typedef int (*real_bind_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef struct hostent *(*real_gethostbyname_t)(const char *name);
typedef int (*real_getaddrinfo_t)(const char *node, const char *service,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res);
typedef int (*real_connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef ssize_t (*real_send_t)(int sockfd, const void *buf, size_t len, int flags);
typedef ssize_t (*real_recv_t)(int sockfd, void *buf, size_t len, int flags);
typedef int (*real_close_t)(int fd);
typedef int (*real_listen_t)(int sockfd, int backlog);
typedef int (*real_accept_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*real_open_t)(const char *pathname, int flags, ...);
typedef ssize_t (*real_write_t)(int fd, const void *buf, size_t count);
typedef ssize_t (*real_read_t)(int fd, void *buf, size_t count);
typedef int (*real_unlink_t)(const char *pathname);
typedef int (*real_rename_t)(const char *oldpath, const char *newpath);
typedef pid_t (*real_fork_t)(void);
typedef void (*real_exit_t)(int status);
typedef void *(*real_mmap_t)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
typedef void *(*real_malloc_t)(size_t size);
typedef int (*real_setuid_t)(uid_t uid);
typedef int (*real_chmod_t)(const char *path, mode_t mode);
typedef void (*signal_handler_t)(int);
typedef signal_handler_t (*real_signal_t)(int signum, signal_handler_t handler);
typedef int (*real_putenv_t)(char *string);

// 获取当前时间字符串
static void get_current_time(char *buffer, size_t size)
{
    time_t now = time(NULL);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", localtime(&now));
}

// 获取进程名称的辅助函数
static void get_process_name(char *buffer, size_t size)
{
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", getpid());

    FILE *cmd_file = fopen(proc_path, "r");
    if (cmd_file)
    {
        size_t len = fread(buffer, 1, size - 1, cmd_file);
        if (len > 0)
        {
            buffer[len] = '\0';
        }
        else
        {
            snprintf(buffer, size, "unknown");
        }
        fclose(cmd_file);
    }
    else
    {
        snprintf(buffer, size, "unknown");
    }
}

// socket 系统调用的钩子函数
int socket(int domain, int type, int protocol)
{
    real_socket_t real_socket = (real_socket_t)dlsym(RTLD_NEXT, "socket");

    int sockfd = real_socket(domain, type, protocol);

    if (sockfd >= 0)
    {
        audit_log(AUDIT_SOCKET,
                  "Socket created: fd=%d\n"
                  "        Domain: %d (%s)\n"
                  "        Type: %d (%s)\n"
                  "        Protocol: %d",
                  sockfd,
                  domain,
                  domain == AF_INET ? "AF_INET" : domain == AF_INET6 ? "AF_INET6"
                                              : domain == AF_UNIX    ? "AF_UNIX"
                                                                     : "OTHER",
                  type,
                  type == SOCK_STREAM ? "SOCK_STREAM" : type == SOCK_DGRAM ? "SOCK_DGRAM"
                                                    : type == SOCK_RAW     ? "SOCK_RAW"
                                                                           : "OTHER",
                  protocol);
    }

    return sockfd;
}

// bind 系统调用的钩子函数
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    real_bind_t real_bind = (real_bind_t)dlsym(RTLD_NEXT, "bind");
    char addr_str[256];
    audit_network_addr(addr, addr_str, sizeof(addr_str));

    audit_log(AUDIT_NETWORK, "Binding socket:\n"
                             "        Socket fd=%d\n"
                             "        Address=%s",
              sockfd, addr_str);

    return real_bind(sockfd, addr, addrlen);
}

// 我们的替换函数
int execve(const char *pathname, char *const argv[], char *const envp[])
{
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");

    // 构建参数字符串
    char args_buf[4096] = "";
    size_t total_len = 0;
    for (int i = 0; argv[i] != NULL && total_len < sizeof(args_buf) - 100; i++)
    {
        total_len += snprintf(args_buf + total_len, sizeof(args_buf) - total_len,
                              "\n        arg[%d]: %s", i, argv[i]);
    }

    audit_log(AUDIT_EXEC, "Execute: %s%s", pathname, args_buf);

    return real_execve(pathname, argv, envp);
}

// getaddrinfo 钩子函数
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    real_getaddrinfo_t real_getaddrinfo = (real_getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
    int result = real_getaddrinfo(node, service, hints, res);

    audit_log(AUDIT_DNS, "DNS Query (getaddrinfo):\n"
                         "        Host: %s\n"
                         "        Service: %s\n"
                         "        Result: %s",
              node ? node : "NULL",
              service ? service : "NULL",
              result == 0 ? "success" : gai_strerror(result));

    if (result == 0 && res != NULL && *res != NULL)
    {
        char resolved_addrs[1024] = "";
        size_t offset = 0;

        for (struct addrinfo *rp = *res; rp != NULL && offset < sizeof(resolved_addrs) - 100; rp = rp->ai_next)
        {
            char host[NI_MAXHOST];
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen,
                            host, sizeof(host),
                            NULL, 0,
                            NI_NUMERICHOST) == 0)
            {
                offset += snprintf(resolved_addrs + offset, sizeof(resolved_addrs) - offset,
                                   "\n                %s", host);
            }
        }

        if (offset > 0)
        {
            audit_log(AUDIT_DNS, "Resolved addresses:%s", resolved_addrs);
        }
    }

    return result;
}

// gethostbyname 钩子函数
struct hostent *gethostbyname(const char *name)
{
    real_gethostbyname_t real_gethostbyname = (real_gethostbyname_t)dlsym(RTLD_NEXT, "gethostbyname");
    struct hostent *result = real_gethostbyname(name);

    audit_log(AUDIT_DNS, "DNS Query (gethostbyname):\n"
                         "        Host: %s\n"
                         "        Result: %s",
              name,
              result != NULL ? "success" : hstrerror(h_errno));

    if (result != NULL)
    {
        char resolved_addrs[1024] = "";
        size_t offset = 0;

        for (char **addr_list = result->h_addr_list; *addr_list != NULL && offset < sizeof(resolved_addrs) - 100; addr_list++)
        {
            struct in_addr addr;
            memcpy(&addr, *addr_list, sizeof(struct in_addr));
            offset += snprintf(resolved_addrs + offset, sizeof(resolved_addrs) - offset,
                               "\n                %s", inet_ntoa(addr));
        }

        if (offset > 0)
        {
            audit_log(AUDIT_DNS, "Resolved addresses:%s", resolved_addrs);
        }
    }

    return result;
}

// connect 系统调用的钩子函数
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    real_connect_t real_connect = (real_connect_t)dlsym(RTLD_NEXT, "connect");
    char remote_addr[256];
    char local_addr[256];
    struct sockaddr_storage local_addr_storage;
    socklen_t local_addr_len = sizeof(local_addr_storage);

    audit_network_addr(addr, remote_addr, sizeof(remote_addr));

    if (getsockname(sockfd, (struct sockaddr *)&local_addr_storage, &local_addr_len) == 0)
    {
        audit_network_addr((struct sockaddr *)&local_addr_storage, local_addr, sizeof(local_addr));
    }
    else
    {
        snprintf(local_addr, sizeof(local_addr), "unknown");
    }

    audit_log(AUDIT_NETWORK, "Connect attempt:\n"
                             "        Socket fd=%d\n"
                             "        Remote: %s\n"
                             "        Local: %s",
              sockfd, remote_addr, local_addr);

    int result = real_connect(sockfd, addr, addrlen);

    audit_log(AUDIT_NETWORK, "Connect result:\n"
                             "        Socket fd=%d\n"
                             "        Result: %s",
              sockfd,
              result == 0 ? "success" : strerror(errno));

    return result;
}

// send 系统调用的钩子函数
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    real_send_t real_send = (real_send_t)dlsym(RTLD_NEXT, "send");
    ssize_t result = real_send(sockfd, buf, len, flags);

    audit_log(AUDIT_NETWORK, "Send:\n"
                             "        Socket fd=%d\n"
                             "        Size=%zu bytes\n"
                             "        Result=%zd",
              sockfd, len, result);

    return result;
}

// recv 系统调用的钩子函数
ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    real_recv_t real_recv = (real_recv_t)dlsym(RTLD_NEXT, "recv");
    ssize_t result = real_recv(sockfd, buf, len, flags);

    audit_log(AUDIT_NETWORK, "Receive:\n"
                             "        Socket fd=%d\n"
                             "        Requested=%zu bytes\n"
                             "        Received=%zd",
              sockfd, len, result);

    return result;
}

// close 系统调用的钩子函数
int close(int fd)
{
    real_close_t real_close = (real_close_t)dlsym(RTLD_NEXT, "close");
    int is_socket = 0;
    int type;
    socklen_t type_len = sizeof(type);

    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) == 0)
    {
        is_socket = 1;
    }

    int result = real_close(fd);

    if (is_socket)
    {
        audit_log(AUDIT_NETWORK, "Close socket:\n"
                                 "        Socket fd=%d\n"
                                 "        Result=%s",
                  fd, result == 0 ? "success" : strerror(errno));
    }

    return result;
}

// listen 系统调用的钩子函数
int listen(int sockfd, int backlog)
{
    real_listen_t real_listen = (real_listen_t)dlsym(RTLD_NEXT, "listen");
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    char addr_str[256] = "unknown";

    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &local_addr_len) == 0)
    {
        audit_network_addr((struct sockaddr *)&local_addr, addr_str, sizeof(addr_str));
    }

    audit_log(AUDIT_NETWORK, "Listen:\n"
                             "        Socket fd=%d\n"
                             "        Backlog=%d\n"
                             "        Local address=%s",
              sockfd, backlog, addr_str);

    return real_listen(sockfd, backlog);
}

// accept 系统调用的钩子函数
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    real_accept_t real_accept = (real_accept_t)dlsym(RTLD_NEXT, "accept");
    int new_fd = real_accept(sockfd, addr, addrlen);

    if (new_fd >= 0 && addr != NULL)
    {
        char client_addr[256];
        audit_network_addr(addr, client_addr, sizeof(client_addr));

        audit_log(AUDIT_NETWORK, "Accept:\n"
                                 "        Listen socket=%d\n"
                                 "        New socket=%d\n"
                                 "        Client=%s",
                  sockfd, new_fd, client_addr);
    }

    return new_fd;
}

// 检查文件描述符是否指向普通文件
static int is_regular_file(int fd)
{
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        return 0;
    }
    return S_ISREG(sb.st_mode);
}

// 获取文件描述符对应的文件路径
static void get_fd_path(int fd, char *buffer, size_t size)
{
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(proc_path, buffer, size - 1);
    if (len != -1)
    {
        buffer[len] = '\0';
    }
    else
    {
        snprintf(buffer, size, "unknown");
    }
}

// open 系统调用的钩子函数
int open(const char *pathname, int flags, ...)
{
    real_open_t real_open = (real_open_t)dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT)
    {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    int fd = real_open(pathname, flags, mode);

    audit_log(AUDIT_FILE,
              "File open: %s\n"
              "        Flags: %s%s%s%s\n"
              "        Result: fd=%d",
              pathname,
              (flags & O_WRONLY) ? "WRONLY " : (flags & O_RDWR) ? "RDWR "
                                                                : "RDONLY ",
              (flags & O_CREAT) ? "CREAT " : "",
              (flags & O_TRUNC) ? "TRUNC " : "",
              (flags & O_APPEND) ? "APPEND " : "",
              fd);

    return fd;
}

// write 系统调用的钩子函数
ssize_t write(int fd, const void *buf, size_t count)
{
    real_write_t real_write = (real_write_t)dlsym(RTLD_NEXT, "write");

    // 只记录普通文件的写操作
    if (is_regular_file(fd))
    {
        char filepath[PATH_MAX];
        get_fd_path(fd, filepath, sizeof(filepath));
        ssize_t result = real_write(fd, buf, count);

        audit_log(AUDIT_FILE, "File write:\n"
                              "        File: %s (fd=%d)\n"
                              "        Size: %zu bytes\n"
                              "        Result: %zd",
                  filepath, fd, count, result);

        return result;
    }

    return real_write(fd, buf, count);
}

// unlink 系统调用的钩子函数
int unlink(const char *pathname)
{
    real_unlink_t real_unlink = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    int result = real_unlink(pathname);

    audit_log(AUDIT_FILE, "File delete:\n"
                          "        Path: %s\n"
                          "        Result: %s",
              pathname,
              result == 0 ? "success" : strerror(errno));

    return result;
}

// rename 系统调用的钩子函数
int rename(const char *oldpath, const char *newpath)
{
    real_rename_t real_rename = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    int result = real_rename(oldpath, newpath);

    audit_log(AUDIT_FILE, "File rename:\n"
                          "        Old path: %s\n"
                          "        New path: %s\n"
                          "        Result: %s",
              oldpath, newpath,
              result == 0 ? "success" : strerror(errno));

    return result;
}

// 进程管理监控
pid_t fork(void)
{
    real_fork_t real_fork = (real_fork_t)dlsym(RTLD_NEXT, "fork");
    pid_t pid = real_fork();

    audit_log(AUDIT_PROCESS, "Process fork:\n"
                             "        Parent PID: %d\n"
                             "        Child PID: %d",
              getpid(), pid);
    return pid;
}

__attribute__((noreturn)) void exit(int status)
{
    real_exit_t real_exit = (real_exit_t)dlsym(RTLD_NEXT, "exit");

    audit_log(AUDIT_PROCESS, "Process exit:\n"
                             "        PID: %d\n"
                             "        Status: %d",
              getpid(), status);

    real_exit(status);
    __builtin_unreachable(); // 告诉编译器这里永远不会到达
}

// 内存操作监控
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    real_mmap_t real_mmap = (real_mmap_t)dlsym(RTLD_NEXT, "mmap");
    void *result = real_mmap(addr, len, prot, flags, fd, offset);

    audit_log(AUDIT_MEMORY, "Memory map:\n"
                            "        Size: %zu bytes\n"
                            "        Protection: %s%s%s\n"
                            "        Address: %p",
              len,
              (prot & PROT_READ) ? "READ " : "",
              (prot & PROT_WRITE) ? "WRITE " : "",
              (prot & PROT_EXEC) ? "EXEC" : "",
              result);
    return result;
}

// 权限监控
int setuid(uid_t uid)
{
    real_setuid_t real_setuid = (real_setuid_t)dlsym(RTLD_NEXT, "setuid");
    int result = real_setuid(uid);

    audit_log(AUDIT_SECURITY, "User ID change:\n"
                              "        Old UID: %d\n"
                              "        New UID: %d\n"
                              "        Result: %s",
              getuid(), uid,
              result == 0 ? "success" : "failed");
    return result;
}

int chmod(const char *path, mode_t mode)
{
    real_chmod_t real_chmod = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    int result = real_chmod(path, mode);

    audit_log(AUDIT_SECURITY, "File permission change:\n"
                              "        Path: %s\n"
                              "        Mode: %o\n"
                              "        Result: %s",
              path, mode,
              result == 0 ? "success" : strerror(errno));
    return result;
}

// 信号处理监控
signal_handler_t signal(int signum, signal_handler_t handler)
{
    real_signal_t real_signal = (real_signal_t)dlsym(RTLD_NEXT, "signal");
    signal_handler_t result = real_signal(signum, handler);

    audit_log(AUDIT_SIGNAL, "Signal handler change:\n"
                            "        Signal: %d (%s)\n"
                            "        Handler: %p",
              signum,
              strsignal(signum),
              (void *)handler);
    return result;
}

// 环境变量监控
int putenv(char *string)
{
    real_putenv_t real_putenv = (real_putenv_t)dlsym(RTLD_NEXT, "putenv");

    audit_log(AUDIT_ENV, "Environment change:\n"
                         "        Change: %s",
              string);
    return real_putenv(string);
}

// 初始化函数，在动态库加载时自动执行
__attribute__((constructor)) static void init_syscall_proxy(void)
{
    const char *log_dir = getenv("SYSCALL_PROXY_LOG_DIR");
    if (!log_dir)
    {
        log_dir = "/var/log/syscall-proxy";
    }

    audit_init(log_dir);
    printf("Your process will be audited! Log directory: %s\n", g_audit_config.log_dir);
}
