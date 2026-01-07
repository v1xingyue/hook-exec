#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../include/audit_log.h"
#include "../include/hook_config.h"

// 定义原始函数的类型
typedef int (*real_execve_t)(const char *pathname, char *const argv[], char *const envp[]);
typedef int (*real_open_t)(const char *pathname, int flags, ...);
typedef ssize_t (*real_write_t)(int fd, const void *buf, size_t count);
typedef int (*real_unlink_t)(const char *pathname);
typedef int (*real_rename_t)(const char *oldpath, const char *newpath);
typedef pid_t (*real_fork_t)(void);
typedef void (*real_exit_t)(int status);
typedef void *(*real_mmap_t)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
typedef int (*real_setuid_t)(uid_t uid);
typedef int (*real_chmod_t)(const char *path, mode_t mode);
typedef void (*signal_handler_t)(int);
typedef signal_handler_t (*real_signal_t)(int signum, signal_handler_t handler);
typedef int (*real_putenv_t)(char *string);
typedef int (*real_connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*real_listen_t)(int sockfd, int backlog);
typedef struct hostent *(*real_gethostbyname_t)(const char *name);
typedef int (*real_getaddrinfo_t)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

// DNS header structure
struct dns_header
{
    uint16_t id;      // identification number
    uint16_t flags;   // DNS flags
    uint16_t qdcount; // number of question entries
    uint16_t ancount; // number of answer entries
    uint16_t nscount; // number of authority entries
    uint16_t arcount; // number of resource entries
};

// Function types for UDP operations
typedef ssize_t (*real_sendto_t)(int sockfd, const void *buf, size_t len, int flags,
                                 const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*real_recvfrom_t)(int sockfd, void *buf, size_t len, int flags,
                                   struct sockaddr *src_addr, socklen_t *addrlen);

// DNS Record Types
#define DNS_TYPE_A 1     // IPv4 address
#define DNS_TYPE_NS 2    // Nameserver
#define DNS_TYPE_CNAME 5 // Canonical name
#define DNS_TYPE_SOA 6   // Start of Authority
#define DNS_TYPE_TYPE9 9 // NSEC3PARAM (DNSSEC)
#define DNS_TYPE_PTR 12  // Pointer record

// DNS name parsing function
static void parse_dns_name(const unsigned char *reader, const unsigned char *buffer, char *name, int *count)
{
    unsigned char *name_ptr = (unsigned char *)name;
    unsigned int jumped = 0, offset;
    int i, j;
    *count = 1;

    name[0] = '\0';

    while (*reader != 0)
    {
        if (*reader >= 192)
        { // Compression pointer
            offset = (*reader) * 256 + *(reader + 1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else
        {
            *name_ptr++ = *reader;
        }
        reader++;
        if (jumped == 0)
            (*count)++;
    }

    *name_ptr = '\0';

    // Convert DNS name format to dot format
    for (i = 0; i < strlen((const char *)name); i++)
    {
        int len = name[i];
        for (j = 0; j < len; j++)
        {
            name[i] = name[i + 1];
            i++;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';
}

// Parse DNS packet
static void parse_dns_packet(const unsigned char *buffer, size_t len)
{
    if (len < sizeof(struct dns_header))
    {
        return;
    }

    // 创建一个临时的 header 结构体来存储转换后的值，而不是直接修改原始数据
    struct dns_header dns_tmp;
    memcpy(&dns_tmp, buffer, sizeof(struct dns_header));

    // 在临时结构体上进行网络字节序转换
    dns_tmp.id = ntohs(dns_tmp.id);
    dns_tmp.flags = ntohs(dns_tmp.flags);
    dns_tmp.qdcount = ntohs(dns_tmp.qdcount);
    dns_tmp.ancount = ntohs(dns_tmp.ancount);
    dns_tmp.nscount = ntohs(dns_tmp.nscount);
    dns_tmp.arcount = ntohs(dns_tmp.arcount);

    const unsigned char *reader = buffer + sizeof(struct dns_header);
    char name[256];
    int count;

    // Check if this is a query or response
    int is_response = (dns_tmp.flags & 0x8000) != 0;

    // Parse questions
    for (int i = 0; i < dns_tmp.qdcount && reader < buffer + len; i++)
    {
        parse_dns_name(reader, buffer, name, &count);
        if (!is_response)
        {
            uint16_t qtype;
            memcpy(&qtype, reader + count, sizeof(qtype));
            qtype = ntohs(qtype);

            audit_log(AUDIT_DNS, "DNS Query:\n"
                                 "        Name: %s\n"
                                 "        Type: %d\n"
                                 "        Transaction ID: 0x%04x",
                      name, qtype, dns_tmp.id);
        }
        reader += count + 4; // Skip qtype and qclass
    }

    // Parse answers if this is a response
    if (is_response && dns_tmp.ancount > 0)
    {
        char log_buf[4096] = "";
        int log_len = 0;

        log_len += snprintf(log_buf + log_len, sizeof(log_buf) - log_len,
                            "DNS Response:\n"
                            "        Transaction ID: 0x%04x\n"
                            "        Answers:",
                            dns_tmp.id);

        for (int i = 0; i < dns_tmp.ancount && reader < buffer + len; i++)
        {
            parse_dns_name(reader, buffer, name, &count);
            reader += count;

            // 临时变量存储转换后的值
            uint16_t type, class;
            uint32_t ttl;
            uint16_t rdlength;

            // 安全地读取并转换网络字节序
            memcpy(&type, reader, sizeof(type));
            type = ntohs(type);
            reader += 2;

            memcpy(&class, reader, sizeof(class));
            class = ntohs(class);
            reader += 2;

            memcpy(&ttl, reader, sizeof(ttl));
            ttl = ntohl(ttl);
            reader += 4;

            memcpy(&rdlength, reader, sizeof(rdlength));
            rdlength = ntohs(rdlength);
            reader += 2;

            switch (type)
            {
            case 1: // A Record
                if (rdlength == 4)
                {
                    struct in_addr addr;
                    memcpy(&addr, reader, 4);
                    log_len += snprintf(log_buf + log_len, sizeof(log_buf) - log_len,
                                        "\n        %s -> IPv4: %s (TTL: %u)",
                                        name, inet_ntoa(addr), ttl);
                }
                break;
            case 5: // CNAME Record
            {
                char cname[256];
                int cname_count;
                parse_dns_name(reader, buffer, cname, &cname_count);
                log_len += snprintf(log_buf + log_len, sizeof(log_buf) - log_len,
                                    "\n        %s -> CNAME: %s (TTL: %u)",
                                    name, cname, ttl);
            }
            break;
            case 28: // AAAA Record
                if (rdlength == 16)
                {
                    char ipv6str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, reader, ipv6str, INET6_ADDRSTRLEN);
                    log_len += snprintf(log_buf + log_len, sizeof(log_buf) - log_len,
                                        "\n        %s -> IPv6: %s (TTL: %u)",
                                        name, ipv6str, ttl);
                }
                break;
            }
            reader += rdlength;
        }

        if (log_len > 0)
        {
            audit_log(AUDIT_DNS, "%s", log_buf);
        }
    }
}

// Hook for sendto
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    real_sendto_t real_sendto = (real_sendto_t)dlsym(RTLD_NEXT, "sendto");

    // 先调用原始函数，确保数据发送不受影响
    ssize_t result = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

    // 然后再进行日志记录
    if (hook_config_is_enabled(HOOK_TYPE_DNS) && dest_addr && dest_addr->sa_family == AF_INET)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)dest_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ip, sizeof(ip));

        audit_log(AUDIT_DNS, "UDP Send:\n"
                             "        Socket: %d\n"
                             "        Destination: %s:%d\n"
                             "        Length: %zu bytes",
                  sockfd, ip, ntohs(addr->sin_port), len);

        if (ntohs(addr->sin_port) == 53)
        {
            parse_dns_packet(buf, len);
        }
    }

    return result;
}

// Hook for recvfrom
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    real_recvfrom_t real_recvfrom = (real_recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");

    // 先接收数据
    ssize_t result = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

    // 然后再进行日志记录
    if (hook_config_is_enabled(HOOK_TYPE_DNS) && result > 0 && src_addr && src_addr->sa_family == AF_INET)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)src_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ip, sizeof(ip));

        audit_log(AUDIT_DNS, "UDP Receive:\n"
                             "        Socket: %d\n"
                             "        Source: %s:%d\n"
                             "        Length: %zd bytes",
                  sockfd, ip, ntohs(addr->sin_port), result);

        if (ntohs(addr->sin_port) == 53)
        {
            parse_dns_packet(buf, result);
        }
    }

    return result;
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

// execve 系统调用的钩子函数
int execve(const char *pathname, char *const argv[], char *const envp[])
{
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");

    if (hook_config_is_enabled(HOOK_TYPE_EXECVE)) {
        // 构建参数字符串
        char args_buf[4096] = "";
        size_t total_len = 0;
        for (int i = 0; argv[i] != NULL && total_len < sizeof(args_buf) - 100; i++)
        {
            total_len += snprintf(args_buf + total_len, sizeof(args_buf) - total_len,
                                  "\n        arg[%d]: %s", i, argv[i]);
        }

        audit_log(AUDIT_EXEC, "Execute: %s%s", pathname, args_buf);
    }

    return real_execve(pathname, argv, envp);
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
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = real_open(pathname, flags, mode);

    if (hook_config_is_enabled(HOOK_TYPE_FILE)) {
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
    }

    return fd;
}

// write 系统调用的钩子函数
ssize_t write(int fd, const void *buf, size_t count)
{
    real_write_t real_write = (real_write_t)dlsym(RTLD_NEXT, "write");

    if (hook_config_is_enabled(HOOK_TYPE_FILE)) {
        // 只记录普通文件的写操作
        if (!g_hook_config.filter_file_write || is_regular_file(fd))
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
    }

    return real_write(fd, buf, count);
}

// unlink 系统调用的钩子函数
int unlink(const char *pathname)
{
    real_unlink_t real_unlink = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    int result = real_unlink(pathname);

    if (hook_config_is_enabled(HOOK_TYPE_FILE)) {
        audit_log(AUDIT_FILE, "File delete:\n"
                              "        Path: %s\n"
                              "        Result: %s",
                  pathname,
                  result == 0 ? "success" : strerror(errno));
    }

    return result;
}

// rename 系统调用的钩子函数
int rename(const char *oldpath, const char *newpath)
{
    real_rename_t real_rename = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    int result = real_rename(oldpath, newpath);

    if (hook_config_is_enabled(HOOK_TYPE_FILE)) {
        audit_log(AUDIT_FILE, "File rename:\n"
                              "        Old path: %s\n"
                              "        New path: %s\n"
                              "        Result: %s",
                  oldpath, newpath,
                  result == 0 ? "success" : strerror(errno));
    }

    return result;
}

// 进程管理监控
pid_t fork(void)
{
    real_fork_t real_fork = (real_fork_t)dlsym(RTLD_NEXT, "fork");
    pid_t pid = real_fork();

    if (hook_config_is_enabled(HOOK_TYPE_PROCESS)) {
        audit_log(AUDIT_PROCESS, "Process fork:\n"
                                 "        Parent PID: %d\n"
                                 "        Child PID: %d",
                  getpid(), pid);
    }
    return pid;
}

__attribute__((noreturn)) void exit(int status)
{
    real_exit_t real_exit = (real_exit_t)dlsym(RTLD_NEXT, "exit");

    if (hook_config_is_enabled(HOOK_TYPE_PROCESS)) {
        audit_log(AUDIT_PROCESS, "Process exit:\n"
                                 "        PID: %d\n"
                                 "        Status: %d",
                  getpid(), status);
    }

    real_exit(status);
    __builtin_unreachable();
}

// 内存操作监控
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    real_mmap_t real_mmap = (real_mmap_t)dlsym(RTLD_NEXT, "mmap");
    void *result = real_mmap(addr, len, prot, flags, fd, offset);

    if (hook_config_is_enabled(HOOK_TYPE_MEMORY)) {
        audit_log(AUDIT_MEMORY, "Memory map:\n"
                                "        Size: %zu bytes\n"
                                "        Protection: %s%s%s\n"
                                "        Address: %p",
                  len,
                  (prot & PROT_READ) ? "READ " : "",
                  (prot & PROT_WRITE) ? "WRITE " : "",
                  (prot & PROT_EXEC) ? "EXEC" : "",
                  result);
    }
    return result;
}

// 权限监控
int setuid(uid_t uid)
{
    real_setuid_t real_setuid = (real_setuid_t)dlsym(RTLD_NEXT, "setuid");
    int result = real_setuid(uid);

    if (hook_config_is_enabled(HOOK_TYPE_SECURITY)) {
        audit_log(AUDIT_SECURITY, "User ID change:\n"
                                  "        Old UID: %d\n"
                                  "        New UID: %d\n"
                                  "        Result: %s",
                  getuid(), uid,
                  result == 0 ? "success" : "failed");
    }
    return result;
}

int chmod(const char *path, mode_t mode)
{
    real_chmod_t real_chmod = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    int result = real_chmod(path, mode);

    if (hook_config_is_enabled(HOOK_TYPE_SECURITY)) {
        audit_log(AUDIT_SECURITY, "File permission change:\n"
                                  "        Path: %s\n"
                                  "        Mode: %o\n"
                                  "        Result: %s",
                  path, mode,
                  result == 0 ? "success" : strerror(errno));
    }
    return result;
}

// 信号处理监控
signal_handler_t signal(int signum, signal_handler_t handler)
{
    real_signal_t real_signal = (real_signal_t)dlsym(RTLD_NEXT, "signal");
    signal_handler_t result = real_signal(signum, handler);

    if (hook_config_is_enabled(HOOK_TYPE_SIGNAL)) {
        audit_log(AUDIT_SIGNAL, "Signal handler change:\n"
                                "        Signal: %d (%s)\n"
                                "        Handler: %p",
                  signum,
                  strsignal(signum),
                  (void *)handler);
    }
    return result;
}

// 环境变量监控
int putenv(char *string)
{
    real_putenv_t real_putenv = (real_putenv_t)dlsym(RTLD_NEXT, "putenv");

    if (hook_config_is_enabled(HOOK_TYPE_ENV)) {
        audit_log(AUDIT_ENV, "Environment change:\n"
                             "        Change: %s",
                  string);
    }
    return real_putenv(string);
}

// DNS解析钩子函数 - gethostbyname
struct hostent *gethostbyname(const char *name)
{
    real_gethostbyname_t real_gethostbyname = (real_gethostbyname_t)dlsym(RTLD_NEXT, "gethostbyname");
    struct hostent *result = real_gethostbyname(name);

    if (hook_config_is_enabled(HOOK_TYPE_DNS)) {
        char resolved[1024] = "";
        if (result != NULL && result->h_addr_list != NULL)
        {
            struct in_addr addr;
            memcpy(&addr, result->h_addr_list[0], sizeof(struct in_addr));
            snprintf(resolved, sizeof(resolved), " -> %s", inet_ntoa(addr));
        }

        audit_log(AUDIT_DNS, "DNS Query (gethostbyname):\n"
                             "        Host: %s%s\n"
                             "        Result: %s",
                  name, resolved,
                  result != NULL ? "success" : "failed");
    }

    return result;
}

// DNS解析钩子函数 - getaddrinfo
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    real_getaddrinfo_t real_getaddrinfo = (real_getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
    int result = real_getaddrinfo(node, service, hints, res);

    if (hook_config_is_enabled(HOOK_TYPE_DNS)) {
        char resolved[1024] = "";
        if (result == 0 && res != NULL && *res != NULL)
        {
            char host[NI_MAXHOST];
            if (getnameinfo((*res)->ai_addr, (*res)->ai_addrlen,
                            host, sizeof(host), NULL, 0, NI_NUMERICHOST) == 0)
            {
                snprintf(resolved, sizeof(resolved), " -> %s", host);
            }
        }

        audit_log(AUDIT_DNS, "DNS Query (getaddrinfo):\n"
                             "        Host: %s\n"
                             "        Service: %s%s\n"
                             "        Result: %s",
                  node ? node : "NULL",
                  service ? service : "NULL",
                  resolved,
                  result == 0 ? "success" : gai_strerror(result));
    }

    return result;
}

// 连接请求钩子函数
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    real_connect_t real_connect = (real_connect_t)dlsym(RTLD_NEXT, "connect");

    int result = real_connect(sockfd, addr, addrlen);

    if (hook_config_is_enabled(HOOK_TYPE_NETWORK)) {
        char remote_addr[256];
        format_socket_address(addr, remote_addr, sizeof(remote_addr));

        audit_log(AUDIT_CONNECT, "Connection attempt:\n"
                                 "        Socket: %d\n"
                                 "        Remote address: %s\n"
                                 "        Address length: %d\n"
                                 "        Result: %s\n"
                                 "        Error: %s",
                  sockfd, remote_addr, addrlen,
                  result == 0 ? "success" : "failed",
                  result == 0 ? "none" : strerror(errno));
    }

    return result;
}

// 监听请求钩子函数
int listen(int sockfd, int backlog)
{
    real_listen_t real_listen = (real_listen_t)dlsym(RTLD_NEXT, "listen");

    int result = real_listen(sockfd, backlog);

    if (hook_config_is_enabled(HOOK_TYPE_NETWORK)) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        char local_addr[256] = "unknown";

        if (getsockname(sockfd, (struct sockaddr *)&addr, &addr_len) == 0)
        {
            format_socket_address((struct sockaddr *)&addr, local_addr, sizeof(local_addr));
        }

        audit_log(AUDIT_LISTEN, "Listen request:\n"
                                "        Socket: %d\n"
                                "        Local address: %s\n"
                                "        Backlog: %d",
                  sockfd, local_addr, backlog);
    }

    return result;
}

// 初始化函数，在动态库加载时自动执行
__attribute__((constructor)) static void init_syscall_proxy(void)
{
    static int initialized = 0;
    if (initialized)
        return;
    initialized = 1;

    // 初始化拦截配置
    hook_config_init();

    // 初始化审计日志
    const char *log_dir = getenv("SYSCALL_PROXY_LOG_DIR");
    if (!log_dir)
    {
        log_dir = "/var/log/syscall-proxy";
    }

    audit_init(log_dir);
    printf("Hook Execve initialized! Log directory: %s\n", g_audit_config.log_dir);
    fflush(stdout);
}

