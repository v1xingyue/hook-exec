# Hook Execve - 系统调用审计工具

## 项目简介

Hook Execve 是一个基于 LD_PRELOAD 机制的系统调用审计工具，通过动态库注入的方式监控和记录程序执行过程中的各种系统调用和库函数调用。该工具可以用于安全审计、行为分析、调试和合规性检查等场景。

## 核心特性

### 1. 系统调用监控
- **程序执行监控**：监控 `execve` 调用，记录执行的程序和参数
- **文件操作监控**：监控 `open`、`write`、`unlink`、`rename` 等文件操作
- **进程管理监控**：监控 `fork`、`exit` 等进程创建和退出操作
- **内存操作监控**：监控 `mmap` 内存映射操作
- **权限变更监控**：监控 `setuid`、`chmod` 等权限相关操作
- **信号处理监控**：监控 `signal` 信号处理器的设置
- **环境变量监控**：监控 `putenv` 环境变量修改

### 2. 网络活动监控
- **连接监控**：监控 `connect` 网络连接请求
- **监听监控**：监控 `listen` 网络监听请求
- **DNS 解析监控**：
  - 监控 `gethostbyname` 和 `getaddrinfo` DNS 解析函数
  - 解析和记录 DNS 查询和响应数据包
  - 支持 A、AAAA、CNAME 等常见 DNS 记录类型
  - 监控 UDP sendto/recvfrom 的 DNS 流量

### 3. 审计日志功能
- **多级别日志**：支持 NONE、ERROR、INFO、DEBUG 四个日志级别
- **双重输出**：支持同时输出到文件和控制台
- **详细记录**：每条日志包含时间戳、进程ID、进程名称、操作类型和详细信息
- **线程安全**：使用文件锁确保多进程环境下的日志写入安全
- **可配置**：通过环境变量灵活配置日志行为

### 4. 灵活的拦截配置
- **按类型控制**：可以单独启用或禁用每种类型的系统调用拦截
- **环境变量配置**：通过简单的环境变量即可配置拦截行为
- **性能优化**：禁用不需要的拦截可以减少性能开销
- **详细文档**：提供完整的配置说明文档

## 项目结构

```
hook-exec/
├── src/               # 源代码目录
│   ├── hook_execve.c  # 主程序，实现各种系统调用的 hook
│   ├── audit_log.c    # 审计日志实现
│   └── hook_config.c  # 拦截配置实现
├── include/           # 头文件目录
│   ├── audit_log.h    # 审计日志头文件
│   └── hook_config.h  # 拦截配置头文件
├── config/            # 配置文件目录
│   └── README.md      # 配置说明文档
├── tests/             # 测试程序目录
│   └── dns_test.c     # DNS 测试程序
├── build/             # 编译输出目录
│   └── hook_execve.so # 编译生成的动态库
├── log/               # 日志目录
│   └── audit.log      # 审计日志文件
├── docs/              # 文档目录
│   └── readme.md      # 项目文档
├── Makefile           # 构建脚本
├── Dockerfile         # Docker 镜像构建文件
└── README.md          # 项目说明文档
```

## 编译和安装

### 前置要求

- GCC 编译器
- Make 构建工具
- Linux 系统（支持 LD_PRELOAD）
- 标准 C 库（glibc）

### 编译步骤

1. **克隆或下载项目**
   ```bash
   cd hook-exec
   ```

2. **编译项目**
   ```bash
   make
   ```

   编译完成后，会在 `build/` 目录下生成 `hook_execve.so` 动态库文件。

3. **编译测试程序（可选）**
   ```bash
   make test
   ```

   编译完成后，会在 `build/` 目录下生成 `dns_test` 测试程序。

4. **清理编译文件**
   ```bash
   make clean
   ```

### 安装（可选）

```bash
sudo make install
```

安装后，动态库会被复制到 `/usr/lib/hook_execve.so`。

## 使用方法

### 基本使用

使用 `LD_PRELOAD` 环境变量加载动态库来监控程序：

```bash
LD_PRELOAD=./build/hook_execve.so your_program
```

### 拦截配置

通过环境变量可以灵活控制哪些系统调用需要被拦截。详细配置说明请参考 [config/README.md](config/README.md)。

#### 快速配置示例

**只监控文件操作和网络连接：**
```bash
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_NETWORK=1
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0

LD_PRELOAD=./build/hook_execve.so your_program
```

**只监控 DNS 查询：**
```bash
export HOOK_ENABLE_DNS=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_NETWORK=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0

LD_PRELOAD=./build/hook_execve.so your_program
```

**全部启用（默认）：**
```bash
LD_PRELOAD=./build/hook_execve.so your_program
```

所有可配置项：
- `HOOK_ENABLE_EXECVE` - 程序执行拦截
- `HOOK_ENABLE_FILE` - 文件操作拦截
- `HOOK_ENABLE_PROCESS` - 进程操作拦截
- `HOOK_ENABLE_MEMORY` - 内存操作拦截
- `HOOK_ENABLE_SECURITY` - 安全操作拦截
- `HOOK_ENABLE_SIGNAL` - 信号处理拦截
- `HOOK_ENABLE_ENV` - 环境变量拦截
- `HOOK_ENABLE_DNS` - DNS 拦截
- `HOOK_ENABLE_NETWORK` - 网络拦截
- `HOOK_FILTER_FILE_WRITE` - 文件写入过滤（只记录普通文件）

### 配置日志目录

默认日志目录为 `/var/log/syscall-proxy`，可以通过环境变量自定义：

```bash
export SYSCALL_PROXY_LOG_DIR=/path/to/log/dir
LD_PRELOAD=./build/hook_execve.so your_program
```

### 配置日志级别

通过 `AUDIT_LOG_LEVEL` 环境变量设置日志级别：

```bash
# 不输出任何日志
export AUDIT_LOG_LEVEL=NONE

# 只输出错误信息
export AUDIT_LOG_LEVEL=ERROR

# 输出基本信息（默认）
export AUDIT_LOG_LEVEL=INFO

# 输出所有调试信息
export AUDIT_LOG_LEVEL=DEBUG

LD_PRELOAD=./build/hook_execve.so your_program
```

### 配置输出目标

控制是否输出到控制台或文件：

```bash
# 启用控制台输出
export AUDIT_CONSOLE_OUTPUT=1

# 禁用文件输出
export AUDIT_FILE_OUTPUT=0

LD_PRELOAD=./build/hook_execve.so your_program
```

### 完整示例

```bash
# 设置日志目录
export SYSCALL_PROXY_LOG_DIR=./log

# 设置日志级别为 DEBUG
export AUDIT_LOG_LEVEL=DEBUG

# 启用控制台输出
export AUDIT_CONSOLE_OUTPUT=1

# 运行被监控的程序
LD_PRELOAD=./build/hook_execve.so ls -la /tmp
```

## 日志格式

审计日志采用结构化格式，每条日志包含以下信息：

```
[2024-01-01 12:00:00] [Type=EXEC(0)] [pid=12345] [process=/bin/ls]
    Execute: /bin/ls
        arg[0]: /bin/ls
        arg[1]: -la
        arg[2]: /tmp
    ------------------------------------------
```

### 日志类型说明

| 类型代码 | 类型名称 | 说明 |
|---------|---------|------|
| 0 | EXEC | 程序执行 |
| 1 | FILE | 文件操作 |
| 2 | PROCESS | 进程操作 |
| 3 | MEMORY | 内存操作 |
| 4 | SECURITY | 安全相关操作 |
| 5 | SIGNAL | 信号处理 |
| 6 | ENV | 环境变量 |
| 7 | DNS | DNS 解析 |
| 8 | CONNECT | 网络连接 |
| 9 | LISTEN | 网络监听 |

## 监控的系统调用和函数

### 系统调用

- `execve` - 执行程序
- `open` - 打开文件
- `write` - 写入文件
- `unlink` - 删除文件
- `rename` - 重命名文件
- `fork` - 创建子进程
- `exit` - 退出进程
- `mmap` - 内存映射
- `setuid` - 设置用户ID
- `chmod` - 修改文件权限

### 库函数

- `signal` - 信号处理
- `putenv` - 设置环境变量
- `connect` - 建立网络连接
- `listen` - 监听网络端口
- `sendto` - UDP 发送数据
- `recvfrom` - UDP 接收数据
- `gethostbyname` - DNS 解析（已废弃但支持）
- `getaddrinfo` - DNS 解析（推荐）

## DNS 监控功能

该工具特别增强了 DNS 监控功能，可以：

1. **解析 DNS 数据包**：自动识别和解析 UDP 端口 53 的 DNS 查询和响应
2. **记录 DNS 查询**：记录查询的域名、类型和事务ID
3. **记录 DNS 响应**：记录解析结果，包括：
   - A 记录（IPv4 地址）
   - AAAA 记录（IPv6 地址）
   - CNAME 记录（别名）
   - TTL 值

### DNS 监控示例

运行 DNS 测试程序：

```bash
# 先编译测试程序
make test

# 运行测试（需要启用 DNS 拦截）
export HOOK_ENABLE_DNS=1
LD_PRELOAD=./build/hook_execve.so ./build/dns_test
```

日志输出示例：

```
[2024-01-01 12:00:00] [Type=DNS(7)] [pid=12345] [process=dns_test]
    DNS Query:
        Name: example.com
        Type: 1
        Transaction ID: 0x0001
    ------------------------------------------
[2024-01-01 12:00:01] [Type=DNS(7)] [pid=12345] [process=dns_test]
    DNS Response:
        Transaction ID: 0x0001
        Answers:
        example.com -> IPv4: 93.184.216.34 (TTL: 86400)
    ------------------------------------------
```

## Docker 使用

### 构建 Docker 镜像

```bash
make build-docker
```

### 运行 Docker 容器

```bash
make start-docker
```

或者手动运行：

```bash
docker run -it --rm \
  -v $(pwd)/log:/var/log/syscall-proxy \
  audit_alpine:latest
```

容器启动后，所有命令都会自动被监控。

## 环境变量配置

### 日志配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `SYSCALL_PROXY_LOG_DIR` | 日志文件目录 | `/var/log/syscall-proxy` |
| `AUDIT_LOG_LEVEL` | 日志级别（NONE/ERROR/INFO/DEBUG） | `INFO` |
| `AUDIT_CONSOLE_OUTPUT` | 是否输出到控制台（0/1） | `0`（关闭） |
| `AUDIT_FILE_OUTPUT` | 是否输出到文件（0/1） | `1`（开启） |

### 拦截配置

拦截配置用于控制哪些系统调用需要被监控。详细说明请参考 [config/README.md](config/README.md)。

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `HOOK_ENABLE_EXECVE` | 是否拦截程序执行 | `1`（启用） |
| `HOOK_ENABLE_FILE` | 是否拦截文件操作 | `1`（启用） |
| `HOOK_ENABLE_PROCESS` | 是否拦截进程操作 | `1`（启用） |
| `HOOK_ENABLE_MEMORY` | 是否拦截内存操作 | `1`（启用） |
| `HOOK_ENABLE_SECURITY` | 是否拦截安全操作 | `1`（启用） |
| `HOOK_ENABLE_SIGNAL` | 是否拦截信号处理 | `1`（启用） |
| `HOOK_ENABLE_ENV` | 是否拦截环境变量 | `1`（启用） |
| `HOOK_ENABLE_DNS` | 是否拦截 DNS 操作 | `1`（启用） |
| `HOOK_ENABLE_NETWORK` | 是否拦截网络操作 | `1`（启用） |
| `HOOK_FILTER_FILE_WRITE` | 是否过滤文件写入（只记录普通文件） | `1`（启用） |

## 注意事项

### 权限要求

1. **日志目录权限**：确保日志目录对运行程序的用户可写
2. **LD_PRELOAD 限制**：某些安全机制（如 SELinux、AppArmor）可能会限制 LD_PRELOAD 的使用
3. **setuid/setgid 程序**：对于设置了 setuid/setgid 的程序，LD_PRELOAD 可能不会生效（出于安全考虑）

### 性能影响

- 该工具会对每个被监控的系统调用增加少量开销
- 对于高频系统调用（如 `write`），可能产生大量日志
- 建议在生产环境中根据实际需求调整日志级别

### 兼容性

- 仅支持 Linux 系统
- 需要支持 `/proc` 文件系统（用于获取进程信息）
- 需要支持文件锁（用于线程安全的日志写入）

### 安全考虑

1. **日志文件安全**：确保日志文件不会被未授权访问
2. **敏感信息**：日志可能包含敏感信息（如文件路径、网络地址等），需要妥善保管
3. **递归调用**：代码中已实现递归调用保护，避免在日志记录过程中再次触发监控

## 故障排查

### 日志文件未生成

1. 检查日志目录是否存在且可写
2. 检查 `AUDIT_FILE_OUTPUT` 环境变量是否设置为 `0`
3. 检查磁盘空间是否充足

### 监控未生效

1. 确认 `LD_PRELOAD` 环境变量设置正确
2. 确认动态库路径正确
3. 检查程序是否为 setuid/setgid 程序
4. 查看是否有 SELinux 或 AppArmor 限制

### 日志过多

1. 降低日志级别（设置为 `ERROR` 或 `INFO`）
2. 禁用控制台输出（`AUDIT_CONSOLE_OUTPUT=0`）
3. 考虑只监控特定的系统调用类型

## 开发说明

### 添加新的监控点

1. 在 `hook_execve.c` 中定义原始函数类型
2. 实现 hook 函数，调用 `audit_log` 记录信息
3. 使用 `dlsym(RTLD_NEXT, "function_name")` 获取原始函数
4. 调用原始函数并返回结果

### 编译调试版本

修改 `Makefile` 中的 `CFLAGS`：

```makefile
CFLAGS=-Wall -fPIC -g -O0
```

## 许可证

请查看项目根目录下的许可证文件。

## 贡献

欢迎提交 Issue 和 Pull Request。

## 更新日志

### 当前版本

- 支持多种系统调用和库函数监控
- 增强的 DNS 解析和监控功能
- 可配置的日志级别和输出目标
- Docker 支持
- 线程安全的日志记录

## 联系方式

如有问题或建议，请通过 Issue 反馈。

