# 配置场景示例

本文档提供了几个常用的配置场景示例，帮助您快速配置和使用 Hook Execve 工具。

## 场景 1: 监控文件打开，日志同步输出到终端

此场景用于实时监控文件打开操作，并将日志直接显示在终端上，方便调试和观察。

### 配置步骤

```bash
# 1. 只启用文件操作监控
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=0

# 2. 启用控制台输出
export AUDIT_CONSOLE_OUTPUT=1

# 3. 禁用文件输出（可选，如果只想在终端查看）
export AUDIT_FILE_OUTPUT=0

# 4. 设置日志级别为 INFO（显示基本信息）
export AUDIT_LOG_LEVEL=INFO

# 5. 运行被监控的程序
LD_PRELOAD=./build/hook_execve.so your_program
```

### 使用示例

```bash
# 监控 ls 命令的文件打开操作
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=0
export AUDIT_CONSOLE_OUTPUT=1
export AUDIT_FILE_OUTPUT=0
export AUDIT_LOG_LEVEL=INFO

LD_PRELOAD=./build/hook_execve.so ls -la /tmp
```

### 预期输出

终端会实时显示类似以下格式的日志：

```
[2024-01-01 12:00:00] [Type=FILE(1)] [pid=12345] [process=ls]
    File open: /etc/passwd
    Mode: O_RDONLY
    ------------------------------------------
[2024-01-01 12:00:00] [Type=FILE(1)] [pid=12345] [process=ls]
    File open: /tmp
    Mode: O_RDONLY|O_DIRECTORY
    ------------------------------------------
```

---

## 场景 2: 监控网络连接，日志写入到文件

此场景用于监控网络连接操作，并将日志保存到指定的日志文件中，适合生产环境使用。

### 配置步骤

```bash
# 1. 只启用网络连接监控
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=1

# 2. 禁用控制台输出
export AUDIT_CONSOLE_OUTPUT=0

# 3. 启用文件输出
export AUDIT_FILE_OUTPUT=1

# 4. 设置日志文件目录（确保目录存在且有写权限）
# 日志文件将写入到该目录下的 audit.log 文件
export SYSCALL_PROXY_LOG_DIR=/var/log

# 5. 设置日志级别
export AUDIT_LOG_LEVEL=INFO

# 6. 运行被监控的程序
LD_PRELOAD=./build/hook_execve.so your_program
```

### 使用示例

```bash
# 监控 curl 命令的网络连接，日志写入到 /var/log/hook.log
# 注意：实际日志文件路径为 SYSCALL_PROXY_LOG_DIR/audit.log
export HOOK_ENABLE_NETWORK=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export AUDIT_CONSOLE_OUTPUT=0
export AUDIT_FILE_OUTPUT=1
export SYSCALL_PROXY_LOG_DIR=/var/log
export AUDIT_LOG_LEVEL=INFO

# 确保日志目录存在且有写权限
sudo mkdir -p /var/log
sudo chmod 755 /var/log

LD_PRELOAD=./build/hook_execve.so curl https://www.example.com
```

### 查看日志

日志会写入到 `/var/log/audit.log` 文件（即 `SYSCALL_PROXY_LOG_DIR/audit.log`），可以使用以下命令查看：

```bash
# 实时查看日志
tail -f /var/log/audit.log

# 或者查看最后 100 行
tail -n 100 /var/log/audit.log

# 如果需要将日志保存到特定文件名（如 hook.log），可以使用符号链接
sudo ln -sf /var/log/audit.log /var/log/hook.log
```

### 预期日志内容

日志文件会包含类似以下格式的内容：

```
[2024-01-01 12:00:00] [Type=CONNECT(8)] [pid=12345] [process=curl]
    Network Connect:
        Socket: 6
        Remote Address: 93.184.216.34:443
    ------------------------------------------
```

**注意**: 默认日志文件名是 `audit.log`，如果需要自定义日志文件名，请参考场景 3 的实现方式。

---

## 场景 3: 监控网络连接，日志发送到 Unix Socket

此场景用于将网络连接监控日志实时发送到 Unix Socket 文件，适合与日志收集系统（如 syslog-ng、rsyslog 等）集成。

### 配置步骤

```bash
# 1. 只启用网络连接监控
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=1

# 2. 禁用控制台输出
export AUDIT_CONSOLE_OUTPUT=0

# 3. 禁用文件输出
export AUDIT_FILE_OUTPUT=0

# 4. 启用 Socket 输出并指定 Socket 文件路径
export AUDIT_SOCKET_OUTPUT=1
export AUDIT_SOCKET_PATH=/var/log/collect.sock

# 5. 设置日志级别
export AUDIT_LOG_LEVEL=INFO

# 6. 运行被监控的程序
LD_PRELOAD=./build/hook_execve.so your_program
```

### 使用示例

```bash
# 监控网络连接并发送到 Socket
export HOOK_ENABLE_NETWORK=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export AUDIT_CONSOLE_OUTPUT=0
export AUDIT_FILE_OUTPUT=0
export AUDIT_SOCKET_OUTPUT=1
export AUDIT_SOCKET_PATH=/var/log/collect.sock
export AUDIT_LOG_LEVEL=INFO

# 确保 Socket 文件目录存在
sudo mkdir -p /var/log
sudo chmod 755 /var/log

LD_PRELOAD=./build/hook_execve.so curl https://www.example.com
```

### 接收 Socket 日志的示例程序

如果需要接收 Socket 日志，可以使用以下 Python 示例程序：

```python
#!/usr/bin/env python3
import socket
import os

SOCKET_PATH = '/var/log/collect.sock'

# 如果 Socket 文件已存在，先删除
if os.path.exists(SOCKET_PATH):
    os.unlink(SOCKET_PATH)

# 创建 Unix Socket 服务器
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)
server.listen(1)

print(f"Listening on {SOCKET_PATH}...")

while True:
    conn, addr = server.accept()
    print("Client connected")
    
    while True:
        data = conn.recv(4096)
        if not data:
            break
        print(data.decode('utf-8'), end='')
    
    conn.close()
    print("Client disconnected")
```

或者使用 `socat` 工具接收日志：

```bash
# 使用 socat 接收并显示日志
socat - UNIX-LISTEN:/var/log/collect.sock,fork

# 或者将日志保存到文件
socat - UNIX-LISTEN:/var/log/collect.sock,fork >> /var/log/hook.log
```

### 注意事项

1. **Socket 文件权限**: 确保运行程序的用户对 Socket 文件目录有写权限
2. **Socket 服务器**: 需要先启动 Socket 服务器来接收日志，否则日志发送会失败
3. **非阻塞模式**: Socket 输出采用非阻塞模式，如果接收端不可用，日志可能会丢失
4. **性能影响**: Socket 输出相比文件输出可能有轻微的性能开销

---

## 组合场景

您也可以组合多个场景，例如同时输出到终端和文件：

```bash
# 监控文件操作，同时输出到终端和文件
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=0

export AUDIT_CONSOLE_OUTPUT=1    # 同时输出到终端
export AUDIT_FILE_OUTPUT=1       # 同时输出到文件
export SYSCALL_PROXY_LOG_DIR=./log
export AUDIT_LOG_LEVEL=INFO

LD_PRELOAD=./build/hook_execve.so your_program
```

---

## 快速参考

### 环境变量速查表

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `HOOK_ENABLE_FILE` | 启用文件操作监控 | 1 |
| `HOOK_ENABLE_NETWORK` | 启用网络连接监控 | 1 |
| `AUDIT_CONSOLE_OUTPUT` | 启用控制台输出 | 0 |
| `AUDIT_FILE_OUTPUT` | 启用文件输出 | 1 |
| `AUDIT_SOCKET_OUTPUT` | 启用 Socket 输出 | 0 |
| `AUDIT_SOCKET_PATH` | Socket 文件路径 | - |
| `SYSCALL_PROXY_LOG_DIR` | 日志文件目录 | `/var/log/syscall-proxy` |
| `AUDIT_LOG_LEVEL` | 日志级别 (NONE/ERROR/INFO/DEBUG) | INFO |

### 常见问题

**Q: 为什么日志没有输出？**  
A: 检查以下几点：
- 确认对应的 `HOOK_ENABLE_*` 环境变量已设置为 1
- 确认 `AUDIT_CONSOLE_OUTPUT` 或 `AUDIT_FILE_OUTPUT` 已启用
- 确认日志级别设置正确

**Q: Socket 输出失败怎么办？**  
A: 检查以下几点：
- 确认 Socket 服务器已启动并监听
- 确认 Socket 文件路径正确
- 确认有写权限
- 查看错误日志（如果启用了控制台输出）

**Q: 如何同时监控多种操作？**  
A: 将对应的 `HOOK_ENABLE_*` 环境变量都设置为 1 即可。

