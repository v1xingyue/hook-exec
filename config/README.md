# 拦截配置说明

## 环境变量配置

通过环境变量可以灵活控制哪些系统调用需要被拦截和记录。

### 基本配置

所有配置项都通过环境变量设置，格式为 `HOOK_ENABLE_<类型>=1|0|yes|no`

### 可配置的拦截类型

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `HOOK_ENABLE_EXECVE` | 是否拦截程序执行 (execve) | 1 (启用) |
| `HOOK_ENABLE_FILE` | 是否拦截文件操作 (open, write, unlink, rename) | 1 (启用) |
| `HOOK_ENABLE_PROCESS` | 是否拦截进程操作 (fork, exit) | 1 (启用) |
| `HOOK_ENABLE_MEMORY` | 是否拦截内存操作 (mmap) | 1 (启用) |
| `HOOK_ENABLE_SECURITY` | 是否拦截安全操作 (setuid, chmod) | 1 (启用) |
| `HOOK_ENABLE_SIGNAL` | 是否拦截信号处理 (signal) | 1 (启用) |
| `HOOK_ENABLE_ENV` | 是否拦截环境变量 (putenv) | 1 (启用) |
| `HOOK_ENABLE_DNS` | 是否拦截 DNS 操作 (gethostbyname, getaddrinfo, sendto, recvfrom) | 1 (启用) |
| `HOOK_ENABLE_NETWORK` | 是否拦截网络操作 (connect, listen) | 1 (启用) |
| `HOOK_FILTER_FILE_WRITE` | 是否过滤文件写入（只记录普通文件） | 1 (启用) |

### 使用示例

#### 示例 1: 只监控文件操作和网络连接

```bash
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=1

LD_PRELOAD=./build/hook_execve.so your_program
```

#### 示例 2: 只监控 DNS 查询

```bash
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=1
export HOOK_ENABLE_NETWORK=0

LD_PRELOAD=./build/hook_execve.so your_program
```

#### 示例 3: 禁用所有拦截（仅用于测试）

```bash
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=0

LD_PRELOAD=./build/hook_execve.so your_program
```

### 配置优先级

- 如果环境变量未设置，使用默认值（全部启用）
- 环境变量值为 `1` 或 `yes` 表示启用
- 环境变量值为 `0` 或 `no` 表示禁用
- 其他值会被视为禁用

### 注意事项

1. 配置在动态库加载时读取，之后不会重新读取
2. 修改配置后需要重新运行程序才能生效
3. 禁用某些拦截可以减少性能开销
4. 建议根据实际需求只启用必要的拦截类型

