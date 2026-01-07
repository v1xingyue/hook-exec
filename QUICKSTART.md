# 快速开始指南

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
├── build/             # 编译输出目录（自动生成）
│   └── hook_execve.so # 编译生成的动态库
└── log/               # 日志目录
    └── audit.log      # 审计日志文件
```

## 快速编译

```bash
# 编译动态库
make

# 编译测试程序（可选）
make test

# 清理编译文件
make clean
```

## 基本使用

### 1. 默认使用（全部拦截）

```bash
LD_PRELOAD=./build/hook_execve.so your_program
```

### 2. 只监控文件操作

```bash
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=1
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_DNS=0
export HOOK_ENABLE_NETWORK=0

LD_PRELOAD=./build/hook_execve.so your_program
```

### 3. 只监控 DNS 查询

```bash
export HOOK_ENABLE_DNS=1
export HOOK_ENABLE_EXECVE=0
export HOOK_ENABLE_FILE=0
export HOOK_ENABLE_PROCESS=0
export HOOK_ENABLE_MEMORY=0
export HOOK_ENABLE_SECURITY=0
export HOOK_ENABLE_SIGNAL=0
export HOOK_ENABLE_ENV=0
export HOOK_ENABLE_NETWORK=0

LD_PRELOAD=./build/hook_execve.so your_program
```

### 4. 测试 DNS 监控

```bash
# 编译测试程序
make test

# 运行测试
export HOOK_ENABLE_DNS=1
LD_PRELOAD=./build/hook_execve.so ./build/dns_test
```

## 日志配置

### 设置日志目录

```bash
export SYSCALL_PROXY_LOG_DIR=./log
LD_PRELOAD=./build/hook_execve.so your_program
```

### 设置日志级别

```bash
export AUDIT_LOG_LEVEL=DEBUG  # NONE, ERROR, INFO, DEBUG
export AUDIT_CONSOLE_OUTPUT=1  # 输出到控制台
LD_PRELOAD=./build/hook_execve.so your_program
```

## 拦截配置说明

所有拦截配置通过环境变量控制，格式为 `HOOK_ENABLE_<类型>=1|0|yes|no`

可配置的拦截类型：
- `HOOK_ENABLE_EXECVE` - 程序执行拦截
- `HOOK_ENABLE_FILE` - 文件操作拦截
- `HOOK_ENABLE_PROCESS` - 进程操作拦截
- `HOOK_ENABLE_MEMORY` - 内存操作拦截
- `HOOK_ENABLE_SECURITY` - 安全操作拦截
- `HOOK_ENABLE_SIGNAL` - 信号处理拦截
- `HOOK_ENABLE_ENV` - 环境变量拦截
- `HOOK_ENABLE_DNS` - DNS 拦截
- `HOOK_ENABLE_NETWORK` - 网络拦截
- `HOOK_FILTER_FILE_WRITE` - 文件写入过滤

详细配置说明请参考 [config/README.md](config/README.md)

## 查看日志

日志默认保存在 `/var/log/syscall-proxy/audit.log`，或通过 `SYSCALL_PROXY_LOG_DIR` 环境变量指定。

```bash
# 查看日志
tail -f /var/log/syscall-proxy/audit.log

# 或使用自定义目录
tail -f ./log/audit.log
```

## 安装到系统（可选）

```bash
sudo make install
```

安装后使用：
```bash
LD_PRELOAD=/usr/lib/hook_execve.so your_program
```

## 更多信息

- 详细文档：查看 [README.md](README.md)
- 配置说明：查看 [config/README.md](config/README.md)

