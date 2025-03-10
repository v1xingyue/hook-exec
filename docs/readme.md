# 项目概述

该项目旨在审计系统调用并记录各种活动，如文件操作、网络连接和进程管理。它由多个模块组成，每个模块负责审计过程的不同方面。

## 模块

### 1. `audit_log.h`

- **目的**：定义审计日志的结构和函数原型。
- **关键组件**：
  - `audit_config_t`：用于保存审计日志全局配置的结构。
  - `audit_type_t`：不同类型审计日志的枚举（例如，EXEC、SOCKET、NETWORK）。
  - 初始化审计日志和记录网络地址的函数原型。

### 2. `hook_execve.c`

- **目的**：实现各种系统调用的钩子以记录其活动。
- **关键组件**：
  - 钩子用于系统调用，如 `execve`、`socket`、`bind`、`connect`、`send`、`recv`、`open`、`write`、`unlink`、`rename`、`fork`、`exit`、`mmap`、`setuid`、`chmod`、`signal` 和 `putenv`。
  - 每个钩子使用 `audit_log` 函数记录系统调用的相关信息。

### 3. `audit_server.c`

- **目的**：实现一个服务器以接收和记录审计消息。
- **关键组件**：
  - 设置一个 UNIX 域套接字以接收日志消息。
  - 将接收到的消息写入日志文件。
  - 处理信号以优雅地关闭服务器。

### 4. `audit_log.c`

- **目的**：提供记录审计消息的实现。
- **关键组件**：
  - `audit_init`：初始化审计日志配置。
  - `audit_log`：将消息记录到文件中，包含时间戳、进程名称和审计类型等详细信息。
  - 文件锁定和解锁的辅助函数，以及格式化网络地址。

### 5. `Makefile`

- **目的**：自动化项目的构建过程。
- **关键组件**：
  - 构建共享对象（`hook_execve.so`）和审计服务器的目标。
  - 管理构建工件和安装的清理和安装目标。

### 6. `package.sh`

- **目的**：打包项目以便分发的脚本。
- **关键组件**：
  - 创建打包目录并复制必要的文件。
  - 生成安装脚本和包的 README。
  - 将目录打包成压缩包。

### 7. `Dockerfile`

- **目的**：定义用于构建和运行项目的 Docker 镜像。
- **关键组件**：
  - 多阶段构建以在 Alpine Linux 环境中编译项目。
  - 将编译的共享对象复制到最终镜像中并设置 `LD_PRELOAD`。

### 8. `.github/workflows/docker-build.yml`

- **目的**：GitHub Actions 工作流，用于构建和推送 Docker 镜像。
- **关键组件**：
  - 在标签推送和手动调度时触发。
  - 构建并推送 Docker 镜像到 GitHub 容器注册表。

## 使用

1. **启动审计服务器**：运行审计服务器以开始记录。
   ```bash
   ./audit_server /path/to/log/dir
   ```

2. **运行带审计的程序**：使用 `LD_PRELOAD` 来审计程序。
   ```bash
   LD_PRELOAD=/usr/lib/hook_execve.so your_program
   ```

## 安装

- 按照 `package.sh` 生成的 `install.sh` 脚本中的说明安装共享对象和服务器。

## 注意事项

- 确保日志目录对运行审计服务器的用户可写。
- 项目支持多种架构和 GLIBC 版本，如 `package.sh` 生成的 `README.md` 中所述。 