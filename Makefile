# 编译器配置
CC = gcc
CFLAGS = -Wall -fPIC -O2 -I./include
LDFLAGS = -shared -ldl

# 目录配置
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
TEST_DIR = tests

# 目标文件
TARGET = hook_execve.so
TEST_TARGET = dns_test

# 源文件
SRCS = $(SRC_DIR)/hook_execve.c $(SRC_DIR)/audit_log.c $(SRC_DIR)/hook_config.c
OBJS = $(SRCS:.c=.o)

# 测试文件
TEST_SRC = $(TEST_DIR)/dns_test.c
TEST_OBJ = $(TEST_SRC:.c=.o)

# 默认目标
all: $(BUILD_DIR)/$(TARGET)

# 编译动态库
$(BUILD_DIR)/$(TARGET): $(BUILD_DIR) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# 编译测试程序
test: $(BUILD_DIR)/$(TEST_TARGET)

$(BUILD_DIR)/$(TEST_TARGET): $(BUILD_DIR) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) -o $@
	@echo "Test program built: $@"

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译规则
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o
	@echo "Clean complete"

# 安装
install: $(BUILD_DIR)/$(TARGET)
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install requires root privileges"; \
		exit 1; \
	fi
	cp $(BUILD_DIR)/$(TARGET) /usr/lib/$(TARGET)
	@echo "Installed $(TARGET) to /usr/lib/$(TARGET)"
	@echo "Usage: LD_PRELOAD=/usr/lib/$(TARGET) your_program"

# Docker 构建
build-docker: all
	docker build . -t audit_alpine

start-docker:
	docker rm -f syscall-proxy-container || true
	docker run -it --rm --name syscall-proxy-container \
		-v $(shell pwd)/log:/var/log/syscall-proxy \
		-p 8080:8080 audit_alpine:latest

.PHONY: all clean install test build-docker start-docker
