CC=gcc
CFLAGS=-Wall -fPIC -O2
LDFLAGS=-shared -ldl

# 定义主要目标平台
PLATFORMS = \
    x86_64-glibc-2.17 \
    aarch64-glibc-2.17

# 目标文件和目录
TARGET=hook_execve.so
BUILD_DIR=build

# 源文件和目标文件
SRCS = hook_execve.c audit_log.c
OBJS = $(SRCS:.c=.o)

all: $(PLATFORMS)

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# x86_64 最低 GLIBC 2.17
x86_64-glibc-2.17: $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $(SRCS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BUILD_DIR)/$(TARGET).x86_64 $(LDFLAGS)
	rm -f *.o

# aarch64 最低 GLIBC 2.17
aarch64-glibc-2.17: $(BUILD_DIR)
	aarch64-linux-gnu-gcc $(CFLAGS) -c $(SRCS)
	aarch64-linux-gnu-gcc $(CFLAGS) $(OBJS) -o $(BUILD_DIR)/$(TARGET).aarch64 $(LDFLAGS)
	rm -f *.o

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o

.PHONY: all clean $(PLATFORMS) 