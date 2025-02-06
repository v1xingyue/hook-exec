CC=gcc
CFLAGS=-Wall -fPIC -O2
LDFLAGS=-shared -ldl

# 目标文件和目录
TARGET=hook_execve.so
SERVER_TARGET=audit_server
BUILD_DIR=build

# 源文件和目标文件
SRCS = hook_execve.c audit_log.c
OBJS = $(SRCS:.c=.o)

all: so server

so: $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $(SRCS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BUILD_DIR)/$(TARGET) $(LDFLAGS)
	rm -f *.o

server: $(BUILD_DIR)
	$(CC) $(CFLAGS) audit_server.c -o $(BUILD_DIR)/$(SERVER_TARGET)

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o

.PHONY: all clean server so

install:
	@cp $(BUILD_DIR)/$(TARGET) /usr/lib/$(TARGET)
	@cp $(BUILD_DIR)/$(SERVER_TARGET) /usr/bin/$(SERVER_TARGET)
	@echo "install $(TARGET) to /usr/lib/$(TARGET)"
	@echo "install $(SERVER_TARGET) to /usr/bin/$(SERVER_TARGET)"
	@echo "Usage:"
	@echo "1. Start audit server: audit_server /path/to/log/dir"
	@echo "2. Run program with audit: LD_PRELOAD=/usr/lib/$(TARGET) your_program"