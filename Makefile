CC=gcc
CFLAGS=-Wall -fPIC -O2
LDFLAGS=-shared -ldl

# 目标文件和目录
TARGET=hook_execve.so
BUILD_DIR=build

# 源文件和目标文件
SRCS = hook_execve.c audit_log.c 
OBJS = $(SRCS:.c=.o)

so: $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $(SRCS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BUILD_DIR)/$(TARGET) $(LDFLAGS)
	rm -f *.o

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o

.PHONY: all clean $(PLATFORMS) 

install:
	@cp $(BUILD_DIR)/$(TARGET).x86_64 /usr/lib/$(TARGET)
	@echo "install $(TARGET) to /usr/lib/$(TARGET)"
	@echo " LD_PRELOAD=/usr/lib/$(TARGET) /bin/bash "