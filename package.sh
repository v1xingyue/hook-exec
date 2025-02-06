#!/bin/bash

VERSION="1.0.0"
PACKAGE_DIR="hook_package_${VERSION}"

# 创建打包目录
mkdir -p "${PACKAGE_DIR}"

# 复制不同版本的 so 文件
cp build/hook_execve.so.* "${PACKAGE_DIR}/"

# 创建安装脚本
cat > "${PACKAGE_DIR}/install.sh" << 'EOF'
#!/bin/bash

# 检测系统环境
ARCH=$(uname -m)
GLIBC_VERSION=$(ldd --version | head -n1 | grep -oE '[0-9]+\.[0-9]+')

# 检查 GLIBC 版本
if [[ $(echo "$GLIBC_VERSION < 2.17" | bc) -eq 1 ]]; then
    echo "Error: Required GLIBC >= 2.17"
    exit 1
fi

# 选择合适的 so 文件
select_so() {
    case "$ARCH" in
        "x86_64")
            echo "hook_execve.so.x86_64"
            ;;
        "aarch64")
            echo "hook_execve.so.aarch64"
            ;;
        *)
            echo "Error: Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
}

# 安装
INSTALL_DIR="/usr/local/lib"
SO_FILE=$(select_so)

if [[ -f "$SO_FILE" ]]; then
    mkdir -p "$INSTALL_DIR"
    cp "$SO_FILE" "$INSTALL_DIR/hook_execve.so"
    chmod 755 "$INSTALL_DIR/hook_execve.so"
    ldconfig
    echo "Installation successful: $INSTALL_DIR/hook_execve.so"
else
    echo "Error: Required SO file not found: $SO_FILE"
    exit 1
fi
EOF

chmod +x "${PACKAGE_DIR}/install.sh"

# 创建文档
cat > "${PACKAGE_DIR}/README.md" << EOF
# Hook Library ${VERSION}

支持的环境：
- x86_64 with GLIBC 2.17 (CentOS 7)
- x86_64 with GLIBC 2.28 (Ubuntu 20.04)
- x86_64 with GLIBC 2.31 (Ubuntu 22.04)
- aarch64 with GLIBC 2.28

## 安装
\`\`\`bash
./install.sh
\`\`\`

## 使用
\`\`\`bash
export LD_PRELOAD=/usr/local/lib/hook_execve.so
\`\`\`
EOF

# 打包
tar czf "${PACKAGE_DIR}.tar.gz" "${PACKAGE_DIR}"
rm -rf "${PACKAGE_DIR}"

echo "Package created: ${PACKAGE_DIR}.tar.gz" 