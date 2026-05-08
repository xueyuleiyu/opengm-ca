#!/bin/bash
set -e

SERVICE_NAME="opengm-ca"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/opt/opengm-ca"
ENV_FILE="${INSTALL_DIR}/.env"

echo "========================================"
echo "  openGM-CA systemd 安装脚本"
echo "========================================"

# 检查安装目录
if [ ! -d "$INSTALL_DIR" ]; then
    echo "错误: 安装目录 $INSTALL_DIR 不存在"
    exit 1
fi

# 检查二进制文件
if [ ! -f "${INSTALL_DIR}/ca-server" ]; then
    echo "错误: 二进制文件 ${INSTALL_DIR}/ca-server 不存在"
    exit 1
fi

# 检查环境变量文件
if [ ! -f "$ENV_FILE" ]; then
    echo "警告: 环境变量文件 $ENV_FILE 不存在，将尝试创建"
    echo "CA_MASTER_KEY=$(openssl rand -hex 32)" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "已生成随机 CA_MASTER_KEY 到 $ENV_FILE"
fi

# 复制服务文件
cp "$(dirname "$0")/opengm-ca.service" "$SERVICE_FILE"
echo "已复制服务文件到 $SERVICE_FILE"

# 重新加载 systemd
systemctl daemon-reload

# 启用服务
systemctl enable "$SERVICE_NAME"

# 停止旧进程（如果有）
if pgrep -f "ca-server" > /dev/null; then
    echo "停止旧进程..."
    pkill -f "ca-server" || true
    sleep 2
fi

# 启动服务
systemctl start "$SERVICE_NAME"
sleep 2

# 检查状态
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "========================================"
    echo "  安装成功！"
    echo "  服务状态: $(systemctl is-active "$SERVICE_NAME")"
    echo "  查看日志: journalctl -u $SERVICE_NAME -f"
    echo "========================================"
else
    echo "错误: 服务启动失败"
    systemctl status "$SERVICE_NAME" --no-pager
    exit 1
fi
