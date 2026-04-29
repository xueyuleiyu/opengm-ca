#!/bin/bash
# openGM-CA 数据库初始化脚本
# 适用于 openGauss / PostgreSQL

set -e

# 配置
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-ca_admin}
DB_PASSWORD=${DB_PASSWORD:-}
DB_NAME=${DB_NAME:-opengm_ca}
SUPER_USER=${SUPER_USER:-gaussdb}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查环境变量
if [ -z "$DB_PASSWORD" ]; then
    log_error "请设置 DB_PASSWORD 环境变量"
    exit 1
fi

# 检查gsql/psql是否可用
if command -v gsql &> /dev/null; then
    SQL_CMD="gsql"
    log_info "使用 gsql (openGauss)"
elif command -v psql &> /dev/null; then
    SQL_CMD="psql"
    log_info "使用 psql (PostgreSQL)"
else
    log_error "未找到 gsql 或 psql，请先安装openGauss客户端"
    exit 1
fi

# 设置连接参数
export PGPASSWORD="$DB_PASSWORD"
CONN="-h $DB_HOST -p $DB_PORT -U $DB_USER"

log_info "开始初始化数据库: $DB_NAME"

# 1. 检查数据库是否存在
log_info "检查数据库是否存在..."
DB_EXISTS=$($SQL_CMD $CONN -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || echo "0")

if [ "$DB_EXISTS" = "1" ]; then
    log_warn "数据库 $DB_NAME 已存在，跳过创建"
else
    log_info "创建数据库 $DB_NAME..."
    $SQL_CMD $CONN -d postgres -c "CREATE DATABASE $DB_NAME ENCODING 'UTF8';"
    log_info "数据库创建成功"
fi

# 2. 创建扩展
log_info "创建数据库扩展..."
$SQL_CMD $CONN -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" || log_warn "uuid-ossp扩展可能已存在"

# 3. 执行建表SQL
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="$SCRIPT_DIR/../configs/sql/init.sql"

if [ -f "$SQL_FILE" ]; then
    log_info "执行建表SQL: $SQL_FILE"
    $SQL_CMD $CONN -d "$DB_NAME" -f "$SQL_FILE"
else
    log_warn "未找到建表SQL文件，跳过: $SQL_FILE"
    log_info "请使用 'make init-db' 通过Go程序初始化数据库"
fi

# 4. 初始化系统配置
log_info "初始化系统配置..."
$SQL_CMD $CONN -d "$DB_NAME" << EOF
INSERT INTO system_config (config_key, config_value, config_type, description)
VALUES 
    ('master_key_version', '1', 'INT', '当前活动的主密钥版本'),
    ('serial_number_counter', '1', 'INT', '下一个证书序列号'),
    ('crl_update_hours', '24', 'INT', 'CRL更新间隔(小时)'),
    ('cert_default_validity_days', '365', 'INT', '默认证书有效期(天)'),
    ('audit_retention_days', '2555', 'INT', '审计日志保留天数(默认7年)'),
    ('key_export_requires_approval', 'true', 'BOOL', '私钥导出是否需要审批'),
    ('key_export_max_daily', '10', 'INT', '每日最大私钥导出次数')
ON CONFLICT (config_key) DO NOTHING;
EOF

# 5. 创建初始管理员(密码需手动修改)
ADMIN_PASSWORD_HASH='\$2a\$10\$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' # bcrypt("changeme")
$SQL_CMD $CONN -d "$DB_NAME" << EOF
INSERT INTO operators (username, password_hash, real_name, email, role, created_by)
VALUES 
    ('admin', '$ADMIN_PASSWORD_HASH', '系统管理员', 'admin@localhost', 'SUPER_ADMIN', 1)
ON CONFLICT (username) DO NOTHING;
EOF

log_info "数据库初始化完成!"
log_warn "默认管理员账号: admin / changeme"
log_warn "请在首次登录后立即修改默认密码!"

# 清理环境变量
unset PGPASSWORD
