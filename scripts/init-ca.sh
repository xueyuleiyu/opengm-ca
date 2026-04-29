#!/bin/bash
# openGM-CA 根CA和中间CA初始化脚本
# 用于离线环境或首次部署时创建CA证书链

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 配置
CA_DIR=${CA_DIR:-/etc/opengm-ca}
KEY_DIR="$CA_DIR/keys"
CERT_DIR="$CA_DIR/certs"
CONFIG_FILE=${CONFIG_FILE:-./configs/config.yaml}

# 检查权限
if [ "$EUID" -ne 0 ]; then
    log_warn "建议使用root权限运行，或使用 sudo"
fi

# 创建目录
log_info "创建CA目录结构..."
mkdir -p "$KEY_DIR" "$CERT_DIR" "$CA_DIR/crl" "$CA_DIR/newcerts"
chmod 700 "$KEY_DIR"
chmod 755 "$CERT_DIR"

# 检查openssl或gmssl
if command -v gmssl &> /dev/null; then
    SSL_CMD="gmssl"
    log_info "使用 gmssl (国密SSL工具)"
elif command -v openssl &> /dev/null; then
    SSL_CMD="openssl"
    log_info "使用 openssl"
else
    log_error "未找到 gmssl 或 openssl"
    exit 1
fi

# 生成根CA密钥
log_info "生成根CA SM2密钥..."
if [ "$SSL_CMD" = "gmssl" ]; then
    gmssl ecparam -genkey -name sm2p256v1 -out "$KEY_DIR/root-ca.key"
else
    openssl ecparam -genkey -name prime256v1 -out "$KEY_DIR/root-ca.key"
fi
chmod 400 "$KEY_DIR/root-ca.key"
log_info "根CA密钥已生成: $KEY_DIR/root-ca.key"

# 生成根CA证书
log_info "生成根CA自签名证书..."
cat > /tmp/root-ca.cnf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = openGM Root CA
O = MyOrganization
C = CN

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:2
keyUsage = critical, keyCertSign, cRLSign
crlDistributionPoints = URI:http://ca.example.com/crl/root-ca.crl
EOF

if [ "$SSL_CMD" = "gmssl" ]; then
    gmssl req -new -x509 -days 7300 -key "$KEY_DIR/root-ca.key" \
        -out "$CERT_DIR/root-ca.crt" -config /tmp/root-ca.cnf \
        -sm3 -sigopt sm2_id:1234567812345678
else
    openssl req -new -x509 -days 7300 -key "$KEY_DIR/root-ca.key" \
        -out "$CERT_DIR/root-ca.crt" -config /tmp/root-ca.cnf -sha256
fi

log_info "根CA证书已生成: $CERT_DIR/root-ca.crt"

# 生成中间CA密钥和证书请求
for CA_NAME in SSL-CA AUTH-CA VPN-CA; do
    log_info "生成中间CA: $CA_NAME ..."
    
    # 生成密钥
    if [ "$SSL_CMD" = "gmssl" ]; then
        gmssl ecparam -genkey -name sm2p256v1 -out "$KEY_DIR/$CA_NAME.key"
    else
        openssl ecparam -genkey -name prime256v1 -out "$KEY_DIR/$CA_NAME.key"
    fi
    chmod 400 "$KEY_DIR/$CA_NAME.key"
    
    # 生成证书请求
    cat > /tmp/$CA_NAME.cnf << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = openGM $CA_NAME Intermediate CA
O = MyOrganization
C = CN
EOF
    
    $SSL_CMD req -new -key "$KEY_DIR/$CA_NAME.key" \
        -out "$CERT_DIR/$CA_NAME.csr" -config /tmp/$CA_NAME.cnf
    
    # 使用根CA签发中间CA证书
    cat > /tmp/$CA_NAME-ext.cnf << EOF
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
crlDistributionPoints = URI:http://ca.example.com/crl/$CA_NAME.crl
authorityInfoAccess = caIssuers;URI:http://ca.example.com/ca/$CA_NAME.crt
EOF
    
    if [ "$SSL_CMD" = "gmssl" ]; then
        gmssl x509 -req -in "$CERT_DIR/$CA_NAME.csr" \
            -CA "$CERT_DIR/root-ca.crt" -CAkey "$KEY_DIR/root-ca.key" \
            -CAcreateserial -out "$CERT_DIR/$CA_NAME.crt" \
            -days 3650 -extfile /tmp/$CA_NAME-ext.cnf \
            -sm3 -sigopt sm2_id:1234567812345678
    else
        openssl x509 -req -in "$CERT_DIR/$CA_NAME.csr" \
            -CA "$CERT_DIR/root-ca.crt" -CAkey "$KEY_DIR/root-ca.key" \
            -CAcreateserial -out "$CERT_DIR/$CA_NAME.crt" \
            -days 3650 -extfile /tmp/$CA_NAME-ext.cnf -sha256
    fi
    
    # 生成证书链
    cat "$CERT_DIR/$CA_NAME.crt" "$CERT_DIR/root-ca.crt" > "$CERT_DIR/$CA_NAME-chain.crt"
    
    log_info "$CA_NAME 中间CA证书已生成"
done

# 清理临时文件
rm -f /tmp/root-ca.cnf /tmp/SSL-CA.cnf /tmp/AUTH-CA.cnf /tmp/VPN-CA.cnf
rm -f /tmp/SSL-CA-ext.cnf /tmp/AUTH-CA-ext.cnf /tmp/VPN-CA-ext.cnf
rm -f "$CERT_DIR"/*.csr

# 设置权限
chmod 400 "$KEY_DIR"/*.key
chmod 444 "$CERT_DIR"/*.crt

log_info "CA初始化完成!"
log_info "证书目录: $CERT_DIR"
log_info "密钥目录: $KEY_DIR (权限: 400)"
log_warn "请安全备份根CA私钥: $KEY_DIR/root-ca.key"
log_warn "建议将根CA私钥离线保存到加密U盘或HSM设备"

# 显示证书信息
echo ""
log_info "根CA证书信息:"
$SSL_CMD x509 -in "$CERT_DIR/root-ca.crt" -noout -subject -dates -serial

echo ""
log_info "中间CA证书信息:"
for CA_NAME in SSL-CA AUTH-CA VPN-CA; do
    echo "--- $CA_NAME ---"
    $SSL_CMD x509 -in "$CERT_DIR/$CA_NAME.crt" -noout -subject -dates -serial
done
