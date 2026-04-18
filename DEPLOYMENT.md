# openGM-CA 部署记录

## 1. 部署概述

| 项目 | 内容 |
|------|------|
| **目标服务器** | `192.168.24.132` (openEuler 22.03 LTS-SP3, x86_64) |
| **部署时间** | 2026-04-18 |
| **部署方式** | 远程 SSH 直连部署（源码编译） |
| **服务版本** | v1.0.0 |
| **Go 版本** | go1.21.6 linux/amd64 |
| **数据库** | openGauss 6.0.3 (兼容 PostgreSQL 协议) |
| **监听端口** | `0.0.0.0:8443` |
| **部署路径** | `/opt/opengm-ca` |

---

## 2. 环境信息

### 2.1 服务器硬件
```
CPU:    x86_64
内存:   7.2 GiB (可用 4.6 GiB)
磁盘:   35G (已用 5.1G, 可用 28G)
OS:     openEuler 22.03 (LTS-SP3)
```

### 2.2 预装软件
- **openGauss 6.0.3**: 已运行，监听 `0.0.0.0:5432`，进程 `gaussdb`
  - 数据目录: `/opt/software/openGauss/data/single_node`
  - 系统用户: `omm` / `dbgroup`
- **Git**: `/usr/bin/git`
- **PostgreSQL 13**: 已安装但端口被 openGauss 占用，未使用

### 2.3 SSH 连接
```bash
# 连接方式
ssh root@192.168.24.132
# 密码: WOai@8680186
```

---

## 3. 部署步骤详解

### 3.1 安装 Go 编译器

由于 openEuler 仓库无 Go 1.21，从阿里云镜像下载二进制包安装：

```bash
# 下载 Go 1.21.6
wget https://mirrors.aliyun.com/golang/go1.21.6.linux-amd64.tar.gz -O /tmp/go1.21.6.linux-amd64.tar.gz

# 解压到 /usr/local
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go1.21.6.linux-amd64.tar.gz

# 创建符号链接
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# 验证
go version
# 输出: go version go1.21.6 linux/amd64
```

### 3.2 拉取项目源码

```bash
rm -rf /opt/opengm-ca
mkdir -p /opt/opengm-ca
cd /opt
git clone https://github.com/xueyuleiyu/opengm-ca.git opengm-ca
```

### 3.3 配置 Go 代理

```bash
export GOPROXY=https://goproxy.cn,direct
```

### 3.4 修复编译错误（关键步骤）

原始代码存在多处编译错误，需逐一修复：

#### 错误 1: `gmsm/x509` 包不存在
- **文件**: `internal/core/signer.go`, `internal/core/ca.go`
- **原因**: `github.com/emmansun/gmsm` v0.28.0 无 `x509` 子包
- **修复**: 
  - `signer.go`: 移除 `gmsm/x509` 导入，使用本地 `SignatureAlgorithm` 枚举
  - `ca.go`: 使用 `smx509 "github.com/emmansun/gmsm/smx509"` 替代标准库 `crypto/x509`，`smx509.Certificate` 是 `x509.Certificate` 的别名并额外支持 SM2

#### 错误 2: `bun` ORM 调试模块版本不兼容
- **文件**: `internal/repository/db.go`
- **原因**: `bundebug` v1.2.x 与 `bun` v1.1.17 的 `schema.Formatter` 接口不兼容
- **修复**: 移除 `bundebug` 导入及相关调试代码

#### 错误 3: struct tag 语法错误
- **文件**: `internal/model/certificate.go`
- **原因**: 23 个 struct tag 缺少闭合反引号 `` ` ``
- **修复**: 逐行补全缺失的闭合反引号

#### 错误 4: 中间件导入错误
- **文件**: `internal/api/middleware/auth.go`
- **原因**: 缺少 `fmt` 包，导入了未使用的 `github.com/rs/zerolog/log`
- **修复**: 添加 `"fmt"`，移除 `"github.com/rs/zerolog/log"`

#### 错误 5: `crypto` 包名冲突
- **文件**: `internal/service/enrollment.go`, `internal/service/key_export.go`
- **原因**: 同时导入标准库 `"crypto"` 和项目包 `"github.com/opengm-ca/opengm-ca/internal/crypto"`，Go 禁止同名包
- **修复**: 给项目包加别名 `opengmcrypto`，并替换所有内部 `crypto.` 引用为 `opengmcrypto.`

#### 错误 6: `x509.KeyUsageNonRepudiation` 未定义
- **文件**: `internal/service/enrollment.go`
- **原因**: Go 标准库使用 `x509.KeyUsageContentCommitment` (值 0x02)
- **修复**: `x509.KeyUsageNonRepudiation` → `x509.KeyUsageContentCommitment`

#### 错误 7: `auth.go` 缺少 `strconv`
- **文件**: `internal/api/handler/auth.go`
- **修复**: 添加 `"strconv"` 导入

#### 错误 8: `cert_repo.go` 未使用的 `fmt`
- **文件**: `internal/repository/cert_repo.go`
- **修复**: 移除 `"fmt"` 导入

#### 错误 9: Gin 路由冲突
- **文件**: `internal/api/router.go`
- **原因**: `/crl/:ca_name.crl` 与 `/crl/:ca_name.pem` 在 Gin 中被视为通配符冲突
- **修复**: 合并为 `/crl/:ca_name`，通过查询参数区分格式

#### 错误 10: `sm2.PublicKey` 未定义
- **文件**: `internal/crypto/keygen.go`
- **修复**: 返回类型改为 `crypto.PublicKey`，使用 `privKey.Public()`

#### 错误 11: `sm2.SignOpts` 未定义
- **文件**: `internal/core/signer.go`
- **修复**: 简化 `SignDigest` 方法，移除 `sm2.SignOpts`

#### 错误 12: CAInstance 字段缺失
- **文件**: `internal/core/ca.go`
- **原因**: `Initialize()` 期望 `CAInstance` 有 `CAID` 和 `CertPEM` 字段
- **修复**: 添加 `CAID int` 和 `CertPEM string` 字段

### 3.5 编译二进制

```bash
cd /opt/opengm-ca
export PATH=/usr/local/go/bin:$PATH
export GOPROXY=https://goproxy.cn,direct
go mod tidy
go build -o ca-server ./cmd/ca-server

# 验证
ls -lh ca-server
# -rwxr-xr-x 1 root root 16M Apr 18 14:39 ca-server
```

### 3.6 初始化数据库

#### 3.6.1 创建数据库和用户
```bash
# 使用 openGauss 的 omm 用户
su - omm -c "gsql -d postgres -p 5432 -c \"CREATE USER ca_admin WITH PASSWORD 'ca_admin_pass123' SYSADMIN;\""
su - omm -c "gsql -d postgres -p 5432 -c \"CREATE DATABASE opengm_ca WITH OWNER = ca_admin;\""

# 配置本地访问权限
HBA=/opt/software/openGauss/data/single_node/pg_hba.conf
echo "host all ca_admin 127.0.0.1/32 md5" >> "$HBA"
echo "host all ca_admin ::1/128 md5" >> "$HBA"
su - omm -c "gs_ctl reload -D /opt/software/openGauss/data/single_node"
```

#### 3.6.2 执行数据迁移
```bash
cd /opt/opengm-ca
./ca-server -config ./configs/config.yaml -init-db
```

迁移会自动创建 8 张表：
| 表名 | 说明 |
|------|------|
| `ca_chains` | CA 证书链 |
| `certificates` | 签发的终端证书 |
| `cert_keys` | 密钥记录 |
| `subjects` | 证书主体 |
| `operators` | 系统操作员 |
| `audit_logs` | 审计日志 |
| `api_keys` | API 密钥 |
| `system_configs` | 系统配置项 |

**注意**: openGauss 不支持 `ON CONFLICT` 语法，系统配置和默认管理员的初始化 SQL 会报 `syntax error at or near "CONFLICT"`，需后续手动插入。

### 3.7 初始化 CA 根证书

```bash
cd /opt/opengm-ca
./ca-server -config ./configs/config.yaml -init-ca
```

输出示例：
```
INFO 根CA创建成功  subject="CN=openGM Root CA,O=MyOrganization,C=CN" algorithm=SM2
INFO 中间CA创建成功 ca_name=SSL-CA
INFO 中间CA创建成功 ca_name=AUTH-CA
INFO 中间CA创建成功 ca_name=VPN-CA
INFO CA系统初始化完成 sub_cas=3
INFO CA初始化完成
```

**注意**: `-init-ca` 在首次成功运行时已将 CA 数据写入 `ca_chains` 表。如重复执行需先清空表：
```bash
su - omm -c "gsql -d opengm_ca -U ca_admin -W ca_admin_pass123 -p 5432 -c 'TRUNCATE TABLE ca_chains CASCADE;'"
```

### 3.8 启动服务

```bash
cd /opt/opengm-ca
nohup ./ca-server -config ./configs/config.yaml > /var/log/opengm-ca.log 2>&1 &
```

### 3.9 插入默认管理员

由于 openGauss 不支持 `ON CONFLICT`，`runDBMigration` 中的默认管理员插入失败，需手动执行：

```bash
su - omm -c "gsql -d opengm_ca -U ca_admin -W ca_admin_pass123 -p 5432 -c \"INSERT INTO operators (username, password_hash, real_name, email, role, created_by) SELECT 'admin', '\$2a\$10\$LWE9mXK81uPqcgMdhv7GXO789QBLj.m2Krg1F1DgzVIHIJChxM8hu', '系统管理员', 'admin@localhost', 'SUPER_ADMIN', 1 WHERE NOT EXISTS (SELECT 1 FROM operators WHERE username = 'admin');\""
```

---

## 4. 配置文件说明

配置文件路径: `/opt/opengm-ca/configs/config.yaml`

### 4.1 关键配置项

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: false   # 当前使用 HTTP，TLS 证书待配置

database:
  driver: "opengauss"
  host: "localhost"
  port: 5432
  user: "ca_admin"
  password: "ca_admin_pass123"
  dbname: "opengm_ca"
  ssl_mode: "disable"

ca:
  root_ca:
    subject:
      common_name: "openGM Root CA"
      organization: "MyOrganization"
      country: "CN"
    algorithm: "SM2"
    validity_years: 20

  intermediate_cas:
    - ca_name: "SSL-CA"
      algorithm: "SM2"
      validity_years: 10
      cert_types: ["SSL"]
    - ca_name: "AUTH-CA"
      algorithm: "SM2"
      validity_years: 10
      cert_types: ["AUTH"]
    - ca_name: "VPN-CA"
      algorithm: "SM2"
      validity_years: 10
      cert_types: ["VPN_SIGN", "VPN_ENC"]

auth:
  jwt:
    secret: "opengm-ca-jwt-secret-change-in-production"
    issuer: "openGM-CA"
    access_token_ttl: "1h"
```

### 4.2 环境变量

| 变量名 | 说明 | 当前值 |
|--------|------|--------|
| `DB_PASSWORD` | 数据库密码 | `ca_admin_pass123`（已硬编码到 config） |
| `JWT_SECRET` | JWT 签名密钥 | `opengm-ca-jwt-secret-change-in-production` |
| `CA_MASTER_KEY` | 私钥加密主密钥 | **未设置**（私钥加密功能不可用） |

---

## 5. 验证结果

### 5.1 健康检查
```bash
curl -s http://192.168.24.132:8443/health
```
响应：
```json
{
  "code": "OK",
  "data": {
    "ca_initialized": true,
    "stats": {
      "active_certificates": 0,
      "expired_certificates": 0,
      "revoked_certificates": 0,
      "total_certificates": 0
    },
    "status": "healthy",
    "version": "1.0.0"
  }
}
```

### 5.2 登录验证
```bash
curl -s -X POST http://192.168.24.132:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'
```
响应：
```json
{
  "code": "OK",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 3600,
    "operator": {
      "id": 1,
      "real_name": "系统管理员",
      "role": "SUPER_ADMIN",
      "username": "admin"
    },
    "token_type": "Bearer"
  }
}
```

### 5.3 CA 链数据

```
 id |    ca_name     |   ca_type    | algorithm | serial_number | valid_to
----+----------------+--------------+-----------+---------------+------------------------------
  8 | openGM Root CA | ROOT         | SM2       | 1             | 2046-04-18 15:02:19.97128+08
  9 | SSL-CA         | INTERMEDIATE | SM2       | ica-SSL-CA-1  | 2046-04-18 15:02:19.97128+08
 10 | AUTH-CA        | INTERMEDIATE | SM2       | ica-AUTH-CA-1 | 2046-04-18 15:02:19.97128+08
 11 | VPN-CA         | INTERMEDIATE | SM2       | ica-VPN-CA-1  | 2046-04-18 15:02:19.97128+08
```

---

## 6. 服务管理

### 6.1 查看服务状态
```bash
ps aux | grep ca-server | grep -v grep
ss -tlnp | grep 8443
```

### 6.2 查看日志
```bash
tail -f /var/log/opengm-ca.log
```

### 6.3 停止服务
```bash
pkill -f "ca-server -config"
```

### 6.4 重启服务
```bash
pkill -f "ca-server -config"
sleep 1
cd /opt/opengm-ca
nohup ./ca-server -config ./configs/config.yaml > /var/log/opengm-ca.log 2>&1 &
```

---

## 7. 已知问题与限制

| 问题 | 说明 | 影响 |
|------|------|------|
| **主密钥未设置** | `CA_MASTER_KEY` 环境变量未配置 | 私钥加密/导出功能不可用 |
| **TLS 未启用** | 配置文件 `tls.enabled: false` | 服务使用明文 HTTP |
| **ON CONFLICT 不支持** | openGauss 语法差异 | 系统配置初始化需手动执行 |
| **SM2 证书解析降级** | `smx509.ParseCertificate` 对中间CA证书解析失败 | 中间CA的 SubjectDN/IssuerDN 使用配置值而非证书实际值 |
| **私钥未持久化** | CA 初始化生成的私钥未保存到数据库 | 服务重启后 CA 引擎需重新加载（当前未实现完整加载逻辑） |

---

## 8. 后续优化建议

1. **启用 TLS**: 生成服务器证书，修改 `configs/config.yaml` 中 `tls.enabled: true`
2. **配置主密钥**: `export CA_MASTER_KEY=$(openssl rand -hex 32)` 后重启服务
3. **完善私钥持久化**: 将 CA 私钥加密后存入数据库或 HSM
4. **系统配置补全**: 手动执行 `system_configs` 表的数据插入
5. **备份策略**: 定期备份 `/opt/software/openGauss/data/single_node` 和 `/opt/opengm-ca/configs`
