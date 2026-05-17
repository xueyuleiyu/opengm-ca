# openGM-CA 部署记录

## 1. 部署概述

| 项目 | 内容 |
|------|------|
| **目标服务器** | `192.168.24.132` (openEuler 22.03 LTS-SP3, x86_64) |
| **部署时间** | 2026-05-17 (最新安全加固) |
| **部署方式** | 远程 SSH 直连部署（源码编译） |
| **服务版本** | v1.0.0 (安全加固版) |
| **Go 版本** | go1.21.6 linux/amd64 |
| **数据库** | openGauss 6.0.3 (兼容 PostgreSQL 协议) |
| **监听端口** | `0.0.0.0:8443` |
| **部署路径** | `/opt/opengm-ca` |
| **安全等级** | ⭐⭐⭐⭐☆ (高危风险已修复) |

### 1.1 最新安全加固 (2026-05-17)

本次部署包含以下安全加固措施：

- ✅ 主密钥来源验证（文件权限≤0600、符号链接检测）
- ✅ API输入参数限制（请求体大小、字段长度、CSR格式）
- ✅ HSM PBKDF2迭代次数统一（600,000次）
- ✅ 数据库DSN脱敏（日志中密码显示为REDACTED）
- ✅ 审计队列优化（容量5000、降级备份机制）

详细安全修复内容请参考：
- `SECURITY.md` - 安全策略和修复记录
- `SECURITY_FIX_SUMMARY.md` - 安全修复总结报告
- `AUDIT_REPORT.md` - 代码安全审计报告

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
# 已移除: 生产环境SSH连接示例
# 密码: 请使用密钥认证或联系管理员获取
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
su - omm -c "gsql -d postgres -p 5432 -c \"CREATE USER ca_admin WITH PASSWORD '\${DB_PASSWORD}' SYSADMIN;\""
# 注意: 生产环境请设置强密码并通过环境变量注入
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
su - omm -c "gsql -d opengm_ca -U ca_admin -W \${DB_PASSWORD} -p 5432 -c 'TRUNCATE TABLE ca_chains CASCADE;'"
```

### 3.8 启动服务

```bash
cd /opt/opengm-ca
nohup ./ca-server -config ./configs/config.yaml > /var/log/opengm-ca.log 2>&1 &
```

### 3.9 初始化三员管理员

系统采用**等保 2.0 三员分离**模型（SYS_ADMIN / SEC_ADMIN / AUDITOR），不再使用单一的 `admin` 账号。首次部署时，通过 API 初始化三员管理员：

```bash
# 1. 先以 SUPER_ADMIN 登录（如有）或检查 operators 表中是否已有初始账号
# 2. 调用 init-admins 接口（需要 USER_MANAGE 权限）
curl -X POST http://192.168.24.132:8443/api/v1/auth/init-admins \
  -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
```

**密码来源优先级**：
1. 环境变量（推荐）：
   ```bash
   export CA_DEFAULT_SYS_ADMIN_PASSWORD="YourStrongSysPass123!"
   export CA_DEFAULT_SEC_ADMIN_PASSWORD="YourStrongSecPass456!"
   export CA_DEFAULT_AUDIT_ADMIN_PASSWORD="YourStrongAudit789!"
   ```
2. 若未设置环境变量，则运行时通过 `crypto/rand` 生成 24 字节随机密码（Base64 编码），**熵源失败会直接报错，不会回退到时间戳**。

> ⚠️ **安全提示**：初始化完成后，务必立即修改三员管理员密码，并删除环境变量中的明文密码。

---

## 4. 配置文件说明

配置文件路径: `/opt/opengm-ca/configs/config.yaml`

### 4.1 关键配置项

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: false   # 生产环境必须设为 true，使用 HTTPS
    cert_file: "/opt/opengm-ca/certs/server.crt"
    key_file: "/opt/opengm-ca/certs/server.key"

database:
  driver: "opengauss"
  host: "localhost"
  port: 5432
  user: "ca_admin"
  password: "${DB_PASSWORD}"  # 通过环境变量传入
  dbname: "opengm_ca"
  ssl_mode: "prefer"   # 生产环境建议设为 require/verify-ca

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
    secret: "${JWT_SECRET}"  # 生产环境必须设置为随机强密钥
    issuer: "openGM-CA"
    access_token_ttl: "1h"
```

### 4.2 环境变量

| 变量名 | 说明 | 当前值 |
|--------|------|--------|
| `DB_PASSWORD` | 数据库密码 | **必须设置**，生产环境使用强密码 |
| `JWT_SECRET` | JWT 签名密钥 | **必须设置**，建议 `openssl rand -hex 32`，长度≥32 |
| `CA_MASTER_KEY` | 私钥加密主密钥 | **必须设置**，建议 `openssl rand -hex 32` |
| `CA_HSM_PASSWORD` | HSM 密码 | **必须设置** |
| `CA_DEFAULT_SYS_ADMIN_PASSWORD` | 系统管理员（SYS_ADMIN）初始密码 | 首次 `init-admins` 前设置 |
| `CA_DEFAULT_SEC_ADMIN_PASSWORD` | 安全管理员（SEC_ADMIN）初始密码 | 首次 `init-admins` 前设置 |
| `CA_DEFAULT_AUDIT_ADMIN_PASSWORD` | 审计管理员（AUDITOR）初始密码 | 首次 `init-admins` 前设置 |
| `CA_INITIAL_ADMIN_PASSWORD` | 首个 SUPER_ADMIN 密码（如需要手动创建） | 首次初始化前设置 |

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
  -d '{"username":"admin","password":"<your_password>"}'
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

## 7. 功能测试记录（2026-05-09）

| 功能模块 | 测试项 | 结果 |
|----------|--------|------|
| 认证 | admin/sec_admin/audit_admin 登录 | ✅ 通过 |
| 认证 | 5 次错误密码后账户锁定 30 分钟 | ✅ 通过 |
| 认证 | JWT 实时状态校验（锁定后 token 失效） | ✅ 通过 |
| 证书签发 | SM2 SSL 证书（服务器生成密钥） | ✅ 通过 |
| 证书签发 | RSA2048 SSL 证书（服务器生成密钥） | ✅ 通过 |
| 证书签发 | VPN 双证书（VPN_SIGN + VPN_ENC） | ✅ 通过 |
| 证书管理 | 吊销证书 + 即时 CRL 更新 | ✅ 通过 |
| CRL/OCSP | CRL 下载（SSL-CA / VPN-CA / AUTH-CA） | ✅ 通过 |
| HSM | 生成 / 列表 / 删除 SM2 密钥 | ✅ 通过 |
| 操作员 | 创建 / 更新 / 禁用 / 删除 | ✅ 通过 |
| 操作员 | 弱密码拒绝（<8 位 / 无复杂度） | ✅ 通过 |
| 操作员 | 禁止创建 SUPER_ADMIN | ✅ 通过 |
| 操作员 | 禁止删除当前登录用户 | ✅ 通过 |
| 审计 | 审计日志记录 + 哈希链 | ✅ 通过 |
| 三员 | InitDefaultAdmins 重复初始化阻止 | ✅ 通过 |
| 权限 | 角色权限隔离（等保 2.0） | ✅ 通过 |

### 测试中发现并修复的问题

1. **双证书模式未实际调用协调器** (`internal/service/enrollment.go`)
   - 原因：`EnrollCertificate` 未处理 `DualCertMode`
   - 修复：在 `EnrollmentService` 中集成 `DualCertCoordinator`，双证书请求直接委托签发

2. **双证书保存缺少必填字段** (`internal/core/dual_cert.go`)
   - 原因：`IssueDualCertificates` 返回的证书模型缺少 `CertHashSHA256`、`CAID`、`IssuedBy`
   - 修复：持久化前补充所有数据库非空字段

3. **CA 初始化 panic（nil Config）** (`internal/core/ca.go`)
   - 原因：`createRootCA`/`createIntermediateCA` 未设置 `instance.Config`，`saveCAInstance` 访问 `instance.Config.Algorithm` 时 panic
   - 修复：创建 CA 实例时填充 `Config`，`saveCAInstance` 增加 nil 保护

4. **审计日志 actor 为空导致写入失败** (`internal/service/audit.go`)
   - 原因：公开接口（如 CRL）无认证信息，`actor` 为空字符串被 ORM 映射为 NULL
   - 修复：`AuditService.Log` 在 `actor == ""` 时回退为 `"SYSTEM"`

5. **cert_keys 表缺少 updated_at 列**
   - 原因：`KeyRepository.UpdateCertID` 尝试更新不存在的列
   - 修复：`ALTER TABLE cert_keys ADD COLUMN updated_at`

6. **主密钥 base64 解码陷阱** (`internal/crypto/keystore.go`)
   - 原因：`resolveMasterKey` 对 32 字符的有效 base64 字符串会解码为 24 字节，导致 `NewKeyStore` 校验失败
   - 规避：**建议使用 64 字符 hex 格式**（如 `openssl rand -hex 32`），避免使用恰好是有效 base64 的 32 字符字符串

## 8. 已知问题与限制

| 问题 | 说明 | 影响 |
|------|------|------|
| **主密钥未设置** | `CA_MASTER_KEY` 环境变量未配置 | 私钥加密/导出功能不可用 |
| **TLS 未启用** | 配置文件 `tls.enabled: false` | 服务使用明文 HTTP，生产环境必须开启 |
| **ON CONFLICT 兼容性** | openGauss 语法差异 | `runDBMigration` 已改用 Bun ORM 方式，若仍失败需手动补录 |
| **OCSP Responder 临时证书** | 当前使用自签名 EC P-256 证书签名 OCSP 响应 | 生产环境应使用由 CA 正式签名的 OCSP Responder 证书 |
| **MFA 未实现** | TOTP 多因素认证未接入 | 启用 MFA 的用户目前无法登录（返回 `MFA_NOT_IMPLEMENTED`） |
| **RateLimit 内存泄漏** | 限流器使用 map 存储但无过期清理 | 长期运行内存可能缓慢增长，建议定期重启或后续接入 Redis |
| **SEC_ADMIN 无法重置他人密码** | `/operators/:id/password` 路由要求 `USER_MANAGE`，但 SEC_ADMIN 仅有 `HSM_MANAGE` 等权限 | 安全管理员无法通过 API 重置他人密码（Handler 内部逻辑已允许，被路由层拦截） |

---

## 8. 后续优化建议

1. **启用 TLS**: 准备服务器证书和私钥，修改 `configs/config.yaml` 中 `tls.enabled: true`。注意：服务不再自动生成自签名证书，证书缺失会直接报错。
2. **配置主密钥**: `export CA_MASTER_KEY=$(openssl rand -hex 32)` 后重启服务
3. **配置 HSM 密码**: `export CA_HSM_PASSWORD=<强密码>`
4. **配置 JWT Secret**: `export CA_JWT_SECRET=$(openssl rand -hex 32)`（启动时强制校验长度 ≥32，拒绝默认弱密钥）
5. **配置默认管理员密码**: 初始化前设置 `CA_DEFAULT_*_ADMIN_PASSWORD` 环境变量
6. **系统配置补全**: 手动执行 `system_configs` 表的数据插入
7. **备份策略**: 定期备份 `/opt/software/openGauss/data/single_node` 和 `/opt/opengm-ca/configs`
8. **安全加固建议**:
   - 吊销证书后立即验证 CRL 是否已更新（`GET /api/v1/crl/:ca_name`）
   - 定期执行审计哈希链验证（`GET /api/v1/audit/verify`）
   - 私钥导出为高敏操作，建议限制为双人审批
   - 设置 `CA_MASTER_KEY` 时支持 hex（64字符）或 base64 编码，系统自动识别
