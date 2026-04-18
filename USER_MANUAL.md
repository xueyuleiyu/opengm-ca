# openGM-CA 用户使用手册

## 1. 系统简介

openGM-CA 是一个支持国密算法（SM2/SM3/SM4）的证书认证中心（CA）系统，采用 openGauss 数据库存储，提供证书申请、签发、管理、吊销、审计等完整功能。

### 1.1 核心能力

| 功能 | 说明 |
|------|------|
| **国密证书签发** | 支持 SM2 签名算法 + SM3 哈希算法 |
| **双证书体系** | 支持签名证书 + 加密证书分离（VPN 场景） |
| **多级 CA** | 根 CA → 中间 CA（SSL/AUTH/VPN）→ 终端证书 |
| **密钥托管** | 私钥加密存储，支持受控导出 |
| **审计追踪** | 完整操作日志 + 哈希链防篡改 |
| **RBAC 权限** | SUPER_ADMIN / ADMIN / AUDITOR / OPERATOR 四级角色 |

### 1.2 系统架构

```
┌─────────────────────────────────────────┐
│           HTTP API (8443)               │
├─────────────────────────────────────────┤
│  Auth │ Certs │ Keys │ CRL │ OCSP │ Audit│
├─────────────────────────────────────────┤
│         Service Layer (业务逻辑)         │
├─────────────────────────────────────────┤
│         CA Engine (SM2 签名)             │
├─────────────────────────────────────────┤
│   openGauss 6.0.3  (localhost:5432)     │
└─────────────────────────────────────────┘
```

---

## 2. 快速开始

### 2.1 访问地址

```
Base URL: http://192.168.24.132:8443
API Prefix: /api/v1
```

### 2.2 默认管理员账号

| 字段 | 值 |
|------|-----|
| 用户名 | `admin` |
| 密码 | `changeme` |
| 角色 | `SUPER_ADMIN` |
| 权限 | 全部权限 |

> ⚠️ **安全提示**: 首次登录后请立即修改默认密码！

---

## 3. 登录与认证

### 3.1 获取访问令牌

**请求:**
```bash
curl -X POST http://192.168.24.132:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "changeme"
  }'
```

**响应:**
```json
{
  "code": "OK",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
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

### 3.2 使用 Token 访问受保护接口

所有受保护接口需在请求头中携带 `Authorization`:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -s http://192.168.24.132:8443/api/v1/system/status \
  -H "Authorization: Bearer ${TOKEN}"
```

### 3.3 Token 有效期

- **Access Token**: 1 小时（3600 秒）
- **Refresh Token**: 7 天（168 小时）

---

## 4. API 接口指南

### 4.1 接口概览

| 分类 | 路径 | 方法 | 权限要求 | 说明 |
|------|------|------|----------|------|
| **健康** | `/health` | GET | 公开 | 服务状态 |
| **认证** | `/api/v1/auth/login` | POST | 公开 | 用户登录 |
| **认证** | `/api/v1/auth/refresh` | POST | 公开 | 刷新 Token |
| **系统** | `/api/v1/system/status` | GET | 需登录 | 系统状态 |
| **证书** | `/api/v1/certificates` | GET | 需登录 | 证书列表 |
| **证书** | `/api/v1/certificates/:id` | GET | 需登录 | 证书详情 |
| **证书** | `/api/v1/certificates/enroll` | POST | 需登录 | 申请证书 |
| **证书** | `/api/v1/certificates/:id/revoke` | POST | CERT_REVOKE | 吊销证书 |
| **证书** | `/api/v1/certificates/:id/renew` | POST | 需登录 | 续期证书 |
| **密钥** | `/api/v1/keys` | GET | 需登录 | 密钥列表 |
| **密钥** | `/api/v1/keys/:id/export` | POST | KEY_EXPORT | 导出私钥 |
| **审计** | `/api/v1/audit/logs` | GET | AUDIT_READ | 审计日志 |
| **审计** | `/api/v1/audit/verify` | GET | AUDIT_VERIFY | 验证哈希链 |
| **CRL** | `/api/v1/crl/:ca_name` | GET | 公开 | 下载 CRL |
| **OCSP** | `/api/v1/ocsp` | POST | 公开 | OCSP 查询 |

### 4.2 健康检查

```bash
curl -s http://192.168.24.132:8443/health
```

**响应:**
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

### 4.3 申请证书

**请求:**
```bash
curl -X POST http://192.168.24.132:8443/api/v1/certificates/enroll \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_type": "SSL",
    "algorithm": "SM2",
    "validity_days": 365,
    "gen_key_locally": true,
    "subject": {
      "common_name": "www.example.com",
      "organization": "Example Corp",
      "country": "CN",
      "organizational_unit": "IT Department",
      "state": "Beijing",
      "locality": "Beijing"
    },
    "extensions": {
      "subject_alt_names": [
        {"type": "dns", "value": "www.example.com"},
        {"type": "dns", "value": "example.com"}
      ]
    }
  }'
```

**字段说明:**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `cert_type` | string | ✅ | `SSL` / `AUTH` / `VPN_SIGN` / `VPN_ENC` |
| `algorithm` | string | ✅ | `SM2` / `RSA2048` / `RSA4096` / `EC256` / `EC384` |
| `validity_days` | int | ✅ | 1 ~ 3650 |
| `gen_key_locally` | bool | ✅ | true: CA生成并托管私钥; false: 用户提供 CSR |
| `csr_pem` | string | ❌ | 当 `gen_key_locally=false` 时必填 |
| `subject.common_name` | string | ✅ | 证书主题 CN |
| `subject.organization` | string | ✅ | 组织 O |
| `subject.country` | string | ✅ | 国家 C |
| `extensions.subject_alt_names` | array | ❌ | SAN 列表，支持 `dns` / `ip` |

### 4.4 证书列表查询

```bash
curl -s "http://192.168.24.132:8443/api/v1/certificates?status=VALID&page=1&page_size=10" \
  -H "Authorization: Bearer ${TOKEN}"
```

### 4.5 吊销证书

```bash
curl -X POST "http://192.168.24.132:8443/api/v1/certificates/123/revoke" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "密钥泄露",
    "reason_code": 1
  }'
```

**吊销原因代码 (RFC 5280):**

| 代码 | 含义 |
|------|------|
| 0 | 未指定 |
| 1 | 密钥泄露 |
| 2 | CA 泄露 |
| 3 | 关系变更 |
| 4 | 证书被取代 |
| 5 | 业务终止 |

### 4.6 导出私钥

> ⚠️ **安全警告**: 私钥导出是高危操作，每次导出都会记录审计日志！

```bash
curl -X POST "http://192.168.24.132:8443/api/v1/keys/key-uuid/export" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "业务系统部署",
    "export_format": "PKCS8",
    "password": "optional-encryption-password"
  }'
```

### 4.7 查询审计日志

```bash
curl -s "http://192.168.24.132:8443/api/v1/audit/logs?event_type=CERT_ISSUE&start_time=2026-04-01T00:00:00Z&page=1&page_size=20" \
  -H "Authorization: Bearer ${TOKEN}"
```

---

## 5. 证书类型与使用场景

### 5.1 SSL 证书

- **用途**: HTTPS 网站、TLS 通信加密
- **KeyUsage**: DigitalSignature + KeyEncipherment
- **ExtKeyUsage**: ServerAuth + ClientAuth
- **签发 CA**: SSL-CA

### 5.2 AUTH 证书

- **用途**: 身份认证、数字签名、邮件签名
- **KeyUsage**: DigitalSignature + NonRepudiation
- **ExtKeyUsage**: ClientAuth + EmailProtection
- **签发 CA**: AUTH-CA

### 5.3 VPN 双证书（国密规范）

国密 VPN 场景要求**签名证书**和**加密证书**分离：

| 类型 | 证书 | KeyUsage | 用途 |
|------|------|----------|------|
| VPN 签名证书 | `VPN_SIGN` | DigitalSignature + NonRepudiation | 身份认证、签名验证 |
| VPN 加密证书 | `VPN_ENC` | KeyEncipherment + DataEncipherment | 密钥协商、数据加密 |

- **签发 CA**: VPN-CA

---

## 6. 数据库表结构速查

### 6.1 CA 证书链 (`ca_chains`)

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int PK | 自增主键 |
| `ca_name` | string UNIQUE | CA 名称 |
| `ca_type` | string | `ROOT` / `INTERMEDIATE` |
| `parent_ca_id` | int FK | 父 CA ID（根 CA 为 NULL） |
| `cert_pem` | text | 证书 PEM 内容 |
| `subject_dn` | string | 证书主题 DN |
| `issuer_dn` | string | 签发者 DN |
| `serial_number` | string | 序列号 |
| `algorithm` | string | `SM2` / `RSA2048` 等 |
| `valid_from` | timestamp | 生效时间 |
| `valid_to` | timestamp | 过期时间 |

### 6.2 证书 (`certificates`)

| 字段 | 说明 |
|------|------|
| `id` | 自增 ID |
| `cert_type` | `SSL` / `AUTH` / `VPN_SIGN` / `VPN_ENC` |
| `serial_number` | 十六进制序列号 |
| `cert_pem` | 证书 PEM |
| `subject_dn` | 主题 DN |
| `issuer_dn` | 签发者 DN |
| `status` | `VALID` / `REVOKED` / `EXPIRED` |
| `revoked_at` | 吊销时间 |
| `revocation_reason` | 吊销原因代码 |

### 6.3 操作员 (`operators`)

| 字段 | 说明 |
|------|------|
| `id` | 自增 ID |
| `username` | 登录名（唯一） |
| `password_hash` | bcrypt 哈希密码 |
| `real_name` | 真实姓名 |
| `email` | 邮箱 |
| `role` | `SUPER_ADMIN` / `ADMIN` / `AUDITOR` / `OPERATOR` |
| `permissions` | 权限列表（JSON） |
| `login_fail_count` | 连续登录失败次数 |
| `locked_until` | 账户锁定截止时间 |
| `is_active` | 是否启用 |

---

## 7. 权限体系 (RBAC)

### 7.1 角色定义

| 角色 | 权限范围 |
|------|----------|
| `SUPER_ADMIN` | 全部权限：CA 管理、系统配置、用户管理 |
| `ADMIN` | 证书签发/吊销/续期、审计查看 |
| `AUDITOR` | 仅审计日志查询和哈希链验证 |
| `OPERATOR` | 证书查询、个人密钥管理 |

### 7.2 权限代码

| 权限代码 | 说明 |
|----------|------|
| `CERT_ISSUE` | 签发证书 |
| `CERT_REVOKE` | 吊销证书 |
| `KEY_EXPORT` | 导出私钥 |
| `AUDIT_READ` | 查看审计日志 |
| `AUDIT_VERIFY` | 验证审计哈希链 |
| `CA_MANAGE` | 管理 CA 配置 |
| `USER_MANAGE` | 管理操作员 |

---

## 8. 常见问题排查

### 8.1 无法连接服务

```bash
# 检查进程
ps aux | grep ca-server

# 检查端口
ss -tlnp | grep 8443

# 检查日志
tail -20 /var/log/opengm-ca.log
```

### 8.2 数据库连接失败

```bash
# 检查 openGauss 是否运行
ps aux | grep gaussdb

# 测试连接
su - omm -c "gsql -d opengm_ca -U ca_admin -p 5432 -c 'SELECT 1;'"
```

### 8.3 登录返回 "用户名或密码错误"

1. 确认 `operators` 表中有记录：
```bash
su - omm -c "gsql -d opengm_ca -U ca_admin -p 5432 -c 'SELECT username FROM operators;'"
```

2. 如记录为空，手动插入默认管理员（见 DEPLOYMENT.md 第 3.9 节）

### 8.4 CA 未初始化错误

```bash
# 清空 CA 链并重新初始化
su - omm -c "gsql -d opengm_ca -U ca_admin -p 5432 -c 'TRUNCATE TABLE ca_chains CASCADE;'"
cd /opt/opengm-ca
./ca-server -config ./configs/config.yaml -init-ca
```

### 8.5 私钥导出失败

- 确认 `CA_MASTER_KEY` 环境变量已设置
- 确认密钥的 `exportable` 字段为 `true`
- 检查当日导出次数是否超过上限（默认 10 次）

---

## 9. 安全最佳实践

1. **修改默认密码**: 首次登录后立即修改 `admin` 密码
2. **启用 HTTPS**: 配置 TLS 证书，关闭 HTTP 明文传输
3. **设置主密钥**: `export CA_MASTER_KEY=$(openssl rand -hex 32)` 并重启服务
4. **定期轮换 JWT Secret**: 修改配置文件中 `auth.jwt.secret`
5. **数据库备份**: 每日备份 openGauss 数据目录
6. **审计监控**: 定期查看 `/api/v1/audit/logs`，关注 `SEVERITY_CRITICAL` 级别事件
7. **私钥导出审批**: 生产环境务必开启 `key_management.export.requires_approval: true`

---

## 10. 联系与支持

- **项目仓库**: https://github.com/xueyuleiyu/opengm-ca
- **部署文档**: `/opt/opengm-ca/DEPLOYMENT.md`
- **日志位置**: `/var/log/opengm-ca.log`
