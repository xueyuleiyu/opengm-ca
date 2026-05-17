# openGM-CA

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**openGM-CA** 是一套支持国际算法与国密算法(SM2/SM3/SM4)的自建CA系统，专为openEuler操作系统和openGauss数据库设计，满足国内企业级SSL证书、个人认证证书和国密IPSec VPN双证书体系的签发需求。

---

## 特性

- **双算法体系**: 同时支持RSA/ECC国际算法和SM2/SM3/SM4国密算法
- **双证书体系**: 遵循GM/T 0015标准，支持IPSec VPN签名证书+加密证书
- **多证书类型**: SSL/TLS证书、个人认证证书、国密VPN证书
- **密钥安全管理**: 软件加密存储(AES-256-GCM + HKDF-SHA256)、HSM集成、私钥托管(Escrow)
- **私钥受控导出**: 密码加密导出(PBKDF2+AES-256-GCM)、审批 gate、完整审计追踪
- **数据库**: 基于openGauss(PostgreSQL兼容)的企业级存储
- **审计不可篡改**: 哈希链式审计日志，有界异步写入，支持完整性校验
- **CRL/OCSP**: 标准 DER 格式响应，符合 RFC 5280 / RFC 6960
- **国密TLS**: 支持GMTLS双栈(国际TLS + 国密TLS)
- **JWT安全**: 仅HS256，显式校验claims，拒绝none算法
- **密码策略**: 服务端强制强度校验(≥8位，大小写+数字+特殊字符)；三员管理员初始密码支持环境变量注入或密码学安全随机生成
- **等保三员分离**: SUPER_ADMIN / SYS_ADMIN / SEC_ADMIN / AUDITOR 四级角色，通过 `init-admins` API 初始化
- **证书有效期截断**: 终端证书有效期自动限制在 CA 有效期范围内，防止签发超期证书
- **吊销即时生效**: 吊销证书后自动重新生成并保存 CRL，失败时回滚吊销状态
- **私钥导出原子计数**: 数据库层原子更新导出次数，消除并发竞态条件
- **审计防篡改**: 哈希链式审计日志，内存串行化计算， graceful shutdown 保障完整性
- **OCSP 实时响应**: 标准 DER/JSON 格式，使用正确 CA 证书作为 Issuer
- **HSM 安全存储**: 软 HSM 实现，GCM 标准格式，PBKDF2 600,000 迭代
- **JWT密钥强度校验**: 启动时强制校验密钥长度≥32字节，拒绝弱密钥
- **私钥导出密码策略**: 导出密码要求12位以上，包含大小写字母、数字和特殊字符
- **主密钥编码检测**: 自动识别hex(64字符)和base64格式，确保32字节密钥长度
- **主密钥来源验证**: 文件权限校验(≤0600)、符号链接检测、来源类型审计日志
- **API输入限制**: 请求体大小限制(全局10MB/证书申请1MB)、字段长度校验、CSR格式验证
- **数据库DSN脱敏**: 日志和错误消息中密码显示为REDACTED，防止凭证泄露
- **审计队列优化**: 队列容量5000，降级备份机制，避免阻塞业务请求
- **密码修改权限优化**: 所有用户可修改自己密码，SEC_ADMIN可重置他人密码
- **前端权限一致性**: 菜单和按钮权限与后端API权限完全一致
- **三员权限分离**: SYS_ADMIN(系统配置+用户管理)、SEC_ADMIN(证书签发+密钥管理)、AUDITOR(审计查看)
- **角色显示优化**: 使用中文显示名称，提升用户体验

---

## 系统要求

| 组件 | 版本要求 |
|------|----------|
| 操作系统 | openEuler 22.03 LTS SP3+ |
| 数据库 | openGauss 3.1.0+ |
| Go | 1.21+ |
| 内存 | 2GB+ |
| 磁盘 | 20GB+ (根据证书数量调整) |

---

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/opengm-ca/opengm-ca.git
cd opengm-ca
```

### 2. 安装依赖

```bash
make mod
```

### 3. 配置数据库

编辑 `configs/config.yaml`，配置openGauss连接信息：

```yaml
database:
  host: "localhost"
  port: 5432
  user: "ca_admin"
  password: "${DB_PASSWORD}"  # 通过环境变量传入
  dbname: "opengm_ca"
  ssl_mode: "prefer"          # 生产环境建议 require/verify-ca

auth:
  jwt:
    secret: "${JWT_SECRET}"   # 启动时强制校验长度≥32，拒绝默认弱密钥
```

### 4. 初始化数据库

```bash
export DB_PASSWORD="your_db_password"
make init-db
```

### 5. 初始化CA

```bash
make init-ca
```

### 6. 初始化三员管理员

```bash
# 启动服务后，以 SUPER_ADMIN 登录，调用 init-admins 接口
curl -X POST https://localhost:8443/api/v1/auth/init-admins \
  -H "Authorization: Bearer <token>"
```

生产环境建议预先设置环境变量：
```bash
export CA_DEFAULT_SYS_ADMIN_PASSWORD="<强密码>"
export CA_DEFAULT_SEC_ADMIN_PASSWORD="<强密码>"
export CA_DEFAULT_AUDIT_ADMIN_PASSWORD="<强密码>"
```

### 7. 启动服务

```bash
make run
```

服务将监听 `https://localhost:8443`

---

## 项目结构

```
opengm-ca/
├── cmd/
│   ├── ca-server/          # CA服务主程序
│   ├── ca-cli/             # 命令行工具
│   └── ca-init/            # CA初始化工具
├── internal/
│   ├── config/             # 配置管理
│   ├── core/               # 核心CA引擎(签名、证书模板、CRL)
│   ├── service/            # 业务服务层
│   ├── repository/         # 数据访问层(openGauss)
│   ├── api/                # HTTP API层(Gin)
│   ├── crypto/             # 国密算法封装
│   └── model/              # 领域模型
├── configs/                # 配置文件
├── deployments/            # 部署脚本(Docker/systemd/K8s)
├── scripts/                # 运维脚本
└── docs/                   # 文档
```

---

## 核心概念

### 证书类型

| 类型 | 用途 | 算法 |
|------|------|------|
| SSL | HTTPS服务器/客户端证书 | SM2/RSA/ECC |
| AUTH | 个人身份认证、电子签章 | SM2 |
| VPN_SIGN | IPSec VPN身份认证签名 | SM2 |
| VPN_ENC | IPSec VPN密钥协商加密 | SM2 |

### 双证书体系

国密VPN采用**签名证书+加密证书**分离机制：
- **签名证书**: 用于身份认证和数字签名，私钥用户自持
- **加密证书**: 用于密钥交换和数据加密，私钥可托管于CA

---

## API接口

详见 [API.md](docs/API.md)

### 证书申请示例

```bash
curl -X POST https://localhost:8443/api/v1/certificates/enroll \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "cert_type": "SSL",
    "algorithm": "SM2",
    "subject": {
      "common_name": "www.example.com",
      "organization": "Example Corp",
      "country": "CN"
    },
    "validity_days": 365,
    "extensions": {
      "subject_alt_names": [
        {"type": "dns", "value": "www.example.com"}
      ]
    },
    "gen_key_locally": true
  }'
```

---

## 安全建议

1. **根CA离线保存**: 根CA私钥应保存在离线环境或HSM中
2. **主密钥保护**: 生产环境务必通过环境变量或KMS注入主密钥
3. **私钥导出控制**: 启用双人审批和导出次数限制
4. **定期轮换**: 建议每年轮换中间CA密钥
5. **审计监控**: 启用审计日志完整性校验，定期检查哈希链

---

## 许可证

MIT License

---

## 联系我们

- 项目主页: https://github.com/opengm-ca/opengm-ca
- 问题反馈: https://github.com/opengm-ca/opengm-ca/issues
