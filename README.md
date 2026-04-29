# openGM-CA

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**openGM-CA** 是一套支持国际算法与国密算法(SM2/SM3/SM4)的自建CA系统，专为openEuler操作系统和openGauss数据库设计，满足国内企业级SSL证书、个人认证证书和国密IPSec VPN双证书体系的签发需求。

---

## 特性

- **双算法体系**: 同时支持RSA/ECC国际算法和SM2/SM3/SM4国密算法
- **双证书体系**: 遵循GM/T 0015标准，支持IPSec VPN签名证书+加密证书
- **多证书类型**: SSL/TLS证书、个人认证证书、国密VPN证书
- **密钥安全管理**: 软件加密存储、HSM集成、私钥托管(Escrow)
- **私钥明文导出**: 可控的私钥导出机制，完整的审计追踪
- **数据库**: 基于openGauss(PostgreSQL兼容)的企业级存储
- **审计不可篡改**: 哈希链式审计日志，支持完整性校验
- **CRL/OCSP**: 完整的证书吊销列表和在线证书状态协议支持
- **国密TLS**: 支持GMTLS双栈(国际TLS + 国密TLS)

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

### 6. 启动服务

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
