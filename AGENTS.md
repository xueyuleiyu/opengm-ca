# openGM-CA 项目指南

> 本文档面向 AI 编码助手，用于快速理解项目结构、技术栈、构建方式与开发约定。

---

## 项目概述

**openGM-CA** 是一套支持国际算法与国密算法（SM2/SM3/SM4）的自建 CA（Certificate Authority）系统，基于 Go 开发，专为 openEuler 操作系统和 openGauss 数据库设计。核心能力包括：

- 双算法体系：RSA/ECC 国际算法 + SM2/SM3/SM4 国密算法
- 双证书体系：遵循 GM/T 0015 标准，支持 IPSec VPN 签名证书 + 加密证书
- 多级 CA：根 CA → 中间 CA（SSL-CA / AUTH-CA / VPN-CA）→ 终端证书
- 密钥安全管理：软件加密存储、HSM 集成、私钥托管（Escrow）、受控导出
- 审计不可篡改：哈希链式审计日志，支持完整性校验
- CRL / OCSP：完整的证书吊销列表和在线证书状态协议

---

## 技术栈

| 层级 | 技术 |
|------|------|
| 语言 | Go 1.21+ |
| Web 框架 | Gin (github.com/gin-gonic/gin) |
| 数据库 | openGauss 3.1.0+（PostgreSQL 协议兼容） |
| 数据库驱动 | gitee.com/opengauss/openGauss-connector-go-pq |
| ORM | uptrace/bun + pgdialect |
| 国密算法 | github.com/emmansun/gmsm (sm2, sm3, sm4, smx509) |
| JWT | github.com/golang-jwt/jwt/v5 |
| 配置管理 | spf13/viper |
| 日志 | rs/zerolog（结构化 JSON 日志） |
| 指标 | Prometheus client_golang |
| 构建工具 | Makefile + go modules |

---

## 项目结构

```
opengm-ca/
├── cmd/
│   ├── ca-server/          # CA 服务主程序（HTTP API 服务器）
│   ├── ca-cli/             # 命令行工具（维护脚本）
│   └── ca-init/            # CA 初始化工具
├── internal/
│   ├── api/                # HTTP API 层
│   │   ├── handler/        # Gin Handler（按领域拆分）
│   │   └── middleware/     # JWT 认证、权限检查、限流、RequestID
│   ├── config/             # 配置管理（Viper 封装）
│   ├── core/               # 核心 CA 引擎
│   │   ├── ca.go           # CA 初始化、加载、证书签发
│   │   ├── signer.go       # 签名逻辑
│   │   ├── cert_template.go# 证书模板
│   │   └── dual_cert.go    # 双证书体系（VPN 签名+加密）
│   ├── crypto/             # 国密算法封装
│   │   ├── keygen.go       # 密钥生成（SM2/RSA/EC）
│   │   └── keystore.go     # 主密钥加密存储（SM4-GCM）
│   ├── hsm/                # HSM 集成
│   │   ├── provider.go     # HSM 接口抽象
│   │   └── softhsm.go      # 软件 HSM 实现（文件存储）
│   ├── metrics/            # Prometheus 指标暴露
│   ├── model/              # 领域模型与常量
│   ├── repository/         # 数据访问层（Bun ORM）
│   │   ├── db.go           # 数据库连接初始化
│   │   ├── ca_repo.go      # CA 链仓储
│   │   ├── cert_repo.go    # 证书仓储
│   │   ├── key_repo.go     # 密钥仓储
│   │   ├── audit_repo.go   # 审计日志仓储
│   │   ├── operator_repo.go# 操作员仓储
│   │   └── subject_repo.go # 证书主题仓储
│   └── service/            # 业务服务层
│       ├── enrollment.go   # 证书申请/签发
│       ├── management.go   # 证书管理（查询、吊销、续期）
│       ├── key_export.go   # 私钥导出审批
│       ├── operator.go     # 操作员管理
│       ├── audit.go        # 审计日志与哈希链
│       └── scheduler.go    # 证书到期扫描任务
├── web/
│   └── index.html          # 单页 Web 管理界面（纯前端 HTML/CSS/JS）
├── configs/
│   └── config.yaml         # 主配置文件
├── deployments/
│   ├── docker/             # Dockerfile + docker-compose.yml
│   └── systemd/            # systemd service 安装脚本
├── scripts/
│   ├── init-ca.sh          # CA 初始化脚本
│   └── init-db.sh          # 数据库初始化脚本
├── Makefile
├── go.mod
└── go.sum
```

---

## 构建与运行命令

项目使用 **Makefile** 管理构建生命周期。常用命令：

```bash
# 安装依赖
cd /root/opengm-ca && make mod

# 构建所有二进制文件（输出到 ./build/）
make build                    # 构建 ca-server + ca-cli + ca-init
make build-server             # 仅构建主服务

# 运行开发服务器
make run                      # go run ./cmd/ca-server
make run-dev                  # DEBUG 级别日志运行

# 代码质量
make fmt                      # go fmt ./...
make vet                      # go vet ./...
make lint                     # golangci-lint run ./...
make test                     # go test -v -race -coverprofile=coverage.out ./...
make test-short               # 快速测试
make coverage                 # 生成 HTML 覆盖率报告

# 数据库与 CA 初始化
make init-db                  # 编译并执行 -init-db（创建表+默认数据）
make init-ca                  # 编译并执行 -init-ca（生成根CA和中间CA）

# 清理
make clean                    # 清理 build/ 和 dist/

# Docker
make docker                   # 构建镜像 opengm-ca:$(VERSION)

# 发布
make release                  # 交叉编译 linux/amd64、linux/arm64 并打包
```

**直接编译（不使用 Makefile）：**
```bash
go build -o ca-server ./cmd/ca-server
go build -o opengm-ca-cli ./cmd/ca-cli
go build -o opengm-ca-init ./cmd/ca-init
```

---

## 运行时架构

### 启动流程

1. **加载配置**：`configs/config.yaml`，支持 `${ENV_VAR}` 环境变量引用
2. **连接数据库**：openGauss（PostgreSQL 协议），使用 Bun ORM
3. **初始化数据库**（可选 `--init-db`）：创建 8 张表 + 默认系统配置 + 默认管理员
4. **初始化 CA**（可选 `--init-ca`）：生成根 CA 和配置的中间 CA，写入数据库和文件
5. **检查 CA 状态**：启动前必须确认数据库中已有根 CA
6. **启动 HTTP 服务**：Gin 引擎，监听 `0.0.0.0:8443`
7. **后台任务**：启动证书到期扫描调度器

### 必要环境变量

| 变量名 | 说明 | 是否必需 |
|--------|------|----------|
| `DB_PASSWORD` | openGauss 数据库密码 | 是 |
| `JWT_SECRET` | JWT 签名密钥（建议 ≥32 字节随机字符串） | 是 |
| `CA_HSM_PASSWORD` | 软 HSM 访问密码 | 是 |
| `CA_MASTER_KEY` | 私钥加密主密钥（建议 64 字符 hex，如 `openssl rand -hex 32`） | 否（未设置则私钥加密/导出不可用） |
| `CA_DEFAULT_SYS_ADMIN_PASSWORD` | 系统管理员（SYS_ADMIN）初始密码 | 否（未设置则随机生成） |
| `CA_DEFAULT_SEC_ADMIN_PASSWORD` | 安全管理员（SEC_ADMIN）初始密码 | 否（未设置则随机生成） |
| `CA_DEFAULT_AUDIT_ADMIN_PASSWORD` | 审计管理员（AUDITOR）初始密码 | 否（未设置则随机生成） |

### 服务入口参数

```bash
./ca-server -config ./configs/config.yaml          # 正常启动
./ca-server -config ./configs/config.yaml -init-db  # 初始化数据库
./ca-server -config ./configs/config.yaml -init-ca  # 初始化 CA
```

### 首次部署初始化管理员

```bash
# 登录任意已有账号（如 SUPER_ADMIN）后调用
POST /api/v1/auth/init-admins
# 需要权限：USER_MANAGE
```

三员管理员（SYS_ADMIN / SEC_ADMIN / AUDITOR）的初始密码可通过以下方式指定（优先级从高到低）：
1. 环境变量：`CA_DEFAULT_SYS_ADMIN_PASSWORD`、`CA_DEFAULT_SEC_ADMIN_PASSWORD`、`CA_DEFAULT_AUDIT_ADMIN_PASSWORD`
2. 运行时密码学安全随机生成（24 字节 Base64，熵源失败则直接报错，**禁止回退到时间戳**）

### 目录布局（运行期）

```
./data/
├── ca_keys/              # CA 私钥文件（加密 JSON，需保护）
└── hsm/                  # 软 HSM 存储目录
./web/                    # 前端静态资源
./configs/config.yaml     # 主配置文件
```

---

## 代码组织与模块划分

### 分层架构

项目采用经典的分层架构，依赖关系自上而下：

```
Handler (api/handler)  →  Service (service)  →  Repository (repository)
         ↓                      ↓                      ↓
    Middleware              Core / Crypto           Model / DB
```

**不允许跨层调用**，例如 Handler 不直接调用 Repository。

### 核心领域模块

| 模块 | 职责 | 关键文件 |
|------|------|----------|
| **CA Engine** | 根 CA / 中间 CA 的创建、加载、证书签发、CRL 生成 | `internal/core/ca.go`, `signer.go` |
| **Enrollment** | 处理证书申请（CSR / 本地生成密钥）、签发、续期；终端证书有效期自动截断至 CA 有效期 | `internal/service/enrollment.go` |
| **Key Management** | 密钥生成、加密存储（SM4-GCM）、受控导出；导出计数原子化（`WHERE export_count < max_exports`） | `internal/crypto/keystore.go`, `internal/service/key_export.go` |
| **Audit** | 操作审计日志记录、哈希链完整性校验；内存变量 `lastHash` + `sync.Mutex` 串行化计算，worker `recover()` 防崩溃 | `internal/service/audit.go`, `internal/repository/audit_repo.go` |
| **Auth** | 操作员登录、JWT 签发、RBAC 权限校验；`sub` 强制字符串断言；密码强度服务端校验；JWT 实时状态校验（账户禁用/锁定即时生效） | `internal/api/handler/auth.go`, `internal/api/middleware/auth.go` |
| **HSM** | 密钥的 HSM 安全存储接口（当前为软实现）；GCM 标准格式加密；PBKDF2 600,000 迭代 | `internal/hsm/softhsm.go` |
| **Dual Cert** | VPN 双证书体系（签名+加密），签发后真实私钥持久化到密钥库 | `internal/core/dual_cert.go` |

### 证书类型

系统支持 4 种证书类型，在 `internal/model/certificate.go` 中定义：

- `SSL`：HTTPS 服务器/客户端证书
- `AUTH`：个人身份认证、电子签章
- `VPN_SIGN`：IPSec VPN 身份认证签名
- `VPN_ENC`：IPSec VPN 密钥协商加密

---

## 代码风格指南

- **格式化**：使用 `go fmt`，Makefile 提供 `make fmt`
- **注释**：使用中文注释，描述函数职责和参数含义
- **错误处理**：使用 `fmt.Errorf("...: %w", err)` 包装错误，禁止吞掉错误
- **日志**：使用 `rs/zerolog`，结构化字段方式记录。示例：
  ```go
  log.Info().Str("ca", caName).Int("keys", count).Msg("HSM初始化完成")
  log.Warn().Err(err).Msg("主密钥加载失败")
  ```
- **包别名规则**：
  - 若标准库包名与项目内部包冲突，给项目包加别名 `opengmcrypto`。示例见 `internal/service/enrollment.go`
  - 国密 x509 使用别名 `smx509 "github.com/emmansun/gmsm/smx509"`
- **代码去重约定**：
  - 角色权限查询统一走 `model.GetRolePermissions()`，禁止各 handler 重复维护角色→权限映射表
  - CRL RevokedEntry 构建统一走 `core.BuildRevokedEntries()`，禁止 service/handler 各写一套
  - 私钥编码统一走 `crypto.EncodePrivateKey()`，统一 SM2/RSA/EC 的 PEM 编码逻辑
  - 审计日志字段映射统一走 `model.AuditLog.toMap()`，消除 `ComputeHash` 与 `BuildRecordContent` 的重复 marshal 逻辑
  - KeyUsage / ExtKeyUsage 映射优先使用 map 查找，禁止双层 switch 重复列举
- **模型标签**：Bun ORM 模型使用 ``bun:"column_name,notnull"`` 标签，JSON 序列化使用 ``json:"column_name,omitempty"``

---

## 测试策略

> **当前状态**：项目中 **没有任何 `*_test.go` 文件**，测试覆盖率为 0。

Makefile 已预留测试命令，新增测试应遵循：

```bash
make test          # 运行全部测试（含竞态检测）
make test-short    # 运行短测试
make coverage      # 生成覆盖率报告
```

**建议优先补充测试的领域：**
- `internal/core/`：CA 引擎的证书签发、CRL 生成逻辑
- `internal/crypto/`：密钥生成、加密/解密 round-trip
- `internal/service/`：业务规则校验（有效期、权限、导出限制）
- `internal/api/middleware/`：JWT 签发与校验、权限中间件

---

## 安全注意事项

### 密钥与凭证管理

- **生产环境必须通过环境变量注入所有密钥**，禁止在代码或配置文件中硬编码密码
- `configs/config.yaml` 中敏感字段使用 `${ENV_NAME}` 占位符，由 `config.resolveEnvVariables()` 解析
- JWT Secret 启动时强制校验：长度必须 ≥32，且不能包含默认弱密钥字符串
- 主密钥（`CA_MASTER_KEY`）用于 SM4-GCM 加密私钥，丢失将导致所有加密私钥无法解密
- **`CA_MASTER_KEY` 格式建议**：使用 64 字符 hex 字符串（如 `openssl rand -hex 32`），系统会自动识别 hex/base64。避免使用恰好是有效 base64 的 32 字符字符串，否则 `resolveMasterKey` 会将其解码为 24 字节，导致 `NewKeyStore` 长度校验失败

### HSM

- 当前使用软件 HSM（`internal/hsm/softhsm.go`），密钥以文件形式存储于 `./data/hsm/`
- 生产环境建议对接真实 HSM，实现 `hsm.Provider` 接口即可替换

### 私钥导出

- 私钥导出受配置 `key_management.export` 控制：需要审批、每日上限、每把密钥上限
- 导出操作会记录 `CRITICAL` 级别审计日志

### 文件权限

- CA 私钥文件 `./data/ca_keys/*.key` 应设置为 `0600`
- TLS 私钥文件应设置为 `0600`

### TLS

- 生产环境必须开启 `server.tls.enabled: true`
- 若 TLS 证书文件不存在，启动时会自动生成自签名 RSA 证书（仅用于测试，生产环境应替换为正规证书）

---

## 部署流程

### 1. 二进制部署（systemd）

```bash
make build
# 将 build/opengm-ca* 复制到 /opt/opengm-ca/
# 复制 configs/ 到 /opt/opengm-ca/configs/
# 配置 systemd 服务（参考 deployments/systemd/opengm-ca.service）
```

### 2. Docker 部署

```bash
make docker
# 或
docker build -t opengm-ca -f deployments/docker/Dockerfile .
```

镜像基于 `openeuler/openeuler:22.03-lts-sp3`，多阶段构建，运行用户为非 root 的 `opengm-ca`。

### 3. 首次部署初始化顺序

```bash
# 1. 创建 openGauss 数据库和用户
# 2. 设置环境变量：export DB_PASSWORD=... JWT_SECRET=... CA_HSM_PASSWORD=...
# 3. 初始化数据库表
./ca-server -config ./configs/config.yaml -init-db
# 4. 初始化 CA 根证书和中间 CA
./ca-server -config ./configs/config.yaml -init-ca
# 5. 正常启动服务
./ca-server -config ./configs/config.yaml
```

---

## 已知限制与注意事项

1. **openGauss 兼容性**：
   - openGauss 不支持 PostgreSQL 的 `ON CONFLICT` 语法，因此 `runDBMigration` 中的初始化 SQL 可能执行失败，需手动插入默认管理员和系统配置。
   - 使用 `gitee.com/opengauss/openGauss-connector-go-pq` 驱动，DSN 与 PostgreSQL 相同。

2. **CA 私钥持久化**：
   - 当前 CA 私钥同时保存到 `./data/ca_keys/` 文件和数据库（加密）。服务重启时优先尝试从文件加载私钥，文件缺失则无法恢复签名能力。

3. **smx509 解析限制**：
   - `github.com/emmansun/gmsm/smx509` 对中间 CA 证书解析时可能出现 SubjectDN/IssuerDN 降级，系统使用配置值作为回退。

4. **数据库 Schema 兼容性**：
   - `cert_keys` 表需包含 `updated_at` 列，否则 `KeyRepository.UpdateCertID` 会失败。旧环境请执行：
     ```sql
     ALTER TABLE cert_keys ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT pg_systimestamp();
     ```

5. **无单元测试**：
   - 当前没有测试文件，任何修改都应通过本地编译和手动 API 测试验证。

---

## 常用 API 端点

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/health` | 健康检查 | 公开 |
| POST | `/api/v1/auth/login` | 登录获取 JWT | 公开 |
| POST | `/api/v1/certificates/enroll` | 申请/签发证书 | `CERT_ISSUE` |
| GET | `/api/v1/certificates` | 证书列表 | `CERT_READ` |
| POST | `/api/v1/certificates/:cert_id/revoke` | 吊销证书 | `CERT_REVOKE` |
| POST | `/api/v1/keys/:key_id/export` | 导出私钥 | `KEY_EXPORT` |
| GET | `/api/v1/audit/logs` | 审计日志 | `AUDIT_READ` |
| GET | `/api/v1/crl/:ca_name` | 下载 CRL | 公开 |
| POST | `/api/v1/ocsp` | OCSP 查询 | 公开 |
| GET | `/api/v1/metrics` | Prometheus 指标 | 公开 |

完整的 API 文档参考 `docs/API.md`（如果存在）或 `internal/api/router.go` 中的路由定义。

---

## 相关文档

- `README.md`：项目介绍、快速开始
- `DEPLOYMENT.md`：实际部署记录、环境信息、问题修复记录
- `USER_MANUAL.md`：用户操作手册、API 调用示例
- `PASSWORD_RESET.md`：密码重置记录（含敏感信息，生产环境应删除）
