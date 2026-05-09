# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] - 2026-05-09

### Security（高风险修复）

- **审计哈希链并发保护** (`internal/service/audit.go`)
  - 为 `AuditService` 增加 `sync.Mutex`，串行化"读 prevHash → 计算 currHash → 入队"流程
  - 消除并发场景下哈希链分叉风险

- **init-admins 接口鉴权加固** (`internal/api/router.go`)
  - `/auth/init-admins` 从公开路由移入认证路由组
  - 增加 `RequirePermission("USER_MANAGE")` 中间件，防止未授权创建管理员

- **随机密码熵源安全** (`internal/api/handler/auth.go`)
  - `getEnvOrRandomPassword` 在 `crypto/rand.Read` 失败时直接返回 `error`
  - **彻底移除** `time.Now().UnixNano()` 回退逻辑，防止低熵密码

- **VPN 双证书私钥持久化** (`internal/core/dual_cert.go`)
  - `DualCertCoordinator` 注入 `keyStore` + `keyRepo`
  - 签发签名证书和加密证书后，真实私钥经 `crypto.EncodePrivateKey` 编码并持久化到密钥库
  - 解决此前仅生成证书、私钥未保存的缺陷

- **禁止加载明文私钥** (`internal/core/ca.go`)
  - `decryptKeyFile` 在 JSON 解析失败或 `Encrypted=false` 时直接返回 `error`
  - 彻底移除 PEM 明文回退分支，防止误将明文密钥投入生产

- **SM2 SignDigest 消除二次哈希** (`internal/core/signer.go`)
  - `SignDigest` 改为 `sm2.NewSM2SignerOption(false, s.UID)`（`autoHash=false`）
  - 对已通过 SM3 计算出的 digest 直接签名，避免 `sm2.Sign` 内部再次哈希

- **CA 算法配置一致性** (`internal/core/ca.go`)
  - `saveCAInstance` 使用 `instance.Config.Algorithm` 替代强制根 CA 算法
  - 允许中间 CA 使用与根 CA 不同的算法（如根 CA 为 SM2，中间 CA 为 RSA2048）

- **证书模板解析请求扩展** (`internal/core/ca.go`)
  - `buildCertTemplate` 解析 `req.Extensions.KeyUsage` / `ExtKeyUsage` 为 `x509.KeyUsage`
  - 解决此前请求的 KeyUsage 被忽略的缺陷

- **终端证书有效期截断** (`internal/service/enrollment.go`)
  - `notAfter` 上限自动截断至 `ca.ValidTo`
  - 防止签发有效期超过 CA 自身的无效证书

- **吊销后立即生成 CRL** (`internal/service/management.go`)
  - `RevokeCertificate` 成功后立即调用 `generateAndSaveCRL`
  - 解决此前吊销后 CRL 不同步的延迟问题

- **导出计数原子化** (`internal/repository/key_repo.go`, `internal/service/key_export.go`)
  - `IncrementExportCount` 改为 `UPDATE ... WHERE export_count < max_exports` + `RowsAffected` 判定
  - 消除并发场景下导出次数超限的竞态条件

### Security（中风险修复）

- **默认管理员密码去硬编码** (`cmd/ca-server/main.go`, `internal/api/handler/auth.go`)
  - 三员管理员（SYS_ADMIN / SEC_ADMIN / AUDITOR）初始密码改为环境变量注入
  - 环境变量缺失时通过 `crypto/rand` 生成 24 字节随机 Base64 密码

- **审计日志 marshal 错误处理** (`internal/model/audit.go`)
  - 提取 `toMap()` 统一字段映射，消除 `ComputeHash` 与 `BuildRecordContent` 的重复 marshal
  - marshal 失败时 `panic`（不应发生的编程错误），替代此前的静默忽略

- **非法证书类型拒绝** (`internal/service/enrollment.go`)
  - `selectCA` 对未知证书类型返回 `error`，替代此前的默认降级逻辑

- **密码重置强制强度校验** (`internal/api/handler/operator.go`)
  - 密码重置接口增加 `validatePasswordStrength` 校验（≥8位，大小写+数字+特殊字符）

- **角色更新合法性校验** (`internal/api/handler/operator.go`, `internal/model/operator.go`)
  - 新增 `model.IsValidRole()`，操作员创建/更新时强制校验角色合法性

- **JWT `sub` 类型断言** (`internal/api/middleware/auth.go`)
  - `claims["sub"]` 强制 `.(string)` 断言，非字符串类型直接返回 401

### Changed（代码精简与重构）

- **角色权限集中定义** (`internal/model/operator.go`)
  - 提取包级 `rolePerms` map 和 `GetRolePermissions(role)` 公共函数
  - `auth.go` 的 `getRolePermissions` 改为直接调用 `model.GetRolePermissions`
  - 消除 handler/service 层重复硬编码的角色→权限映射

- **CRL RevokedEntry 复用** (`internal/core/ca.go`, `internal/api/handler/crl.go`, `internal/service/management.go`)
  - 新增 `core.BuildRevokedEntries()`，统一将 `[]model.Certificate` 转换为 `[]pkix.RevokedCertificate`
  - `crl.go` handler 和 `management.go` service 均复用该函数

- **私钥编码统一入口** (`internal/crypto/keygen.go`)
  - 新增 `EncodePrivateKey(privKey, algorithm)`，统一 SM2/RSA/EC 的 PEM 编码
  - `enrollment.go` 和 `dual_cert.go` 均调用此函数

- **审计字段映射去重** (`internal/model/audit.go`)
  - 提取 `AuditLog.toMap()`，供 `ComputeHash` 和 `BuildRecordContent` 复用
  - 消除两份 marshal 逻辑的差异风险

- **Subject 字段清理循环化** (`internal/service/enrollment.go`)
  - `sanitizeSubject` 使用循环遍历字段 map，替代原先的 6 次重复字段调用

- **KeyUsage 映射表化** (`internal/core/ca.go`)
  - `buildCertTemplate` 中使用 `map[string]x509.KeyUsage` 查找替代双层 switch

### Added

- **启动时 JWT Secret 强制校验** (`cmd/ca-server/main.go`)
  - 长度必须 ≥32，且不能包含默认弱密钥字符串（如 `change-in-production`）
  - 未配置或弱密钥时 `log.Fatal` 阻止启动

- **启动时 TLS 强制检查** (`cmd/ca-server/main.go`)
  - TLS 证书文件缺失时不再自动生成自签名证书，直接报错退出

- **数据库迁移 ORM 化** (`cmd/ca-server/main.go`)
  - `runDBMigration` 改用 Bun ORM 的 `On("CONFLICT...")` 处理 openGauss 兼容性

### Security（第三轮审计修复 — 2026-05-09）

- **审计服务全面重构** (`internal/service/audit.go`)
  - 增加 `atomic.Bool closed` 标志，防止向已关闭 channel 发送导致 panic
  - 引入内存变量 `lastHash` + `hashMu` 替代数据库查询，彻底消除哈希链并发分叉
  - 队列满时同步直写使用独立 `context.Background()`，避免受调用方 context 取消影响
  - Worker 增加 `recover()` 防止 panic 导致审计服务崩溃

- **OCSP 响应使用正确 Issuer** (`internal/api/handler/ocsp.go`)
  - `ocsp.CreateResponse` 第一个参数改为被查询证书的签发 CA 证书
  - 修复此前将 Responder 证书误作为 Issuer 传入的问题

- **吊销后 CRL 失败回滚** (`internal/service/management.go`)
  - CRL 生成失败时回滚数据库中的证书状态，防止吊销与 CRL 不一致

- **Subject GetOrCreate 事务化** (`internal/repository/subject_repo.go`)
  - 使用 `bun.RunInTx` 包装 SELECT + INSERT，消除 TOCTOU 竞态条件

- **限流器内存泄漏修复** (`internal/api/middleware/auth.go`)
  - 每 1000 次请求触发一次过期条目清理，防止 map 无限增长导致 OOM

- **JWT 实时状态校验** (`internal/api/middleware/auth.go`, `internal/api/router.go`)
  - `JWTMiddleware` 增加可选的 `UserStatusChecker` 回调
  - 路由层注入操作员数据库查询，校验账户是否仍有效、未被锁定

- **登录失败锁定原子化** (`internal/api/handler/auth.go`, `internal/repository/operator_repo.go`)
  - `IncrementLoginFail` 改为 `RETURNING login_fail_count`，返回原子递增后的最新值
  - 消除并发登录失败时的锁定阈值绕过

- **OperatorRepository 全字段更新修复** (`internal/repository/operator_repo.go`, `internal/service/operator.go`)
  - 拆分 `Update` 为 `UpdateProfile` / `UpdatePassword` / `ToggleStatus`
  - 使用 `Column` 白名单，防止敏感字段被意外覆盖

- **用户自助改密增加强度校验** (`internal/api/handler/operator.go`)
  - 自助改密路径统一调用 `validatePasswordStrength()`

- **输入校验标签修正** (`internal/model/certificate.go`)
  - `CertificateRequest.CertType` 的 `oneof` 枚举增加 `VPN_SIGN` / `VPN_ENC`

- **HSM GCM 密文格式标准化** (`internal/hsm/softhsm.go`)
  - 加密改用 `gcm.Seal(nil, nonce, plaintext, nil)` 标准格式
  - 解密兼容旧格式（跳过重复 nonce 前缀）

- **私钥导出审批逻辑修正** (`internal/service/key_export.go`)
  - 启用审批时检查 `ExportApprovers` 数量是否达到 `ApprovalLevels`
  - 增加导出密码最低 12 位长度校验

- **PBKDF2 迭代次数提升** (`internal/hsm/softhsm.go`, `internal/service/key_export.go`)
  - HSM KEK 派生：10,000 → 600,000（旧数据通过 `KEKIterations` 字段兼容）
  - 私钥导出加密：100,000 → 600,000

- **证书 NotBefore 时钟容差** (`internal/core/ca.go`)
  - 统一设为 `time.Now().Add(-1 * time.Hour)`，防止时钟偏慢客户端拒绝证书

- **CRL NextUpdate 配置化** (`internal/api/handler/crl.go`, `internal/service/management.go`)
  - 移除硬编码 `48 * time.Hour`，改为从 `cfg.CRL.NextUpdateHours` 读取
  - 吊销证书查询移除 10,000 条限制

- **密钥-证书关联持久化** (`internal/service/enrollment.go`, `internal/repository/key_repo.go`)
  - 实现 TODO，调用 `keyRepo.UpdateCertID` 持久化 `cert_keys.cert_id`

- **双证书配对 ID 持久化** (`internal/core/dual_cert.go`, `internal/repository/cert_repo.go`)
  - `certRepo.Create` 增加 `Returning("*")` 回填自增 ID
  - 签发后持久化证书，再设置 `DualCertPairID`

### Changed（代码质量与可靠性）

- **安全响应头** (`cmd/ca-server/main.go`)
  - 增加 `X-Content-Type-Options`、`X-Frame-Options`、`X-XSS-Protection`、`Referrer-Policy`
  - TLS 启用时增加 `Strict-Transport-Security` (HSTS)

- **HSM 删除密钥安全擦除** (`internal/hsm/softhsm.go`)
  - 删除前对 `EncryptedKey` 执行显式清零覆盖

- **HSM 加载错误日志** (`internal/hsm/softhsm.go`)
  - 读取/解析失败时记录结构化 Warn 日志，替代静默 `continue`

- **GenerateKeyID 移除随机回退** (`internal/core/ca.go`)
  - 公钥序列化失败时返回零值切片，替代随机值

- **主密钥自动编码检测** (`internal/crypto/keystore.go`)
  - 支持 hex（64 字符）和 base64 编码的自动识别与解码

- **证书调度器 panic recover** (`internal/service/scheduler.go`)
  - 每次扫描任务增加 `recover()`，防止 panic 导致调度器永久退出

### Fixed（功能完整性修复）

- **AuditService.Log 空 actor 保护** (`internal/service/audit.go`)
  - 当 `actor` 为空字符串时自动回退为 `"SYSTEM"`
  - 解决公开接口（如 CRL 请求）未认证时 `actor=null` 导致审计写入失败的问题

- **EnrollmentService 集成 DualCertCoordinator** (`internal/service/enrollment.go`)
  - `NewEnrollmentService` 内部初始化 `dualCertCoord`
  - `EnrollCertificate` 在 `req.DualCertMode=true` 时委托双证书协调器签发 VPN 签名+加密证书

- **DualCertCoordinator 补充数据库必填字段** (`internal/core/dual_cert.go`)
  - 持久化前补充 `CertHashSHA256`、`CAID`、`IssuedBy`
  - 解决此前双证书保存因字段缺失导致的数据库 not-null 约束失败

- **CAEngine.IssueCertificate 返回完整模型字段** (`internal/core/ca.go`)
  - 补充 `CAID`、`SerialNumberDec`、`CertHashSHA256`、`SignatureAlg`、`PublicKeyAlg`
  - 确保证书模型满足数据库全部非空约束，供单证书和双证书流程复用

- **CAEngine saveCAInstance nil Config 保护** (`internal/core/ca.go`)
  - `saveCAInstance` 在 `instance.Config == nil` 时回退空算法字符串
  - 解决 `-init-ca` 流程中 `createRootCA`/`createIntermediateCA` 未设置 `Config` 导致的 panic

- **CAEngine 创建 CA 时设置 Config** (`internal/core/ca.go`)
  - `createRootCA` 与 `createIntermediateCA` 在返回的 `CAInstance` 中填充 `Config`（含算法）
  - 从源头消除 `saveCAInstance` 的 nil pointer 风险

- **cert_keys 表补充 updated_at 列** (数据库 schema)
  - `ALTER TABLE cert_keys ADD COLUMN updated_at`
  - 解决 `KeyRepository.UpdateCertID` 因列不存在导致的关联更新失败

### Security（第四轮审计修复 — 2026-05-09）

- **JWT密钥长度强制校验** (`internal/api/middleware/auth.go`, `internal/config/config.go`)
  - `GenerateJWT` 增加密钥长度校验，要求至少32字节(256位)
  - `config.Load` 在配置加载时即校验JWT密钥长度，不足则拒绝启动
  - 防止弱密钥导致的Token伪造攻击

- **主密钥解析歧义修复** (`internal/crypto/keystore.go`)
  - `ResolveMasterKey` 优化编码检测逻辑：优先hex格式(64字符)，其次base64格式(必须解码为32字节)，最后原始字节(必须32字节)
  - 消除此前base64自动解码可能导致的长度不足问题

- **导出密码强度强化** (`internal/service/key_export.go`)
  - `ValidateExportPasswordStrength` 增加复杂度校验：至少12位，必须包含大小写字母、数字和特殊字符
  - 提升私钥导出密码安全性

- **SM2私钥编码统一** (`internal/core/ca.go`)
  - `encodePrivateKeyToPEM` 和 `parsePrivateKeyPEM` 统一调用 `crypto/keygen.go` 的公共函数
  - 消除core模块与crypto模块编码格式不一致的问题

- **代码去重优化** (`internal/core/ca.go`)
  - 移除重复的私钥编解码逻辑，复用 `opengmcrypto.EncodePrivateKey` 和 `opengmcrypto.ParsePrivateKeyFromPEM`

### Added（单元测试补充）

- **crypto模块测试** (`internal/crypto/keystore_test.go`, `internal/crypto/keygen_test.go`)
  - 主密钥解析测试（hex/base64/raw格式）
  - 密钥生成测试（SM2/RSA/EC）
  - 加密解密循环测试

- **middleware模块测试** (`internal/api/middleware/auth_test.go`)
  - JWT生成测试（有效密钥/弱密钥）

- **service模块测试** (`internal/service/key_export_test.go`)
  - 导出密码强度验证测试

### Known Issues（已知未修复）

- **MFA 未实现**: `auth.go` 中启用 MFA 的用户无法登录（返回 `MFA_NOT_IMPLEMENTED`）
- **Token 刷新与撤销**: `RefreshToken` 返回 501，无 JWT 黑名单机制
- **数据库 SSL 默认 `prefer`**: 存在 MITM 降级风险，建议改为 `require`
- **无单元测试**: 测试覆盖率为 0，建议优先为核心模块补充测试
- **主密钥 base64 自动解码陷阱**: `resolveMasterKey` 对任意 32 字符且符合 base64 的字符串会解码为不足 32 字节，建议使用 64 字符 hex 格式设置 `CA_MASTER_KEY`
