# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-05-18

### Documentation（文档整合与优化）

- **文档体系重构**
  - 删除冗余文档：AUDIT_REPORT.md、AUDIT_REPORT_V3.md、SECURITY_AUDIT_REPORT.md、CERTIFICATE_COMPARISON_REPORT.md
  - 创建文档导航中心：`doc/index.md`
  - 创建文档整合报告：`doc/DOCUMENT_INTEGRATION_REPORT.md`
  - 统一文档引用路径，所有技术文档引用统一使用`doc/`前缀
  - 文档总数从28个减少到20个，减少28.6%

- **文档分类优化**
  - 核心文档（5个）：README.md、DEPLOYMENT.md、SECURITY.md、USER_MANUAL.md、CHANGELOG.md
  - 安全文档（7个）：CODE_AUDIT_REPORT.md、SECURITY_FIX_SUMMARY.md等
  - 测试文档（2个）：COMPLETE_FUNCTION_TEST_REPORT.md、FRONTEND_FUNCTION_TEST_REPORT.md
  - 优化文档（3个）：CERTIFICATE_OPTIMIZATION_REPORT.md等
  - 修复文档（3个）：DATABASE_PASSWORD_RESET_REPORT.md等
  - 归档文档（3个）：DOCUMENT_ORGANIZATION_REPORT.md等

- **文档引用路径更新**
  - DEPLOYMENT.md：更新所有技术文档引用路径
  - USER_MANUAL.md：更新所有技术文档引用路径
  - 添加文档导航中心链接

### Security（安全审计）

- **代码安全审计完成**
  - 审计日期：2026-05-17
  - 安全等级：⭐⭐⭐⭐☆ (良好)
  - 高危漏洞：0个
  - 中危问题：3个（配置验证、MFA功能、测试覆盖）
  - 低危问题：5个
  - 完成OWASP Top 10和等保2.0合规性检查
  - 生成详细审计报告：`doc/CODE_AUDIT_REPORT.md`

## [Unreleased] - 2026-05-17

### Fixed（问题修复）

- **审计哈希链验证修复** (`internal/model/audit.go`, `internal/repository/audit_repo.go`, `internal/service/audit.go`)
  - 修复 `ActorType` 未设置导致数据库默认值与哈希计算不一致的问题
  - 修复 `VerifyHashChain` 验证逻辑未使用 `log.PrevHash` 的问题
  - 修复时间精度问题：Go `time.Now()` 纳秒精度与 openGauss 微秒精度不匹配导致哈希验证失败
  - 在 `BuildRecordContent` 中统一截断到微秒精度
  - 在 `ComputeHash` 中优先使用已存储的 `RecordContent` 避免重新序列化差异

- **前端证书吊销字段修复** (`web/index.html`)
  - 后端 `Revoke` handler 期望 `reason` (int) 和 `reason_text` (string)
  - 前端原传 `reason` (string) 和 `reason_code` (int)
  - 统一为 `reason:0, reason_text:'管理员吊销'`

- **前端 CA 证书链硬编码修复** (`web/index.html`, `internal/api/handler/ca.go`, `internal/api/router.go`, `cmd/ca-server/main.go`)
  - 新增 `/api/v1/ca/chain` 公开 API，返回数据库中真实 CA 链数据
  - 前端 `loadCaChain` 改为动态调用 API

- **Prometheus Metrics 路由修复** (`internal/api/router.go`)
  - `/api/v1/metrics` 从认证路由组移至公开路由组
  - 符合 AGENTS.md 文档描述

- **根 CA CRL 生成修复** (`internal/core/ca.go`)
  - `GetCA` 方法增加对根 CA 的支持
  - 之前仅查询 `subCAs`，根 CA 请求返回 "CA不存在或未加载"

- **三员权限控制前后端对齐** (`web/index.html`, `internal/model/operator.go`)
  - 前端 `canApprove` 移除 `SYS_ADMIN`（后端 `KEY_EXPORT` 仅分配给 SEC_ADMIN/SUPER_ADMIN）
  - 前端导出审批说明文字修正：删除"系统管理员"
  - 前端三员管理说明修正：`SYS_ADMIN` 不负责 CA策略/证书策略（实际由 SEC_ADMIN 负责）
  - `internal/model/operator.go` 注释修正以匹配实际权限分配
  - 仪表盘 HSM 状态卡片仅 SEC_ADMIN/SUPER_ADMIN 加载，其他角色显示"无权限查看"

- **前端友好度提升** (`web/index.html`)
  - 新增时间格式化：`formatDateTime`、`formatDate`、`formatRelativeTime`
  - 新增 Toast 通知系统替代原生 `alert`
  - 改进加载状态：旋转动画 + "正在加载数据，请稍候..."
  - 改进空状态：图标 + 更友好文案
  - 改进错误状态：⚠️ 图标 + 错误提示
  - 证书列表：添加详情弹窗、分页显示、有效期范围显示、主题DN截断+tooltip
  - 审计日志：事件类型中文映射、严重性标签着色、结果标签着色、分页显示
  - 操作员管理：开关样式状态显示、最近登录相对时间、登录时间列
  - 导出审批：过期时间列、状态颜色统一、ID tooltip
  - HSM管理：密钥类型中文映射、创建时间格式化、403错误Toast提示
  - CA证书链：动态加载真实数据、类型中文映射
  - 全局移除 `alert()`，统一使用 `showToast`

- **前端导出私钥"权限不足"误报修复** (`web/index.html`, `internal/api/handler/key.go`)
  - **根因**: 后端业务拒绝（如"需要审批"）错误返回 HTTP `403`，前端 `api()` 拦截所有 `403` 并直接返回硬编码 `"权限不足"`，吞掉了后端的 `EXPORT_DENIED` 详细响应
  - **后端修复**: 将业务逻辑拒绝的 HTTP 状态码从 `403 Forbidden` 统一改为 `400 Bad Request`（保留 body 中 `code: EXPORT_DENIED`）
    - `Export()` / `CreateExportRequest()` / `ApproveExportRequest()` / `RejectExportRequest()` / `ExecuteExportRequest()`
  - **前端修复**: `api()` 对 `403` 优先尝试解析响应体中的 `code` 字段，识别到 `EXPORT_DENIED` 等详细错误码后原样返回，仅在解析失败时回退到 `"权限不足"`
  - **效果**: 直接导出时若配置 `requires_approval: true`，前端可正确捕获 `"需要审批"` 并自动提交导出申请，跳转至审批页面

### Security（安全加固）

- **主密钥来源验证增强** (`internal/crypto/keystore.go`)
  - 增加主密钥文件权限校验（必须≤0600）
  - 增加符号链接检测，拒绝符号链接文件
  - 增加来源类型记录（environment_variable/file）
  - 增加主密钥加载成功审计日志（不记录密钥内容）

- **API输入参数安全限制** (`internal/api/middleware/request_limit.go`, `internal/api/handler/certificate.go`)
  - 全局请求体大小限制：10MB
  - 证书申请接口请求体限制：1MB
  - CSR PEM大小限制：100KB
  - Subject字段长度限制：256字符
  - SAN数量限制：100个
  - KeyUsage/ExtKeyUsage数量限制：10个
  - CSR PEM格式校验（起始/结束标记）

- **HSM PBKDF2迭代次数统一** (`internal/hsm/softhsm.go`)
  - 主密钥派生迭代次数统一为600,000次
  - 密钥加密密钥派生迭代次数统一为600,000次
  - 符合OWASP推荐标准

- **数据库连接字符串脱敏** (`internal/repository/db.go`)
  - 错误消息中使用脱敏DSN（password=REDACTED）
  - 日志输出使用脱敏DSN
  - 防止数据库密码在日志中泄露

- **审计日志队列优化** (`internal/service/audit.go`)
  - 队列容量从1000增加到5000
  - 增加备份文件路径配置
  - 队列满时写入备份文件（异步，不阻塞业务请求）
  - 增加丢弃计数器和警告日志

- **密码修改权限优化** (`internal/api/router.go`)
  - 移除密码修改接口的USER_MANAGE权限要求
  - 允许所有认证用户修改自己的密码
  - SEC_ADMIN和SUPER_ADMIN可以重置他人密码
  - 函数内部保留完善的权限控制逻辑

- **前端权限逻辑修复** (`web/index.html`)
  - 修复操作员管理菜单权限（改为sys-admin-only）
  - 修复审计日志菜单权限（添加audit-admin-only）
  - 修复申请证书菜单权限（改为sec-admin-only）
  - 添加证书吊销按钮权限控制（仅SEC_ADMIN可见）
  - 添加私钥导出按钮权限控制（仅SEC_ADMIN可见）
  - 修复角色显示格式（使用中文显示名称）
  - 更新操作员管理页面说明（与实际权限一致）

- **数据库密码重置与服务启动**
  - 重置数据库用户ca_admin密码
  - 配置环境变量DB_PASSWORD和JWT_SECRET
  - 服务成功启动并验证健康状态
  - 生成启动脚本和systemd服务配置

### Added（新增功能）

- **国密扩展字段支持** (`internal/core/gm_extensions.go`)
  - 新增国密身份标识扩展支持（OID: 1.2.156.112562.2.1.1.23）
  - 新增国密特有扩展支持（OID: 2.16.840.1.113732.5）
  - 新增Netscape证书类型扩展支持
  - 新增CRL分发点扩展支持（OID: 2.5.29.31）
  - 提供便捷函数EnhanceCertificateWithGMExtensions一次性添加所有扩展
  - 自动生成国密身份标识值（基于主题CN+组织+国家）

- **证书主题字段完善** (`internal/core/ca.go`)
  - 新增State/Province字段支持（省份）
  - 新增Locality字段支持（城市）
  - 正确处理空字符串，避免证书中出现空字段
  - 提高证书信息完整性

### Changed（功能改进）

- **证书生成流程优化**
  - buildCertTemplate函数支持完整的主题字段
  - 证书模板构建更加灵活和完整
  - 提高国密应用兼容性

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
