# TASK-A02 修复 openGauss 驱动认证挂死 + 清理 TableName() 死代码

| 项目 | 内容 |
|---|---|
| 执行者 | claude（本项目唯一实现者） |
| 前置 | 数据库口令已重设并写入 `.env`（`gsql` 侧已验证可连），`password_effect_time` 已设 0 |

## 任务 1（主）：修复 Go 驱动连接挂死

### 已确证的根因（Hermes 实测，勿重新推断）

`ca-server` 启动时卡在 `repository.NewDB` 永不返回。**不是网络、不是口令、不是表名问题**——
`gsql` 用 `.env` 里同一口令连接完全正常（`SELECT count(*) FROM ca_chains` 返回 4）。

SIGQUIT goroutine dump 定位到精确位置：

```
crypto/sha1.(*digest).Sum
crypto/hmac.(*hmac).Sum
golang.org/x/crypto/pbkdf2.Key({...}, {...}, 0x35376161, 0x20, ...)   ← 第3个参数是迭代次数
  gitee.com/opengauss/openGauss-connector-go-pq.generateKFromPBKDF2  (rfcdigest.go:41)
  gitee.com/opengauss/openGauss-connector-go-pq.RFC5802Algorithm     (rfcdigest.go:136)
  gitee.com/opengauss/openGauss-connector-go-pq.(*conn).auth         (conn.go:947)
  (*conn).startup                                                     (conn.go:838)
```

**关键数字**：传给 `pbkdf2.Key` 的迭代次数是 `0x35376161` = **893,993,313**。
`0x35`=`'5'`, `0x37`=`'7'`, `0x61`=`'a'`, `0x61`=`'a'` → 即 ASCII 字符串 `"57aa"` 被当作 4 字节大端整数读取。

**结论**：驱动 v1.0.6 把服务端 sha256 认证报文中的 `iteration` 字段（十六进制**字符串**形式，如 `"57aa"` = 22442）
错误地按二进制整数解析，导致 PBKDF2 迭代 8.9 亿次。进程不是死锁而是在狂算 CPU（预计数十分钟至数小时），
`context.WithTimeout` 因纯 CPU 循环无法抢占而失效。

环境版本：
- 服务端 `openGauss 6.0.3 build 4e5c48e7`（compiled 2025-12-23），`password_encryption_type=2`（仅 sha256）
- 驱动 `gitee.com/opengauss/openGauss-connector-go-pq v1.0.6`
- 驱动模块路径：`/root/go/pkg/mod/gitee.com/opengauss/open!gauss-connector-go-pq@v1.0.6`（只读，勿直接改）

### 你要做的

1. **先复现并确认上述判断**：读 `rfcdigest.go` 的 `RFC5802Algorithm` 与 `generateKFromPBKDF2`，
   以及 `conn.go:900-960` 的 `auth()`，确认 iteration 字段的解析方式（是否用了 `binary.BigEndian.Uint32`
   之类而非 `strconv.ParseInt(s, 16, 32)`）。把你的确认结论和行号写下来。

2. **选择并实施修复方案**。可选路径（自行判断哪个最稳，说明理由）：
   - **升级驱动**到兼容 openGauss 6.x 的版本（先 `go list -m -versions gitee.com/opengauss/openGauss-connector-go-pq`
     看有哪些版本；网络可出外网，`git fetch` 已验证可用）。**这是首选**——若有修复版本，优先升级而非打补丁。
   - 若无可用新版本，用 `replace` 指向修正后的 fork，或在项目内实现最小化的认证适配层。
     **不要直接编辑 GOMODCACHE 里的只读模块**。
   - 若驱动确实无解，评估改用 `pgx`/`lib/pq` + `md5` 认证是否可行
     （需改 `password_encryption_type`，属环境变更，**先问不要做**）。

3. **验证（硬性要求，缺一不可）**：
   - `go build ./...` 0 error；
   - 写一个真实连接测试（可放 `internal/repository/db_test.go`），
     实测 `NewDB` 能在 **5 秒内**返回并成功 `Ping`，且能 `SELECT count(*) FROM ca_chains` 得到 **4**；
     口令从环境变量 `DB_PASSWORD` 读取（`.env` 已有，测试里不要硬编码，缺变量时 `t.Fatal` 而非 `t.Skip`）；
   - **实际启动服务**：`./build/ca-server -config configs/config.yaml`，
     确认日志出现 `数据库连接成功`，且服务监听起来（配置中的端口）；把完整启动日志贴进汇报；
   - `go test ./...` 全绿。

## 任务 2（附带）：清理 TableName() 死代码

`internal/model/` 下 10 个模型定义了 `TableName() string` 方法，但 **bun ORM 不消费这个方法**
（那是 GORM/xorm 的约定）。bun 只认 `bun:"table:xxx"` 标签或嵌入 `bun.BaseModel`，本仓两者皆无，
因此实际表名由 bun 反射推导（下划线+复数），与库中 10 张表完全一致。

已实测确认（`schema.NewTables(pgdialect.New())` 反射打印）：
`CAChain→ca_chains`、`AuditLog→audit_logs`、`SystemConfig→system_configs`、
`KeyExportRequestRecord→key_export_request_records`、`KeyExportApprovalRecord→key_export_approval_records`、
`Certificate→certificates`、`Operator→operators`、`CertKey→cert_keys`、`APIKey→api_keys`、`Subject→subjects`。

这些 `TableName()` 返回的却是**单数**（如 `"ca_chain"`），已经误导过一次代码审查
（被误判为「表名与库不一致」的严重阻塞）。

### 要求

- **删除**这 10 个 `TableName()` 方法：
  `ca.go:44`、`audit.go:85`、`apikey.go:31`、`apikey.go:81`、`key.go:80`、`key.go:162`、`key.go:177`、
  `certificate.go:87`、`operator.go:51`、`subject.go:44`（行号为删除前，逐个确认）
- **绝对禁止**改成 `bun:"table:..."` 标签——那会真的把表名变成单数，与库不符，会搞坏现在正常的代码
- 删除前先 `grep -rn "TableName()" --include="*.go"` 确认**没有任何调用点**；若有调用点，停下报告，不要硬删
- 删完 `go build ./...` + `go test ./...` 必须全绿

## 禁令

- 禁止用 `t.Skip` / `t.Skipf` / `xfail` / `if err != nil { return }` 之类稀释断言的手法；样本或环境缺失应 `t.Fatal`
- 禁止直接修改 `/root/go/pkg/mod/` 下的只读模块文件
- 禁止改 `password_encryption_type` 或其他数据库 GUC（需要就先问）
- 禁止把口令写进代码、测试或提交内容；一律从 `DB_PASSWORD` 环境变量读
- 禁止把 `TableName()` 改成 bun 标签
- 提交信息用中文，格式 `fix(db): ...` / `chore(model): ...`，**分两个 commit**（驱动修复、死代码清理各一个）
- 汇报里必须贴：`go build` 结果、`go test ./...` 完整计数行、真实启动日志、`SELECT count(*) FROM ca_chains` 的实测值
