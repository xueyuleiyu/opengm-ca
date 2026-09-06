# openGM-CA 启动前置缺口清单（2026-09-06）

> 任务：TASK-A01（只读调查）。所有结论均附 文件:行号 或命令输出证据；未执行的命令仅列于"最小启动清单"，本任务全程未启动服务、未改库、未改源码/配置/证书。所有口令/密钥一律以 `[REDACTED]` 表示。

## 一、结论摘要

- **能否启动：不能。** 当前 `/root/opengm-ca` 状态下直接启动 ca-server 会失败。
- **硬阻塞项数量：3 个**（详见第三节），任一未解决都无法完成启动：
  1. 数据库口令 `DB_PASSWORD` 缺失（`config.yaml:23` 引用，`.env` 无此项，配置加载 fail-fast 退出）。
  2. `.env` 文件不会被 Go 进程自动加载（无 godotenv，当前无 systemd 单元，`make run` 也不 export）——即使 `.env` 里已有的 3 个变量也不会进入进程环境。
  3. 无构建产物，需先 `go build`（详见阻塞 3）。
  4. 无构建产物：`build/` 为空，`ca-server` 二进制缺失（需先 `go build`）。
- **最小启动条件一句话**：先 `go build` 产出二进制，以 `/root/opengm-ca` 为工作目录、显式 export `DB_PASSWORD`（真实值需用户提供）/`JWT_SECRET`/`CA_MASTER_KEY`/`CA_HSM_PASSWORD`，即可启动（表名无需处理，见第四节非阻塞项 0）。

## 二、环境变量依赖表

> 说明：Go 程序只读 `os.Getenv`（`internal/config/config.go:285,294,302`；`cmd/ca-server/main.go:129,167,211,365`），**不读取 `.env` 文件**（`go.mod` 中无 godotenv/dotenv 依赖；全仓仅 `deployments/systemd/opengm-ca.service:23` 的 `EnvironmentFile` 与 `deployments/docker/docker-compose.yml:37-39` 引用 .env）。因此下表"`.env` 是否提供"仅表示文件里有没有该项，不等于进程环境里一定有。

| 变量 | config.yaml 行号 | .env 是否提供 | 缺失时行为 | 证据（代码行号） |
|---|---|---|---|---|
| `DB_PASSWORD` | 23（`password: "${DB_PASSWORD}"`） | **否**（`.env` 仅 3 行，见下） | **fail-fast**：`resolveEnvVariables` 取 `os.Getenv("DB_PASSWORD")`，为空返回 `环境变量 DB_PASSWORD 未设置` → `Load` 报错 → `main` 打印"加载配置失败"并 `os.Exit(1)` | `internal/config/config.go:283-288`；`cmd/ca-server/main.go:41-45` |
| `JWT_SECRET` | 149（`secret: "${JWT_SECRET}"`） | 是（`.env` 第 2 行，值 `[REDACTED]`） | 缺失→同上 fail-fast；且加载后强制校验长度 `<32` 即报错 | `internal/config/config.go:292-298, 240-242` |
| `CA_MASTER_KEY` | 104（`env_name: "CA_MASTER_KEY"`，非 `${}` 语法） | 是（`.env` 第 1 行，值 `[REDACTED]`） | **非致命**：`source: env` 时取不到仅 `log.Warn`"私钥加密功能将不可用"，继续启动 | `internal/config/config.go:301-307`；`cmd/ca-server/main.go:142-146` |
| `CA_HSM_PASSWORD` | 无（config.yaml 不含此项） | 是（`.env` 第 3 行，值 `[REDACTED]`） | **fatal**：`startServer` 直接 `os.Getenv`，为空 `log.Fatal` | `cmd/ca-server/main.go:129-132` |
| `CA_JWT_SECRET` | 无（config.yaml 不含此项） | 否 | 可选覆盖：为空则回退 `cfg.Auth.JWT.Secret`（即 `JWT_SECRET`）；最终值空/含 `change-in-production`/长度 `<32` 则 fatal | `cmd/ca-server/main.go:167-174` |
| `CA_INITIAL_ADMIN_PASSWORD` | 无 | 否 | 仅 `--init-db`/`--init-ca` 建默认管理员时用；缺省生成随机密码（非致命） | `cmd/ca-server/main.go:365-369` |
| `GM_CA_ALLOW_HTTP` | 无 | 否 | 仅当 `server.tls.enabled=false` 时相关；当前为 `true`，不触发 | `cmd/ca-server/main.go:211-213`；`configs/config.yaml:7` |

补充证据：
- `.env` 实际内容（键名，值已脱敏）：`CA_MASTER_KEY` / `JWT_SECRET` / `CA_HSM_PASSWORD`（`/root/opengm-ca/.env`，共 3 行）。
- `.env.example` 不存在：`ls -la .env.example` → `No such file or directory`。
- viper 侧存在二级机制：`v.SetEnvPrefix("GM_CA")` + `AutomaticEnv()`（`internal/config/config.go:218-220`），理论上 `GM_CA_DATABASE_PASSWORD` 等 `GM_CA_*` 变量可覆盖对应配置键；但仓库/文档未使用该前缀，主通道仍是 `${DB_PASSWORD}` 的 `resolveEnvVariables` 展开（`config.go:234-237`）。

## 三、阻塞项（必须解决才能启动）

### 阻塞 1：数据库口令 `DB_PASSWORD` 缺失

- **现象**：`configs/config.yaml:23` 为 `password: "${DB_PASSWORD}"`；`.env` 无 `DB_PASSWORD`。
- **根因**：配置加载对 `${DB_PASSWORD}` 做 `os.Getenv("DB_PASSWORD")`，空则直接返回错误（非空值继续、非默认值兜底）。
- **证据**：
  - `configs/config.yaml:23`
  - `internal/config/config.go:283-288`（空值 → `return fmt.Errorf("环境变量 %s 未设置", envName)`）
  - `cmd/ca-server/main.go:41-45`（`Load` 出错 → `os.Exit(1)`）
  - `/root/opengm-ca/.env`（无 DB_PASSWORD 项）
- **DB_PASSWORD 来源调查（任务 1.2）**：
  - 当前代码/配置中**无硬编码明文**，仅 `${DB_PASSWORD}` 占位（`config.yaml:23`、`internal/config/config.go:23`）。
  - 无 `.env.example`（见上）。
  - `DEPLOYMENT.md:355` 明确 `DB_PASSWORD` **必须设置**；建用户示例 `DEPLOYMENT.md:213`（`CREATE USER ca_admin WITH PASSWORD '${DB_PASSWORD}'`）；连接示例 `DEPLOYMENT.md:317`（`password: "${DB_PASSWORD}"`）；清表示例 `DEPLOYMENT.md:263`（`-W ${DB_PASSWORD}`）。
  - `deployments/docker/docker-compose.yml:37` 提供占位默认 `DB_PASSWORD: "${DB_PASSWORD:-ChangeMeInProduction}"`（仅 docker 占位，非真实口令）。
  - `scripts/init-db.sh:11,34-35,52`：脚本强制要求 `DB_PASSWORD` 已导出，否则报"请设置 DB_PASSWORD 环境变量"退出。
  - systemd 模板 `deployments/systemd/opengm-ca.service:23` 只加载 `EnvironmentFile=/opt/opengm-ca/.env`，其安装脚本 `deployments/systemd/install.sh:26-31` 仅在缺文件时生成 `CA_MASTER_KEY`，**不写 DB_PASSWORD**；当前系统亦无该 unit（`systemctl list-unit-files` 无 opengm）。
  - 部署目录 `/opt/opengm-ca/.env`（历史部署副本）实际仅含 `CA_MASTER_KEY`/`CA_JWT_SECRET`（值 `[REDACTED]`），**同样无 DB_PASSWORD**。
  - 历史文档出现过一次具体口令：`doc/DATABASE_PASSWORD_RESET_REPORT.md:86`（`export DB_PASSWORD='[REDACTED]'`，一次重置动作的记录）；另有 `doc/FIXES_INTEGRATED.md:70`、`doc/CERTIFICATE_ENROLL_EMPTY_RESPONSE_FIX.md:262` 等重复记载（值均 `[REDACTED]`）。git 历史中 `346c4ca "security: remove all hardcoded credentials and reset passwords"` 移除了硬编码口令并删除 `PASSWORD_RESET.md`。
- **需要什么才能解决**：**需用户提供** `ca_admin` 用户在 openGauss 中的真实口令（`configs/config.yaml:22` 数据库用户为 `ca_admin`），并在启动进程环境中导出 `DB_PASSWORD`。本任务不猜测、不填写该值。

### 阻塞 2：`.env` 不被进程加载，环境变量注入链路缺失

- **现象**：`.env` 中已有的 `CA_MASTER_KEY`/`JWT_SECRET`/`CA_HSM_PASSWORD` 也不会在直接运行时进入进程。
- **根因**：Go 程序无 dotenv 加载逻辑，全部走 `os.Getenv`；当前无 systemd 单元注入；`make run` 未 export。
- **证据**：
  - `go.mod` 无 godotenv/dotenv/joho 依赖（`grep -iE "godotenv|dotenv|joho" go.mod` → 无匹配）。
  - `internal/config/config.go:285,294,302` 与 `cmd/ca-server/main.go:129,167,211,365` 均直接 `os.Getenv`。
  - `Makefile:147`（`run` 目标）：`go run ./cmd/ca-server -config ./configs/config.yaml`，无 `set -a && . ./.env` 之类注入。
  - `systemctl list-unit-files | grep -i opengm` → 无结果（unit 未安装）。
- **需要什么才能解决**：二选一——(a) 启动前 `export $(cat .env | xargs)` 或逐条 `export`；(b) 安装 systemd 单元并保证其 `EnvironmentFile` 指向的 `.env` 含全部必需变量。此缺口不涉及新口令，但需用户确认采用哪种注入方式。

### 阻塞 3：无构建产物（ca-server 二进制缺失）

- **现象**：`build/` 目录为空，无法直接执行服务。
- **证据**：`ls -la build/` → 空目录；`Makefile:48`（`build-server` 输出到 `$(BUILD_DIR)/$(BINARY_NAME)` = `build/opengm-ca`）。
- **需要什么才能解决**：先执行构建（如 `make build-server` 或 `CGO_ENABLED=0 go build -o build/opengm-ca ./cmd/ca-server`）。注意 `/opt/opengm-ca/ca-server`（26 MB，`-rwx------ root root`）是另一部署副本的旧二进制，非本工作目录产物。

## 四、非阻塞项（可延后）

0. **数据库表名与代码模型「不一致」——经复核为误判，实际完全一致（Hermes 2026-09-06 实测推翻）**：

   初版报告曾将此列为阻塞 3，依据是各模型定义了 `TableName()` 方法返回单数表名
   （如 `internal/model/ca.go:44-45` 返回 `"ca_chain"`），与库中 `ca_chains` 不符。

   **该判断错误。根因：bun ORM 不消费 `TableName()` 方法**——那是 GORM/xorm 的约定。
   bun v1.1.17（`go.mod`）仅识别两种表名来源：
   - 结构体字段上的 `bun:"table:xxx"` 标签 —— 全仓 grep 无任何命中；
   - 嵌入 `bun.BaseModel` —— 全仓 grep 无任何命中。

   两者皆无时，bun 走反射自动推导（下划线化 + 复数化）。

   **实测证据**（用 `schema.NewTables(pgdialect.New())` 真实反射推导并打印）：

   | 模型 | bun 实际表名 | 库中实际表 | 一致 |
   |---|---|---|---|
   | `model.CAChain` | `ca_chains` | `ca_chains` | ✅ |
   | `model.AuditLog` | `audit_logs` | `audit_logs` | ✅ |
   | `model.SystemConfig` | `system_configs` | `system_configs` | ✅ |
   | `model.KeyExportRequestRecord` | `key_export_request_records` | `key_export_request_records` | ✅ |
   | `model.KeyExportApprovalRecord` | `key_export_approval_records` | `key_export_approval_records` | ✅ |
   | `model.Certificate` | `certificates` | `certificates` | ✅ |
   | `model.Operator` | `operators` | `operators` | ✅ |
   | `model.CertKey` | `cert_keys` | `cert_keys` | ✅ |
   | `model.APIKey` | `api_keys` | `api_keys` | ✅ |
   | `model.Subject` | `subjects` | `subjects` | ✅ |

   10/10 完全对应，库中恰好也只有这 10 张表。

   **结论：不需要改代码，也不需要重建表。** 若照初版报告去"对齐表名"，反而会把正确的代码改坏。

   **遗留技术债（非阻塞，建议后续清理）**：那 10 个 `TableName()` 方法是死代码
   （`ca.go:44`、`audit.go:85`、`apikey.go:31,81`、`key.go:80,162,177`、
   `certificate.go:87`、`operator.go:51`、`subject.go:44`），bun 从不调用，
   留着会持续误导阅读者（本次即被误读一次）。清理方式：删除方法，或改为
   `bun:"table:..."` 标签使其真正生效——**注意后者会真的改变表名，需同步库**。

1. **国密双证书 `/opt/opengm-ca/certs/server_{sign,enc}.{crt,key}`（任务 1.3）——不阻塞**：
   - 该段位于 `server.tls.gm_tls` 下，父级开关 `gm_tls.enabled: false`（`configs/config.yaml:11-12`，证书路径在 13-16）。
   - 代码中 `GMTLSConfig` 仅定义于 `internal/config/config.go:43-50`，全仓无任何运行时读取（`grep -n "GMTLS|gm_tls|SignCert|EncCert"` 仅命中结构体定义与 `config.yaml`），未被 `startServer`/TLS 初始化使用。
   - 真正用于 HTTPS 的是 `server.tls.cert_file/key_file` = `data/certs/server.crt`/`server.key`（`configs/config.yaml:8-9`），这两个文件**存在**（`ls -la data/certs/` → `server.crt`(668B)/`server.key`(227B)）。
   - 结论：`gm_tls.enabled=false`，即便 `/opt/opengm-ca/certs` 只有 `server.crt`/`server.key`（无 `server_sign/enc.*`）也不影响启动。

2. **OCSP responder 证书缺失——不阻塞**：
   - `configs/config.yaml:134` `ocsp.enabled: true`，证书路径 137-138 指向 `data/certs/ocsp_responder.crt/key`，实际 `data/certs/` 无此二文件。
   - `InitOCSPResponder` 读文件失败即返回错误（`internal/api/handler/ocsp.go:34-40`），但调用处仅 `log.Warn`（`cmd/ca-server/main.go:197-200`），非致命。

3. **端口 8443 空闲——无冲突**：`ss -ltnp` 仅见 `5432`（gaussdb pid 1137），无 8443 监听；无 ca-server 进程；无 systemd 单元（第二节证据已列）。

4. **日志输出路径——不阻塞**：`log.output: "stdout"`（`configs/config.yaml:161`），`file_path`（162）仅在 `output=file` 时使用（`cmd/ca-server/main.go:312-314`），故 `/var/log/opengm-ca/app.log` 可写性非启动必需。审计备份路径 `/var/log/opengm-ca/audit_backup.log` 在 `internal/service/audit.go:39` 硬编码，仅当审计队列写满时才落盘（worker 内），启动期不写；该目录 `drwxr-xr-x root root`，若以非 root 运行且发生满队列写盘会失败，属运行期隐患，非启动阻塞。

5. **数据目录与权限——条件项**：`data/` 及 `data/{ca_keys,certs,hsm}` 均为 `drwx------ root:root`（`ls -la data/` 输出）。以 **root** 运行无问题；若以 **omm**（uid 1000）运行则无法访问 `./data/hsm`（`main.go:133`）、`./data/certs`、`./data/ca_keys`（`main.go:156,445`）。当前 openGauss 由 `omm` 运行（`su - omm -c id` → `uid=1000(omm)`），但 ca-server 的运行用户未在 systemd 单元中指定（`opengm-ca.service` 无 `User=`，默认 root）。属需用户确认"以何用户运行"的条件项。

6. **主密钥/HSM 数据已存在**：`data/hsm/` 含 `.salt` 与 3 个 `.json` 密钥文件，`data/ca_keys/` 含 `openGM Root CA.key`、`SSL-CA.key`、`AUTH-CA.key`、`VPN-CA.key`（均 452B）。配合正确的 `CA_HSM_PASSWORD`/`CA_MASTER_KEY` 才可解密，口令值需用户提供且与历史运行一致。

## 五、最小启动清单（按顺序，**本任务不执行**）

> 口令以 `$VAR` 表示，实际值需用户提供/导出；以下命令仅为还原启动所需步骤，未在本次调查中执行。

```bash
# 0) 确认数据库运行中（现状：gaussdb 已监听 5432）
#    （已由 Hermes 实证，无需操作）

# 1) 构建二进制（阻塞 4）
cd /root/opengm-ca
make build-server            # 产出 build/opengm-ca

# 2) 注入环境变量（阻塞 1、2；DB_PASSWORD 真实值需用户提供）
export DB_PASSWORD='<需用户提供 ca_admin 口令>'
export JWT_SECRET='<与历史一致或重新生成，≥32 字节>'
export CA_MASTER_KEY='<与历史一致或 openssl rand -hex 32>'
export CA_HSM_PASSWORD='<与 data/hsm 历史一致的密码，需用户提供>'

# 3) 初始化 CA（若库中尚无对应表名下的根 CA 数据）
./build/opengm-ca -config ./configs/config.yaml -init-ca

# 4) 启动服务（工作目录必须是 /root/opengm-ca，因证书/HSM/密钥路径均为相对路径）
./build/opengm-ca -config ./configs/config.yaml
```

注意事项（均有代码依据）：
- 工作目录必须为 `/root/opengm-ca`：配置默认 `./configs/config.yaml`（`main.go:32`），TLS 证书 `data/certs/server.crt`（`configs/config.yaml:8-9`）、HSM `./data/hsm`（`main.go:133`）、CA 密钥 `./data/ca_keys`（`main.go:156,445`）均为相对路径。
- 若以非 root 运行，需先解决 `data/` 目录 `700 root:root` 权限（见非阻塞项 5）。
- `server.tls.enabled=true`（`configs/config.yaml:7`），`ensureTLSCerts` 会校验 `data/certs/server.crt/key` 存在，缺失即 fatal（`main.go:247-251,466-481`）；此二文件当前已存在。

---

## 修订记录

| 日期 | 修订人 | 内容 |
|---|---|---|
| 2026-09-06 | claude | 初版，列 4 个硬阻塞 |
| 2026-09-06 | Hermes（独立核验） | **推翻原阻塞 3「表名不一致」**：bun 不消费 `TableName()` 方法，反射推导实测 10/10 表名与库一致；阻塞数 4→3，原阻塞 4 顺位为阻塞 3；新增第四节第 0 条记录证伪过程与 `TableName()` 死代码技术债 |

**核验方法留档**：判定 ORM 表名不能只读模型代码里的 `TableName()`/注释，必须用该 ORM 自身的 schema API 反射推导并打印真实表名（本次用 `schema.NewTables(pgdialect.New()).Get(reflect.Type)`），再与 `pg_tables` 实际清单逐一比对。
