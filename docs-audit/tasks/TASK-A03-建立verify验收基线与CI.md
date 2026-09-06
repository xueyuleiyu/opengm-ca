# TASK-A03 建立 make verify 验收基线 + 最简 CI

| 项目 | 内容 |
|---|---|
| 执行者 | claude（本项目唯一实现者） |
| 目标 | 把「当前可运行、测试全绿」这个状态钉成**可复现、可回归**的基线闸门 |
| 红线 | **不得为了让 verify 通过而降低标准**（禁止 skip、禁止调低阈值凑数、禁止 `|| true` 吞错误） |

## 0. 已实测的基线现状（Hermes 2026-09-06 测量，勿重新摸底）

**服务状态**：可运行。`https://127.0.0.1:8443/health` → HTTP 200，
`{"ca_initialized":true,"total_certificates":42,"active_certificates":30,"revoked_certificates":12,"status":"healthy"}`

**Makefile 已存在**（180 行，23 个 target）：
`all build build-server build-cli build-init clean test test-short coverage fmt vet lint mod docker docker-push install uninstall init-db init-ca run run-dev generate release help`

**CI：完全没有**（无 `.github/workflows/`、无 `.gitlab-ci.yml`、无 `Jenkinsfile`）

**真实覆盖率 23.9%**（`go test ./... -coverprofile`）：

| 包 | 源码文件 | 测试文件 | 覆盖率 |
|---|---|---|---|
| `internal/hsm` | 2 | 1 | 72.0% |
| `internal/crypto` | 2 | 2 | 63.5% |
| `internal/core` | 5 | 3 | 24.7% |
| `internal/service` | 7 | 3 | 8.9% |
| `internal/api/middleware` | 2 | 1 | 4.5% |
| `internal/repository` | 8 | 1 | 4.2% |
| **`internal/api/handler`** | **11** | **0** | **无测试** |
| **`internal/model`** | **7** | **0** | **无测试** |
| **`internal/config`** | **1** | **0** | **无测试** |
| `internal/api` | 1 | 0 | 无测试 |
| `internal/metrics` | 1 | 0 | 无测试 |
| `cmd/ca-server` | 1 | 0 | 无测试 |
| `cmd/gen-certs` | 1 | 0 | 无测试 |

**工具链**：`go` `gofmt` 有；`staticcheck` `golangci-lint` `gosec` **均未安装**（可出外网，`go install` 可用）

**数据库**：openGauss 6.0.3 原地运行，口令在 `.env` 的 `DB_PASSWORD`（`.env` 已被 gitignore，进程**不会**自动加载，需显式 export）

## 1. 任务一：`make verify` 闸门

在现有 Makefile 中新增 `verify` target，串联下列检查，**任一失败即整体失败**（非零退出码）：

1. `fmt-check` —— `gofmt -l` 输出非空即失败（**不要**用 `make fmt` 自动改写，CI 里必须是只读检查）
2. `vet` —— 复用现有 target
3. `staticcheck ./...` —— 若未安装则先 `go install honnef.co/go/tools/cmd/staticcheck@latest`
4. `build` —— 复用现有 target
5. `test` —— `go test ./... -count=1`（禁用缓存，保证真跑）
6. `coverage-gate` —— 总覆盖率**低于当前实测基线 23.9% 即失败**

### coverage-gate 要求

- 阈值定为 **23**（略低于实测 23.9，留 gofmt 级抖动余量），写成 Makefile 变量 `COVERAGE_MIN ?= 23` 便于后续调高
- 用 `go tool cover -func` 取 `total:` 行的百分比，与阈值比较；**用整数或定点比较，不要用 shell 浮点字符串比较**（`23.9` vs `9.5` 字符串比会出错）
- 失败时打印当前值与阈值，信息要能直接看懂

### 数据库依赖处理（关键）

`internal/repository/db_test.go` 需要真实数据库和 `DB_PASSWORD`。要求：

- `make verify` 默认**包含**数据库测试（这是本项目的价值所在，不能绕过）
- 若 `DB_PASSWORD` 未设置，`verify` 应**立即失败并给出明确提示**（如 `DB_PASSWORD 未设置，请先 export 或 source .env`），
  **不得**静默跳过或让测试 `t.Skip`
- 额外提供 `make verify-nodb` 变体，用 `go test -short` 跳过需要库的测试，供纯离线场景（CI 用它）
- 对应地：`db_test.go` 里需要库的测试应加 `if testing.Short() { t.Skip("需要数据库，-short 模式跳过") }`
  —— **这是唯一允许的 skip**，且必须仅由 `-short` 触发，不得因"环境缺失"自行跳过

## 2. 任务二：最简 CI

新建 `.github/workflows/ci.yml`：

- 触发：`push` 到任意分支 + `pull_request`
- 环境：`ubuntu-latest`，Go 版本与本地一致（**1.21.6**，从 `go.mod` 读或写死）
- 步骤：checkout → setup-go（带 module 缓存）→ `make verify-nodb`
- **不要**在 CI 里起 openGauss 容器（openGauss 官方镜像体积大、启动慢，且本项目单机定位）；
  数据库测试留给本地 `make verify`
- CI 里必须能看到覆盖率数字（把 `go tool cover -func` 的 total 行 echo 出来）
- 用 `actions/checkout@v4`、`actions/setup-go@v5`（不要用已废弃的 v2/v3）

## 3. 任务三：基线文档

新建 `docs-audit/BASELINE.md`，记录：

- 基线建立日期、当时的 commit hash
- 上面那张覆盖率表（**用你自己实测的数字，不要照抄本任务书**，若与本任务书不同以你实测为准并说明）
- `make verify` 的 6 项检查清单与各自含义
- 覆盖率阈值当前值与调整原则（只允许调高，不允许调低；调低需在文档记录理由）
- **测试空白清单与风险排序**：按"出问题的后果严重程度"排，不是按文件数排。
  例如 `internal/api/handler` 11 个文件 0 测试意味着所有 HTTP 入参校验、
  权限判断、错误响应都无回归保护 —— 对 CA 系统而言这是签发/吊销接口的防线缺失。
  给出你认为最该先补测试的 **3 个具体文件**及理由（要具体到文件名和它承担的职责）。

## 4. 顺带处理：未跟踪文件

工作区有 4 个未跟踪文件，按下列处置：

- `.env.bak.20260906140817` —— **含明文口令**，加入 `.gitignore`（规则 `/.env.bak.*`），**不提交**
- `docs-audit/`（含 `STARTUP-GAPS.md`、`BASELINE.md`）—— **提交**，这是审计留档
- `docs-audit-task.md`、`task-a02.md` —— 任务书，移动到 `docs-audit/tasks/` 下并提交
  （重命名为 `TASK-A01-启动前置缺口清查.md`、`TASK-A02-驱动修复与死代码清理.md`）

## 5. 验收（硬性，缺一不可）

必须在汇报中贴出**真实输出**：

1. `make verify` 完整输出（带 `DB_PASSWORD`），最后必须是成功
2. `make verify` 在**故意制造失败**时确实拦得住 —— 做一次反证：
   临时把某个 go 文件格式弄乱（如多加空行）或临时把 `COVERAGE_MIN` 设为 99，
   确认 `make verify` **非零退出**并打印可读原因，然后还原。贴出这次失败输出和还原确认。
   **这一步不能省** —— 只证明"能通过"不算基线，必须证明"能拦住"。
3. `make verify-nodb` 完整输出
4. `go tool cover -func` 的 `total:` 行实测值
5. `git status --short` 显示工作区干净（除 `.env.bak.*` 被忽略）

## 6. 禁令

- 禁止用 `|| true`、`- ` 前缀（make 忽略错误）、`2>/dev/null` 等手法吞掉失败
- 禁止为了让 verify 通过而删测试、加 skip、调低阈值
- 禁止 `t.Skip` —— 唯一例外是 `-short` 模式下跳过数据库测试
- 禁止提交 `.env`、`.env.bak.*` 或任何含口令的文件；口令一律从环境变量读
- 禁止在 CI 配置里写死任何口令或密钥
- 禁止改动 `third_party/` 下的驱动 fork（已验证可用，与本任务无关）
- 提交信息中文，格式 `chore(ci): ...` / `docs: ...`，可分多个 commit
