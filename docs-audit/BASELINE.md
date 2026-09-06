# 测试验收基线（BASELINE）

> 任务：TASK-A03（建立 make verify 验收基线 + 最简 CI）
> 建立日期：2026-09-06
> 基线 commit：`79b8baf09ab8537fefb25209dfc85f48c9434594`（本基线的测量对象；本文件随后续 commit 归档）

## 一、基线结论

- **服务可运行**：`https://127.0.0.1:8443/health` → HTTP 200，CA 已初始化。
- **测试全绿**：`make verify`（含数据库测试）全部通过，`make verify-nodb`（离线）全部通过。
- **完整覆盖率 24.0%**（任务书给出 23.9%，差异见下文实测表说明）。
- **CI**：新增 `.github/workflows/ci.yml`，跑 `make verify-nodb`。

## 二、覆盖率实测表

测量方式：`go test -count=1 -coverprofile=coverage.out ./...`（`DB_PASSWORD` 已从 `.env` 注入）。
总覆盖率取自 `go tool cover -func=coverage.out` 的 `total:` 行。

| 包 | 源码文件 | 测试文件 | 覆盖率 |
|---|---|---|---|
| `internal/hsm` | 2 | 1 | 72.0% |
| `internal/crypto` | 2 | 2 | 63.5% |
| `internal/core` | 5 | 3 | 24.5% |
| `internal/service` | 7 | 3 | 9.1% |
| `internal/api/middleware` | 2 | 1 | 4.5% |
| `internal/repository` | 8 | 1 | 4.2% |
| `internal/api/handler` | 11 | 0 | 无测试 |
| `internal/model` | 7 | 0 | 无测试 |
| `internal/config` | 1 | 0 | 无测试 |
| `internal/api` | 1 | 0 | 无测试 |
| `internal/metrics` | 1 | 0 | 无测试 |
| `cmd/ca-server` | 1 | 0 | 无测试 |
| `cmd/gen-certs` | 1 | 0 | 无测试 |

**总覆盖率：24.0%**。

> 与任务书差异说明：任务书给出 23.9%。本次在清理 staticcheck 报告的 3 处死代码
> （`ensureBackupDir` / `getCurrentUserID` / `DistributionPointName`）后实测为 24.0%
> —— 删除未覆盖的死代码使分母变小，覆盖率微升。除 `internal/core`（24.7%→24.5%）、
> `internal/service`（8.9%→9.1%）外，其余各包与任务书一致。

### 离线（-short）覆盖率

`make verify-nodb` 使用 `go test -short`，`internal/repository` 的数据库测试被跳过（该包覆盖率降为 0.0%），
总覆盖率降至 **23.3%**。该值仍高于阈值 23，但余量仅 0.3%，是当前最薄的一环，见第六节风险提示。

## 三、`make verify` 六项检查清单

`make verify` 串联以下检查，**任一失败即整体非零退出**：

| 顺序 | 目标 | 含义 |
|---|---|---|
| 0 | `check-db-env`（前置守卫） | `DB_PASSWORD` 未设置时立即失败并提示，不静默跳过数据库测试 |
| 1 | `fmt-check` | `gofmt -l`（只读，不自动改写），输出非空即失败 |
| 2 | `vet` | `go vet ./...` 静态检查 |
| 3 | `staticcheck` | `staticcheck ./...` 静态分析；未安装则自动 `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| 4 | `build` | 构建全部二进制（`ca-server` + `gen-certs`） |
| 5 | `test` | `go test -count=1 -coverprofile=coverage.out ./...`（禁用缓存，含数据库测试） |
| 6 | `coverage-gate` | 总覆盖率低于 `COVERAGE_MIN` 即失败 |

`make verify-nodb` 与 `verify` 相同，唯第 5 项改用 `go test -short`（`-short` 是唯一允许的 skip，仅跳过数据库测试）。

## 四、覆盖率阈值与调整原则

- 当前阈值：`COVERAGE_MIN ?= 23`（Makefile 变量，可命令行覆盖）。
- 依据：完整覆盖率实测 23.9%，阈值取 23，预留约 0.9% 的 gofmt/Go 版本级抖动余量。
- **调整原则：只允许调高，不允许调低。** 若确需调低，必须在本文件记录理由、审批人及日期。

## 五、测试空白清单与风险排序

按「出问题后果严重程度」排序（非按文件数）。`internal/api/handler` 的 11 个文件 0 测试，
意味着所有 HTTP 入参校验、权限判断、错误响应均无回归保护——对 CA 系统而言，
这是**签发、吊销、私钥导出、鉴权**接口的防线缺失，属最高风险。

### 最该先补测试的 3 个文件

1. **`internal/api/handler/certificate.go`**
   职责：`Enroll`（签发）、`Revoke`（吊销）、`Renew`（续期）、`List`/`Detail`（查询），
   以及 `validateCertEnrollRequest`（SAN/KeyUsage/Subject 字段长度等入参校验）。
   理由：这是 CA 的核心防线。签发/吊销接口一旦在校验或权限判断上出错，会直接导致
   越权签发证书或吊销失效，后果是「CA 的公信力被击穿」，风险最高。

2. **`internal/api/handler/auth.go`**
   职责：`Login`（登录）、`RefreshToken`、`InitDefaultAdmins`、角色权限映射
   （`getRolePermissions`）与口令强度校验（`validatePasswordStrength`）。
   理由：认证与授权是所有其它接口的前置防线。此处出现绕过或提权，等于把签发/吊销/
   私钥导出接口全部暴露给未授权者，后果与 certificate.go 同级。

3. **`internal/api/handler/key.go`**
   职责：私钥导出审批全流程 `CreateExportRequest` → `ApproveExportRequest`/
   `RejectExportRequest` → `ExecuteExportRequest`，以及 `Export` 直接导出。
   理由：私钥是 CA 最敏感的材料。审批流程或权限判断出错会导致私钥泄漏，且泄漏后
   无法撤销已泄露的私钥，只能吊销整批证书，代价极高。

### 其余空白（按严重度降序）

- `internal/api/handler/ocsp.go`、`crl.go`：吊销状态查询（OCSP/CRL）。出错会导致
  已吊销证书仍被判定为有效。
- `internal/api/handler/ca.go`：CA 链查询，权限判断缺失风险。
- `internal/service`（7 文件仅 8.9%）：签发/审批/审计业务逻辑，逻辑缺陷会向上传导到接口。
- `internal/repository`（8 文件仅 4.2%，且唯一测试依赖真实库）：SQL 正确性、权限过滤缺少保护。
- `internal/model`、`internal/config`、`internal/metrics`、`cmd/*`：相对低危，但同样无测试。

## 六、风险提示

- **-short 覆盖率余量薄**：`verify-nodb` 的总覆盖率 23.3% 仅比阈值 23 高 0.3%，
  CI 环境若与本地有微小差异可能贴线。后续补测试时应优先补 `internal/service` /
  `internal/api/handler` 的纯内存测试（不依赖数据库），以抬高 -short 模式下的覆盖率。
- **数据库测试口令来源**：数据库测试仅从环境变量 `DB_PASSWORD` 读取，进程不会自动加载
  `.env`；运行 `make verify` 前需 `set -a && . ./.env && set +a` 或显式 export。
