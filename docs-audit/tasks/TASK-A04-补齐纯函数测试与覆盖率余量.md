# TASK-A04 补齐纯函数单元测试，做出覆盖率安全余量

| 项目 | 内容 |
|---|---|
| 执行者 | claude（本项目唯一实现者） |
| 目标 | 让 `make verify-nodb`（CI 走的那条）覆盖率**从 23.3% 提到 ≥ 30%**，脱离贴线状态 |
| 前置 | 服务在跑、`make verify` 当前 6 项全过、`-short` 23.3% / 完整 24.0% |

---

## 一、为什么做这件事（背景，别改错方向）

CI 跑的是 `make verify-nodb`（`-short`，跳过数据库测试），实测覆盖率 **23.3%**，闸门阈值 **23** —— 余量只有 **0.3 个百分点**。任何人删几行测试或加一批新代码，CI 立刻变红，且红的原因跟他的改动无关。这是个假警报制造机。

**解决方向只能是把真实覆盖率做上去，严禁调低 `COVERAGE_MIN`。**

---

## 二、现状实测数据（我方已测，不要重新调查）

`internal/service` 包完整模式覆盖率 **9.1%**，包内**唯一**非零函数：

```
enrollment.go:541  validatePublicKeyStrength  77.8%
```

三个已有测试文件（`audit_test.go` / `enrollment_test.go` / `key_export_test.go`）**都真实运行且通过**，没有被 skip —— 它们只是覆盖面极窄。**不要去"解封"它们，没有东西被封。**

`-short` 下 0% 覆盖函数最集中的文件：

| 文件 | 0% 函数数 |
|---|---|
| internal/core/ca.go | 15 |
| internal/repository/operator_repo.go | 13 |
| internal/service/operator.go | 11 |
| internal/repository/key_export_repo.go | 11 |
| internal/service/key_export.go | 10 |

---

## 三、任务：只补纯函数/近纯函数测试

**硬约束：新增测试必须在 `-short` 模式下运行（不得依赖数据库、不得依赖 HSM 硬件、不得依赖网络）。** 这是本任务的全部意义 —— 提升的必须是 CI 那条路径的覆盖率。

按价值排序，以下是我方已确认的纯函数清单（行号实测）：

### 优先级 1：安全关键且零测试

| 目标 | 位置 | 为什么优先 |
|---|---|---|
| `ValidatePasswordPolicy` | `internal/service/password.go`（全文件 36 行） | 统一口令强度校验，**全仓无任何测试**（已 grep 确认）。口令策略失效 = 弱口令进系统 |
| `AuditLog.ComputeHash` | `internal/model/audit.go:106` | 审计哈希链的核心。链断 = 审计不可信 = 合规失效 |

`ComputeHash` 的测试必须包含：
- 相同输入产生相同哈希（确定性）
- **任一字段变化都导致哈希变化**（逐字段扰动，这是防篡改的本质）
- `prevHash` 参与计算（传不同 prevHash 得不同结果）
- 链式验证：三条记录串成链，改中间一条则后续校验失败

### 优先级 2：证书解析路径（CA 的核心输入面）

| 目标 | 位置 |
|---|---|
| `extractSubjectFromCSR` | `internal/service/enrollment.go:412`（包级函数，无 receiver 依赖） |
| `parseCSR` | `internal/service/enrollment.go:382` |
| `validateRequest` | `internal/service/enrollment.go:274` |
| `encodePrivateKey` | `internal/service/enrollment.go:377` |

`parseCSR` / `validateRequest` 必须有**负向用例**：畸形 PEM、空 CSR、签名不匹配的 CSR、缺 CN 的 subject、非法算法名。只测 happy path 不算完成。

### 优先级 3：密钥导出的口令与加密

| 目标 | 位置 |
|---|---|
| `verifyPassword` | `internal/service/key_export.go:341` |
| `encryptPrivateKeyWithPassword` | `internal/service/key_export.go:346` |

`encryptPrivateKeyWithPassword` 必须验证：加密结果**可解密回原文**（回环测试），且**错误口令解密必须失败**。只断言"返回了非空字符串"不算测试。

### 优先级 4：审计服务的非 DB 路径

| 目标 | 位置 | 注意 |
|---|---|---|
| `BackupFilePath` | `internal/service/audit.go:177` | 一行 getter，顺手 |
| `writeToBackup` | `internal/service/audit.go:136` | **用 `t.TempDir()` 造临时路径，禁止写 `/var/log/`** |

`writeToBackup` 当前硬编码 `/var/log/opengm-ca/audit_backup.log`（`audit.go:36`）。若为了可测性需要让路径可注入，**允许**改成可配置（`config.go:273` 已有 `audit.backup_path` 默认值可用），但：
- 必须保持默认行为不变（默认仍是 `/var/log/opengm-ca/audit_backup.log`）
- 改动要最小，不许顺手重构 AuditService 的其他部分

---

## 四、红线（违反即打回）

1. **禁止调低 `COVERAGE_MIN`**，也禁止改 `coverage-gate` 的判定逻辑；
2. **禁止 `t.Skip` / `t.Skipf`**（`db_test.go` 里已有的那个 `testing.Short()` 守卫除外，不要碰它）；
3. **禁止空转断言**：不许只断言 `err == nil` 或 `!= ""` 就算测过。每个测试必须断言**具体的值或具体的失败原因**；
4. **禁止为了数字删除或简化现有代码**；
5. **禁止改 `third_party/`**；
6. **禁止新增测试依赖数据库/HSM/网络**（否则 `-short` 下不跑，本任务白做）；
7. 口令类测试用例里的口令值随便写，但**不得从 `.env` 读真实口令写进测试文件**；
8. **禁止改 `internal/` 下的业务逻辑来"方便测试"**，唯一例外是上面第四优先级明确允许的 `backupFile` 路径可注入。

---

## 五、验收标准（每条都要在汇报里给出证据）

1. `make verify` **exit 0**，贴出完整 6 项输出与 `total: (statements) XX.X%` 行；
2. `make verify-nodb` **exit 0**，且 `total` **≥ 30.0%**，贴出该行；
3. 贴出 `go test -short -count=1 -v ./internal/service/ ./internal/model/` 的 `--- PASS` 列表（证明新测试真在 `-short` 下运行）；
4. 贴出 `go tool cover -func=coverage.out | grep -E "ValidatePasswordPolicy|ComputeHash|parseCSR|extractSubjectFromCSR|verifyPassword|encryptPrivateKeyWithPassword"` 的覆盖率行（证明目标函数真被覆盖）；
5. **反证实验**：随便挑一个新增测试，故意把被测函数的返回值改错（如让 `ValidatePasswordPolicy` 永远返回 nil），确认对应测试**失败**，贴出失败输出，然后还原。这一步证明测试有判别力、不是恒真断言；
6. `git status --short` 干净；
7. `grep -rn "t.Skip" internal/ --include=*_test.go` 输出只有 `db_test.go` 那一处。

## 六、提交

按性质分 commit，中文 message：
- `test(service): 补充口令策略与证书解析纯函数单元测试`
- `test(model): 补充审计哈希链完整性测试`
- 若改了 backupFile 可注入：`refactor(audit): 备份文件路径改为可注入以支持测试`（单独一个 commit）

完成后在汇报里明确回答：**新增了多少个测试函数、覆盖率从 23.3% 提到了多少、有没有为了数字妥协过任何断言。**
