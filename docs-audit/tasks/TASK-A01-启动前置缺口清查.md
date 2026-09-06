# TASK-A01 启动前置缺口清查（只查不改）

| 项目 | 内容 |
|---|---|
| 状态 | 待执行 |
| 执行者 | claude（本项目唯一实现者，用户 2026-09-06 定） |
| 类型 | 摸底调查 |
| 红线 | **本任务只读不写**：禁止修改任何源码/配置/证书，禁止启动服务，禁止写入数据库 |

## 0. 背景（已由 Hermes 实证）

`/root/opengm-ca` 当前**未运行**：无 ca-server 进程、8443 无监听、无 systemd 单元；二进制已被清理（构建产物，预期删除）。
openGauss 运行中（pid 1137，5432），数据库 `opengm_ca` 存在。
`go build ./...` / `go vet` / `go test ./...` 均已验证通过（HEAD = afca06a）。

已发现两个疑似缺口，需你查实并补全清单：
- `configs/config.yaml` 数据库口令引用 `${DB_PASSWORD}`，但 `.env` 只有 `CA_MASTER_KEY` / `JWT_SECRET` / `CA_HSM_PASSWORD`，**无 DB_PASSWORD**；
- `config.yaml:13-16` 引用国密双证书 `/opt/opengm-ca/certs/server_{sign,enc}.{crt,key}`，实际该目录只有 `server.crt` / `server.key`。

## 1. 需要查清的问题（逐条给结论 + 证据行号）

### 1.1 配置项与环境变量的完整依赖清单
遍历 `configs/config.yaml` 与配置加载代码（`internal/config/`），列出**所有** `${VAR}` 形式的环境变量引用，并逐项标注：
- 变量名 / 在 config.yaml 的行号 / 是否在 `.env` 中已提供 / 缺失时的启动行为（panic？空值继续？有默认值？）

判定"缺失时行为"必须**读配置加载代码求证**（viper 的 `AutomaticEnv`/`SetDefault`/自定义展开逻辑），不要凭经验推断。

### 1.2 DB_PASSWORD 的真实来源
查清这个口令原本从哪来：是否在 `.env.example`、`DEPLOYMENT.md`、`docker-compose*.yml`、`scripts/` 下的部署脚本、systemd unit 模板、或历史提交里出现过。
若能找到**部署文档中记载的默认值或设置方式**，写明出处（文件:行号）。
**不要试图连接数据库或猜测口令**。

### 1.3 双证书配置是否为启动必需
读配置加载与 TLS 初始化代码（`cmd/ca-server/main.go` 的启动链、`internal/api/` 的 server 初始化），判定：
- `config.yaml:13-16` 那段国密双证书配置属于哪个开关下（是否有 `enabled: true/false` 之类的父级开关）；
- 该开关当前取值；
- 若开关开启但文件缺失，启动是 fail-fast 还是降级；给出对应代码行号。

### 1.4 数据库 schema 与代码模型的一致性
`opengm_ca` 库已存在（历史运行留下）。查：
- `runDBMigration`（`cmd/ca-server/main.go:~320`）注册的模型清单，与最近提交 `7467491` 新增的 `KeyExportRequestRecord` / `KeyExportApprovalRecord` 对应表**在库中是否已存在**；
- 若不存在，启动时自动迁移是否会创建（读代码判定 bun 的 `CreateTable IfNotExists` 语义）；
- **只读查询**：可用 `su - omm -c "gsql -d opengm_ca -c '\dt'"` 之类只读命令列表，禁止任何 DDL/DML。

### 1.5 其他启动前置
- 数据目录（`data/`、HSM 数据目录）是否存在、权限是否满足；
- 端口 8443（或配置中实际端口）是否被占用；
- 是否有 OCSP/CRL 相关文件路径依赖（`config.yaml:137-138` 提到 responder 证书）；
- 日志输出路径是否可写。

## 2. 交付物

在 `/root/opengm-ca/docs-audit/STARTUP-GAPS.md` 新建报告（**这是唯一允许写入的文件**），结构：

```markdown
# openGM-CA 启动前置缺口清单（2026-09-06）

## 一、结论摘要
（能否启动：能/不能；阻塞项数量；最小启动条件一句话）

## 二、环境变量依赖表
| 变量 | config.yaml 行号 | .env 是否提供 | 缺失时行为 | 证据（代码行号） |

## 三、阻塞项（必须解决才能启动）
（逐项：现象 / 根因 / 证据行号 / 需要什么才能解决 / 是否需要用户提供信息）

## 四、非阻塞项（可延后）

## 五、最小启动清单
（按顺序列出启动所需的确切步骤与命令，但**不执行**）
```

## 3. 禁令

- **禁止修改任何源码、配置、证书、数据库**（本任务是调查，不是修复）；
- 禁止启动 ca-server 或任何服务；
- 禁止执行 DDL/DML；只读查询可以；
- 禁止猜测或填写口令值；缺什么就写"需用户提供"；
- 禁止把"我认为应该是"写成结论——每条结论必须有文件:行号 或命令输出作为证据；
- 报告里不得出现任何口令、密钥明文（涉及则写 `[REDACTED]`）。
