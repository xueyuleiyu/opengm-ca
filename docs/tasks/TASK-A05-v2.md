# TASK-A05 v2：CA 体系重建（A）+ 闸门有效性反证

## 任务范围

仅执行 **任务 A（CA 体系重建）** 和 **反证实验**。
**任务 C（防御性拦截）已于 commit `6c7e78a` 完成**，无需重复。

本任务书覆盖：A1 备份 / A2 清空重建 / A3 验证 / 反证实验。

---

## 前置（必须先做，不做不要进 A1）

### F1. 现状自查

`task-a05.md` 是 2026-09-06 写的，距今已 15 天。**先确认假设仍成立**：

```bash
cd /home/omm/opengm-ca

# 1. 数据库当前 ca_chains 行数（应为 4）
export $(grep -v '^#' .env | xargs)
DBP=$(grep DB_PASSWORD .env | cut -d= -f2)
DBU=$(grep DB_USER .env | cut -d= -f2)
DB=$(grep DB_NAME .env | cut -d= -f2)
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 \
  -c "SELECT ca_name, is_root, length(cert_pem) FROM ca_chains ORDER BY is_root DESC, ca_name;"

# 2. certificates 状态分布（task-a05.md 记的是 VALID 29 + REVOKED 13 = 42）
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 \
  -c "SELECT status, count(*) FROM certificates GROUP BY status;"

# 3. 4 个私钥文件 mtime（task-a05.md 记的是 2026-05-19 17:00:55）
ls -la data/ca_keys/

# 4. 解密 4 个私钥并 SHA256(MarshalPKIXPublicKey)[:24]，对比 ca_chains 证书公钥指纹
#    详见下方"配对状态检查"脚本
```

如果自查发现：
- ca_chains 行数 != 4
- certificates 分布变化（VALID 数不等于 29）
- 私钥 mtime 不是 2026-05-19
- 私钥公钥已和证书公钥配对

**立即停下来汇报，不要执行 A1/A2/A3**——状态假设已变，需要重写任务书。

### F2. 配对状态检查脚本（验收辅助）

`scripts/check_ca_pair.sh`（若不存在则新建）：

```bash
#!/bin/bash
set -e
cd "$(dirname "$0")/.."
export $(grep -v '^#' .env | xargs)

python3 <<'PYEOF'
import json, base64, hashlib, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_private_key, Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

master = bytes.fromhex(open(".env").read().split("CA_MASTER_KEY=")[1].split("\n")[0])
aes = AESGCM(master)

def fp(pubkey):
    der = pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:24]

print(f"{'CA name':<22} {'Cert FP':<26} {'Key FP':<26}  match")
print("-" * 90)

# ca_chains 用 gsql 提
import subprocess
DBP = open(".env").read().split("DB_PASSWORD=")[1].split("\n")[0]
DBU = open(".env").read().split("DB_USER=")[1].split("\n")[0]
DB = open(".env").read().split("DB_NAME=")[1].split("\n")[0]
sql = "SELECT ca_name, cert_pem FROM ca_chains ORDER BY is_root DESC, ca_name;"
out = subprocess.check_output(
    ["gsql", "-d", DB, "-U", DBU, "-W", DBP, "-h", "127.0.0.1", "-p", "5432",
     "-t", "-A", "-F", "|", "-c", sql]
).decode().strip().splitlines()

from cryptography import x509
for line in out:
    name, pem = line.split("|", 1)
    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    cert_fp = fp(cert.public_key())

    # 找对应私钥
    candidates = [f for f in os.listdir("data/ca_keys") if f.endswith(".key")]
    matched = False
    for kf in candidates:
        with open(f"data/ca_keys/{kf}") as f:
            d = json.load(f)
        nonce = base64.b64decode(d["nonce"])
        ct = base64.b64decode(d["ciphertext"])
        try:
            pt = aes.decrypt(nonce, ct, None)
            inner = json.loads(pt)
            # SM2 私钥 JSON 字段名按 ca-server 实际格式
            d_b64 = inner.get("D") or inner.get("d")
            if not d_b64:
                continue
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateNumbers
            d_int = int.from_bytes(base64.b64decode(d_b64), "big")
            # SM2 curve OID 1.2.156.10197.1.301
            # cryptography 库对 SM2 支持参差，可能需要走 getsm2 等
            # 若 library 不支持 SM2，本脚本会跑不通——fallback：用 openssl
            # 这里假设 library 支持；不支持则改为外部 openssl 调用
            raise NotImplementedError("SM2 support in cryptography lib is incomplete; use openssl instead")
        except Exception as e:
            sys.stderr.write(f"key {kf} decode failed: {e}\n")
            continue

    print(f"{name:<22} {cert_fp:<26} {'':26}  (key decode not implemented)")
PYEOF
```

> **重要**：上面 Python 脚本里 SM2 私钥解析是占位（cryptography 库对 SM2 支持参差）。如果脚本跑不通，**改用外部 `openssl` 命令** 完成 key decode + 指纹计算，或直接读取 ca-server 启动日志里的 `[SECURITY] 公钥指纹 xxx`。

### F3. 决定怎么干私钥指纹

**推荐做法**：把 `verifyCertKeyPair` 的内部函数（`internal/core/ca.go` 已实现的 `verifyCertKeyPair` + 公钥指纹计算函数）抽成可独立 import 的小工具，跑一次脚本输出所有 4 对指纹。这比重新发明轮子稳。

---

## A1. 备份（不可跳过）

### A1.1 命令

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 1. 数据库导出（ca_chains + certificates 全表）
BACKUP_DIR="/root/opengm-ca-backup-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"
DBP=$(grep DB_PASSWORD .env | cut -d= -f2)
DBU=$(grep DB_USER .env | cut -d= -f2)
DB=$(grep DB_NAME .env | cut -d= -f2)

# 用 gsql COPY 导出（比 pg_dump 简单）
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 \
  -c "COPY ca_chains TO '$BACKUP_DIR/ca_chains.csv' CSV HEADER;"
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 \
  -c "COPY certificates TO '$BACKUP_DIR/certificates.csv' CSV HEADER;"

# 2. 私钥目录整体复制
cp -a data/ca_keys "$BACKUP_DIR/ca_keys.bak.$(date +%s)"

# 3. 备份完整性自检：打印每个文件的字节数 + 行数
echo "=== 备份清单 ==="
ls -la "$BACKUP_DIR"
echo
echo "=== 行数 ==="
wc -l "$BACKUP_DIR"/*.csv 2>/dev/null
echo
echo "=== 私钥文件清单 ==="
ls -la "$BACKUP_DIR"/ca_keys.bak.*/
```

### A1.2 验收

- `$BACKUP_DIR` 不在仓库内（应在 `/root/` 或 `/home/omm/`）
- `$BACKUP_DIR` 内至少有：
  - `ca_chains.csv`（CSV，含 header）
  - `certificates.csv`（CSV，含 header）
  - `ca_keys.bak.<ts>/`（完整复制，含 4 个 .key）
- `ls -la "$BACKUP_DIR"` 输出贴进汇报
- `wc -l` 输出贴进汇报

### A1.3 红线

- **禁把 `$BACKUP_DIR` 放在仓库内**（会被 `git status` 误报）
- **禁 `rm` 原私钥后再备份**（先 cp 再 rm）
- **禁备份到 /tmp 或被自动清理的目录**

---

## A2. 清空 + 重建

### A2.1 清空（必须先备份再清空）

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 1. 把失配私钥移到备份目录（不 rm）
BACKUP_KEY_DIR="/root/opengm-ca-backup-<date>/ca_keys.mismatch"
mkdir -p "$BACKUP_KEY_DIR"
for f in data/ca_keys/*.key; do
  mv "$f" "$BACKUP_KEY_DIR/"
done
ls -la data/ca_keys/  # 应为空

# 2. 清表
DBP=$(grep DB_PASSWORD .env | cut -d= -f2)
DBU=$(grep DB_USER .env | cut -d= -f2)
DB=$(grep DB_NAME .env | cut -d= -f2)
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 -c "
TRUNCATE certificates CASCADE;
TRUNCATE ca_chains CASCADE;
"
gsql -d "$DB" -U "$DBU" -W "$DBP" -h 127.0.0.1 -p 5432 -c "SELECT count(*) FROM ca_chains; SELECT count(*) FROM certificates;"
# 两条 SELECT 应都返回 0
```

### A2.2 重建（执行 -init-ca）

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 1. 确保 build/ca-server 是最新的
make build  # 或 `go build -o build/ca-server ./cmd/ca-server/main.go`

# 2. 跑 -init-ca
./build/ca-server -config configs/config.yaml -init-ca 2>&1 | tee /tmp/init-ca.log
```

### A2.3 验收

- **ca_chains** 应有 4 行（1 ROOT + 3 INTERMEDIATE）
- **certificates** 仍 0 行（CA 证书是 ROOT/INTERMEDIATE，不进 certificates 表）
- **data/ca_keys/** 应有 4 个新 .key 文件
- **/tmp/init-ca.log** 应有"主密钥加载成功"+"4 个 CA 初始化成功"类日志
- 全部贴输出进汇报

### A2.4 红线

- **禁未备份就清空**
- **禁清表后 init-ca 失败又没回滚机制**（如失败应能 cp 备份恢复）
- **禁改 configs/config.yaml 的 ca: 段**（CA 配置应保持现状，除非用户额外要求）

---

## A3. 验证

### A3.1 配对验证

```bash
cd /home/omm/opengm-ca

# 跑 F3 决定的指纹脚本
./scripts/check_ca_pair.sh
```

**期望输出**：4 行，每行 `match: ✓`

### A3.2 服务启动

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 启动（注意：6c7e78a 已改 LoadFromDB 失败为 log.Fatal，
#   所以服务能启动本身就是 C 闸门有效的证据）
./build/ca-server -config configs/config.yaml > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 5

# 检查进程在
ps -p $SERVER_PID && echo "server alive"

# 检查 log 无 fatal/error
grep -iE "fatal|panic|error" /tmp/server.log || echo "no fatal/panic/error in log"
```

### A3.3 health 端点

```bash
curl -k -s -o /tmp/health.json -w "HTTP=%{http_code}\n" https://127.0.0.1:8443/health
cat /tmp/health.json | python3 -m json.tool
```

**期望**：`HTTP=200`，JSON 含 `"ca_initialized": true`

### A3.4 端到端签发一张证书（核心）

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 1. 登录拿 JWT（用 /root/login-credentials.txt 里的账号）
LOGIN=$(cat /root/login-credentials.txt)  # 用户名:口令 格式
USER=$(echo "$LOGIN" | cut -d: -f1)
PASS=$(echo "$LOGIN" | cut -d: -f2)

JWT=$(curl -k -s -X POST https://127.0.0.1:8443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. 申请证书（选一个子 CA，如 SSL-CA）
#    endpoint / payload 格式见 USER_MANUAL.md
curl -k -s -X POST https://127.0.0.1:8443/api/v1/certificates/enroll \
  -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_cn": "verify-test.example.com",
    "ca_name": "SSL-CA",
    "validity_days": 90,
    "key_algorithm": "SM2"
  }' -o /tmp/issued.pem

# 3. 解析返回的 PEM
openssl x509 -in /tmp/issued.pem -noout -text | head -40

# 4. 用 SSL-CA 证书验证签名
SSL_CA_PEM=$(gsql -d ... -c "SELECT cert_pem FROM ca_chains WHERE ca_name='SSL-CA';")
echo "$SSL_CA_PEM" > /tmp/ssl_ca.pem
openssl verify -CAfile /tmp/ssl_ca.pem /tmp/issued.pem
# 期望：`/tmp/issued.pem: OK`

# 5. 确认签名算法是 SM2-with-SM3（OID 1.2.156.10197.1.501）
openssl x509 -in /tmp/issued.pem -noout -text | grep -i "Signature Algorithm"
```

**期望**：
- `openssl verify` 返回 OK
- 签名算法显示 SM2 相关（OID 含 1.2.156.10197.1.501 或 SM3-with-SM2）

### A3.5 CRL 生成

```bash
# 触发一个子 CA 的 CRL 生成（endpoint 见 USER_MANUAL.md）
curl -k -s -X POST https://127.0.0.1:8443/api/v1/ca/SSL-CA/crl/generate \
  -H "Authorization: Bearer $JWT" -o /tmp/crl.pem

# 解析
openssl crl -in /tmp/crl.pem -noout -text | head -30

# 关键断言：没有 "doesn't match parent's PublicKey" 类错误
```

**期望**：CRL 生成成功，issuer 与 SSL-CA cert 一致

### A3.6 停止服务（清理）

```bash
kill $SERVER_PID 2>/dev/null
```

---

## A4. 反证实验（必做，C 闸门的最后验证）

这一步证明 commit `6c7e78a` 的 `log.Fatal` + `verifyCertKeyPair` 真的在工作。

### A4.1 命令

```bash
cd /home/omm/opengm-ca
export $(grep -v '^#' .env | xargs)

# 1. 先备份当前 SSL-CA.key（重建后的）
cp -a data/ca_keys/SSL-CA.key /tmp/SSL-CA.key.original

# 2. 用别的 CA 的私钥替换（任选一个不是 SSL-CA 的 .key）
#    推荐用 VPN-CA.key（确认当前 VPN-CA.key 不是 SSL-CA.key 的拷贝）
cp data_ca_keys/VPN-CA.key data/ca_keys/SSL-CA.key

# 3. 尝试启动服务（必须在后台短超时跑，因为预计会 fatal）
timeout 10 ./build/ca-server -config configs/config.yaml > /tmp/reverse.log 2>&1
echo "exit_code=$?"

# 4. 看错误信息是否符合预期
echo "=== /tmp/reverse.log ==="
cat /tmp/reverse.log
echo
echo "=== 关键断言 ==="
grep -E "SSL-CA.*证书与私钥不配对" /tmp/reverse.log && echo "✓ 闸门拦截生效" || echo "✗ 闸门未拦，C 没做到位"
grep -E "指纹 [0-9a-f]{16,}.*指纹 [0-9a-f]{16,}" /tmp/reverse.log && echo "✓ 错误带两侧指纹" || echo "✗ 错误信息缺指纹"

# 5. 还原 SSL-CA.key
cp /tmp/SSL-CA.key.original data/ca_keys/SSL-CA.key
chmod 600 data/ca_keys/SSL-CA.key
chown omm:dbgroup data/ca_keys/SSL-CA.key

# 6. 再次启动，应成功
./build/ca-server -config configs/config.yaml > /tmp/restored.log 2>&1 &
SERVER_PID=$!
sleep 5
ps -p $SERVER_PID > /dev/null && echo "✓ 还原后服务启动成功"
kill $SERVER_PID 2>/dev/null

# 7. 配对验证恢复
./scripts/check_ca_pair.sh
```

### A4.2 验收

| 步骤 | 期望 | 失败动作 |
|------|------|---------|
| 替换 SSL-CA.key 后启动 | 启动失败 / timeout 内退出 | 检查 main.go 的 log.Fatal 是否生效 |
| 错误信息含 "SSL-CA.*证书与私钥不配对" | 是 | 检查 verifyCertKeyPair 是否被调用 |
| 错误信息含**两个不同**的 16+ hex 指纹 | 是 | 检查 ca.go 的错误文案是否带指纹 |
| 还原后启动 | 成功 | 检查 cp 还原是否彻底 |
| 还原后 `git status --short` | 干净 | 不应有未提交修改（备份/还原不应改 git 跟踪的文件） |

### A4.3 红线

- **禁忘记备份 SSL-CA.key**（先 cp 才能 mv/cp 覆盖）
- **禁还原时用错文件**（cp 的源和目标反了会导致永久丢失）
- **禁把反证实验期间产生的日志/git 改动 commit 进仓库**

---

## 红线（贯穿 A1-A4）

1. **禁 `t.Skip` / `-short` 之外的跳过**
2. **禁空转断言**：只断言 `err != nil` / `err == nil` 不算完
3. **禁 `|| true`、`- ` 前缀、`2>/dev/null` 吞错误**
4. **禁调低 `COVERAGE_MIN`**（只许调高）
5. **禁为凑覆盖率删代码**
6. **禁改 `third_party/`、GOMODCACHE、数据库 GUC**
7. **口令只从环境变量 / `.env` 读**，禁硬编码进代码或提交
8. **备份目录必须在仓库外**，禁提交备份数据或私钥
9. **必须提交**，commit 用语义化前缀：
   - `chore(backup)` 或 `docs(backup)` — A1 备份（如有 commit 需要）
   - `chore(db)` — A2 清空（一般无 commit）
   - `fix(core)` 或 `feat(core)` — A2 重建（一般无新代码）
   - `test(core)` — A3/A4 验证（如新增脚本/测试）
   - A 与 C 已分开（A 全部一次提交或按 A1/A2/A3 拆多次提交）
10. **全量测试计数行必须贴进汇报**：`make verify` 和 `make verify-nodb` 各一份，含 total 覆盖率百分比

---

## 质检机制（三层）

### L1 — 脚本层（自动化）

执行 A3 后跑：

```bash
cd /home/omm/opengm-ca
make verify-nodb  # 单元测试全跑（不应有 DB 依赖），coverage 应 >= task-a05.md 设定阈值
make verify       # 全量测试（含 DB），如 openGauss 可用
```

`make verify-nodb` 必须返回 0；coverage 输出贴汇报。

### L2 — LLM 独立核验（由我执行）

任务完成后我会**独立跑一遍**：
1. F1 自查脚本（看数据库当前状态是否符合 A3 期望）
2. 反向构造失配（用 cp 制造 SSL-CA.key 错位再启动）—— **不破坏现状**，立即还原
3. 检查 git diff（不应有意外修改）
4. 阅读 `internal/core/ca.go` 的 `verifyCertKeyPair` 实现（确认仍存在）

### L3 — 人工终审（你）

L1 + L2 通过后给你看汇报，**你最终拍板**：
- 看汇报贴出的指纹对照表
- 看反证实验的"替换→失败→还原"三步输出
- 看 git log（确认 commit 合理）
- 看 /root/opengm-ca-backup-<date>/ 的备份清单

---

## 验收判据（每项必须通过）

| 项 | 判据 |
|----|------|
| F1 自查 | 4 个私钥 + 4 张证书失配状态已被脚本确认（或已修复） |
| A1 备份 | 备份目录存在且不在仓库内；清单完整 |
| A2 清空重建 | ca_chains=4, certificates=0, data/ca_keys/ 有 4 个新 .key |
| A3.1 配对 | 4 对全部 match ✓ |
| A3.2 服务启动 | 进程在、无 fatal/panic/error |
| A3.3 health | HTTP 200, ca_initialized=true |
| A3.4 端到端签发 | openssl verify OK, 签名算法是 SM2 |
| A3.5 CRL | 生成成功，issuer 一致 |
| A4 反证 | 替换 → 启动失败（错误带两侧指纹）→ 还原 → 启动成功 |
| L1 脚本 | make verify-nodb = 0，coverage 贴汇报 |
| L2 独立核验 | 我跑完三项检查无异常 |
| L3 人工终审 | 你看完汇报后无异议 |

---

## 汇报格式

完成后回复必须包含：

1. **每一步命令的实际输出**（不是"应该"，是"实际跑了，结果是"）
2. **A3.1 的 4 行配对表**（CA 名 + 两侧指纹 + match 列）
3. **A3.4 的 openssl verify 输出 + 签名算法 OID**
4. **A4 反证实验的三步输出**（替换前、失败、还原后）
5. **`make verify-nodb` 的 total + coverage 数字**
6. **`git log --oneline -5` 输出**
7. **backup 目录 `ls -la` 输出**

---

## 不要做的事

- 不要重新发明 `verifyCertKeyPair`（已在 6c7e78a 实现）
- 不要改 configs/config.yaml 的 ca: 段（除非用户明确要求）
- 不要碰 task-a05.md（v2 是新文件，不动 v1）
- 不要把备份放到 /tmp（会被自动清）
- 不要在没有完成 F1 自查就动手 A1