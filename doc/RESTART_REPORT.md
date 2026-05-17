# 项目重启报告

**重启日期**: 2026-05-17  
**重启状态**: ⚠️ 数据库连接失败  

---

## 一、重启过程

### 1.1 停止服务

**操作**: 停止正在运行的opengm-ca服务

```bash
$ ps aux | grep opengm-ca | grep -v grep
root  25677  0.0  0.3 1246456 24524 ?  Sl  14:08  0:01 ./build/opengm-ca -config ./configs/config.yaml

$ kill 25677
```

**结果**: ✅ 服务已停止

---

### 1.2 重新编译

**操作**: 重新编译项目

```bash
$ go build -o build/opengm-ca ./cmd/ca-server
```

**结果**: ✅ 编译成功

---

### 1.3 启动服务

**操作**: 启动opengm-ca服务

```bash
$ mkdir -p logs
$ nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &
```

**结果**: ⚠️ 服务启动失败

---

## 二、启动失败原因

### 2.1 错误信息

```json
{
  "level": "fatal",
  "error": "数据库连接测试失败: failed to connect to `host=::1 port=5432 user=ca_admin database=opengm_ca`: server error pq: Invalid username/password,login denied. (DSN: host=localhost port=5432 user=ca_admin password=REDACTED dbname=opengm_ca sslmode=prefer)",
  "time": "2026-05-17T16:23:43+08:00",
  "message": "数据库连接失败"
}
```

### 2.2 问题分析

**问题**: 数据库认证失败

**原因**:
- 数据库用户名或密码不正确
- 配置文件中的数据库凭据与实际数据库不匹配

**影响**: 服务无法启动，无法连接到数据库

---

## 三、解决方案

### 方案1: 检查数据库配置

**步骤**:

1. 查看配置文件中的数据库配置
   ```bash
   cat configs/config.yaml | grep -A 10 database
   ```

2. 验证数据库连接
   ```bash
   psql -h localhost -U ca_admin -d opengm_ca
   ```

3. 如果密码错误，更新配置文件中的数据库密码

### 方案2: 重置数据库密码

**步骤**:

1. 连接到数据库（使用管理员账户）
   ```bash
   psql -h localhost -U postgres -d opengm_ca
   ```

2. 重置ca_admin用户密码
   ```sql
   ALTER USER ca_admin WITH PASSWORD 'new_password';
   ```

3. 更新配置文件中的密码
   ```yaml
   database:
     password: "new_password"
   ```

### 方案3: 检查数据库服务状态

**步骤**:

1. 检查PostgreSQL服务状态
   ```bash
   systemctl status postgresql
   ```

2. 如果服务未运行，启动服务
   ```bash
   systemctl start postgresql
   ```

---

## 四、配置文件检查

### 4.1 数据库配置项

**配置文件**: `configs/config.yaml`

**需要检查的配置项**:
```yaml
database:
  host: "localhost"
  port: 5432
  user: "ca_admin"
  password: "your_password"  # 需要确认
  dbname: "opengm_ca"
  sslmode: "prefer"
```

### 4.2 检查建议

1. **确认数据库用户存在**
   ```sql
   SELECT usename FROM pg_user WHERE usename = 'ca_admin';
   ```

2. **确认数据库存在**
   ```sql
   SELECT datname FROM pg_database WHERE datname = 'opengm_ca';
   ```

3. **测试连接**
   ```bash
   psql -h localhost -p 5432 -U ca_admin -d opengm_ca -c "SELECT 1;"
   ```

---

## 五、重启状态总结

| 步骤 | 状态 | 说明 |
|------|------|------|
| 停止服务 | ✅ 成功 | 服务已停止 |
| 重新编译 | ✅ 成功 | 编译无错误 |
| 启动服务 | ❌ 失败 | 数据库连接失败 |

**当前状态**: ⚠️ 服务未运行

**阻塞原因**: 数据库认证失败

---

## 六、下一步操作建议

### 立即操作

1. **检查数据库配置**
   ```bash
   cat configs/config.yaml
   ```

2. **验证数据库连接**
   ```bash
   psql -h localhost -U ca_admin -d opengm_ca
   ```

3. **修复数据库连接问题后重新启动**
   ```bash
   nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &
   ```

### 验证服务

修复数据库连接后，验证服务状态：

```bash
# 检查进程
ps aux | grep opengm-ca | grep -v grep

# 检查日志
tail -f logs/server.log

# 检查健康状态
curl -k https://localhost:8443/health
```

---

## 七、常见问题排查

### 问题1: 数据库用户不存在

**症状**: `role "ca_admin" does not exist`

**解决**:
```sql
CREATE USER ca_admin WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE opengm_ca TO ca_admin;
```

### 问题2: 数据库不存在

**症状**: `database "opengm_ca" does not exist`

**解决**:
```sql
CREATE DATABASE opengm_ca OWNER ca_admin;
```

### 问题3: 权限不足

**症状**: `permission denied for database opengm_ca`

**解决**:
```sql
GRANT ALL PRIVILEGES ON DATABASE opengm_ca TO ca_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ca_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ca_admin;
```

### 问题4: PostgreSQL服务未运行

**症状**: `connection refused`

**解决**:
```bash
systemctl start postgresql
systemctl enable postgresql
```

---

**重启人员**: 华为云码道（CodeArts）代码智能体  
**重启日期**: 2026-05-17  
**报告版本**: v1.0
