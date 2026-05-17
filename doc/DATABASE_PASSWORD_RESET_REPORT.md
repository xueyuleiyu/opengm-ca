# 数据库密码重置与服务启动报告

**操作日期**: 2026-05-17  
**操作状态**: ✅ 成功  

---

## 一、操作摘要

### 总体评估

**数据库密码重置**: ✅ 成功  
**服务启动**: ✅ 成功  
**服务健康状态**: ✅ 健康  

### 操作统计

| 操作步骤 | 状态 | 说明 |
|---------|------|------|
| 检查数据库服务 | ✅ 成功 | openGauss运行正常 |
| 检查数据库配置 | ✅ 成功 | 配置正确 |
| 重置数据库密码 | ✅ 成功 | 密码已更新 |
| 验证数据库连接 | ✅ 成功 | 连接正常 |
| 启动项目服务 | ✅ 成功 | 服务运行中 |
| 验证服务状态 | ✅ 成功 | 服务健康 |

---

## 二、数据库密码重置

### 2.1 数据库信息

**数据库类型**: openGauss (PostgreSQL兼容)  
**数据库版本**: PostgreSQL 13.23  
**监听地址**: 0.0.0.0:5432  
**进程ID**: 25116

### 2.2 密码重置操作

**原密码**: `OpenGM@2026#DB`  
**新密码**: `OpenGM@2026#NewPass`

**重置命令**:
```sql
ALTER USER ca_admin WITH PASSWORD 'OpenGM@2026#NewPass';
```

**结果**: ✅ 密码重置成功

### 2.3 数据库验证

**用户验证**:
```sql
SELECT usename FROM pg_user WHERE usename='ca_admin';
-- 结果: ca_admin
```

**数据库验证**:
```sql
SELECT datname FROM pg_database WHERE datname='opengm_ca';
-- 结果: opengm_ca
```

**权限验证**:
```sql
GRANT ALL PRIVILEGES ON DATABASE opengm_ca TO ca_admin;
-- 结果: GRANT
```

**连接测试**:
```bash
gsql -d opengm_ca -p 5432 -U ca_admin -W 'OpenGM@2026#NewPass' -c "SELECT current_user, current_database();"
-- 结果: ca_admin | opengm_ca
```

**结果**: ✅ 数据库连接验证成功

---

## 三、服务启动

### 3.1 环境变量设置

**数据库密码**:
```bash
export DB_PASSWORD='OpenGM@2026#NewPass'
```

**JWT密钥**:
```bash
export JWT_SECRET='opengm-ca-jwt-secret-key-2026-very-strong-secret'
```

**说明**: JWT密钥长度必须≥32字节

### 3.2 服务启动命令

```bash
nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &
```

**进程信息**:
- PID: 35911
- 启动时间: 16:44:55
- 状态: 运行中

### 3.3 启动日志分析

**关键日志**:

1. **配置加载** ✅
   ```json
   {"level":"info","message":"配置文件加载成功"}
   ```

2. **数据库连接** ✅
   ```json
   {"level":"info","host":"localhost","port":5432,"dbname":"opengm_ca","user":"ca_admin","message":"数据库连接成功"}
   ```

3. **HSM初始化** ✅
   ```json
   {"level":"info","type":"SOFT_HSM","keys":1,"path":"./data/hsm","message":"HSM初始化完成"}
   ```

4. **CA链加载** ✅
   ```json
   {"level":"info","ca_count":4,"sub_cas":0,"message":"CA链从数据库加载完成"}
   ```

5. **HTTPS服务启动** ✅
   ```json
   {"level":"info","addr":"0.0.0.0:8443","message":"HTTPS服务启动中"}
   ```

**警告信息**:

1. **主密钥警告** ⚠️
   ```json
   {"level":"warn","message":"主密钥加载失败，私钥加密功能将不可用"}
   ```
   **影响**: 私钥加密功能不可用，但不影响基本功能

2. **SSL模式警告** ⚠️
   ```json
   {"level":"warn","ssl_mode":"prefer","message":"数据库连接未强制启用TLS"}
   ```
   **建议**: 生产环境应设置为 `require` 或 `verify-full`

---

## 四、服务验证

### 4.1 健康检查

**请求**:
```bash
curl -k https://localhost:8443/health
```

**响应**:
```json
{
  "code": "OK",
  "data": {
    "ca_initialized": true,
    "stats": {
      "active_certificates": 3,
      "expired_certificates": 0,
      "revoked_certificates": 1,
      "total_certificates": 4
    },
    "status": "healthy",
    "version": "1.0.0"
  }
}
```

**结果**: ✅ 服务健康

### 4.2 服务状态

| 指标 | 值 | 状态 |
|------|-----|------|
| 服务状态 | healthy | ✅ |
| CA初始化 | true | ✅ |
| 活跃证书 | 3 | ✅ |
| 已吊销证书 | 1 | ✅ |
| 过期证书 | 0 | ✅ |
| 总证书数 | 4 | ✅ |
| 版本 | 1.0.0 | ✅ |

---

## 五、配置文件说明

### 5.1 数据库配置

**配置文件**: `configs/config.yaml`

```yaml
database:
  driver: "opengauss"
  host: "localhost"
  port: 5432
  user: "ca_admin"
  password: "${DB_PASSWORD}"  # 从环境变量读取
  dbname: "opengm_ca"
  ssl_mode: "prefer"
```

**环境变量**:
- `DB_PASSWORD`: 数据库密码（必须设置）
- `JWT_SECRET`: JWT密钥（必须设置，≥32字节）

### 5.2 启动脚本建议

**创建启动脚本**: `/root/opengm-ca/start.sh`

```bash
#!/bin/bash

# 设置环境变量
export DB_PASSWORD='OpenGM@2026#NewPass'
export JWT_SECRET='opengm-ca-jwt-secret-key-2026-very-strong-secret'

# 启动服务
cd /root/opengm-ca
nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &

# 等待启动
sleep 3

# 验证服务
ps aux | grep opengm-ca | grep -v grep
curl -k https://localhost:8443/health
```

**使用方法**:
```bash
chmod +x /root/opengm-ca/start.sh
./start.sh
```

---

## 六、下次启动保证

### 6.1 启动前检查清单

- [x] 数据库服务运行中 (openGauss)
- [x] 数据库用户存在 (ca_admin)
- [x] 数据库存在 (opengm_ca)
- [x] 数据库密码正确
- [x] 环境变量已设置
- [x] 配置文件正确
- [x] 可执行文件存在

### 6.2 启动命令

**方式1: 直接启动**
```bash
export DB_PASSWORD='OpenGM@2026#NewPass'
export JWT_SECRET='opengm-ca-jwt-secret-key-2026-very-strong-secret'
nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &
```

**方式2: 使用启动脚本**
```bash
./start.sh
```

**方式3: systemd服务（推荐生产环境）**

创建服务文件: `/etc/systemd/system/opengm-ca.service`

```ini
[Unit]
Description=openGM-CA Certificate Authority
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/opengm-ca
Environment="DB_PASSWORD=OpenGM@2026#NewPass"
Environment="JWT_SECRET=opengm-ca-jwt-secret-key-2026-very-strong-secret"
ExecStart=/root/opengm-ca/build/opengm-ca -config /root/opengm-ca/configs/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

**使用systemd管理**:
```bash
# 启用服务
systemctl enable opengm-ca

# 启动服务
systemctl start opengm-ca

# 查看状态
systemctl status opengm-ca

# 查看日志
journalctl -u opengm-ca -f
```

---

## 七、安全建议

### 7.1 密码安全

**当前密码**: `OpenGM@2026#NewPass`

**建议**:
- ✅ 密码强度良好（包含大小写、数字、特殊字符）
- ⚠️ 建议定期更换密码（如每90天）
- ⚠️ 建议使用密码管理器存储

### 7.2 JWT密钥安全

**当前密钥**: `opengm-ca-jwt-secret-key-2026-very-strong-secret`

**建议**:
- ✅ 密钥长度足够（≥32字节）
- ⚠️ 建议使用随机生成的密钥
- ⚠️ 建议定期轮换密钥

**生成随机密钥**:
```bash
# 生成32字节随机密钥
openssl rand -base64 32
```

### 7.3 主密钥配置

**当前状态**: ⚠️ 主密钥未配置

**影响**: 私钥加密功能不可用

**建议**: 配置主密钥以启用私钥加密功能

**配置方法**:
```bash
# 生成主密钥（64字符hex）
export CA_MASTER_KEY=$(openssl rand -hex 32)
echo "主密钥: $CA_MASTER_KEY"
```

### 7.4 数据库SSL配置

**当前配置**: `ssl_mode: "prefer"`

**建议**: 生产环境设置为 `require` 或 `verify-full`

**修改配置**:
```yaml
database:
  ssl_mode: "require"  # 或 "verify-full"
```

---

## 八、故障排查

### 8.1 常见问题

**问题1: 数据库连接失败**

**症状**: `Invalid username/password`

**解决**:
```bash
# 检查密码
echo $DB_PASSWORD

# 重置密码
su - omm -c "gsql -d postgres -p 5432 -c \"ALTER USER ca_admin WITH PASSWORD '新密码';\""
```

**问题2: JWT密钥长度不足**

**症状**: `JWT密钥长度不足，至少需要32字节`

**解决**:
```bash
# 设置足够长的密钥
export JWT_SECRET='your-very-long-jwt-secret-key-at-least-32-bytes'
```

**问题3: 服务无法启动**

**症状**: 进程不存在

**解决**:
```bash
# 查看日志
tail -f logs/server.log

# 检查端口占用
netstat -tlnp | grep 8443

# 检查进程
ps aux | grep opengm-ca
```

### 8.2 日志查看

**查看服务日志**:
```bash
tail -f logs/server.log
```

**查看数据库日志**:
```bash
su - postgres -c "cat /var/lib/pgsql/data/log/*.log | tail -50"
```

---

## 九、总结

### ✅ 操作成功

**数据库密码重置**: ✅ 成功  
**服务启动**: ✅ 成功  
**服务健康**: ✅ 正常  

### 📊 服务状态

- **进程**: 运行中 (PID: 35911)
- **端口**: 8443 (HTTPS)
- **状态**: healthy
- **CA**: 已初始化
- **证书**: 4张（3张活跃，1张已吊销）

### 🔐 凭据信息

- **数据库用户**: ca_admin
- **数据库密码**: OpenGM@2026#NewPass
- **数据库名称**: opengm_ca
- **JWT密钥**: opengm-ca-jwt-secret-key-2026-very-strong-secret

### 💡 下次启动

**启动命令**:
```bash
export DB_PASSWORD='OpenGM@2026#NewPass'
export JWT_SECRET='opengm-ca-jwt-secret-key-2026-very-strong-secret'
nohup ./build/opengm-ca -config ./configs/config.yaml > logs/server.log 2>&1 &
```

**验证命令**:
```bash
curl -k https://localhost:8443/health
```

---

**操作人员**: 华为云码道（CodeArts）代码智能体  
**操作日期**: 2026-05-17  
**报告版本**: v1.0
