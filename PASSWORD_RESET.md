# 密码重置记录

> ⚠️ **警告**: 本文件包含敏感信息，请妥善保管，并在使用后立即删除或加密存储。
> 生成时间: 2026-05-08

## Web 界面登录账号密码

以下账号密码已重置并更新到数据库，同时代码中的默认密码也已同步更新。

| 用户名 | 角色 | 新密码 | 说明 |
|--------|------|--------|------|
| `admin` | SYS_ADMIN | `SHCo7bLnx6nLc4hY` | 系统管理员（原 SUPER_ADMIN 已降级） |
| `sys_admin` | SYS_ADMIN | `iRqk5kj7WH9sBgMH` | 系统管理员（三员分立） |
| `sec_admin` | SEC_ADMIN | `wBqpVuGbqUuE6b2u` | 安全保密管理员 |
| `audit_admin` | AUDITOR | `pa9bUFV4B9gPvAJi` | 审计管理员 |

## 环境变量密码

以下环境变量密码**未**自动重置，请手动设置强密码：

| 变量名 | 当前状态 | 建议操作 |
|--------|----------|----------|
| `DB_PASSWORD` | 已从代码中移除硬编码，改为环境变量 | 设置强密码并配置到环境变量 |
| `JWT_SECRET` | 已从代码中移除硬编码，改为环境变量 | 使用 `openssl rand -hex 32` 生成 |
| `CA_MASTER_KEY` | 已从代码中移除硬编码，改为环境变量 | 使用 `openssl rand -hex 32` 生成 |
| `GS_PASSWORD` | 已从 docker-compose 中移除硬编码 | 设置强密码并在 .env 中配置 |

## 数据库连接信息

- 数据库: openGauss
- 主机: localhost:5432
- 数据库名: opengm_ca
- 数据库用户: ca_admin

## 清理范围

本次重置已执行以下清理：

1. ✅ 数据库 `operators` 表中 4 个账号的 `password_hash` 已更新为新的 bcrypt 哈希
2. ✅ `cmd/ca-server/main.go` 中的默认管理员密码哈希已更新
3. ✅ `internal/api/handler/auth.go` 中的三员默认密码已更新
4. ✅ `web/index.html` 登录页默认填充的账号密码已移除
5. ✅ `configs/config.yaml` 中的数据库密码已改为 `${DB_PASSWORD}` 环境变量引用
6. ✅ `deployments/docker/docker-compose.yml` 中的密码已改为环境变量引用
7. ✅ `scripts/init-db.sh` 中的默认密码哈希和提示已更新
8. ✅ `DEPLOYMENT.md` 中的服务器 SSH 密码、数据库密码、JWT 密钥等已删除或替换
9. ✅ `USER_MANUAL.md` 中的默认密码示例已删除或替换
10. ✅ `verify3.sh`、`verify_final.sh`、`remote_verify_final.sh`、`remote_deploy_final.sh`、`deploy2.sh`、`deploy3.sh`、`deploy4.sh`、`wsl-deploy.sh` 中的硬编码密码和 SSH 密钥已改为环境变量引用

## 后续建议

1. 首次登录后请立即修改所有账号密码
2. 配置 MFA（多因素认证）
3. 删除或加密本文件
4. 确保生产环境所有密码通过环境变量或密钥管理系统注入，不要在代码仓库中存储任何凭证
