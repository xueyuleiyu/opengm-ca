# openGM-CA 代码优化执行计划

**执行日期**: 2026-05-18  
**执行范围**: 根据代码质量审计报告分阶段优化  
**执行目标**: 提升代码质量，减少冗余，修复逻辑错误  

---

## 第一阶段：修复高优先级问题（1周内）

### 1.1 重构过长函数

#### 问题函数列表

| 文件 | 函数 | 当前行数 | 目标行数 | 优先级 |
|------|------|---------|---------|--------|
| `internal/service/enrollment.go` | `EnrollCertificate` | 194行 | ≤50行 | 🔴 最高 |
| `internal/service/key_export.go` | `ExportKey` | 143行 | ≤50行 | 🔴 最高 |
| `internal/hsm/softhsm.go` | `GenerateKeyPair` | 101行 | ≤50行 | 🟠 高 |
| `internal/api/handler/auth.go` | `Login` | 101行 | ≤50行 | 🟠 高 |
| `internal/api/handler/auth.go` | `InitDefaultAdmins` | 101行 | ≤50行 | 🟠 高 |

#### 重构策略

**EnrollCertificate 函数重构**:
```go
// 拆分为以下子函数：
func (s *EnrollmentService) EnrollCertificate(...) (*model.CertificateResponse, error) {
    // 1. 验证和预处理
    if err := s.validateEnrollRequest(req); err != nil {
        return nil, err
    }
    
    // 2. 处理双证书模式
    if req.DualCertMode {
        return s.enrollDualCertificate(ctx, req, issuedBy, actorIP)
    }
    
    // 3. 处理CSR模式
    if req.CSRPEM != "" {
        return s.enrollFromCSR(ctx, req, issuedBy, actorIP)
    }
    
    // 4. 标准证书签发
    return s.enrollStandard(ctx, req, issuedBy, actorIP)
}
```

### 1.2 修复并发安全问题

#### 问题列表

| 文件 | 问题 | 修复方案 |
|------|------|---------|
| `internal/service/audit.go:79-91` | lastHash数据竞争 | 扩大锁保护范围 |
| `internal/api/handler/ocsp.go:23-30` | 全局变量并发访问 | 使用sync.Once |
| `internal/api/middleware/auth.go:163-166` | shards初始化问题 | 确保初始化完成 |

#### 修复示例

**OCSP全局变量修复**:
```go
var (
    ocspResponder     *ocspResponderState
    ocspResponderOnce sync.Once
    ocspResponderMu   sync.RWMutex
)

type ocspResponderState struct {
    key  *sm2.PrivateKey
    cert *smx509.Certificate
}

func getOCSPResponder() *ocspResponderState {
    ocspResponderMu.RLock()
    defer ocspResponderMu.RUnlock()
    return ocspResponder
}

func initOCSPResponder(key *sm2.PrivateKey, cert *smx509.Certificate) {
    ocspResponderOnce.Do(func() {
        ocspResponderMu.Lock()
        defer ocspResponderMu.Unlock()
        ocspResponder = &ocspResponderState{
            key:  key,
            cert: cert,
        }
    })
}
```

### 1.3 修复逻辑错误

#### 问题列表

| 文件 | 位置 | 问题 | 修复 |
|------|------|------|------|
| `internal/core/dual_cert.go` | 95-99行 | CA获取错误被忽略 | 添加错误处理 |
| `internal/service/scheduler.go` | 57-105行 | 多次数据库查询 | 优化为单次查询 |

### 1.4 修复MFA问题

**问题**: MFA未实现但允许启用，导致用户无法登录

**修复方案**:
```go
// 在用户更新接口中禁止启用MFA
func (h *OperatorHandler) Update(c *gin.Context) {
    // ...
    if req.MFAEnabled {
        c.JSON(http.StatusBadRequest, gin.H{
            "code": "FEATURE_NOT_AVAILABLE",
            "message": "MFA功能尚未实现，暂不支持启用",
        })
        return
    }
    // ...
}
```

---

## 第二阶段：解决中优先级问题（2周内）

### 2.1 消除代码重复

#### 重复代码统一

**创建公共文件**: `internal/core/keyusage.go`
```go
package core

import "crypto/x509"

// KeyUsageMap 密钥用法映射
var KeyUsageMap = map[string]x509.KeyUsage{
    "digitalSignature":  x509.KeyUsageDigitalSignature,
    "nonRepudiation":    x509.KeyUsageContentCommitment,
    "keyEncipherment":   x509.KeyUsageKeyEncipherment,
    "dataEncipherment":  x509.KeyUsageDataEncipherment,
    "keyAgreement":      x509.KeyUsageKeyAgreement,
    "certSign":          x509.KeyUsageCertSign,
    "crlSign":           x509.KeyUsageCRLSign,
    "encipherOnly":      x509.KeyUsageEncipherOnly,
    "decipherOnly":      x509.KeyUsageDecipherOnly,
}

// ExtKeyUsageMap 扩展密钥用法映射
var ExtKeyUsageMap = map[string]x509.ExtKeyUsage{
    "serverAuth":           x509.ExtKeyUsageServerAuth,
    "clientAuth":           x509.ExtKeyUsageClientAuth,
    "codeSigning":          x509.ExtKeyUsageCodeSigning,
    "emailProtection":      x509.ExtKeyUsageEmailProtection,
    "timeStamping":         x509.ExtKeyUsageTimeStamping,
    "ocspSigning":          x509.ExtKeyUsageOCSPSigning,
    "ipsecEndSystem":       x509.ExtKeyUsageIPSECEndSystem,
    "ipsecTunnel":          x509.ExtKeyUsageIPSECTunnel,
    "ipsecUser":            x509.ExtKeyUsageIPSECUser,
    "anyExtendedKeyUsage":  x509.ExtKeyUsageAny,
}
```

### 2.2 配置化硬编码值

**更新配置文件**: `configs/config.yaml`
```yaml
audit:
  queue_capacity: 5000
  backup_path: "/var/log/opengm-ca/audit_backup.log"

auth:
  max_login_fail: 5
  lock_duration: "30m"

rate_limit:
  shard_count: 8

hsm:
  pbkdf2_iterations: 600000

key_export:
  pbkdf2_iterations: 600000
  password_min_length: 12
```

### 2.3 改进错误处理

**统一错误处理模式**:
```go
// 创建 internal/errors/errors.go
package errors

import "fmt"

type CodeError struct {
    Code    string
    Message string
    Err     error
}

func (e *CodeError) Error() string {
    if e.Err != nil {
        return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
    }
    return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewCodeError(code, message string, err error) *CodeError {
    return &CodeError{
        Code:    code,
        Message: message,
        Err:     err,
    }
}
```

### 2.4 前端代码分离

**创建文件结构**:
```
web/
├── index.html
├── css/
│   └── main.css
└── js/
    ├── app.js
    ├── api.js
    └── utils.js
```

---

## 第三阶段：完成低优先级优化（1个月内）

### 3.1 引入前端框架

**建议**: 使用Vue.js 3 + Vite

**步骤**:
1. 初始化Vue项目
2. 迁移现有功能
3. 组件化重构

### 3.2 增加单元测试

**目标**: 测试覆盖率≥80%

**重点测试**:
- 核心业务逻辑
- 并发安全
- 错误处理

### 3.3 性能优化

**优化项**:
- 数据库查询优化
- 缓存机制
- 异步处理

---

## 测试计划

### 第一阶段测试

**测试范围**:
- 重构后的函数功能正确性
- 并发安全测试
- 逻辑错误修复验证
- MFA功能禁用验证

**测试方法**:
- 单元测试
- 集成测试
- 并发压力测试

### 第二阶段测试

**测试范围**:
- 代码重复消除验证
- 配置化功能测试
- 错误处理改进验证
- 前端功能测试

### 最终测试

**测试范围**:
- 全功能回归测试
- 性能测试
- 安全测试
- 兼容性测试

---

## 文档更新计划

### 需要更新的文档

1. **README.md**: 更新项目特性和使用说明
2. **CHANGELOG.md**: 记录所有优化变更
3. **SECURITY.md**: 更新安全相关内容
4. **USER_MANUAL.md**: 更新用户使用说明
5. **CODE_QUALITY_AUDIT_REPORT.md**: 更新审计结果

### 文档更新内容

- 记录所有优化项
- 更新代码示例
- 补充测试结果
- 更新性能指标

---

**执行计划创建时间**: 2026-05-18  
**计划执行人**: 华为云码道（CodeArts）代码智能体  
**计划版本**: v1.0
