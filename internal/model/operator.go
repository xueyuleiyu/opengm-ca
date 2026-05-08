package model

import "time"

// OperatorRole 操作员角色（等保2.0 三员管理）
type OperatorRole string

const (
	// RoleSysAdmin 系统管理员：负责系统配置、CA策略、证书策略
	RoleSysAdmin OperatorRole = "SYS_ADMIN"
	// RoleSecAdmin 安全保密管理员：负责用户管理、权限分配、密钥管理
	RoleSecAdmin OperatorRole = "SEC_ADMIN"
	// RoleAuditor 安全审计员：负责审计日志查看、日志完整性验证（只读）
	RoleAuditor OperatorRole = "AUDITOR"
	// RoleSuperAdmin 超级管理员：仅系统初始化使用，日常运营中应禁用
	RoleSuperAdmin OperatorRole = "SUPER_ADMIN"
)

// IsValidRole 检查角色是否合法
func IsValidRole(role OperatorRole) bool {
	switch role {
	case RoleSysAdmin, RoleSecAdmin, RoleAuditor, RoleSuperAdmin:
		return true
	}
	return false
}

// Operator 操作员领域模型
type Operator struct {
	ID             int          `bun:"id,pk,autoincrement" json:"id"`
	Username       string       `bun:"username,notnull,unique" json:"username"`
	PasswordHash   string       `bun:"password_hash,notnull" json:"-"`
	RealName       string       `bun:"real_name,notnull" json:"real_name"`
	Email          string       `bun:"email,notnull" json:"email"`
	Phone          string       `bun:"phone" json:"phone,omitempty"`
	Role           OperatorRole `bun:"role,default:'SYS_ADMIN'" json:"role"`
	Permissions    []string     `bun:"permissions,array" json:"permissions,omitempty"`
	IsActive       bool         `bun:"is_active,default:true" json:"is_active"`
	LastLoginAt    *time.Time   `bun:"last_login_at" json:"last_login_at,omitempty"`
	LastLoginIP    string       `bun:"last_login_ip" json:"last_login_ip,omitempty"`
	LoginFailCount int          `bun:"login_fail_count,default:0" json:"login_fail_count"`
	LockedUntil    *time.Time   `bun:"locked_until" json:"locked_until,omitempty"`
	MFAEnabled     bool         `bun:"mfa_enabled,default:false" json:"mfa_enabled"`
	MFASecret      string       `bun:"mfa_secret" json:"-"`
	CreatedAt      time.Time    `bun:"created_at,default:current_timestamp" json:"created_at"`
	UpdatedAt      time.Time    `bun:"updated_at,default:current_timestamp" json:"updated_at"`
	CreatedBy      *int         `bun:"created_by" json:"created_by,omitempty"`
}

// TableName 返回表名
func (o *Operator) TableName() string {
	return "operators"
}

// IsLocked 检查账户是否被锁定
func (o *Operator) IsLocked() bool {
	if o.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*o.LockedUntil)
}

// HasPermission 检查是否有指定权限
func (o *Operator) HasPermission(perm string) bool {
	// 超级管理员拥有所有权限
	if o.Role == RoleSuperAdmin {
		return true
	}
	// 检查显式权限
	for _, p := range o.Permissions {
		if p == perm || p == "*" {
			return true
		}
	}
	// 检查角色默认权限
	return checkRolePermission(o.Role, perm)
}

// CanManageOperators 检查是否可以管理操作员（系统管理员）
func (o *Operator) CanManageOperators() bool {
	return o.Role == RoleSysAdmin || o.Role == RoleSuperAdmin
}

// CanAudit 检查是否可以查看审计日志（审计管理员）
func (o *Operator) CanAudit() bool {
	return o.Role == RoleAuditor || o.Role == RoleSuperAdmin
}

// CanManageSystem 检查是否可以管理系统配置（系统管理员）
func (o *Operator) CanManageSystem() bool {
	return o.Role == RoleSysAdmin || o.Role == RoleSuperAdmin
}

// RoleDisplayName 角色显示名称
func (r OperatorRole) RoleDisplayName() string {
	switch r {
	case RoleSysAdmin:
		return "系统管理员"
	case RoleSecAdmin:
		return "安全保密管理员"
	case RoleAuditor:
		return "安全审计员"
	case RoleSuperAdmin:
		return "超级管理员"
	}
	return string(r)
}

// RoleDescription 角色描述
func (r OperatorRole) RoleDescription() string {
	switch r {
	case RoleSysAdmin:
		return "负责系统配置、CA策略管理、证书策略配置"
	case RoleSecAdmin:
		return "负责用户管理、权限分配、密钥管理、角色配置"
	case RoleAuditor:
		return "负责审计日志查看、日志完整性验证（只读权限）"
	case RoleSuperAdmin:
		return "超级管理员，仅用于系统初始化"
	}
	return ""
}

// 角色默认权限映射（等保2.0 权限分离）
func checkRolePermission(role OperatorRole, perm string) bool {
	rolePerms := map[OperatorRole][]string{
		RoleSysAdmin: {
			"SYSTEM_CONFIG", "USER_MANAGE", "CERT_READ", "AUDIT_READ",
		},
		RoleSecAdmin: {
			"CERT_ISSUE", "CERT_REVOKE", "CERT_RENEW",
			"CA_MANAGE", "CRL_GENERATE", "OCSP_MANAGE", "CERT_POLICY_MANAGE",
			"KEY_MANAGE", "KEY_EXPORT", "HSM_MANAGE",
			"CERT_READ",
		},
		RoleAuditor: {
			"AUDIT_READ", "AUDIT_VERIFY",
			"CERT_READ",
		},
		RoleSuperAdmin: {"*"},
	}
	perms, ok := rolePerms[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == "*" || p == perm {
			return true
		}
	}
	return false
}

// OperatorLoginRequest 登录请求
type OperatorLoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// OperatorLoginResponse 登录响应
type OperatorLoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	TokenType    string    `json:"token_type"`
	Operator     *Operator `json:"operator"`
}

// CreateOperatorRequest 创建操作员请求
type CreateOperatorRequest struct {
	Username  string       `json:"username" validate:"required,max=32"`
	Password  string       `json:"password" validate:"required,min=8,max=64"`
	RealName  string       `json:"real_name" validate:"required,max=64"`
	Email     string       `json:"email" validate:"required,email"`
	Phone     string       `json:"phone" validate:"omitempty,max=20"`
	Role      OperatorRole `json:"role" validate:"required"`
}

// UpdateOperatorRequest 更新操作员请求
type UpdateOperatorRequest struct {
	RealName   *string       `json:"real_name,omitempty" validate:"omitempty,max=64"`
	Email      *string       `json:"email,omitempty" validate:"omitempty,email"`
	Phone      *string       `json:"phone,omitempty" validate:"omitempty,max=20"`
	Role       *OperatorRole `json:"role,omitempty"`
	IsActive   *bool         `json:"is_active,omitempty"`
	Permissions []string      `json:"permissions,omitempty"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=64"`
}
