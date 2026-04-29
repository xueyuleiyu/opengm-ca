package model

import "time"

// OperatorRole 操作员角色
type OperatorRole string

const (
	RoleSuperAdmin  OperatorRole = "SUPER_ADMIN"
	RoleCAAdmin     OperatorRole = "CA_ADMIN"
	RoleOperator    OperatorRole = "OPERATOR"
	RoleAuditor     OperatorRole = "AUDITOR"
	RoleReadonly    OperatorRole = "READONLY"
)

// Operator 操作员领域模型
type Operator struct {
	ID              int        `bun:"id,pk,autoincrement" json:"id"`
	Username        string     `bun:"username,notnull,unique" json:"username"`
	PasswordHash    string     `bun:"password_hash,notnull" json:"-"`
	RealName        string     `bun:"real_name,notnull" json:"real_name"`
	Email           string     `bun:"email,notnull" json:"email"`
	Phone           string     `bun:"phone" json:"phone,omitempty"`

	Role            OperatorRole `bun:"role,default:'OPERATOR'" json:"role"`
	Permissions     []string     `bun:"permissions,array" json:"permissions,omitempty"`

	IsActive        bool       `bun:"is_active,default:true" json:"is_active"`
	LastLoginAt     *time.Time `bun:"last_login_at" json:"last_login_at,omitempty"`
	LastLoginIP     string     `bun:"last_login_ip" json:"last_login_ip,omitempty"`
	LoginFailCount  int        `bun:"login_fail_count,default:0" json:"login_fail_count"`
	LockedUntil     *time.Time `bun:"locked_until" json:"locked_until,omitempty"`

	MFAEnabled      bool       `bun:"mfa_enabled,default:false" json:"mfa_enabled"`
	MFASecret       string     `bun:"mfa_secret" json:"-"`

	CreatedAt       time.Time  `bun:"created_at,default:current_timestamp" json:"created_at"`
	UpdatedAt       time.Time  `bun:"updated_at,default:current_timestamp" json:"updated_at"`
	CreatedBy       *int       `bun:"created_by" json:"created_by,omitempty"`
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
	for _, p := range o.Permissions {
		if p == perm {
			return true
		}
	}
	// 角色默认权限
	return checkRolePermission(o.Role, perm)
}

func checkRolePermission(role OperatorRole, perm string) bool {
	rolePerms := map[OperatorRole][]string{
		RoleSuperAdmin: {"*"},
		RoleCAAdmin:    {"CERT_ISSUE", "CERT_REVOKE", "CERT_RENEW", "KEY_EXPORT", "CA_INIT", "CRL_GENERATE", "ADMIN_ACTION"},
		RoleOperator:   {"CERT_ISSUE", "CERT_REVOKE", "CERT_RENEW"},
		RoleAuditor:    {"AUDIT_READ", "AUDIT_VERIFY"},
		RoleReadonly:   {"CERT_READ", "AUDIT_READ"},
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
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	ExpiresIn    int        `json:"expires_in"`
	TokenType    string     `json:"token_type"`
	Operator     *Operator  `json:"operator"`
}
