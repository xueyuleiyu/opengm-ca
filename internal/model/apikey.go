package model

import "time"

// APIKey API密钥领域模型
type APIKey struct {
	ID              int64      `bun:"id,pk,autoincrement" json:"id"`
	KeyID           string     `bun:"key_id,notnull,unique" json:"key_id"`
	KeyHash         string     `bun:"key_hash,notnull" json:"-"`
	Name            string     `bun:"name,notnull" json:"name"`
	Permissions     []string   `bun:"permissions,array" json:"permissions"`

	ValidFrom       time.Time  `bun:"valid_from,default:current_timestamp" json:"valid_from"`
	ValidTo         *time.Time `bun:"valid_to" json:"valid_to,omitempty"`
	RateLimit       int        `bun:"rate_limit,default:100" json:"rate_limit"`
	IPWhitelist     []string   `bun:"ip_whitelist,array" json:"ip_whitelist,omitempty"`

	IsActive        bool       `bun:"is_active,default:true" json:"is_active"`
	RevokedAt       *time.Time `bun:"revoked_at" json:"revoked_at,omitempty"`
	RevokedBy       *int       `bun:"revoked_by" json:"revoked_by,omitempty"`

	LastUsedAt      *time.Time `bun:"last_used_at" json:"last_used_at,omitempty"`
	LastUsedIP      string     `bun:"last_used_ip" json:"last_used_ip,omitempty"`
	UseCount        int64      `bun:"use_count,default:0" json:"use_count"`

	CreatedAt       time.Time  `bun:"created_at,default:current_timestamp" json:"created_at"`
	CreatedBy       int        `bun:"created_by,notnull" json:"created_by"`
}

// TableName 返回表名
func (a *APIKey) TableName() string {
	return "api_keys"
}

// IsValid 检查API Key是否有效
func (a *APIKey) IsValid(clientIP string) bool {
	if !a.IsActive || a.RevokedAt != nil {
		return false
	}
	if a.ValidTo != nil && time.Now().After(*a.ValidTo) {
		return false
	}
	if len(a.IPWhitelist) > 0 {
		found := false
		for _, ip := range a.IPWhitelist {
			if ip == clientIP {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// HasPermission 检查是否有指定权限
func (a *APIKey) HasPermission(perm string) bool {
	for _, p := range a.Permissions {
		if p == "*" || p == perm {
			return true
		}
	}
	return false
}

// SystemConfig 系统配置模型
type SystemConfig struct {
	ID          int    `bun:"id,pk,autoincrement" json:"id"`
	ConfigKey   string `bun:"config_key,notnull,unique" json:"config_key"`
	ConfigValue string `bun:"config_value,notnull" json:"config_value"`
	ConfigType  string `bun:"config_type,default:'STRING'" json:"config_type"`
	Description string `bun:"description" json:"description,omitempty"`
	IsEncrypted bool   `bun:"is_encrypted,default:false" json:"is_encrypted"`
	UpdatedAt   time.Time `bun:"updated_at,default:current_timestamp" json:"updated_at"`
	UpdatedBy   *int   `bun:"updated_by" json:"updated_by,omitempty"`
}

// TableName 返回表名
func (s *SystemConfig) TableName() string {
	return "system_config"
}
