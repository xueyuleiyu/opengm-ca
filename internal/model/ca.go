package model

import (
	"time"
)

// CAType CA类型
type CAType string

const (
	CATypeRoot          CAType = "ROOT"
	CATypeIntermediate  CAType = "INTERMEDIATE"
)

// CAChain CA证书链领域模型
type CAChain struct {
	ID            int            `bun:"id,pk,autoincrement" json:"id"`
	CAName        string         `bun:"ca_name,notnull,unique" json:"ca_name"`
	CAType        CAType         `bun:"ca_type,notnull" json:"ca_type"`
	ParentCAID    *int           `bun:"parent_ca_id" json:"parent_ca_id,omitempty"`
	CertPEM       string         `bun:"cert_pem,notnull" json:"cert_pem"`
	CertDER       []byte         `bun:"cert_der" json:"cert_der,omitempty"`
	SubjectDN     string         `bun:"subject_dn,notnull" json:"subject_dn"`
	IssuerDN      string         `bun:"issuer_dn,notnull" json:"issuer_dn"`
	SerialNumber  string         `bun:"serial_number,notnull" json:"serial_number"`
	Algorithm     string         `bun:"algorithm,notnull" json:"algorithm"`
	KeyID         string         `bun:"key_id,notnull" json:"key_id"`
	ValidFrom     time.Time      `bun:"valid_from,notnull" json:"valid_from"`
	ValidTo       time.Time      `bun:"valid_to,notnull" json:"valid_to"`
	IsActive      bool           `bun:"is_active,default:true" json:"is_active"`
	CRLDP         string         `bun:"crl_dp" json:"crl_dp,omitempty"`
	AIAURL        string         `bun:"aia_url" json:"aia_url,omitempty"`
	MaxPathLen    int            `bun:"max_path_len,default:-1" json:"max_path_len"`
	CreatedAt     time.Time      `bun:"created_at,default:current_timestamp" json:"created_at"`
	UpdatedAt     time.Time      `bun:"updated_at,default:current_timestamp" json:"updated_at"`

	// 关联对象
	ParentCA      *CAChain       `bun:"rel:belongs-to,join:parent_ca_id=id" json:"parent_ca,omitempty"`
	ChildCAs      []CAChain      `bun:"rel:has-many,join:id=parent_ca_id" json:"child_cas,omitempty"`
	Certificates  []Certificate  `bun:"rel:has-many,join:id=ca_id" json:"certificates,omitempty"`
}

// TableName 返回表名
func (c *CAChain) TableName() string {
	return "ca_chain"
}

// IsRoot 是否为根CA
func (c *CAChain) IsRoot() bool {
	return c.CAType == CATypeRoot
}

// IsValid 检查CA是否在有效期内
func (c *CAChain) IsValid() bool {
	now := time.Now()
	return c.IsActive && now.After(c.ValidFrom) && now.Before(c.ValidTo)
}

// CanIssueCertificates 是否可以签发终端实体证书
func (c *CAChain) CanIssueCertificates() bool {
	return c.IsValid() && c.CAType == CATypeIntermediate
}

// CAInitRequest CA初始化请求
type CAInitRequest struct {
	RootCA           RootCAInitConfig           `json:"root_ca" validate:"required"`
	IntermediateCAs  []IntermediateCAInitConfig `json:"intermediate_cas" validate:"required,min=1,dive"`
}

// RootCAInitConfig 根CA初始化配置
type RootCAInitConfig struct {
	Subject       SubjectInfo `json:"subject" validate:"required"`
	Algorithm     string      `json:"algorithm" validate:"required,oneof=SM2 RSA2048 RSA4096 EC256 EC384"`
	ValidityYears int         `json:"validity_years" validate:"required,min=10,max=30"`
	KeySize       int         `json:"key_size" validate:"required"`
}

// IntermediateCAInitConfig 中间CA初始化配置
type IntermediateCAInitConfig struct {
	CAName        string      `json:"ca_name" validate:"required,max=64"`
	Subject       SubjectInfo `json:"subject" validate:"required"`
	Algorithm     string      `json:"algorithm" validate:"required,oneof=SM2 RSA2048 RSA4096 EC256 EC384"`
	ValidityYears int         `json:"validity_years" validate:"required,min=5,max=20"`
	CertTypes     []string    `json:"cert_types" validate:"required,dive,oneof=SSL AUTH VPN_SIGN VPN_ENC"`
	MaxPathLen    int         `json:"max_path_len" validate:"min=-1,max=0"`
}

// CAInitResponse CA初始化响应
type CAInitResponse struct {
	RootCAID         int                       `json:"root_ca_id"`
	RootCertPEM      string                    `json:"root_cert_pem"`
	IntermediateCAs  []IntermediateCAResponse  `json:"intermediate_cas"`
}

// IntermediateCAResponse 中间CA响应
type IntermediateCAResponse struct {
	CAID     int    `json:"ca_id"`
	CAName   string `json:"ca_name"`
	CertPEM  string `json:"cert_pem"`
}
