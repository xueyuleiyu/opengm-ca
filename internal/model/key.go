package model

import (
	"time"
)

// KeyType 密钥类型
type KeyType string

const (
	KeyTypeSignature  KeyType = "SIGNATURE"
	KeyTypeEncryption KeyType = "ENCRYPTION"
	KeyTypeRoot       KeyType = "ROOT"
)

// KeyAlgorithm 密钥算法
type KeyAlgorithm string

const (
	KeyAlgoSM2     KeyAlgorithm = "SM2"
	KeyAlgoRSA2048 KeyAlgorithm = "RSA2048"
	KeyAlgoRSA4096 KeyAlgorithm = "RSA4096"
	KeyAlgoEC256   KeyAlgorithm = "EC256"
	KeyAlgoEC384   KeyAlgorithm = "EC384"
)

// KeyStorageType 密钥存储类型
type KeyStorageType string

const (
	KeyStorageSoftware KeyStorageType = "SOFTWARE"
	KeyStorageHSM      KeyStorageType = "HSM"
	KeyStorageEscrow   KeyStorageType = "ESCROW"
	KeyStorageOffline  KeyStorageType = "OFFLINE"
)

// CertKey 密钥对领域模型
type CertKey struct {
	ID               int64          `bun:"id,pk,autoincrement" json:"id"`
	KeyID            string         `bun:"key_id,notnull,unique" json:"key_id"`
	KeyType          KeyType        `bun:"key_type,notnull" json:"key_type"`
	Algorithm        KeyAlgorithm   `bun:"algorithm,notnull" json:"algorithm"`
	PublicKeyPEM     string         `bun:"public_key_pem,notnull" json:"public_key_pem"`
	PublicKeyDER     []byte         `bun:"public_key_der" json:"public_key_der,omitempty"`
	PublicKeyHash    string         `bun:"public_key_hash,notnull" json:"public_key_hash"`
	StorageType      KeyStorageType `bun:"storage_type,notnull" json:"storage_type"`

	// 软件加密存储的私钥
	PrivateKeyEnc    []byte `bun:"private_key_enc" json:"-"` // JSON序列化时忽略
	PrivateKeySalt   []byte `bun:"private_key_salt" json:"-"`
	PrivateKeyNonce  []byte `bun:"private_key_nonce" json:"-"`
	PrivateKeyTag    []byte `bun:"private_key_tag" json:"-"`
	MasterKeyVersion int    `bun:"master_key_version,default:1" json:"master_key_version"`

	// 关联关系
	SubjectID *int   `bun:"subject_id" json:"subject_id,omitempty"`
	CertID    *int64 `bun:"cert_id" json:"cert_id,omitempty"`

	// 导出控制
	Exportable      bool       `bun:"exportable,default:false" json:"exportable"`
	ExportCount     int        `bun:"export_count,default:0" json:"export_count"`
	MaxExports      int        `bun:"max_exports,default:0" json:"max_exports"`
	LastExportAt    *time.Time `bun:"last_export_at" json:"last_export_at,omitempty"`
	ExportApprovers []string   `bun:"export_approvers,array" json:"export_approvers,omitempty"`

	// 生命周期
	CreatedAt      time.Time  `bun:"created_at,default:current_timestamp" json:"created_at"`
	ExpiresAt      *time.Time `bun:"expires_at" json:"expires_at,omitempty"`
	CreatedBy      string     `bun:"created_by,notnull" json:"created_by"`
	DeletedAt      *time.Time `bun:"deleted_at" json:"deleted_at,omitempty"`
	DeletionReason string     `bun:"deletion_reason" json:"deletion_reason,omitempty"`

	// 关联对象
	Subject     *Subject     `bun:"rel:belongs-to,join:subject_id=id" json:"subject,omitempty"`
	Certificate *Certificate `bun:"rel:belongs-to,join:cert_id=id" json:"certificate,omitempty"`
}

// TableName 返回表名
func (k *CertKey) TableName() string {
	return "cert_keys"
}

// CanExport 检查是否允许导出
func (k *CertKey) CanExport() bool {
	if !k.Exportable {
		return false
	}
	if k.MaxExports > 0 && k.ExportCount >= k.MaxExports {
		return false
	}
	if k.DeletedAt != nil {
		return false
	}
	return true
}

// RemainingExports 获取剩余导出次数
func (k *CertKey) RemainingExports() int {
	if !k.Exportable || k.MaxExports <= 0 {
		return -1 // 无限制
	}
	remaining := k.MaxExports - k.ExportCount
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IsSoftKey 是否为软件存储的密钥
func (k *CertKey) IsSoftKey() bool {
	return k.StorageType == KeyStorageSoftware || k.StorageType == KeyStorageEscrow
}

// KeyExportRequest 私钥导出请求
type KeyExportRequest struct {
	KeyID        string `json:"key_id" validate:"required"`
	ExportFormat string `json:"export_format" validate:"required,oneof=PKCS1 PKCS8 PEM"`
	Password     string `json:"password,omitempty"`
	Reason       string `json:"reason" validate:"required,min=10"`
}

// KeyExportResponse 私钥导出响应
type KeyExportResponse struct {
	KeyID            string     `json:"key_id"`
	PrivateKeyPEM    string     `json:"private_key_pem"`
	PublicKeyPEM     string     `json:"public_key_pem"`
	Algorithm        string     `json:"algorithm"`
	ExportedAt       time.Time  `json:"exported_at"`
	AuditLogID       string     `json:"audit_log_id"`
	RemainingExports *int       `json:"remaining_exports,omitempty"`
	Warning          string     `json:"warning"`
}
