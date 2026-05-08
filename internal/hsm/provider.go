package hsm

import (
	"crypto"
	"time"
)

// KeyInfo 密钥信息
type KeyInfo struct {
	Handle       string    `json:"handle"`
	Algorithm    string    `json:"algorithm"`
	KeyType      string    `json:"key_type"`
	CreatedAt    time.Time `json:"created_at"`
	PublicKeyPEM string    `json:"public_key_pem,omitempty"`
}

// Provider HSM 提供者接口
type Provider interface {
	GenerateKeyPair(algorithm string, keySize int, keyType string) (handle string, pubKey crypto.PublicKey, err error)
	Sign(handle string, digest []byte, hashAlgo string) ([]byte, error)
	GetPublicKey(handle string) (crypto.PublicKey, error)
	GetPublicKeyPEM(handle string) (string, error)
	DeleteKey(handle string) error
	ListKeys() ([]KeyInfo, error)
	ImportKey(algorithm string, privateKey interface{}, keyType string) (handle string, err error)
	ExportKey(handle string) (interface{}, error)
	GetKeyInfo(handle string) (*KeyInfo, error)
	Status() (*HSMStatus, error)
	Close() error
}

// HSMStatus HSM 状态
type HSMStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	KeyCount    int    `json:"key_count"`
	StoragePath string `json:"storage_path"`
}
