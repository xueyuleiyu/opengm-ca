package model

import (
	"time"
)

// CertificateStatus 证书状态
type CertificateStatus string

const (
	CertStatusValid      CertificateStatus = "VALID"
	CertStatusRevoked    CertificateStatus = "REVOKED"
	CertStatusExpired    CertificateStatus = "EXPIRED"
	CertStatusHold       CertificateStatus = "HOLD"
	CertStatusSuspended  CertificateStatus = "SUSPENDED"
)

// CertType 证书类型
type CertType string

const (
	CertTypeSSL      CertType = "SSL"
	CertTypeAuth     CertType = "AUTH"
	CertTypeVPNSign  CertType = "VPN_SIGN"
	CertTypeVPNEnc   CertType = "VPN_ENC"
	CertTypeSubCA    CertType = "SUB_CA"
)

// SignatureAlgorithm 签名算法
type SignatureAlgorithm string

const (
	AlgoSM2WithSM3       SignatureAlgorithm = "SM2WITHSM3"
	AlgoRSAWithSHA256    SignatureAlgorithm = "SHA256WITHRSA"
	AlgoRSAWithSHA384    SignatureAlgorithm = "SHA384WITHRSA"
	AlgoECDSAWithSHA256  SignatureAlgorithm = "ECDSAWITHSHA256"
	AlgoECDSAWithSHA384  SignatureAlgorithm = "ECDSAWITHSHA384"
)

// PublicKeyAlgorithm 公钥算法
type PublicKeyAlgorithm string

const (
	PubKeySM2    PublicKeyAlgorithm = "SM2"
	PubKeyRSA    PublicKeyAlgorithm = "RSA"
	PubKeyEC     PublicKeyAlgorithm = "EC"
)

// Certificate 证书领域模型
type Certificate struct {
	ID               int64              `bun:"id,pk,autoincrement" json:"id"`
	CertType         CertType           `bun:"cert_type,notnull" json:"cert_type"`
	CAID             int                `bun:"ca_id,notnull" json:"ca_id"`
	SerialNumber     string             `bun:"serial_number,notnull" json:"serial_number"`
	SerialNumberDec  string             `bun:"serial_number_dec" json:"serial_number_dec,omitempty"`
	CertPEM          string             `bun:"cert_pem,notnull" json:"cert_pem"`
	CertDER          []byte             `bun:"cert_der" json:"cert_der,omitempty"`
	CertHashSHA256   string             `bun:"cert_hash_sha256,notnull" json:"cert_hash_sha256"`
	SubjectDN        string             `bun:"subject_dn,notnull" json:"subject_dn"`
	IssuerDN         string             `bun:"issuer_dn,notnull" json:"issuer_dn"`
	SignatureAlg     SignatureAlgorithm `bun:"signature_alg,notnull" json:"signature_alg"`
	PublicKeyAlg     PublicKeyAlgorithm `bun:"public_key_alg,notnull" json:"public_key_alg"`
	PublicKeyPEM     string             `bun:"public_key_pem" json:"public_key_pem,omitempty"`
	PublicKeyHash    string             `bun:"public_key_hash" json:"public_key_hash,omitempty"`
	ValidFrom        time.Time          `bun:"valid_from,notnull" json:"valid_from"`
	ValidTo          time.Time          `bun:"valid_to,notnull" json:"valid_to"`
	Status           CertificateStatus  `bun:"status,default:'VALID'" json:"status"`
	RevokedAt        *time.Time         `bun:"revoked_at" json:"revoked_at,omitempty"`
	RevocationReason *int               `bun:"revocation_reason" json:"revocation_reason,omitempty"`
	CRLEntrySerial   string             `bun:"crl_entry_serial" json:"crl_entry_serial,omitempty"`
	Extensions       map[string]interface{} `bun:"extensions,type:jsonb" json:"extensions"`
	SubjectID        *int               `bun:"subject_id" json:"subject_id,omitempty"`
	KeyID            string             `bun:"key_id" json:"key_id,omitempty"`
	DualCertPairID   *int64             `bun:"dual_cert_pair_id" json:"dual_cert_pair_id,omitempty"`
	IssuedBy         string             `bun:"issued_by,notnull" json:"issued_by"`
	IssuedVia        string             `bun:"issued_via,default:'API'" json:"issued_via"`
	IssuedAt         time.Time          `bun:"issued_at,default:current_timestamp" json:"issued_at"`
	UpdatedAt        time.Time          `bun:"updated_at,default:current_timestamp" json:"updated_at"`

	// 关联对象(不存储)
	Subject     *Subject     `bun:"rel:belongs-to,join:subject_id=id" json:"subject,omitempty"`
	CA          *CAChain     `bun:"rel:belongs-to,join:ca_id=id" json:"ca,omitempty"`
	DualCertPair *Certificate `bun:"rel:belongs-to,join:dual_cert_pair_id=id" json:"dual_cert_pair,omitempty"`
}

// TableName 返回表名
func (c *Certificate) TableName() string {
	return "certificates"
}

// IsExpired 检查证书是否过期
func (c *Certificate) IsExpired() bool {
	return time.Now().After(c.ValidTo)
}

// IsActive 检查证书是否有效(未过期且未吊销)
func (c *Certificate) IsActive() bool {
	return c.Status == CertStatusValid && !c.IsExpired()
}

// GetSubjectAltNames 获取主题备用名称
func (c *Certificate) GetSubjectAltNames() []SubjectAltName {
	if c.Extensions == nil {
		return nil
	}
	sans, ok := c.Extensions["subject_alt_names"].([]interface{})
	if !ok {
		return nil
	}

	var result []SubjectAltName
	for _, v := range sans {
		if m, ok := v.(map[string]interface{}); ok {
			result = append(result, SubjectAltName{
				Type:  m["type"].(string),
				Value: m["value"].(string),
			})
		}
	}
	return result
}

// SubjectAltName 主题备用名称
type SubjectAltName struct {
	Type  string `json:"type"`  // dns | ip | email | uri
	Value string `json:"value"`
}

// CertificateRequest 证书申请请求
type CertificateRequest struct {
	CertType      string            `json:"cert_type" validate:"required,oneof=SSL AUTH VPN"`
	Algorithm     string            `json:"algorithm" validate:"required,oneof=SM2 RSA2048 RSA4096 EC256 EC384"`
	Subject       SubjectInfo       `json:"subject" validate:"required"`
	ValidityDays  int               `json:"validity_days" validate:"required,min=1,max=3650"`
	Extensions    CertExtensions    `json:"extensions,omitempty"`
	GenKeyLocally bool              `json:"gen_key_locally"`
	Exportable    bool              `json:"exportable"`
	DualCertMode  bool              `json:"dual_cert_mode,omitempty"`
	CSRPEM        string            `json:"csr_pem,omitempty"` // 如客户提供CSR
}

// SubjectInfo 证书主题信息
type SubjectInfo struct {
	CommonName         string `json:"common_name" validate:"required,max=128"`
	Organization       string `json:"organization,omitempty" validate:"max=128"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" validate:"max=128"`
	Country            string `json:"country,omitempty" validate:"len=2"`
	State              string `json:"state,omitempty" validate:"max=128"`
	Locality           string `json:"locality,omitempty" validate:"max=128"`
	Email              string `json:"email,omitempty" validate:"omitempty,email,max=128"`
	IDCardNumber       string `json:"id_card_number,omitempty" validate:"omitempty,len=18"`
	EmployeeID         string `json:"employee_id,omitempty" validate:"omitempty,max=32"`
	DeviceID           string `json:"device_id,omitempty" validate:"omitempty,max=64"`
	Department         string `json:"department,omitempty" validate:"omitempty,max=128"`
	VPNDomain          string `json:"vpn_domain,omitempty" validate:"omitempty,max=64"`
}

// CertExtensions 证书扩展
type CertExtensions struct {
	SubjectAltNames []SubjectAltName `json:"subject_alt_names,omitempty"`
	KeyUsage        []string         `json:"key_usage,omitempty" validate:"dive,oneof=digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement certSign crlSign encipherOnly decipherOnly"`
	ExtKeyUsage     []string         `json:"ext_key_usage,omitempty" validate:"dive,oneof=serverAuth clientAuth codeSigning emailProtection timeStamping ocspSigning ipsecEndSystem ipsecTunnel ipsecUser anyExtendedKeyUsage"`
}

// CertificateResponse 证书申请响应
type CertificateResponse struct {
	CertID        string            `json:"cert_id"`
	SerialNumber  string            `json:"serial_number"`
	SerialNumberDec string          `json:"serial_number_dec,omitempty"`
	CertPEM       string            `json:"cert_pem"`
	CertChainPEM  []string          `json:"cert_chain_pem"`
	PrivateKeyPEM *string           `json:"private_key_pem,omitempty"`
	KeyID         string            `json:"key_id,omitempty"`
	Algorithm     string            `json:"algorithm"`
	SubjectDN     string            `json:"subject_dn"`
	IssuerDN      string            `json:"issuer_dn"`
	IssuedAt      time.Time         `json:"issued_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	DualCerts     *DualCertResponse `json:"dual_certs,omitempty"`
}

// DualCertResponse 双证书响应
type DualCertResponse struct {
	SignCert CertKeyPair `json:"sign_cert"`
	EncCert  CertKeyPair `json:"enc_cert"`
}

// CertKeyPair 证书密钥对
type CertKeyPair struct {
	CertID          string `json:"cert_id"`
	SerialNumber    string `json:"serial_number"`
	CertPEM         string `json:"cert_pem"`
	KeyID           string `json:"key_id"`
	PrivateKeyPEM   string `json:"private_key_pem,omitempty"`
	KeyUsage        []string `json:"key_usage,omitempty"`
	ExtKeyUsage     []string `json:"ext_key_usage,omitempty"`
}
