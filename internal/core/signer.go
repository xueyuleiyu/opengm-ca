package core

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/x509"
)

// Signer 统一签名接口
type Signer interface {
	// Sign 对数据签名
	Sign(data []byte) ([]byte, error)
	// SignDigest 对预计算哈希签名
	SignDigest(digest []byte) ([]byte, error)
	// PublicKey 返回公钥
	PublicKey() crypto.PublicKey
	// Algorithm 返回签名算法标识
	Algorithm() x509.SignatureAlgorithm
}

// SM2Signer SM2签名器
type SM2Signer struct {
	PrivateKey *sm2.PrivateKey
}

// NewSM2Signer 创建SM2签名器
func NewSM2Signer(privKey *sm2.PrivateKey) *SM2Signer {
	return &SM2Signer{PrivateKey: privKey}
}

// Sign 使用SM2签名(自动做SM3哈希)
func (s *SM2Signer) Sign(data []byte) ([]byte, error) {
	return s.PrivateKey.Sign(nil, data, nil)
}

// SignDigest 对SM3摘要签名
func (s *SM2Signer) SignDigest(digest []byte) ([]byte, error) {
	// SM2签名需要一个随机数源和UserID，这里使用默认UserID
	return s.PrivateKey.Sign(nil, digest, &sm2.SignOpts{
		Hash: sm3.New(),
		UID:  defaultSM2UID(),
	})
}

// PublicKey 返回SM2公钥
func (s *SM2Signer) PublicKey() crypto.PublicKey {
	return &s.PrivateKey.PublicKey
}

// Algorithm 返回签名算法
func (s *SM2Signer) Algorithm() x509.SignatureAlgorithm {
	return x509.SM2WithSM3
}

// HashFunc 返回哈希函数
func (s *SM2Signer) HashFunc() hash.Hash {
	return sm3.New()
}

// defaultSM2UID 返回默认SM2 UserID
func defaultSM2UID() []byte {
	// 国密标准默认UID: 1234567812345678
	return []byte("1234567812345678")
}

// SignerFactory 签名器工厂
type SignerFactory struct{}

// NewSignerFactory 创建签名器工厂
func NewSignerFactory() *SignerFactory {
	return &SignerFactory{}
}

// CreateSigner 根据算法创建签名器
func (f *SignerFactory) CreateSigner(algorithm string, privateKey interface{}) (Signer, error) {
	switch algorithm {
	case "SM2":
		key, ok := privateKey.(*sm2.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("私钥类型不匹配，期望*sm2.PrivateKey")
		}
		return NewSM2Signer(key), nil
	// TODO: 支持RSA和ECDSA签名器
	default:
		return nil, fmt.Errorf("不支持的签名算法: %s", algorithm)
	}
}

// GetSignatureAlgorithm 根据公钥算法和哈希算法获取签名算法标识
func GetSignatureAlgorithm(pubKeyAlgo string, hashAlgo string) x509.SignatureAlgorithm {
	switch pubKeyAlgo {
	case "SM2":
		return x509.SM2WithSM3
	case "RSA":
		switch hashAlgo {
		case "SHA256":
			return x509.SHA256WithRSA
		case "SHA384":
			return x509.SHA384WithRSA
		case "SHA512":
			return x509.SHA512WithRSA
		}
	case "EC":
		switch hashAlgo {
		case "SHA256":
			return x509.ECDSAWithSHA256
		case "SHA384":
			return x509.ECDSAWithSHA384
		case "SHA512":
			return x509.ECDSAWithSHA512
		}
	}
	return x509.UnknownSignatureAlgorithm
}
