package core

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// SignatureAlgorithm 签名算法标识
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	SM2WithSM3
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
)

// Signer 统一签名接口
type Signer interface {
	Sign(data []byte) ([]byte, error)
	SignDigest(digest []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
	Algorithm() SignatureAlgorithm
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
	return s.PrivateKey.Sign(nil, digest, nil)
}

// PublicKey 返回SM2公钥
func (s *SM2Signer) PublicKey() crypto.PublicKey {
	return s.PrivateKey.Public()
}

// Algorithm 返回签名算法
func (s *SM2Signer) Algorithm() SignatureAlgorithm {
	return SM2WithSM3
}

// HashFunc 返回哈希函数
func (s *SM2Signer) HashFunc() hash.Hash {
	return sm3.New()
}

// defaultSM2UID 返回默认SM2 UserID
func defaultSM2UID() []byte {
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
	default:
		return nil, fmt.Errorf("不支持的签名算法: %s", algorithm)
	}
}

// GetSignatureAlgorithm 根据公钥算法和哈希算法获取签名算法标识
func GetSignatureAlgorithm(pubKeyAlgo string, hashAlgo string) SignatureAlgorithm {
	switch pubKeyAlgo {
	case "SM2":
		return SM2WithSM3
	case "RSA":
		switch hashAlgo {
		case "SHA256":
			return SHA256WithRSA
		case "SHA384":
			return SHA384WithRSA
		case "SHA512":
			return SHA512WithRSA
		}
	case "EC":
		switch hashAlgo {
		case "SHA256":
			return ECDSAWithSHA256
		case "SHA384":
			return ECDSAWithSHA384
		case "SHA512":
			return ECDSAWithSHA512
		}
	}
	return UnknownSignatureAlgorithm
}
