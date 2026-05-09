package core

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"hash"
	"os"

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
	UID        []byte
}

// NewSM2Signer 创建SM2签名器
func NewSM2Signer(privKey *sm2.PrivateKey) *SM2Signer {
	return &SM2Signer{PrivateKey: privKey, UID: resolveSM2UID()}
}

// Sign 使用SM2签名(自动做SM3哈希)
func (s *SM2Signer) Sign(data []byte) ([]byte, error) {
	return sm2.SignASN1(rand.Reader, s.PrivateKey, data, sm2.NewSM2SignerOption(true, s.UID))
}

// SignDigest 对SM3摘要签名（不再内部哈希，直接使用digest）
func (s *SM2Signer) SignDigest(digest []byte) ([]byte, error) {
	return sm2.SignASN1(rand.Reader, s.PrivateKey, digest, sm2.NewSM2SignerOption(false, s.UID))
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

// resolveSM2UID 从环境变量读取SM2 UserID，未设置则生成随机值
func resolveSM2UID() []byte {
	if uid := os.Getenv("CA_SM2_USER_ID"); uid != "" {
		return []byte(uid)
	}
	// 未配置时生成随机16字节UID（避免使用硬编码测试值）
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 熵源失败时panic（系统随机数源不可恢复）
		panic(fmt.Sprintf("SM2 UID生成失败(熵源错误): %v", err))
	}
	return b
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
