package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
)

// KeyGenerator 密钥生成器
type KeyGenerator struct{}

// NewKeyGenerator 创建密钥生成器
func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{}
}

// GenerateKeyPair 生成非对称密钥对
// algorithm: SM2 | RSA2048 | RSA4096 | EC256 | EC384
func (g *KeyGenerator) GenerateKeyPair(algorithm string) (interface{}, interface{}, error) {
	switch algorithm {
	case "SM2":
		return g.generateSM2KeyPair()
	case "RSA2048":
		return g.generateRSAKeyPair(2048)
	case "RSA4096":
		return g.generateRSAKeyPair(4096)
	case "EC256":
		return g.generateECKeyPair(elliptic.P256())
	case "EC384":
		return g.generateECKeyPair(elliptic.P384())
	default:
		return nil, nil, fmt.Errorf("不支持的密钥算法: %s", algorithm)
	}
}

// generateSM2KeyPair 生成SM2密钥对
func (g *KeyGenerator) generateSM2KeyPair() (*sm2.PrivateKey, crypto.PublicKey, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成SM2密钥失败: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// generateRSAKeyPair 生成RSA密钥对
func (g *KeyGenerator) generateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("生成RSA密钥失败: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// generateECKeyPair 生成ECDSA密钥对
func (g *KeyGenerator) generateECKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成EC密钥失败: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// EncodePrivateKeyToPKCS8 将私钥编码为PKCS#8 PEM格式
func EncodePrivateKeyToPKCS8(privateKey interface{}) (string, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("PKCS#8编码失败: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodePrivateKeyToPKCS1 将RSA私钥编码为PKCS#1 PEM格式
func EncodePrivateKeyToPKCS1(privateKey *rsa.PrivateKey) (string, error) {
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodeECPrivateKey 将EC私钥编码为SEC1 PEM格式
func EncodeECPrivateKey(privateKey *ecdsa.PrivateKey) (string, error) {
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("EC私钥编码失败: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodePrivateKey 根据算法自动选择编码格式
func EncodePrivateKey(privKey interface{}, algorithm string) (string, error) {
	switch algorithm {
	case "SM2":
		return EncodeSM2PrivateKey(privKey.(*sm2.PrivateKey))
	case "RSA2048", "RSA4096":
		return EncodePrivateKeyToPKCS1(privKey.(*rsa.PrivateKey))
	case "EC256", "EC384":
		return EncodeECPrivateKey(privKey.(*ecdsa.PrivateKey))
	default:
		return EncodePrivateKeyToPKCS8(privKey)
	}
}

// EncodeSM2PrivateKey 将SM2私钥编码为标准PKCS#8 PEM格式
// 使用 smx509.MarshalPKCS8PrivateKey 确保与国密解析器兼容
func EncodeSM2PrivateKey(privateKey *sm2.PrivateKey) (string, error) {
	privBytes, err := smx509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("SM2 PKCS#8编码失败: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodePublicKeyToPEM 将公钥编码为PEM格式
func EncodePublicKeyToPEM(publicKey interface{}) (string, error) {
	// 优先使用smx509编码(支持SM2国密曲线)
	pubBytes, err := smx509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		// 回退到标准x509
		pubBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	}
	if err != nil {
		return "", fmt.Errorf("公钥编码失败: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// PemEncode PEM编码任意数据
func PemEncode(data []byte, blockType string) string {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	return string(pem.EncodeToMemory(block))
}

// ParsePrivateKeyFromPEM 从PEM解析私钥
// 优先使用 smx509 解析以支持国密SM2算法，失败后再回退到标准库x509
func ParsePrivateKeyFromPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("无效的PEM数据")
	}

	switch block.Type {
	case "PRIVATE KEY":
		// 优先使用 smx509 解析，支持 SM2 的 PKCS#8 格式
		if key, err := smx509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		// 优先使用 smx509 解析，支持 SM2 的 SEC1 格式
		if key, err := smx509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return x509.ParseECPrivateKey(block.Bytes)
	case "SM2 PRIVATE KEY":
		// 向后兼容：原始32字节D值
		if len(block.Bytes) == 32 {
			return sm2.NewPrivateKey(block.Bytes)
		}
		return nil, fmt.Errorf("无效的SM2私钥长度: %d", len(block.Bytes))
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
}
