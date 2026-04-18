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

// EncodePublicKeyToPEM 将公钥编码为PEM格式
func EncodePublicKeyToPEM(publicKey interface{}) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
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
func ParsePrivateKeyFromPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("无效的PEM数据")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
}
