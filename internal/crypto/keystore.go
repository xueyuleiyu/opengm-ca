package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/opengm-ca/opengm-ca/internal/model"
)

// KeyStore 密钥存储管理器
// 使用主密钥派生加密保护存储的私钥
type KeyStore struct {
	masterKey []byte // 32字节AES-256主密钥
}

// NewKeyStore 创建密钥存储管理器
func NewKeyStore(masterKeySource string) (*KeyStore, error) {
	masterKey, err := resolveMasterKey(masterKeySource)
	if err != nil {
		return nil, fmt.Errorf("加载主密钥失败: %w", err)
	}

	if len(masterKey) != 32 {
		return nil, fmt.Errorf("主密钥长度必须为32字节(256位)，当前: %d", len(masterKey))
	}

	return &KeyStore{masterKey: masterKey}, nil
}

// EncryptPrivateKey 使用主密钥加密私钥
// 返回: 密文、盐值、nonce、认证标签
func (ks *KeyStore) EncryptPrivateKey(plaintext []byte) (ciphertext, salt, nonce, tag []byte, err error) {
	// 生成随机盐值(16字节)
	salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成盐值失败: %w", err)
	}

	// 使用HKDF或简单KDF派生加密密钥
	// 简化实现: 直接使用主密钥(生产环境应使用HKDF-SHA256)
	derivedKey := ks.masterKey

	// 生成随机nonce(12字节，GCM标准)
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成nonce失败: %w", err)
	}

	// AES-256-GCM加密
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("创建AES密码器失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("创建GCM模式失败: %w", err)
	}

	// Seal自动附加认证标签
	ciphertextAndTag := gcm.Seal(nil, nonce, plaintext, nil)

	// 分离密文和认证标签(GCM标签在最后16字节)
	tagLen := gcm.Overhead()
	ciphertext = ciphertextAndTag[:len(ciphertextAndTag)-tagLen]
	tag = ciphertextAndTag[len(ciphertextAndTag)-tagLen:]

	return ciphertext, salt, nonce, tag, nil
}

// DecryptPrivateKey 使用主密钥解密私钥
func (ks *KeyStore) DecryptPrivateKey(ciphertext, salt, nonce, tag []byte) ([]byte, error) {
	// 派生密钥(简化实现)
	_ = salt // 盐值预留用于未来KDF扩展
	derivedKey := ks.masterKey

	// AES-256-GCM解密
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码器失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM模式失败: %w", err)
	}

	// 重新组合密文+标签
	ciphertextAndTag := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败(可能密钥错误或数据被篡改): %w", err)
	}

	return plaintext, nil
}

// StoreKey 存储密钥对到数据库模型
func (ks *KeyStore) StoreKey(keyModel *model.CertKey, privateKeyPEM []byte) error {
	if !keyModel.IsSoftKey() {
		return fmt.Errorf("仅软件存储类型的密钥支持加密存储")
	}

	ciphertext, salt, nonce, tag, err := ks.EncryptPrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("加密私钥失败: %w", err)
	}

	keyModel.PrivateKeyEnc = ciphertext
	keyModel.PrivateKeySalt = salt
	keyModel.PrivateKeyNonce = nonce
	keyModel.PrivateKeyTag = tag
	keyModel.MasterKeyVersion = 1 // 当前主密钥版本

	return nil
}

// RetrieveKey 从数据库模型取出并解密私钥
func (ks *KeyStore) RetrieveKey(keyModel *model.CertKey) ([]byte, error) {
	if keyModel.PrivateKeyEnc == nil {
		return nil, fmt.Errorf("密钥未存储或已删除")
	}

	// 检查主密钥版本兼容性
	if keyModel.MasterKeyVersion != 1 {
		return nil, fmt.Errorf("不支持的主密钥版本: %d", keyModel.MasterKeyVersion)
	}

	plaintext, err := ks.DecryptPrivateKey(
		keyModel.PrivateKeyEnc,
		keyModel.PrivateKeySalt,
		keyModel.PrivateKeyNonce,
		keyModel.PrivateKeyTag,
	)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	return plaintext, nil
}

// resolveMasterKey 解析主密钥
func resolveMasterKey(source string) ([]byte, error) {
	// 从环境变量获取
	if envKey := os.Getenv(source); envKey != "" {
		return []byte(envKey), nil
	}
	// 从文件获取
	if data, err := os.ReadFile(source); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("无法从 %s 加载主密钥", source)
}
