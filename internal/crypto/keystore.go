package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"golang.org/x/crypto/hkdf"
)

// KeyStore 密钥存储管理器
// 使用主密钥派生加密保护存储的私钥
type KeyStore struct {
	masterKey []byte // 32字节AES-256主密钥
}

// NewKeyStore 创建密钥存储管理器
func NewKeyStore(masterKeySource string) (*KeyStore, error) {
	masterKey, err := ResolveMasterKey(masterKeySource)
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

	// 使用HKDF-SHA256派生加密密钥
	derivedKey, err := ks.deriveKey(salt)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("派生加密密钥失败: %w", err)
	}

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
	// 使用HKDF-SHA256派生解密密钥
	derivedKey, err := ks.deriveKey(salt)
	if err != nil {
		return nil, fmt.Errorf("派生解密密钥失败: %w", err)
	}

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

// deriveKey 使用HKDF-SHA256从主密钥和盐派生加密密钥
func (ks *KeyStore) deriveKey(salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, ks.masterKey, salt, []byte("opengm-ca-keystore-v1"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF密钥派生失败: %w", err)
	}
	return derivedKey, nil
}

// ResolveMasterKey 解析主密钥（优先使用hex格式，避免base64歧义）
// 增强安全性：验证主密钥来源合法性、校验文件权限
func ResolveMasterKey(source string) ([]byte, error) {
	var raw string
	var sourceType string // 记录主密钥来源类型

	// 从环境变量获取
	if envKey := os.Getenv(source); envKey != "" {
		raw = envKey
		sourceType = "environment_variable"
	} else if data, err := os.ReadFile(source); err == nil {
		// 从文件获取 - 增加文件权限校验
		sourceType = "file"

		// 校验文件权限，确保只有所有者可读写
		fileInfo, statErr := os.Stat(source)
		if statErr != nil {
			return nil, fmt.Errorf("无法获取主密钥文件信息: %w", statErr)
		}

		// 检查文件权限模式（应该 <= 0600，即仅所有者可读写）
		perm := fileInfo.Mode().Perm()
		if perm > 0600 {
			return nil, fmt.Errorf("主密钥文件权限过于宽松: %o，应设置为0600或更严格", perm)
		}

		// 检查文件是否为符号链接（防止符号链接攻击）
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("主密钥文件不能是符号链接")
		}

		raw = string(data)
	} else {
		return nil, fmt.Errorf("无法从 %s 加载主密钥: 环境变量未设置且文件不存在", source)
	}

	// 优先尝试hex解码（64字符 = 32字节，这是推荐的格式）
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil {
			// 记录主密钥加载成功（不记录密钥内容）
			fmt.Printf("[SECURITY] 主密钥加载成功: 来源=%s, 格式=hex, 长度=32字节\n", sourceType)
			return b, nil
		}
	}

	// 如果不是hex，检查是否是base64编码的32字节
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		fmt.Printf("[SECURITY] 主密钥加载成功: 来源=%s, 格式=base64, 长度=32字节\n", sourceType)
		return b, nil
	}

	// 最后尝试直接使用原始字节（必须是32字节）
	if len(raw) == 32 {
		fmt.Printf("[SECURITY] 主密钥加载成功: 来源=%s, 格式=raw, 长度=32字节\n", sourceType)
		return []byte(raw), nil
	}

	return nil, fmt.Errorf("主密钥格式无效，请提供64字符hex编码、44字符base64编码或32字节原始数据，当前长度: %d", len(raw))
}
