package hsm

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"
)

// SoftHSM 软件HSM实现
type SoftHSM struct {
	mu        sync.RWMutex
	baseDir   string
	masterKey []byte
	keys      map[string]*keyRecord
}

type keyRecord struct {
	Handle        string `json:"handle"`
	Algorithm     string `json:"algorithm"`
	KeyType       string `json:"key_type"`
	CreatedAt     int64  `json:"created_at"`
	EncryptedKey  []byte `json:"encrypted_key"`
	Nonce         []byte `json:"nonce"`
	KEKSalt       []byte `json:"kek_salt,omitempty"`       // 独立密钥加密盐值（v2格式）
	KEKIterations int    `json:"kek_iterations,omitempty"` // 0表示旧格式(10000)
	PublicKeyPEM  string `json:"public_key_pem"`
}

// NewSoftHSM 创建软件HSM
func NewSoftHSM(baseDir, password string) (*SoftHSM, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("创建HSM目录失败: %w", err)
	}

	// 使用PBKDF2从密码派生主密钥（使用随机盐）
	salt, err := loadOrGenerateSalt(baseDir)
	if err != nil {
		return nil, fmt.Errorf("加载或生成HSM盐值失败: %w", err)
	}
	// 统一使用600,000次迭代，符合OWASP推荐
	masterKey := pbkdf2.Key([]byte(password), salt, defaultPBKDF2Iterations, 32, sha256.New)

	hsm := &SoftHSM{
		baseDir:   baseDir,
		masterKey: masterKey,
		keys:      make(map[string]*keyRecord),
	}

	// 加载已有密钥
	if err := hsm.loadAllKeys(); err != nil {
		return nil, fmt.Errorf("加载HSM密钥失败: %w", err)
	}

	return hsm, nil
}

// GenerateKeyPair 生成密钥对
func (h *SoftHSM) GenerateKeyPair(algorithm string, keySize int, keyType string) (string, crypto.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var privKey interface{}
	var pubKey crypto.PublicKey
	var err error

	switch strings.ToUpper(algorithm) {
	case "SM2":
		privKey, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			return "", nil, fmt.Errorf("生成SM2密钥失败: %w", err)
		}
		pubKey = privKey.(*sm2.PrivateKey).Public()
	case "RSA2048", "RSA4096":
		size := 2048
		if algorithm == "RSA4096" {
			size = 4096
		}
		privKey, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return "", nil, fmt.Errorf("生成RSA密钥失败: %w", err)
		}
		pubKey = &privKey.(*rsa.PrivateKey).PublicKey
	case "EC256", "EC384":
		curve := elliptic.P256()
		if algorithm == "EC384" {
			curve = elliptic.P384()
		}
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return "", nil, fmt.Errorf("生成EC密钥失败: %w", err)
		}
		pubKey = &privKey.(*ecdsa.PrivateKey).PublicKey
	default:
		return "", nil, fmt.Errorf("不支持的算法: %s", algorithm)
	}

	// 序列化私钥为PKCS#8（统一使用smx509支持SM2国密算法）
	privBytes, err := smx509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		privBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
	}
	if err != nil {
		return "", nil, fmt.Errorf("序列化私钥失败: %w", err)
	}

	// 加密存储（使用独立盐值）
	encrypted, nonce, kekSalt, err := h.encrypt(privBytes)
	if err != nil {
		return "", nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	// 生成公钥PEM（支持SM2）
	pubBytes, err := smx509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		pubBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	}
	if err != nil {
		return "", nil, fmt.Errorf("序列化公钥失败: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	handle := uuid.New().String()
	record := &keyRecord{
		Handle:       handle,
		Algorithm:    algorithm,
		KeyType:      keyType,
		CreatedAt:    time.Now().Unix(),
		EncryptedKey: encrypted,
		Nonce:        nonce,
		KEKSalt:      kekSalt,
		PublicKeyPEM: pubPEM,
	}

	h.keys[handle] = record
	if err := h.saveKeyRecord(record); err != nil {
		delete(h.keys, handle)
		return "", nil, fmt.Errorf("保存密钥失败: %w", err)
	}

	return handle, pubKey, nil
}

// Sign 签名
func (h *SoftHSM) Sign(handle string, digest []byte, hashAlgo string) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	record, ok := h.keys[handle]
	if !ok {
		return nil, fmt.Errorf("密钥不存在: %s", handle)
	}

	// 解密私钥
	privBytes, err := h.decrypt(record.EncryptedKey, record.Nonce, record.KEKSalt, record.KEKIterations)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	privKey, err := smx509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		// 回退到标准库（RSA/EC）
		privKey, err = x509.ParsePKCS8PrivateKey(privBytes)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
	}

	// 签名完成后安全擦解密密钥明文
	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	switch key := privKey.(type) {
	case *sm2.PrivateKey:
		return key.Sign(rand.Reader, digest, nil)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	default:
		return nil, fmt.Errorf("不支持的私钥类型")
	}
}

// GetPublicKey 获取公钥
func (h *SoftHSM) GetPublicKey(handle string) (crypto.PublicKey, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	record, ok := h.keys[handle]
	if !ok {
		return nil, fmt.Errorf("密钥不存在: %s", handle)
	}

	block, _ := pem.Decode([]byte(record.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("公钥PEM解析失败")
	}

	pubKey, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// 回退到标准库（RSA/EC）
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
	}
	return pubKey, nil
}

// GetPublicKeyPEM 获取公钥PEM
func (h *SoftHSM) GetPublicKeyPEM(handle string) (string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	record, ok := h.keys[handle]
	if !ok {
		return "", fmt.Errorf("密钥不存在: %s", handle)
	}
	return record.PublicKeyPEM, nil
}

// DeleteKey 删除密钥（执行安全擦除后删除）
func (h *SoftHSM) DeleteKey(handle string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	record, ok := h.keys[handle]
	if !ok {
		return fmt.Errorf("密钥不存在: %s", handle)
	}

	// 安全擦除内存中的敏感密钥材料
	for i := range record.EncryptedKey {
		record.EncryptedKey[i] = 0
	}

	delete(h.keys, handle)
	path := filepath.Join(h.baseDir, handle+".json")
	_ = os.Remove(path)
	return nil
}

// ListKeys 列出所有密钥
func (h *SoftHSM) ListKeys() ([]KeyInfo, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []KeyInfo
	for _, record := range h.keys {
		result = append(result, KeyInfo{
			Handle:       record.Handle,
			Algorithm:    record.Algorithm,
			KeyType:      record.KeyType,
			CreatedAt:    time.Unix(record.CreatedAt, 0),
			PublicKeyPEM: record.PublicKeyPEM,
		})
	}
	return result, nil
}

// ImportKey 导入密钥
func (h *SoftHSM) ImportKey(algorithm string, privateKey interface{}, keyType string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("序列化私钥失败: %w", err)
	}

	encrypted, nonce, kekSalt, err := h.encrypt(privBytes)
	if err != nil {
		return "", fmt.Errorf("加密私钥失败: %w", err)
	}

	// 提取公钥
	var pubKey crypto.PublicKey
	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		pubKey = k.Public()
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return "", fmt.Errorf("不支持的私钥类型")
	}

	pubBytes, err := smx509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		// 回退到标准库（RSA/EC）
		pubBytes, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return "", fmt.Errorf("序列化公钥失败: %w", err)
		}
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	handle := uuid.New().String()
	record := &keyRecord{
		Handle:       handle,
		Algorithm:    algorithm,
		KeyType:      keyType,
		CreatedAt:    time.Now().Unix(),
		EncryptedKey: encrypted,
		Nonce:        nonce,
		KEKSalt:      kekSalt,
		PublicKeyPEM: pubPEM,
	}

	h.keys[handle] = record
	if err := h.saveKeyRecord(record); err != nil {
		delete(h.keys, handle)
		return "", fmt.Errorf("保存密钥失败: %w", err)
	}

	return handle, nil
}

// ExportKey 导出密钥（生产环境禁止直接导出原始私钥）
func (h *SoftHSM) ExportKey(handle string) (interface{}, error) {
	return nil, fmt.Errorf("HSM禁止直接导出原始私钥，请使用受控导出流程")
}

// GetKeyInfo 获取密钥信息
func (h *SoftHSM) GetKeyInfo(handle string) (*KeyInfo, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	record, ok := h.keys[handle]
	if !ok {
		return nil, fmt.Errorf("密钥不存在: %s", handle)
	}

	return &KeyInfo{
		Handle:       record.Handle,
		Algorithm:    record.Algorithm,
		KeyType:      record.KeyType,
		CreatedAt:    time.Unix(record.CreatedAt, 0),
		PublicKeyPEM: record.PublicKeyPEM,
	}, nil
}

// Status 获取HSM状态
func (h *SoftHSM) Status() (*HSMStatus, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return &HSMStatus{
		Type:        "SOFT_HSM",
		Initialized: true,
		KeyCount:    len(h.keys),
		StoragePath: h.baseDir,
	}, nil
}

// Close 关闭HSM
func (h *SoftHSM) Close() error {
	return nil
}

// loadOrGenerateSalt 加载已有盐值或生成新的随机盐
func loadOrGenerateSalt(baseDir string) ([]byte, error) {
	saltPath := filepath.Join(baseDir, ".salt")
	if data, err := os.ReadFile(saltPath); err == nil && len(data) >= 16 {
		return data, nil
	}
	// 生成新的随机盐
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("生成HSM盐值失败: %w", err)
	}
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return nil, fmt.Errorf("保存HSM盐值失败: %w", err)
	}
	return salt, nil
}

const defaultPBKDF2Iterations = 600000

// deriveKEK 使用主密钥和独立盐值派生密钥加密密钥（KEK）
func (h *SoftHSM) deriveKEK(kekSalt []byte, iterations int) []byte {
	if len(kekSalt) == 0 {
		return h.masterKey
	}
	if iterations <= 0 {
		iterations = defaultPBKDF2Iterations
	}
	return pbkdf2.Key(h.masterKey, kekSalt, iterations, 32, sha256.New)
}

// 内部方法：加密（返回 ciphertext, nonce, kekSalt）
func (h *SoftHSM) encrypt(plaintext []byte) ([]byte, []byte, []byte, error) {
	// 为每个密钥生成独立盐值
	kekSalt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, kekSalt); err != nil {
		return nil, nil, nil, err
	}
	kek := h.deriveKEK(kekSalt, defaultPBKDF2Iterations)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	// 使用标准GCM格式：ciphertext = encrypted_plaintext || tag，nonce单独保存
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, kekSalt, nil
}

// 内部方法：解密（兼容旧格式：无 KEKSalt 时回退到 masterKey）
// 兼容旧格式：旧代码使用 gcm.Seal(nonce, nonce, plaintext, nil)，导致 ciphertext = nonce || encrypted || tag
func (h *SoftHSM) decrypt(ciphertext []byte, nonce []byte, kekSalt []byte, iterations int) ([]byte, error) {
	kek := h.deriveKEK(kekSalt, iterations)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// 尝试标准格式
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err == nil {
		return plain, nil
	}
	// 兼容旧格式：跳过前nonceSize字节的重复nonce前缀
	if len(ciphertext) > gcm.NonceSize() {
		oldPlain, oldErr := gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
		if oldErr == nil {
			return oldPlain, nil
		}
	}
	return nil, err
}

// 内部方法：保存密钥记录到文件
func (h *SoftHSM) saveKeyRecord(record *keyRecord) error {
	path := filepath.Join(h.baseDir, record.Handle+".json")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// 内部方法：加载所有密钥
func (h *SoftHSM) loadAllKeys() error {
	entries, err := os.ReadDir(h.baseDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(h.baseDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warn().Str("file", path).Err(err).Msg("HSM密钥文件读取失败，跳过")
			continue
		}

		var record keyRecord
		if err := json.Unmarshal(data, &record); err != nil {
			log.Warn().Str("file", path).Err(err).Msg("HSM密钥文件解析失败，跳过")
			continue
		}

		h.keys[record.Handle] = &record
	}
	return nil
}
