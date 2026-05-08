package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"

	smx509 "github.com/emmansun/gmsm/smx509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/rs/zerolog/log"
)

// CAEngine CA引擎核心
type CAEngine struct {
	cfg       *config.CAConfig
	rootCA    *CAInstance
	subCAs    map[string]*CAInstance // ca_name -> CAInstance
}

// CAInstance CA实例(根CA或中间CA)
type CAInstance struct {
	CAID       int
	CAName     string
	CertPEM    string
	Config     *model.CAChain
	Cert       *smx509.Certificate
	Signer     crypto.Signer
	PrivateKey interface{} // 解密后的私钥
}

// CARepository CA数据访问接口(避免循环依赖)
type CARepository interface {
	ListAll(ctx context.Context) ([]model.CAChain, error)
	Create(ctx context.Context, ca *model.CAChain) error
}

// KeyEncryptor 密钥加密接口
type KeyEncryptor interface {
	EncryptPrivateKey(plaintext []byte) (ciphertext, salt, nonce, tag []byte, err error)
	DecryptPrivateKey(ciphertext, salt, nonce, tag []byte) ([]byte, error)
}

// NewCAEngine 创建CA引擎
func NewCAEngine(cfg *config.CAConfig) *CAEngine {
	return &CAEngine{
		cfg:    cfg,
		subCAs: make(map[string]*CAInstance),
	}
}

// LoadFromDB 从数据库加载CA证书链并恢复私钥
func (e *CAEngine) LoadFromDB(ctx context.Context, caRepo CARepository, keyEncryptor KeyEncryptor, keyDir string) error {
	cas, err := caRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("查询CA链失败: %w", err)
	}

	for _, ca := range cas {
		instance := &CAInstance{
			CAID:    ca.ID,
			CAName:  ca.CAName,
			CertPEM: ca.CertPEM,
			Config:  &ca,
		}

		// 解析证书
		block, _ := pem.Decode([]byte(ca.CertPEM))
		if block == nil {
			return fmt.Errorf("CA %s 证书PEM解析失败", ca.CAName)
		}
		cert, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("CA %s 证书解析失败: %w", ca.CAName, err)
		}
		instance.Cert = cert

		// 加载私钥
		keyPath := filepath.Join(keyDir, ca.CAName+".key")
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			log.Warn().Str("ca", ca.CAName).Str("path", keyPath).Msg("CA私钥文件不存在，跳过加载")
			continue
		}

		privKeyPEM, err := e.decryptKeyFile(keyData, keyEncryptor)
		if err != nil {
			log.Warn().Str("ca", ca.CAName).Err(err).Msg("CA私钥解密失败，跳过加载")
			continue
		}

		privKey, err := parsePrivateKeyPEM(privKeyPEM, ca.Algorithm)
		if err != nil {
			log.Warn().Str("ca", ca.CAName).Err(err).Msg("CA私钥解析失败，跳过加载")
			continue
		}
		instance.PrivateKey = privKey
		instance.Signer = privKey.(crypto.Signer)

		if ca.CAType == model.CATypeRoot {
			e.rootCA = instance
		} else {
			e.subCAs[ca.CAName] = instance
		}
	}

	log.Info().Int("ca_count", len(cas)).Int("sub_cas", len(e.subCAs)).Msg("CA链从数据库加载完成")
	return nil
}

// decryptKeyFile 解密或读取私钥文件
func (e *CAEngine) decryptKeyFile(data []byte, keyEncryptor KeyEncryptor) ([]byte, error) {
	var wrapper struct {
		Encrypted  bool   `json:"encrypted"`
		Ciphertext string `json:"ciphertext"`
		Salt       string `json:"salt"`
		Nonce      string `json:"nonce"`
		Tag        string `json:"tag"`
		PEM        string `json:"pem"`
	}

	if err := json.Unmarshal(data, &wrapper); err != nil {
		// 不是JSON格式，当作原始PEM返回
		return data, nil
	}

	if !wrapper.Encrypted {
		return []byte(wrapper.PEM), nil
	}

	if keyEncryptor == nil {
		return nil, fmt.Errorf("私钥已加密但无法获取主密钥")
	}

	ct, _ := base64.StdEncoding.DecodeString(wrapper.Ciphertext)
	salt, _ := base64.StdEncoding.DecodeString(wrapper.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(wrapper.Nonce)
	tag, _ := base64.StdEncoding.DecodeString(wrapper.Tag)

	return keyEncryptor.DecryptPrivateKey(ct, salt, nonce, tag)
}

// encryptKeyFile 加密私钥为文件格式
func (e *CAEngine) encryptKeyFile(pemData []byte, keyEncryptor KeyEncryptor) ([]byte, error) {
	if keyEncryptor == nil {
		// 未加密存储(开发/测试环境)
		wrapper := struct {
			Encrypted bool   `json:"encrypted"`
			PEM       string `json:"pem"`
		}{
			Encrypted: false,
			PEM:       string(pemData),
		}
		return json.Marshal(wrapper)
	}

	ct, salt, nonce, tag, err := keyEncryptor.EncryptPrivateKey(pemData)
	if err != nil {
		return nil, err
	}

	wrapper := struct {
		Encrypted  bool   `json:"encrypted"`
		Ciphertext string `json:"ciphertext"`
		Salt       string `json:"salt"`
		Nonce      string `json:"nonce"`
		Tag        string `json:"tag"`
	}{
		Encrypted:  true,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}
	return json.Marshal(wrapper)
}

// SaveToStorage 将CA证书和私钥持久化到数据库和文件
func (e *CAEngine) SaveToStorage(ctx context.Context, caRepo CARepository, keyEncryptor KeyEncryptor, keyDir string) error {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("创建CA密钥目录失败: %w", err)
	}

	// 保存根CA
	if e.rootCA != nil {
		if err := e.saveCAInstance(ctx, caRepo, keyEncryptor, keyDir, e.rootCA, model.CATypeRoot, nil); err != nil {
			return fmt.Errorf("保存根CA失败: %w", err)
		}
	}

	// 保存中间CA
	for name, ca := range e.subCAs {
		if err := e.saveCAInstance(ctx, caRepo, keyEncryptor, keyDir, ca, model.CATypeIntermediate, e.rootCA); err != nil {
			return fmt.Errorf("保存CA %s 失败: %w", name, err)
		}
	}

	log.Info().Int("sub_ca_count", len(e.subCAs)).Msg("CA证书链持久化完成")
	return nil
}

func (e *CAEngine) saveCAInstance(ctx context.Context, caRepo CARepository, keyEncryptor KeyEncryptor, keyDir string, instance *CAInstance, caType model.CAType, parent *CAInstance) error {
	caRecord := &model.CAChain{
		CAName:     instance.CAName,
		CAType:     caType,
		CertPEM:    instance.CertPEM,
		CertDER:    instance.Cert.Raw,
		SubjectDN:  instance.Cert.Subject.String(),
		IssuerDN:   instance.Cert.Issuer.String(),
		SerialNumber: fmt.Sprintf("%X", instance.Cert.SerialNumber),
		Algorithm:  e.cfg.RootCA.Algorithm,
		KeyID:      fmt.Sprintf("ca-key-%s", instance.CAName),
		ValidFrom:  instance.Cert.NotBefore,
		ValidTo:    instance.Cert.NotAfter,
		IsActive:   true,
		MaxPathLen: 0,
	}

	if parent != nil {
		caRecord.ParentCAID = &parent.CAID
	}

	if err := caRepo.Create(ctx, caRecord); err != nil {
		return fmt.Errorf("写入CA数据库记录失败: %w", err)
	}

	instance.CAID = caRecord.ID

	// 编码私钥为PEM
	privKeyPEM, err := encodePrivateKeyToPEM(instance.PrivateKey, caRecord.Algorithm)
	if err != nil {
		return fmt.Errorf("编码CA私钥失败: %w", err)
	}

	// 加密并保存私钥文件
	keyFileData, err := e.encryptKeyFile([]byte(privKeyPEM), keyEncryptor)
	if err != nil {
		return fmt.Errorf("加密CA私钥失败: %w", err)
	}

	keyPath := filepath.Join(keyDir, instance.CAName+".key")
	if err := os.WriteFile(keyPath, keyFileData, 0600); err != nil {
		return fmt.Errorf("写入CA私钥文件失败: %w", err)
	}

	return nil
}

// GetCA 根据名称获取CA实例
func (e *CAEngine) GetCA(name string) (*CAInstance, error) {
	ca, ok := e.subCAs[name]
	if !ok {
		return nil, fmt.Errorf("CA %s 不存在或未加载", name)
	}
	return ca, nil
}

// encodePrivateKeyToPEM 将私钥编码为PEM
func encodePrivateKeyToPEM(privKey interface{}, algorithm string) (string, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		data := x509.MarshalPKCS1PrivateKey(key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: data})), nil
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: data})), nil
	case *sm2.PrivateKey:
		// SM2私钥: 32字节D值
		dBytes := key.D.Bytes()
		data := make([]byte, 32)
		copy(data[32-len(dBytes):], dBytes)
		return string(pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: data})), nil
	default:
		// 其他类型尝试PKCS#8
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})), nil
	}
}

// parsePrivateKeyPEM 解析PEM私钥
func parsePrivateKeyPEM(pemData []byte, algorithm string) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("私钥PEM解码失败")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "SM2 PRIVATE KEY":
		return sm2.NewPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		// 尝试SM2(兼容未标记的SM2密钥)
		if len(block.Bytes) == 32 {
			if pk, err := sm2.NewPrivateKey(block.Bytes); err == nil {
				return pk, nil
			}
		}
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	}
}

// Initialize 初始化CA系统(首次部署)
func (e *CAEngine) Initialize(ctx context.Context, req *model.CAInitRequest) (*model.CAInitResponse, error) {
	log.Info().Msg("开始初始化CA系统...")

	// 1. 生成根CA
	rootResp, err := e.createRootCA(ctx, &req.RootCA)
	if err != nil {
		return nil, fmt.Errorf("创建根CA失败: %w", err)
	}

	e.rootCA = rootResp

	resp := &model.CAInitResponse{
		RootCAID:    rootResp.CAID,
		RootCertPEM: rootResp.CertPEM,
	}

	// 2. 生成中间CA
	for _, subReq := range req.IntermediateCAs {
		subResp, err := e.createIntermediateCA(ctx, rootResp, &subReq)
		if err != nil {
			return nil, fmt.Errorf("创建中间CA %s 失败: %w", subReq.CAName, err)
		}
		e.subCAs[subReq.CAName] = subResp
		resp.IntermediateCAs = append(resp.IntermediateCAs, model.IntermediateCAResponse{
			CAID:    subResp.CAID,
			CAName:  subReq.CAName,
			CertPEM: subResp.CertPEM,
		})
	}

	log.Info().Int("sub_cas", len(resp.IntermediateCAs)).Msg("CA系统初始化完成")
	return resp, nil
}

// createRootCA 创建根CA
func (e *CAEngine) createRootCA(ctx context.Context, req *model.RootCAInitConfig) (*CAInstance, error) {
	// 生成密钥对
	privKey, pubKey, err := generateKeyPair(req.Algorithm, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("生成根CA密钥失败: %w", err)
	}

	// 构建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         req.Subject.CommonName,
			Organization:       []string{req.Subject.Organization},
			Country:            []string{req.Subject.Country},
			OrganizationalUnit: []string{req.Subject.OrganizationalUnit},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(req.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		SubjectKeyId:          generateKeyID(pubKey),
	}

	// 自签名
	certBytes, err := smx509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("自签名根CA证书失败: %w", err)
	}

	cert, err := smx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析根CA证书失败: %w", err)
	}

	certPEM := pemEncode(certBytes, "CERTIFICATE")

	instance := &CAInstance{
		CAID:       int(generateSerialNumber().Int64()),
		CAName:     req.Subject.CommonName,
		CertPEM:    certPEM,
		Cert:       cert,
		Signer:     privKey.(crypto.Signer),
		PrivateKey: privKey,
	}

	log.Info().Str("subject", cert.Subject.String()).Str("algorithm", req.Algorithm).
		Time("valid_to", cert.NotAfter).Msg("根CA创建成功")

	return instance, nil
}

// createIntermediateCA 创建中间CA
func (e *CAEngine) createIntermediateCA(ctx context.Context, parent *CAInstance, req *model.IntermediateCAInitConfig) (*CAInstance, error) {
	// 生成密钥对
	privKey, pubKey, err := generateKeyPair(req.Algorithm, 256)
	if err != nil {
		return nil, fmt.Errorf("生成中间CA密钥失败: %w", err)
	}

	// 构建证书模板
	template := &x509.Certificate{
		SerialNumber: generateSerialNumber(),
		Subject: pkix.Name{
			CommonName:         req.Subject.CommonName,
			Organization:       []string{req.Subject.Organization},
			Country:            []string{req.Subject.Country},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(req.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            req.MaxPathLen,
		SubjectKeyId:          generateKeyID(pubKey),
		AuthorityKeyId:        parent.Cert.SubjectKeyId,
	}

	// 使用父CA签名
	parentCert := parent.Cert
	certBytes, err := smx509.CreateCertificate(rand.Reader, template, parentCert, pubKey, parent.Signer)
	if err != nil {
		return nil, fmt.Errorf("签名中间CA证书失败: %w", err)
	}

	cert, err := smx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析中间CA证书失败: %w", err)
	}

	certPEM := pemEncode(certBytes, "CERTIFICATE")
	instance := &CAInstance{
		CAID:       int(generateSerialNumber().Int64()),
		CAName:     req.CAName,
		CertPEM:    certPEM,
		Cert:       cert,
		Signer:     privKey.(crypto.Signer),
		PrivateKey: privKey,
	}

	log.Info().Str("ca_name", req.CAName).Str("subject", cert.Subject.String()).
		Msg("中间CA创建成功")

	return instance, nil
}

// IssueCertificate 签发终端实体证书
func (e *CAEngine) IssueCertificate(ctx context.Context, caName string, req *model.CertificateRequest, pubKey interface{}) (*model.Certificate, error) {
	ca, ok := e.subCAs[caName]
	if !ok {
		return nil, fmt.Errorf("CA %s 不存在", caName)
	}

	// 构建证书模板
	template, err := buildCertTemplate(req)
	if err != nil {
		return nil, fmt.Errorf("构建证书模板失败: %w", err)
	}

	// 使用CA签名
	parentCert := ca.Cert
	certBytes, err := smx509.CreateCertificate(rand.Reader, template, parentCert, pubKey, ca.Signer)
	if err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}

	cert, err := smx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	certPEM := pemEncode(certBytes, "CERTIFICATE")

	result := &model.Certificate{
		CertType:     model.CertType(req.CertType),
		SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
		CertPEM:      certPEM,
		SubjectDN:    cert.Subject.String(),
		IssuerDN:     cert.Issuer.String(),
		ValidFrom:    cert.NotBefore,
		ValidTo:      cert.NotAfter,
		Status:       model.CertStatusValid,
	}

	log.Info().Str("serial", result.SerialNumber).Str("subject", result.SubjectDN).
		Str("ca", caName).Msg("证书签发成功")

	return result, nil
}

// generateKeyPair 生成密钥对
func generateKeyPair(algorithm string, keySize int) (interface{}, interface{}, error) {
	switch algorithm {
	case "SM2":
		privKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return privKey, &privKey.PublicKey, nil

	case "RSA2048", "RSA4096":
		size := 2048
		if algorithm == "RSA4096" {
			size = 4096
		}
		privKey, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, nil, err
		}
		return privKey, &privKey.PublicKey, nil

	case "EC256", "EC384":
		curve := elliptic.P256()
		if algorithm == "EC384" {
			curve = elliptic.P384()
		}
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return privKey, &privKey.PublicKey, nil

	default:
		return nil, nil, fmt.Errorf("不支持的算法: %s", algorithm)
	}
}

// generateSerialNumber 生成证书序列号
func generateSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

// generateKeyID 生成主题密钥标识符 (RFC 5280: SHA-1 hash of public key DER)
func generateKeyID(pubKey interface{}) []byte {
	pubDER, err := smx509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		// Fallback to standard x509 for non-SM2 keys
		pubDER, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Warn().Err(err).Msg("无法序列化公钥生成SubjectKeyId，使用随机值")
			randBytes := make([]byte, 20)
			_, _ = rand.Read(randBytes)
			return randBytes
		}
	}
	hash := sha1.Sum(pubDER)
	return hash[:]
}

// buildCertTemplate 根据请求构建证书模板
func buildCertTemplate(req *model.CertificateRequest) (*x509.Certificate, error) {
	// TODO: 根据证书类型(SSL/AUTH/VPN)构建不同的KeyUsage和扩展
	return &x509.Certificate{
		SerialNumber: generateSerialNumber(),
		Subject: pkix.Name{
			CommonName:         req.Subject.CommonName,
			Organization:       []string{req.Subject.Organization},
			Country:            []string{req.Subject.Country},
			OrganizationalUnit: []string{req.Subject.OrganizationalUnit},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, req.ValidityDays),
	}, nil
}

// pemEncode PEM编码
func pemEncode(data []byte, blockType string) string {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	return string(pem.EncodeToMemory(block))
}
