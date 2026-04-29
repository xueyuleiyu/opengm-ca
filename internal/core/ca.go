package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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
	Config     *model.CAChain
	Cert       interface{} // *x509.Certificate 或 *sm2x509.Certificate
	Signer     crypto.Signer
	PrivateKey interface{} // 解密后的私钥
}

// NewCAEngine 创建CA引擎
func NewCAEngine(cfg *config.CAConfig) *CAEngine {
	return &CAEngine{
		cfg:    cfg,
		subCAs: make(map[string]*CAInstance),
	}
}

// LoadFromDB 从数据库加载CA证书链
func (e *CAEngine) LoadFromDB(ctx context.Context, caRepo interface{}) error {
	// TODO: 从数据库查询ca_chain表，加载所有CA实例
	_ = caRepo
	return nil
}

// Initialize 初始化CA系统(首次部署)
func (e *CAEngine) Initialize(ctx context.Context, req *model.CAInitRequest) (*model.CAInitResponse, error) {
	log.Info().Msg("开始初始化CA系统...")

	// 1. 生成根CA
	rootResp, err := e.createRootCA(ctx, &req.RootCA)
	if err != nil {
		return nil, fmt.Errorf("创建根CA失败: %w", err)
	}

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
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("自签名根CA证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析根CA证书失败: %w", err)
	}

	certPEM := pemEncode(certBytes, "CERTIFICATE")

	instance := &CAInstance{
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
		AuthorityKeyId:        parent.Cert.(*x509.Certificate).SubjectKeyId,
	}

	// 使用父CA签名
	parentCert := parent.Cert.(*x509.Certificate)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubKey, parent.Signer)
	if err != nil {
		return nil, fmt.Errorf("签名中间CA证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析中间CA证书失败: %w", err)
	}

	instance := &CAInstance{
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
	parentCert := ca.Cert.(*x509.Certificate)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubKey, ca.Signer)
	if err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
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

// generateKeyID 生成主题密钥标识符
func generateKeyID(pubKey interface{}) []byte {
	// TODO: 实现SHA1哈希公钥的SubjectKeyId生成
	return []byte("placeholder")
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
