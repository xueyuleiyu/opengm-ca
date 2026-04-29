package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// EnrollmentService 证书申请服务
type EnrollmentService struct {
	cfg           *config.Config
	caEngine      *core.CAEngine
	keyGen        *crypto.KeyGenerator
	keyStore      *crypto.KeyStore
	certRepo      *repository.CertificateRepository
	keyRepo       *repository.KeyRepository
	subjectRepo   *repository.SubjectRepository
	caRepo        *repository.CAChainRepository
	auditSvc      *AuditService
}

// NewEnrollmentService 创建证书申请服务
func NewEnrollmentService(
	cfg *config.Config,
	caEngine *core.CAEngine,
	keyStore *crypto.KeyStore,
	certRepo *repository.CertificateRepository,
	keyRepo *repository.KeyRepository,
	subjectRepo *repository.SubjectRepository,
	caRepo *repository.CAChainRepository,
	auditSvc *AuditService,
) *EnrollmentService {
	return &EnrollmentService{
		cfg:         cfg,
		caEngine:    caEngine,
		keyGen:      crypto.NewKeyGenerator(),
		keyStore:    keyStore,
		certRepo:    certRepo,
		keyRepo:     keyRepo,
		subjectRepo: subjectRepo,
		caRepo:      caRepo,
		auditSvc:    auditSvc,
	}
}

// EnrollCertificate 证书申请入口
func (s *EnrollmentService) EnrollCertificate(ctx context.Context, req *model.CertificateRequest, issuedBy string) (*model.CertificateResponse, error) {
	log.Info().Str("cert_type", req.CertType).Str("subject", req.Subject.CommonName).Msg("证书申请")

	// 1. 参数校验
	if err := s.validateRequest(req); err != nil {
		return nil, fmt.Errorf("请求参数无效: %w", err)
	}

	// 2. 获取或创建Subject
	subject, err := s.subjectRepo.GetOrCreate(ctx, &req.Subject)
	if err != nil {
		return nil, fmt.Errorf("创建证书主体失败: %w", err)
	}

	// 3. 确定使用哪个CA
	caName := s.selectCA(req.CertType)
	ca, err := s.caRepo.GetByName(ctx, caName)
	if err != nil {
		return nil, fmt.Errorf("获取CA失败: %w", err)
	}

	// 4. 处理密钥
	var privKey interface{}
	var pubKey interface{}
	var keyModel *model.CertKey

	if req.GenKeyLocally {
		// 本地生成密钥对
		privKey, pubKey, err = s.keyGen.GenerateKeyPair(req.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("生成密钥对失败: %w", err)
		}

		// 创建密钥记录
		keyModel, err = s.createKeyRecord(ctx, subject.ID, req, privKey, pubKey, issuedBy)
		if err != nil {
			return nil, fmt.Errorf("保存密钥记录失败: %w", err)
		}
	} else if req.CSRPEM != "" {
		// 解析CSR
		pubKey, err = s.parseCSR(req.CSRPEM)
		if err != nil {
			return nil, fmt.Errorf("解析CSR失败: %w", err)
		}
	} else {
		return nil, fmt.Errorf("必须提供CSR或选择本地生成密钥")
	}

	// 5. 构建证书模板并签发
	template, err := s.buildCertTemplate(req, subject, ca)
	if err != nil {
		return nil, fmt.Errorf("构建证书模板失败: %w", err)
	}

	certBytes, err := s.signCertificate(template, pubKey, ca)
	if err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}

	// 6. 解析并保存证书
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	certModel := &model.Certificate{
		CertType:      model.CertType(req.CertType),
		CAID:          ca.ID,
		SerialNumber:  fmt.Sprintf("%X", cert.SerialNumber),
		SerialNumberDec: cert.SerialNumber.String(),
		CertPEM:       crypto.PemEncode(certBytes, "CERTIFICATE"),
		SubjectDN:     cert.Subject.String(),
		IssuerDN:      cert.Issuer.String(),
		SignatureAlg:  model.SignatureAlgorithm(cert.SignatureAlgorithm.String()),
		PublicKeyAlg:  s.mapPublicKeyAlgorithm(req.Algorithm),
		ValidFrom:     cert.NotBefore,
		ValidTo:       cert.NotAfter,
		Status:        model.CertStatusValid,
		SubjectID:     &subject.ID,
		IssuedBy:      issuedBy,
	}

	if keyModel != nil {
		certModel.KeyID = keyModel.KeyID
	}

	if err := s.certRepo.Create(ctx, certModel); err != nil {
		return nil, fmt.Errorf("保存证书记录失败: %w", err)
	}

	// 7. 更新密钥关联的证书ID
	if keyModel != nil {
		keyModel.CertID = &certModel.ID
		// TODO: update key record
	}

	// 8. 审计日志
	s.auditSvc.Log(ctx, model.EventCertIssue, model.SeverityInfo, issuedBy, "", "CERTIFICATE", certModel.SerialNumber,
		fmt.Sprintf("签发%s证书: %s", req.CertType, req.Subject.CommonName), map[string]interface{}{
			"cert_id":   certModel.ID,
			"serial":    certModel.SerialNumber,
			"algorithm": req.Algorithm,
			"validity":  req.ValidityDays,
		}, model.ResultSuccess, "")

	// 9. 构建响应
	resp := &model.CertificateResponse{
		CertID:       fmt.Sprintf("%d", certModel.ID),
		SerialNumber: certModel.SerialNumber,
		CertPEM:      certModel.CertPEM,
		SubjectDN:    certModel.SubjectDN,
		IssuerDN:     certModel.IssuerDN,
		Algorithm:    req.Algorithm,
		IssuedAt:     certModel.ValidFrom,
		ExpiresAt:    certModel.ValidTo,
	}

	if keyModel != nil {
		resp.KeyID = keyModel.KeyID
		privKeyPEM, _ := s.encodePrivateKey(privKey, req.Algorithm)
		if privKeyPEM != "" {
			resp.PrivateKeyPEM = &privKeyPEM
		}
	}

	return resp, nil
}

// validateRequest 校验证书申请请求
func (s *EnrollmentService) validateRequest(req *model.CertificateRequest) error {
	if req.ValidityDays <= 0 || req.ValidityDays > s.cfg.CertPolicy.MaxValidityDays {
		return fmt.Errorf("有效期必须在1-%d天之间", s.cfg.CertPolicy.MaxValidityDays)
	}

	validAlg := false
	for _, a := range s.cfg.CertPolicy.AllowedAlgorithms {
		if a == req.Algorithm {
			validAlg = true
			break
		}
	}
	if !validAlg {
		return fmt.Errorf("不支持的算法: %s", req.Algorithm)
	}

	return nil
}

// selectCA 根据证书类型选择CA
func (s *EnrollmentService) selectCA(certType string) string {
	switch certType {
	case "SSL":
		return "SSL-CA"
	case "AUTH":
		return "AUTH-CA"
	case "VPN", "VPN_SIGN", "VPN_ENC":
		return "VPN-CA"
	default:
		return "SSL-CA"
	}
}

// createKeyRecord 创建密钥记录
func (s *EnrollmentService) createKeyRecord(ctx context.Context, subjectID int, req *model.CertificateRequest, privKey, pubKey interface{}, createdBy string) (*model.CertKey, error) {
	pubKeyPEM, err := crypto.EncodePublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("编码公钥失败: %w", err)
	}

	keyModel := &model.CertKey{
		KeyID:        uuid.New().String(),
		KeyType:      model.KeyTypeSignature,
		Algorithm:    model.KeyAlgorithm(req.Algorithm),
		PublicKeyPEM: pubKeyPEM,
		StorageType:  model.KeyStorageSoftware,
		SubjectID:    &subjectID,
		Exportable:   req.Exportable,
		MaxExports:   s.cfg.KeyManagement.Export.MaxExportsPerKey,
		CreatedBy:    createdBy,
	}

	// 加密存储私钥
	privKeyPEM, err := s.encodePrivateKey(privKey, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}

	if err := s.keyStore.StoreKey(keyModel, []byte(privKeyPEM)); err != nil {
		return nil, fmt.Errorf("加密存储私钥失败: %w", err)
	}

	if err := s.keyRepo.Create(ctx, keyModel); err != nil {
		return nil, fmt.Errorf("保存密钥记录失败: %w", err)
	}

	return keyModel, nil
}

// encodePrivateKey 编码私钥为PEM
func (s *EnrollmentService) encodePrivateKey(privKey interface{}, algorithm string) (string, error) {
	switch algorithm {
	case "RSA2048", "RSA4096":
		importRSA := privKey.(*rsa.PrivateKey)
		return crypto.EncodePrivateKeyToPKCS1(importRSA)
	case "EC256", "EC384":
		importEC := privKey.(*ecdsa.PrivateKey)
		return crypto.EncodeECPrivateKey(importEC)
	default:
		return crypto.EncodePrivateKeyToPKCS8(privKey)
	}
}

// parseCSR 解析CSR获取公钥
func (s *EnrollmentService) parseCSR(csrPEM string) (interface{}, error) {
	// TODO: 实现CSR解析
	return nil, fmt.Errorf("CSR解析尚未实现")
}

// buildCertTemplate 构建证书模板
func (s *EnrollmentService) buildCertTemplate(req *model.CertificateRequest, subject *model.Subject, ca *model.CAChain) (*x509.Certificate, error) {
	serialNumber := new(big.Int)
	serialNumber.SetBytes([]byte(uuid.New().String()))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         subject.CommonName,
			Organization:       []string{subject.Organization},
			OrganizationalUnit: []string{subject.OrganizationalUnit},
			Country:            []string{subject.Country},
			State:              []string{subject.State},
			Locality:           []string{subject.Locality},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().AddDate(0, 0, req.ValidityDays),
	}

	// 根据证书类型设置KeyUsage和ExtKeyUsage
	switch req.CertType {
	case "SSL":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case "AUTH":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageNonRepudiation
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	case "VPN_SIGN":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageNonRepudiation
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}
	case "VPN_ENC":
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}
	default:
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	// 添加SAN扩展
	if len(req.Extensions.SubjectAltNames) > 0 {
		var dnsNames []string
		var ipAddresses []string
		for _, san := range req.Extensions.SubjectAltNames {
			switch san.Type {
			case "dns":
				dnsNames = append(dnsNames, san.Value)
			case "ip":
				ipAddresses = append(ipAddresses, san.Value)
			}
		}
		template.DNSNames = dnsNames
		// TODO: 添加IP地址
		_ = ipAddresses
	}

	return template, nil
}

// signCertificate 使用CA签名证书
func (s *EnrollmentService) signCertificate(template *x509.Certificate, pubKey interface{}, ca *model.CAChain) ([]byte, error) {
	// TODO: 从CA实例中获取签名密钥和父证书
	// 目前使用简化实现
	return nil, fmt.Errorf("签名功能需要完善CA引擎加载")
}

// mapPublicKeyAlgorithm 映射公钥算法
func (s *EnrollmentService) mapPublicKeyAlgorithm(algorithm string) model.PublicKeyAlgorithm {
	switch algorithm {
	case "SM2":
		return model.PubKeySM2
	case "RSA2048", "RSA4096":
		return model.PubKeyRSA
	case "EC256", "EC384":
		return model.PubKeyEC
	default:
		return model.PubKeySM2
	}
}
