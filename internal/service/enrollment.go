package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
	"github.com/google/uuid"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/core"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// EnrollmentService 证书申请服务
type EnrollmentService struct {
	cfg           *config.Config
	caEngine      *core.CAEngine
	keyGen        *opengmcrypto.KeyGenerator
	keyStore      *opengmcrypto.KeyStore
	certRepo      *repository.CertificateRepository
	keyRepo       *repository.KeyRepository
	subjectRepo   *repository.SubjectRepository
	caRepo        *repository.CAChainRepository
	auditSvc      *AuditService
	dualCertCoord *core.DualCertCoordinator
}

// NewEnrollmentService 创建证书申请服务
func NewEnrollmentService(
	cfg *config.Config,
	caEngine *core.CAEngine,
	keyStore *opengmcrypto.KeyStore,
	certRepo *repository.CertificateRepository,
	keyRepo *repository.KeyRepository,
	subjectRepo *repository.SubjectRepository,
	caRepo *repository.CAChainRepository,
	auditSvc *AuditService,
) *EnrollmentService {
	es := &EnrollmentService{
		cfg:         cfg,
		caEngine:    caEngine,
		keyGen:      opengmcrypto.NewKeyGenerator(),
		keyStore:    keyStore,
		certRepo:    certRepo,
		keyRepo:     keyRepo,
		subjectRepo: subjectRepo,
		caRepo:      caRepo,
		auditSvc:    auditSvc,
	}
	if caEngine != nil && keyStore != nil && keyRepo != nil && certRepo != nil {
		es.dualCertCoord = core.NewDualCertCoordinator(caEngine, keyStore, keyRepo, certRepo)
	}
	return es
}

// EnrollCertificate 证书申请入口
func (s *EnrollmentService) EnrollCertificate(ctx context.Context, req *model.CertificateRequest, issuedBy, actorIP string) (*model.CertificateResponse, error) {
	log.Info().Str("cert_type", req.CertType).Str("subject", req.Subject.CommonName).Bool("dual_cert", req.DualCertMode).Msg("证书申请")

	// 双证书模式：直接委托双证书协调器处理
	if req.DualCertMode {
		if s.dualCertCoord == nil {
			return nil, fmt.Errorf("双证书协调器未初始化")
		}
		if req.CertType != string(model.CertTypeVPNSign) {
			return nil, fmt.Errorf("双证书模式仅支持 VPN_SIGN 类型")
		}
		dualResp, err := s.dualCertCoord.IssueDualCertificates(ctx, req, issuedBy)
		if err != nil {
			return nil, fmt.Errorf("双证书签发失败: %w", err)
		}
		// 记录审计日志
		if s.auditSvc != nil {
			s.auditSvc.Log(ctx, model.EventCertIssue, model.SeverityInfo, issuedBy, actorIP, "CERTIFICATE", dualResp.SignCert.SerialNumber,
				fmt.Sprintf("签发VPN双证书: %s", req.Subject.CommonName), map[string]interface{}{
					"sign_serial": dualResp.SignCert.SerialNumber,
					"enc_serial":  dualResp.EncCert.SerialNumber,
					"algorithm":   req.Algorithm,
				}, model.ResultSuccess, "")
		}
		// 构造统一响应
		resp := &model.CertificateResponse{
			CertID:       dualResp.SignCert.CertID,
			SerialNumber: dualResp.SignCert.SerialNumber,
			CertPEM:      dualResp.SignCert.CertPEM,
			SubjectDN:    req.Subject.CommonName,
			IssuerDN:     "",
			Algorithm:    req.Algorithm,
			IssuedAt:     time.Now(),
			ExpiresAt:    time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
			DualCerts:    dualResp,
		}
		if dualResp.SignCert.PrivateKeyPEM != "" {
			resp.PrivateKeyPEM = &dualResp.SignCert.PrivateKeyPEM
		}
		return resp, nil
	}

	// 预处理CSR（如果提供）
	var csrPubKey interface{}
	if req.CSRPEM != "" {
		pubKey, csrSubject, err := s.parseCSR(req.CSRPEM)
		if err != nil {
			return nil, fmt.Errorf("解析CSR失败: %w", err)
		}
		csrPubKey = pubKey
		// 如果请求中没有指定主题，使用CSR中的主题
		if req.Subject.CommonName == "" {
			req.Subject = *csrSubject
		}
	}

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
	caName, err := s.selectCA(req.CertType)
	if err != nil {
		return nil, fmt.Errorf("选择CA失败: %w", err)
	}
	ca, err := s.caRepo.GetByName(ctx, caName)
	if err != nil {
		return nil, fmt.Errorf("获取CA失败: %w", err)
	}

	// 4. 处理密钥
	var privKey interface{}
	var pubKey interface{}
	var keyModel *model.CertKey

	if req.CSRPEM != "" {
		// 使用CSR中的公钥
		pubKey = csrPubKey
	} else if req.GenKeyLocally {
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
	} else {
		return nil, fmt.Errorf("必须提供CSR或选择本地生成密钥")
	}

	// 5. 校验公钥强度
	if err := validatePublicKeyStrength(pubKey, req.Algorithm); err != nil {
		return nil, fmt.Errorf("公钥强度校验失败: %w", err)
	}

	// 6. 构建证书模板并签发
	template, err := s.buildCertTemplate(req, subject, ca)
	if err != nil {
		return nil, fmt.Errorf("构建证书模板失败: %w", err)
	}

	certBytes, err := s.signCertificate(template, pubKey, ca)
	if err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}

	// 6. 解析并保存证书 (使用smx509支持SM2)
	cert, err := smx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	certHash := sha256.Sum256(certBytes)
	certModel := &model.Certificate{
		CertType:        model.CertType(req.CertType),
		CAID:            ca.ID,
		SerialNumber:    fmt.Sprintf("%X", cert.SerialNumber),
		SerialNumberDec: cert.SerialNumber.String(),
		CertPEM:         opengmcrypto.PemEncode(certBytes, "CERTIFICATE"),
		CertHashSHA256:  hex.EncodeToString(certHash[:]),
		SubjectDN:       cert.Subject.String(),
		IssuerDN:        cert.Issuer.String(),
		SignatureAlg:    model.SignatureAlgorithm(cert.SignatureAlgorithm.String()),
		PublicKeyAlg:    s.mapPublicKeyAlgorithm(req.Algorithm),
		ValidFrom:       cert.NotBefore,
		ValidTo:         cert.NotAfter,
		Status:          model.CertStatusValid,
		SubjectID:       &subject.ID,
		IssuedBy:        issuedBy,
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
		if err := s.keyRepo.UpdateCertID(ctx, keyModel.KeyID, certModel.ID); err != nil {
			return nil, fmt.Errorf("证书已签发但密钥关联失败: %w", err)
		}
	}

	// 8. Metrics 埋点
	metrics.IncCertsIssued(req.CertType)

	// 9. 审计日志
	s.auditSvc.Log(ctx, model.EventCertIssue, model.SeverityInfo, issuedBy, actorIP, "CERTIFICATE", certModel.SerialNumber,
		fmt.Sprintf("签发%s证书: %s", req.CertType, req.Subject.CommonName), map[string]interface{}{
			"cert_id":   certModel.ID,
			"serial":    certModel.SerialNumber,
			"algorithm": req.Algorithm,
			"validity":  req.ValidityDays,
		}, model.ResultSuccess, "")

	// 10. 构建响应
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
		privKeyPEM, err := s.encodePrivateKey(privKey, req.Algorithm)
		if err != nil {
			log.Warn().Err(err).Msg("编码私钥失败，响应中不包含私钥")
		} else if privKeyPEM != "" {
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

	// CSR模式下不校验算法（从CSR自动推断）
	if req.CSRPEM == "" && !slices.Contains(s.cfg.CertPolicy.AllowedAlgorithms, req.Algorithm) {
		return fmt.Errorf("不支持的算法: %s", req.Algorithm)
	}

	// CSR模式下Subject可以为空（从CSR提取）
	if req.CSRPEM == "" {
		if req.Subject.CommonName == "" {
			return fmt.Errorf("缺少证书主题CommonName")
		}
	}

	// 校验Subject字段（防止X.500注入和日志伪造）
	if err := sanitizeSubject(&req.Subject); err != nil {
		return fmt.Errorf("主题字段非法: %w", err)
	}

	// 校验SAN值
	for _, san := range req.Extensions.SubjectAltNames {
		if san.Type == "dns" {
			if strings.Contains(san.Value, "\n") || strings.Contains(san.Value, "\x00") {
				return fmt.Errorf("DNS SAN包含非法字符")
			}
		} else if san.Type == "ip" {
			if net.ParseIP(san.Value) == nil {
				return fmt.Errorf("IP SAN格式无效: %s", san.Value)
			}
		}
	}

	return nil
}

// selectCA 根据证书类型选择CA
func (s *EnrollmentService) selectCA(certType string) (string, error) {
	switch certType {
	case "SSL":
		return "SSL-CA", nil
	case "AUTH":
		return "AUTH-CA", nil
	case "VPN", "VPN_SIGN", "VPN_ENC":
		return "VPN-CA", nil
	default:
		return "", fmt.Errorf("不支持的证书类型: %s", certType)
	}
}

// createKeyRecord 创建密钥记录
func (s *EnrollmentService) createKeyRecord(ctx context.Context, subjectID int, req *model.CertificateRequest, privKey, pubKey interface{}, createdBy string) (*model.CertKey, error) {
	pubKeyPEM, err := opengmcrypto.EncodePublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("编码公钥失败: %w", err)
	}

	// 计算公钥哈希
	pubKeyHash := sha256.Sum256([]byte(pubKeyPEM))
	keyModel := &model.CertKey{
		KeyID:         uuid.New().String(),
		KeyType:       model.KeyTypeSignature,
		Algorithm:     model.KeyAlgorithm(req.Algorithm),
		PublicKeyPEM:  pubKeyPEM,
		PublicKeyHash: hex.EncodeToString(pubKeyHash[:]),
		StorageType:   model.KeyStorageSoftware,
		SubjectID:     &subjectID,
		Exportable:    req.Exportable,
		MaxExports:    s.cfg.KeyManagement.Export.MaxExportsPerKey,
		CreatedBy:     createdBy,
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
	return opengmcrypto.EncodePrivateKey(privKey, algorithm)
}

// parseCSR 解析标准PKCS#10 CSR，返回公钥和主题信息
func (s *EnrollmentService) parseCSR(csrPEM string) (interface{}, *model.SubjectInfo, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("无效的CSR PEM格式")
	}

	// 尝试 smx509（支持SM2国密CSR）
	csrSM2, err := smx509.ParseCertificateRequest(block.Bytes)
	if err == nil {
		if err := csrSM2.CheckSignature(); err != nil {
			return nil, nil, fmt.Errorf("CSR签名验证失败: %w", err)
		}
		subject := extractSubjectFromCSR(csrSM2.Subject, csrSM2.DNSNames)
		return csrSM2.PublicKey, subject, nil
	}

	// 回退到标准x509
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析CSR失败: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR签名验证失败: %w", err)
	}

	subject := extractSubjectFromCSR(csr.Subject, csr.DNSNames)
	return csr.PublicKey, subject, nil
}

func extractSubjectFromCSR(subj pkix.Name, dnsNames []string) *model.SubjectInfo {
	subject := &model.SubjectInfo{
		CommonName:         subj.CommonName,
		Organization:       firstOrEmpty(subj.Organization),
		OrganizationalUnit: firstOrEmpty(subj.OrganizationalUnit),
		Country:            firstOrEmpty(subj.Country),
		State:              firstOrEmpty(subj.Province),
		Locality:           firstOrEmpty(subj.Locality),
	}
	return subject
}

// firstOrEmpty 返回字符串切片的第一个元素，或空字符串
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// buildCertTemplate 构建证书模板
func (s *EnrollmentService) buildCertTemplate(req *model.CertificateRequest, subject *model.Subject, ca *model.CAChain) (*x509.Certificate, error) {
	// 使用加密安全随机数生成证书序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}

	now := time.Now()
	notAfter := now.AddDate(0, 0, req.ValidityDays)
	// 终端证书有效期不得超过签名CA有效期
	if notAfter.After(ca.ValidTo) {
		notAfter = ca.ValidTo
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         subject.CommonName,
			Organization:       []string{subject.Organization},
			OrganizationalUnit: []string{subject.OrganizationalUnit},
			Country:            []string{subject.Country},
			Province:           []string{subject.State},
			Locality:           []string{subject.Locality},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// 根据证书类型应用模板配置（支持YAML驱动）
	if tmplCfg, ok := s.cfg.CertTemplates[req.CertType]; ok {
		if err := core.ApplyCertTemplate(template, tmplCfg); err != nil {
			return nil, fmt.Errorf("应用证书模板失败: %w", err)
		}
	} else {
		// 默认模板
		switch req.CertType {
		case "AUTH":
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		default:
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}

	// 添加SAN扩展
	if len(req.Extensions.SubjectAltNames) > 0 {
		var dnsNames []string
		var ipAddresses []net.IP
		for _, san := range req.Extensions.SubjectAltNames {
			switch san.Type {
			case "dns":
				dnsNames = append(dnsNames, san.Value)
			case "ip":
				if ip := net.ParseIP(san.Value); ip != nil {
					ipAddresses = append(ipAddresses, ip)
				}
			}
		}
		template.DNSNames = dnsNames
		template.IPAddresses = ipAddresses
	}

	return template, nil
}

// signCertificate 使用CA签名证书
func (s *EnrollmentService) signCertificate(template *x509.Certificate, pubKey interface{}, ca *model.CAChain) ([]byte, error) {
	caInstance, err := s.caEngine.GetCA(ca.CAName)
	if err != nil {
		return nil, fmt.Errorf("获取CA实例失败(%s): %w", ca.CAName, err)
	}

	// 添加关键PKI扩展
	keyID, err := core.GenerateKeyID(pubKey)
	if err != nil {
		return nil, fmt.Errorf("生成SubjectKeyId失败: %w", err)
	}
	template.SubjectKeyId = keyID
	template.AuthorityKeyId = caInstance.Cert.SubjectKeyId

	certBytes, err := smx509.CreateCertificate(rand.Reader, template, caInstance.Cert, pubKey, caInstance.Signer)
	if err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}
	return certBytes, nil
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

// validatePublicKeyStrength 校验公钥强度
func validatePublicKeyStrength(pubKey interface{}, algorithm string) error {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if bits < 2048 {
			return fmt.Errorf("RSA密钥强度不足: %d位(最低要求2048位)", bits)
		}
	case *ecdsa.PublicKey:
		curveBits := key.Curve.Params().BitSize
		isSM2Curve := sm2.P256() != nil && key.Curve.Params().Name == sm2.P256().Params().Name
		if algorithm == "SM2" {
			if !isSM2Curve {
				return fmt.Errorf("公钥曲线不是SM2标准曲线")
			}
			if curveBits < 256 {
				return fmt.Errorf("SM2曲线强度不足: %d位(最低要求256位)", curveBits)
			}
			return nil
		}
		if isSM2Curve {
			return fmt.Errorf("SM2公钥不能用于非SM2算法: %s", algorithm)
		}
		if curveBits < 256 {
			return fmt.Errorf("ECDSA曲线强度不足: %d位(最低要求256位)", curveBits)
		}
	default:
		return fmt.Errorf("无法识别的公钥类型: %T", pubKey)
	}
	return nil
}

var invalidChars = regexp.MustCompile(`[\x00-\x08\x0a-\x1f\x7f]`)

// sanitizeSubject 净化证书主题字段，防止X.500注入和日志伪造
func sanitizeSubject(subject *model.SubjectInfo) error {
	for name, value := range map[string]string{
		"CommonName":         subject.CommonName,
		"Organization":       subject.Organization,
		"OrganizationalUnit": subject.OrganizationalUnit,
		"Country":            subject.Country,
		"State":              subject.State,
		"Locality":           subject.Locality,
	} {
		if invalidChars.MatchString(value) {
			return fmt.Errorf("字段 %s 包含非法控制字符", name)
		}
	}
	return nil
}
