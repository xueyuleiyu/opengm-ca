package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// DualCertCoordinator 双证书协调器
// 负责协调VPN签名证书和加密证书的生成、关联和管理
// 遵循GM/T 0015-2012标准
type DualCertCoordinator struct {
	caEngine *CAEngine
	keyStore *opengmcrypto.KeyStore
	keyRepo  *repository.KeyRepository
	certRepo *repository.CertificateRepository
}

// NewDualCertCoordinator 创建双证书协调器
func NewDualCertCoordinator(caEngine *CAEngine, keyStore *opengmcrypto.KeyStore, keyRepo *repository.KeyRepository, certRepo *repository.CertificateRepository) *DualCertCoordinator {
	return &DualCertCoordinator{caEngine: caEngine, keyStore: keyStore, keyRepo: keyRepo, certRepo: certRepo}
}

// IssueDualCertificates 签发VPN双证书
// 返回签名证书和加密证书
func (d *DualCertCoordinator) IssueDualCertificates(ctx context.Context, req *model.CertificateRequest, issuedBy string) (*model.DualCertResponse, error) {
	if !req.DualCertMode {
		return nil, fmt.Errorf("非双证书模式请求")
	}

	log.Info().Str("subject", req.Subject.CommonName).Msg("开始签发VPN双证书")

	// 1. 生成签名密钥对
	signPrivKey, signPubKey, err := generateKeyPair(req.Algorithm, 256)
	if err != nil {
		return nil, fmt.Errorf("生成签名密钥对失败: %w", err)
	}

	// 2. 生成加密密钥对
	encPrivKey, encPubKey, err := generateKeyPair(req.Algorithm, 256)
	if err != nil {
		return nil, fmt.Errorf("生成加密密钥对失败: %w", err)
	}

	// 3. 签发签名证书
	signReq := *req
	signReq.CertType = "VPN_SIGN"
	signReq.Extensions = model.CertExtensions{
		KeyUsage:    []string{"digitalSignature", "nonRepudiation"},
		ExtKeyUsage: []string{"ipsecEndSystem"},
	}

	signCert, err := d.caEngine.IssueCertificate(ctx, "VPN-CA", &signReq, signPubKey)
	if err != nil {
		return nil, fmt.Errorf("签发签名证书失败: %w", err)
	}

	// 4. 签发加密证书
	encReq := *req
	encReq.CertType = "VPN_ENC"
	encReq.Extensions = model.CertExtensions{
		KeyUsage:    []string{"keyEncipherment", "dataEncipherment"},
		ExtKeyUsage: []string{"ipsecTunnel"},
	}

	encCert, err := d.caEngine.IssueCertificate(ctx, "VPN-CA", &encReq, encPubKey)
	if err != nil {
		return nil, fmt.Errorf("签发加密证书失败: %w", err)
	}

	// 5. 持久化证书到数据库（获取自增ID）
	now := time.Now()
	signCert.Status = model.CertStatusValid
	signCert.IssuedAt = now
	encCert.Status = model.CertStatusValid
	encCert.IssuedAt = now
	// 补充数据库必填字段
	if signCert.CertHashSHA256 == "" {
		hash := sha256.Sum256([]byte(signCert.CertPEM))
		signCert.CertHashSHA256 = hex.EncodeToString(hash[:])
	}
	if encCert.CertHashSHA256 == "" {
		hash := sha256.Sum256([]byte(encCert.CertPEM))
		encCert.CertHashSHA256 = hex.EncodeToString(hash[:])
	}
	// 获取CA ID
	ca, err := d.caEngine.GetCA("VPN-CA")
	if err == nil {
		signCert.CAID = ca.CAID
		encCert.CAID = ca.CAID
	}
	signCert.IssuedBy = issuedBy
	encCert.IssuedBy = issuedBy
	if err := d.certRepo.Create(ctx, signCert); err != nil {
		return nil, fmt.Errorf("保存签名证书失败: %w", err)
	}
	if err := d.certRepo.Create(ctx, encCert); err != nil {
		return nil, fmt.Errorf("保存加密证书失败: %w", err)
	}

	// 6. 建立证书关联
	signCert.DualCertPairID = &encCert.ID
	encCert.DualCertPairID = &signCert.ID
	if err := d.certRepo.UpdateDualCertPairID(ctx, signCert.ID, encCert.ID); err != nil {
		log.Warn().Err(err).Msg("双证书配对关联更新失败")
	}

	// 7. 存储私钥并构建响应
	resp := &model.DualCertResponse{
		SignCert: model.CertKeyPair{
			CertID:       fmt.Sprintf("%d", signCert.ID),
			SerialNumber: signCert.SerialNumber,
			CertPEM:      signCert.CertPEM,
			KeyUsage:     []string{"digitalSignature", "nonRepudiation"},
			ExtKeyUsage:  []string{"ipsecEndSystem"},
		},
		EncCert: model.CertKeyPair{
			CertID:       fmt.Sprintf("%d", encCert.ID),
			SerialNumber: encCert.SerialNumber,
			CertPEM:      encCert.CertPEM,
			KeyUsage:     []string{"keyEncipherment", "dataEncipherment"},
			ExtKeyUsage:  []string{"ipsecTunnel"},
		},
	}

	if req.GenKeyLocally {
		signKeyPEM, err := pemEncodePrivateKey(signPrivKey, req.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("编码签名私钥失败: %w", err)
		}
		encKeyPEM, err := pemEncodePrivateKey(encPrivKey, req.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("编码加密私钥失败: %w", err)
		}
		resp.SignCert.PrivateKeyPEM = signKeyPEM
		resp.EncCert.PrivateKeyPEM = encKeyPEM
	}

	// 7. 持久化私钥到密钥库
	if d.keyStore != nil && d.keyRepo != nil {
		if err := d.storeDualKey(ctx, req.Algorithm, signPrivKey, signCert.SerialNumber, true); err != nil {
			log.Warn().Err(err).Msg("签名私钥持久化失败")
		}
		if err := d.storeDualKey(ctx, req.Algorithm, encPrivKey, encCert.SerialNumber, false); err != nil {
			log.Warn().Err(err).Msg("加密私钥持久化失败")
		}
	}

	log.Info().Str("sign_cert_sn", signCert.SerialNumber).
		Str("enc_cert_sn", encCert.SerialNumber).
		Str("subject", req.Subject.CommonName).
		Msg("VPN双证书签发成功")

	return resp, nil
}

// ValidateDualCertPair 验证双证书配对关系
func (d *DualCertCoordinator) ValidateDualCertPair(signCert, encCert *model.Certificate) error {
	if signCert.CertType != model.CertTypeVPNSign {
		return fmt.Errorf("签名证书类型错误: %s", signCert.CertType)
	}
	if encCert.CertType != model.CertTypeVPNEnc {
		return fmt.Errorf("加密证书类型错误: %s", encCert.CertType)
	}
	if signCert.SubjectDN != encCert.SubjectDN {
		return fmt.Errorf("双证书主题不一致")
	}
	if signCert.IssuerDN != encCert.IssuerDN {
		return fmt.Errorf("双证书签发者不一致")
	}
	return nil
}

// pemEncodePrivateKey PEM编码私钥
func pemEncodePrivateKey(privKey interface{}, algorithm string) (string, error) {
	return opengmcrypto.EncodePrivateKey(privKey, algorithm)
}

// storeDualKey 存储双证书中的私钥
func (d *DualCertCoordinator) storeDualKey(ctx context.Context, algorithm string, privKey interface{}, serialNumber string, isSign bool) error {
	keyType := model.KeyTypeEncryption
	if isSign {
		keyType = model.KeyTypeSignature
	}
	keyModel := &model.CertKey{
		KeyID:       uuid.New().String(),
		KeyType:     keyType,
		Algorithm:   model.KeyAlgorithm(algorithm),
		StorageType: model.KeyStorageSoftware,
		Exportable:  false,
	}
	privKeyPEM, err := pemEncodePrivateKey(privKey, algorithm)
	if err != nil {
		return err
	}
	if err := d.keyStore.StoreKey(keyModel, []byte(privKeyPEM)); err != nil {
		return err
	}
	return d.keyRepo.Create(ctx, keyModel)
}
