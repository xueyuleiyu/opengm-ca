package core

import (
	"context"
	"fmt"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/rs/zerolog/log"
)

// DualCertCoordinator 双证书协调器
// 负责协调VPN签名证书和加密证书的生成、关联和管理
// 遵循GM/T 0015-2012标准
type DualCertCoordinator struct {
	caEngine *CAEngine
}

// NewDualCertCoordinator 创建双证书协调器
func NewDualCertCoordinator(caEngine *CAEngine) *DualCertCoordinator {
	return &DualCertCoordinator{caEngine: caEngine}
}

// IssueDualCertificates 签发VPN双证书
// 返回签名证书和加密证书
func (d *DualCertCoordinator) IssueDualCertificates(ctx context.Context, req *model.CertificateRequest) (*model.DualCertResponse, error) {
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

	// 5. 建立证书关联
	signCert.DualCertPairID = &encCert.ID
	encCert.DualCertPairID = &signCert.ID

	// 6. 构建响应
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

	// 如果本地生成密钥，返回私钥
	if req.GenKeyLocally {
		signKeyPEM := pemEncodePrivateKey(signPrivKey)
		encKeyPEM := pemEncodePrivateKey(encPrivKey)
		resp.SignCert.PrivateKeyPEM = signKeyPEM
		resp.EncCert.PrivateKeyPEM = encKeyPEM
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

// pemEncodePrivateKey PEM编码私钥(占位)
func pemEncodePrivateKey(privKey interface{}) string {
	// TODO: 实现PKCS#8编码
	return "placeholder"
}
