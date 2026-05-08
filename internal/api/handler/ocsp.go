package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ocsp"
)

var (
	// ocspResponderKey OCSP Responder 签名私钥
	ocspResponderKey crypto.Signer
	// ocspResponderCert OCSP Responder 证书
	ocspResponderCert *x509.Certificate
	// ocspResponderInitialized 标记是否已初始化
	ocspResponderInitialized bool
)

// InitOCSPResponder 初始化 OCSP Responder 证书和密钥
// 如果配置了正式证书路径，则加载正式证书；否则生成临时自签名证书（仅用于测试）
func InitOCSPResponder(certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		cert, err := parseCertificatePEM(certPEM)
		if err != nil {
			return err
		}
		key, err := parsePrivateKeyPEM(keyPEM)
		if err != nil {
			return err
		}
		ocspResponderCert = cert
		ocspResponderKey = key
		ocspResponderInitialized = true
		log.Info().Str("subject", cert.Subject.String()).Msg("OCSP Responder 使用配置的正式证书")
		return nil
	}

	// 未配置时生成临时证书（仅用于测试/开发）
	log.Warn().Msg("OCSP Responder 未配置正式证书，正在生成临时自签名证书（生产环境不可信任）")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "openGM-CA OCSP Responder (TEMPORARY)",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	ocspResponderCert = cert
	ocspResponderKey = key
	ocspResponderInitialized = true
	return nil
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, os.ErrInvalid
	}
	return signer, nil
}

// OCSPHandler OCSP响应Handler
type OCSPHandler struct {
	certRepo *repository.CertificateRepository
	caRepo   *repository.CAChainRepository
}

// NewOCSPHandler 创建OCSP Handler
func NewOCSPHandler(certRepo *repository.CertificateRepository, caRepo *repository.CAChainRepository) *OCSPHandler {
	return &OCSPHandler{certRepo: certRepo, caRepo: caRepo}
}

// HandleRequest 处理OCSP请求
// 支持标准DER格式: POST Content-Type=application/ocsp-request (body=DER)
// 或JSON格式: POST { "serial_number": "...", "ca_name": "..." }
// 或查询参数: GET ?serial=...&ca_name=...
func (h *OCSPHandler) HandleRequest(c *gin.Context) {
	if !ocspResponderInitialized {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "OCSP Responder 未初始化"})
		return
	}

	metrics.IncOCSPQueries()
	ctx := c.Request.Context()

	contentType := c.ContentType()
	var serialNumber string
	var caName string
	var isDERRequest bool

	if contentType == "application/ocsp-request" || c.GetHeader("Accept") == "application/ocsp-response" {
		isDERRequest = true
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(c.Request.Body); err != nil {
			c.Data(http.StatusBadRequest, "application/ocsp-response", buildOCSPError(int(ocsp.Malformed)))
			return
		}
		req, err := ocsp.ParseRequest(buf.Bytes())
		if err != nil {
			c.Data(http.StatusBadRequest, "application/ocsp-response", buildOCSPError(int(ocsp.Malformed)))
			return
		}
		serialNumber = req.SerialNumber.Text(16)
	} else {
		var req ocspJSONRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.SerialNumber == "" {
			req.SerialNumber = c.Query("serial")
			req.CAName = c.Query("ca_name")
		}
		serialNumber = req.SerialNumber
		caName = req.CAName
	}

	if serialNumber == "" {
		if isDERRequest {
			c.Data(http.StatusBadRequest, "application/ocsp-response", buildOCSPError(int(ocsp.Malformed)))
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_REQUEST", "message": "缺少证书序列号"})
		return
	}

	resp, err := h.queryStatus(ctx, serialNumber, caName)
	if err != nil {
		if isDERRequest {
			c.Data(http.StatusInternalServerError, "application/ocsp-response", buildOCSPError(int(ocsp.TryLater)))
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	// DER格式请求返回DER响应
	if isDERRequest {
		ocspResp := ocsp.Response{
			Status:       resp.StatusCode,
			SerialNumber: resp.SerialBigInt,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
			ProducedAt:   time.Now(),
		}
		if resp.StatusCode == ocsp.Revoked && resp.RevokedAt != nil {
			ocspResp.RevokedAt = *resp.RevokedAt
			if resp.Reason >= 0 {
				ocspResp.RevocationReason = resp.Reason
			}
		}
		derResp, err := ocsp.CreateResponse(ocspResponderCert, ocspResponderCert, ocspResp, ocspResponderKey)
		if err != nil {
			c.Data(http.StatusInternalServerError, "application/ocsp-response", buildOCSPError(int(ocsp.InternalError)))
			return
		}
		c.Data(http.StatusOK, "application/ocsp-response", derResp)
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// buildOCSPError 构建简化的OCSP错误响应 (RFC 6960)
func buildOCSPError(status int) []byte {
	// OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus }
	statusBytes := []byte{0x0a, 0x01, byte(status)} // ENUMERATED, length 1, value
	seqBytes := append([]byte{0x30, byte(len(statusBytes))}, statusBytes...)
	return seqBytes
}

func (h *OCSPHandler) queryStatus(ctx context.Context, serialNumber, caName string) (*ocspJSONResponse, error) {
	resp := &ocspJSONResponse{
		SerialNumber: serialNumber,
		Status:       "UNKNOWN",
		StatusCode:   ocsp.Unknown,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	var caID int
	if caName != "" {
		ca, err := h.caRepo.GetByName(ctx, caName)
		if err == nil {
			caID = ca.ID
			resp.IssuerDN = ca.SubjectDN
		}
	}

	var cert *model.Certificate
	var err error
	if caID > 0 {
		cert, err = h.certRepo.GetBySerialNumber(ctx, caID, serialNumber)
	} else {
		certs, _, err := h.certRepo.List(ctx, map[string]interface{}{"serial_number": serialNumber}, 0, 10)
		if err == nil && len(certs) > 0 {
			cert = &certs[0]
		}
	}
	if err != nil || cert == nil {
		return resp, nil
	}

	resp.IssuerDN = cert.IssuerDN
	sn := new(big.Int)
	if _, ok := sn.SetString(cert.SerialNumber, 16); ok {
		resp.SerialBigInt = sn
	}

	switch cert.Status {
	case model.CertStatusValid:
		if cert.IsExpired() {
			resp.Status = "UNKNOWN"
			resp.StatusCode = ocsp.Unknown
		} else {
			resp.Status = "GOOD"
			resp.StatusCode = ocsp.Good
		}
	case model.CertStatusRevoked:
		resp.Status = "REVOKED"
		resp.StatusCode = ocsp.Revoked
		resp.RevokedAt = cert.RevokedAt
		if cert.RevocationReason != nil {
			resp.Reason = *cert.RevocationReason
		}
	case model.CertStatusExpired:
		resp.Status = "UNKNOWN"
		resp.StatusCode = ocsp.Unknown
	default:
		resp.Status = "UNKNOWN"
		resp.StatusCode = ocsp.Unknown
	}

	return resp, nil
}

type ocspJSONRequest struct {
	SerialNumber string `json:"serial_number" form:"serial"`
	CAName       string `json:"ca_name" form:"ca_name"`
}

type ocspJSONResponse struct {
	SerialNumber string     `json:"serial_number"`
	Status       string     `json:"status"` // GOOD | REVOKED | UNKNOWN
	StatusCode   int        `json:"-"`
	SerialBigInt *big.Int   `json:"-"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Reason       int        `json:"reason,omitempty"`
	ThisUpdate   time.Time  `json:"this_update"`
	NextUpdate   time.Time  `json:"next_update"`
	IssuerDN     string     `json:"issuer_dn,omitempty"`
}
