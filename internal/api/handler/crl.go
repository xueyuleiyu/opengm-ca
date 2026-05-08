package handler

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// CRLHandler CRL管理Handler
type CRLHandler struct {
	caEngine *core.CAEngine
	certRepo *repository.CertificateRepository
	caRepo   *repository.CAChainRepository
	auditSvc *service.AuditService
}

// NewCRLHandler 创建CRL Handler
func NewCRLHandler(caEngine *core.CAEngine, certRepo *repository.CertificateRepository, caRepo *repository.CAChainRepository, auditSvc *service.AuditService) *CRLHandler {
	return &CRLHandler{caEngine: caEngine, certRepo: certRepo, caRepo: caRepo, auditSvc: auditSvc}
}

// GenerateCRL 生成并返回DER编码的CRL (RFC 5280)
func (h *CRLHandler) GenerateCRL(c *gin.Context) {
	caName := c.Param("ca_name")
	if caName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "CA名称不能为空"})
		return
	}

	ctx := c.Request.Context()

	// 验证CA存在
	ca, err := h.caRepo.GetByName(ctx, caName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "CA_NOT_FOUND", "message": "CA不存在"})
		return
	}

	// 获取CA实例（用于签名CRL）
	caInstance, err := h.caEngine.GetCA(caName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "CA引擎未加载: " + err.Error()})
		return
	}

	// 查询该CA下已吊销的证书
	filters := map[string]interface{}{
		"status": string(model.CertStatusRevoked),
	}
	revokedCerts, _, err := h.certRepo.List(ctx, filters, 0, 10000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "查询吊销证书失败: " + err.Error()})
		return
	}

	// Metrics 埋点
	metrics.IncCRLRequests()

	// 构建CRL条目
	var revokedEntries []pkix.RevokedCertificate
	for _, cert := range revokedCerts {
		if cert.CAID != ca.ID {
			continue
		}
		sn := new(big.Int)
		if _, ok := sn.SetString(cert.SerialNumber, 16); !ok {
			sn.SetString(cert.SerialNumber, 10)
		}
		if sn.Sign() <= 0 {
			continue
		}
		rc := pkix.RevokedCertificate{
			SerialNumber:   sn,
			RevocationTime: *cert.RevokedAt,
		}
		if cert.RevocationReason != nil {
			reasonBytes, err := asn1.Marshal(asn1.Enumerated(*cert.RevocationReason))
			if err == nil {
				rc.Extensions = append(rc.Extensions, pkix.Extension{
					Id:    asn1.ObjectIdentifier{2, 5, 29, 21},
					Value: reasonBytes,
				})
			}
		}
		revokedEntries = append(revokedEntries, rc)
	}

	thisUpdate := time.Now()
	nextUpdate := thisUpdate.Add(48 * time.Hour)

	crlBytes, err := caInstance.Cert.CreateCRL(rand.Reader, caInstance.Signer, revokedEntries, thisUpdate, nextUpdate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "CRL_GENERATION_FAILED", "message": "CRL签名生成失败: " + err.Error()})
		return
	}

	if h.auditSvc != nil {
		actor, _ := c.Get("username")
		actorStr, _ := actor.(string)
		h.auditSvc.Log(ctx, model.EventCRLGenerate, model.SeverityInfo, actorStr, c.ClientIP(), "CRL", caName,
			"生成CRL", map[string]interface{}{"ca_name": caName, "entries": len(revokedEntries)}, model.ResultSuccess, "")
	}

	c.Header("Content-Type", "application/pkix-crl")
	c.Data(http.StatusOK, "application/pkix-crl", crlBytes)
}
