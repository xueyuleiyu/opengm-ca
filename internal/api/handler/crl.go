package handler

import (
	"crypto/rand"
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
	caEngine        *core.CAEngine
	certRepo        *repository.CertificateRepository
	caRepo          *repository.CAChainRepository
	auditSvc        *service.AuditService
	nextUpdateHours int
}

// NewCRLHandler 创建CRL Handler
func NewCRLHandler(caEngine *core.CAEngine, certRepo *repository.CertificateRepository, caRepo *repository.CAChainRepository, auditSvc *service.AuditService, nextUpdateHours int) *CRLHandler {
	if nextUpdateHours <= 0 {
		nextUpdateHours = service.DefaultCRLNextUpdateHours
	}
	return &CRLHandler{caEngine: caEngine, certRepo: certRepo, caRepo: caRepo, auditSvc: auditSvc, nextUpdateHours: nextUpdateHours}
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
	revokedCerts, _, err := h.certRepo.List(ctx, filters, 0, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "查询吊销证书失败: " + err.Error()})
		return
	}

	// Metrics 埋点
	metrics.IncCRLRequests()

	// 构建CRL条目
	revokedEntries := core.BuildRevokedEntries(revokedCerts, ca.ID)

	thisUpdate := time.Now()
	nextUpdate := thisUpdate.Add(time.Duration(h.nextUpdateHours) * time.Hour)

	crlBytes, err := caInstance.Cert.CreateCRL(rand.Reader, caInstance.Signer, revokedEntries, thisUpdate, nextUpdate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "CRL_GENERATION_FAILED", "message": "CRL签名生成失败: " + err.Error()})
		return
	}

	if h.auditSvc != nil {
		actorStr := getCurrentUser(c)
		h.auditSvc.Log(ctx, model.EventCRLGenerate, model.SeverityInfo, actorStr, c.ClientIP(), "CRL", caName,
			"生成CRL", map[string]interface{}{"ca_name": caName, "entries": len(revokedEntries)}, model.ResultSuccess, "")
	}

	c.Header("Content-Type", "application/pkix-crl")
	c.Data(http.StatusOK, "application/pkix-crl", crlBytes)
}
