package handler

import (
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

// GenerateCRL 生成并返回CRL
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

	// 查询该CA下已吊销的证书
	filters := map[string]interface{}{
		"status": string(model.CertStatusRevoked),
	}
	revokedCerts, total, err := h.certRepo.List(ctx, filters, 0, 10000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "查询吊销证书失败: " + err.Error()})
		return
	}

	// Metrics 埋点
	metrics.IncCRLRequests()

	// 构建CRL条目
	var entries []crlEntry
	for _, cert := range revokedCerts {
		if cert.CAID != ca.ID {
			continue
		}
		entry := crlEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: cert.RevokedAt,
		}
		if cert.RevocationReason != nil {
			entry.Reason = *cert.RevocationReason
		}
		entries = append(entries, entry)
	}

	crl := crlResponse{
		CAName:         caName,
		IssuerDN:       ca.SubjectDN,
		ThisUpdate:     time.Now(),
		NextUpdate:     time.Now().Add(48 * time.Hour),
		Version:        2,
		TotalEntries:   total,
		CAEntries:      len(entries),
		RevokedCerts:   entries,
	}

	if h.auditSvc != nil {
		actor, _ := c.Get("username")
		actorStr, _ := actor.(string)
		h.auditSvc.Log(ctx, model.EventCRLGenerate, model.SeverityInfo, actorStr, c.ClientIP(), "CRL", caName,
			"生成CRL", map[string]interface{}{"ca_name": caName, "entries": len(entries)}, model.ResultSuccess, "")
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": crl})
}

type crlEntry struct {
	SerialNumber   string     `json:"serial_number"`
	RevocationTime *time.Time `json:"revocation_time,omitempty"`
	Reason         int        `json:"reason,omitempty"`
}

type crlResponse struct {
	CAName       string     `json:"ca_name"`
	IssuerDN     string     `json:"issuer_dn"`
	ThisUpdate   time.Time  `json:"this_update"`
	NextUpdate   time.Time  `json:"next_update"`
	Version      int        `json:"version"`
	TotalEntries int        `json:"total_entries"`
	CAEntries    int        `json:"ca_entries"`
	RevokedCerts []crlEntry `json:"revoked_certificates"`
}
