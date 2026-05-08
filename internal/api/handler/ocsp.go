package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
)

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
// 支持JSON格式: POST { "serial_number": "...", "ca_name": "..." }
// 或查询参数: GET ?serial=...&ca_name=...
func (h *OCSPHandler) HandleRequest(c *gin.Context) {
	metrics.IncOCSPQueries()
	ctx := c.Request.Context()

	var req ocspJSONRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.SerialNumber == "" {
		req.SerialNumber = c.Query("serial")
		req.CAName = c.Query("ca_name")
	}

	if req.SerialNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_REQUEST", "message": "缺少证书序列号"})
		return
	}

	resp, err := h.queryStatus(ctx, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

func (h *OCSPHandler) queryStatus(ctx context.Context, req *ocspJSONRequest) (*ocspJSONResponse, error) {
	resp := &ocspJSONResponse{
		SerialNumber: req.SerialNumber,
		Status:       "UNKNOWN",
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	// 查找CA
	var caID int
	if req.CAName != "" {
		ca, err := h.caRepo.GetByName(ctx, req.CAName)
		if err == nil {
			caID = ca.ID
			resp.IssuerDN = ca.SubjectDN
		}
	}

	// 查询证书
	var cert *model.Certificate
	var err error
	if caID > 0 {
		cert, err = h.certRepo.GetBySerialNumber(ctx, caID, req.SerialNumber)
	} else {
		// 如果不指定CA，尝试模糊查询(先查所有再匹配)
		certs, _, err := h.certRepo.List(ctx, map[string]interface{}{"serial_number": req.SerialNumber}, 0, 10)
		if err == nil && len(certs) > 0 {
			cert = &certs[0]
		}
	}
	if err != nil || cert == nil {
		return resp, nil // UNKNOWN
	}

	resp.IssuerDN = cert.IssuerDN

	switch cert.Status {
	case model.CertStatusValid:
		if cert.IsExpired() {
			resp.Status = "UNKNOWN"
		} else {
			resp.Status = "GOOD"
		}
	case model.CertStatusRevoked:
		resp.Status = "REVOKED"
		resp.RevokedAt = cert.RevokedAt
		if cert.RevocationReason != nil {
			resp.Reason = *cert.RevocationReason
		}
	case model.CertStatusExpired:
		resp.Status = "UNKNOWN"
	default:
		resp.Status = "UNKNOWN"
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
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Reason       int        `json:"reason,omitempty"`
	ThisUpdate   time.Time  `json:"this_update"`
	NextUpdate   time.Time  `json:"next_update"`
	IssuerDN     string     `json:"issuer_dn,omitempty"`
}
