package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// CertificateHandler 证书管理Handler
type CertificateHandler struct {
	enrollSvc *service.EnrollmentService
	mgmtSvc   *service.ManagementService
}

// NewCertificateHandler 创建证书Handler
func NewCertificateHandler(enrollSvc *service.EnrollmentService, mgmtSvc *service.ManagementService) *CertificateHandler {
	return &CertificateHandler{
		enrollSvc: enrollSvc,
		mgmtSvc:   mgmtSvc,
	}
}

// Enroll 证书申请
func (h *CertificateHandler) Enroll(c *gin.Context) {
	var req model.CertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// 获取当前用户
	username, _ := c.Get("username")
	actor := "anonymous"
	if u, ok := username.(string); ok {
		actor = u
	}

	resp, err := h.enrollSvc.EnrollCertificate(c.Request.Context(), &req, actor)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"code": "ISSUANCE_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// List 证书列表
func (h *CertificateHandler) List(c *gin.Context) {
	filters := make(map[string]interface{})
	if certType := c.Query("cert_type"); certType != "" {
		filters["cert_type"] = certType
	}
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}
	if subjectCN := c.Query("subject_cn"); subjectCN != "" {
		filters["subject_cn"] = subjectCN
	}
	if serial := c.Query("serial_number"); serial != "" {
		filters["serial_number"] = serial
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	certs, total, err := h.mgmtSvc.ListCertificates(c.Request.Context(), filters, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"items":      certs,
		},
	})
}

// Detail 证书详情
func (h *CertificateHandler) Detail(c *gin.Context) {
	certID, err := strconv.ParseInt(c.Param("cert_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "证书ID格式错误"})
		return
	}

	cert, err := h.mgmtSvc.GetCertificate(c.Request.Context(), certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "CERT_NOT_FOUND", "message": "证书不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": cert})
}

// Revoke 吊销证书
func (h *CertificateHandler) Revoke(c *gin.Context) {
	certID, err := strconv.ParseInt(c.Param("cert_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "证书ID格式错误"})
		return
	}

	var req struct {
		Reason      int    `json:"reason" binding:"required"`
		ReasonText  string `json:"reason_text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	username, _ := c.Get("username")
	actor := "anonymous"
	if u, ok := username.(string); ok {
		actor = u
	}

	if err := h.mgmtSvc.RevokeCertificate(c.Request.Context(), certID, req.Reason, req.ReasonText, actor); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"code": "REVOKE_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书已吊销"})
}

// Renew 续期证书
func (h *CertificateHandler) Renew(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书续期功能开发中"})
}
