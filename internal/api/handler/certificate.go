package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
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

	// 输入参数安全校验
	if err := validateCertEnrollRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// 获取当前用户
	username, _ := c.Get("username")
	actor := "anonymous"
	if u, ok := username.(string); ok {
		actor = u
	}

	resp, err := h.enrollSvc.EnrollCertificate(c.Request.Context(), &req, actor, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"code": "ISSUANCE_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// validateCertEnrollRequest 校验证书申请请求参数安全性
func validateCertEnrollRequest(req *model.CertificateRequest) error {
	// 校验CSR PEM大小
	if req.CSRPEM != "" {
		if len(req.CSRPEM) > middleware.MaxCSRSize {
			return fmt.Errorf("CSR PEM大小超过限制: %d字节 (最大%d字节)", len(req.CSRPEM), middleware.MaxCSRSize)
		}
		// 校验CSR PEM格式
		if !strings.HasPrefix(req.CSRPEM, "-----BEGIN CERTIFICATE REQUEST-----") {
			return fmt.Errorf("CSR PEM格式无效: 缺少起始标记")
		}
		if !strings.HasSuffix(strings.TrimSpace(req.CSRPEM), "-----END CERTIFICATE REQUEST-----") {
			return fmt.Errorf("CSR PEM格式无效: 缺少结束标记")
		}
	}

	// 校验Subject字段长度
	if len(req.Subject.CommonName) > middleware.MaxSubjectFieldLength {
		return fmt.Errorf("CommonName长度超过限制: %d字符 (最大%d字符)", len(req.Subject.CommonName), middleware.MaxSubjectFieldLength)
	}
	if len(req.Subject.Organization) > middleware.MaxSubjectFieldLength {
		return fmt.Errorf("Organization长度超过限制: %d字符", len(req.Subject.Organization))
	}
	if len(req.Subject.OrganizationalUnit) > middleware.MaxSubjectFieldLength {
		return fmt.Errorf("OrganizationalUnit长度超过限制: %d字符", len(req.Subject.OrganizationalUnit))
	}
	if len(req.Subject.Country) > 2 {
		return fmt.Errorf("Country长度超过限制: %d字符 (应为2字符)", len(req.Subject.Country))
	}
	if len(req.Subject.State) > middleware.MaxSubjectFieldLength {
		return fmt.Errorf("State长度超过限制: %d字符", len(req.Subject.State))
	}
	if len(req.Subject.Locality) > middleware.MaxSubjectFieldLength {
		return fmt.Errorf("Locality长度超过限制: %d字符", len(req.Subject.Locality))
	}

	// 校验SAN数量
	if len(req.Extensions.SubjectAltNames) > middleware.MaxSANCount {
		return fmt.Errorf("SAN数量超过限制: %d (最大%d)", len(req.Extensions.SubjectAltNames), middleware.MaxSANCount)
	}

	// 校验每个SAN值长度
	for i, san := range req.Extensions.SubjectAltNames {
		if len(san.Value) > middleware.MaxSubjectFieldLength {
			return fmt.Errorf("SAN[%d]值长度超过限制: %d字符", i, len(san.Value))
		}
	}

	// 校验KeyUsage和ExtKeyUsage数量（防止滥用）
	if len(req.Extensions.KeyUsage) > 10 {
		return fmt.Errorf("KeyUsage数量超过限制: %d (最大10)", len(req.Extensions.KeyUsage))
	}
	if len(req.Extensions.ExtKeyUsage) > 10 {
		return fmt.Errorf("ExtKeyUsage数量超过限制: %d (最大10)", len(req.Extensions.ExtKeyUsage))
	}

	return nil
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
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	certs, total, err := h.mgmtSvc.ListCertificates(c.Request.Context(), filters, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"total":     total,
			"page":      page,
			"page_size": pageSize,
			"items":     certs,
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
		Reason     int    `json:"reason" binding:"required"`
		ReasonText string `json:"reason_text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// RFC 5280 吊销原因范围 0-10
	if req.Reason < 0 || req.Reason > 10 {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "吊销原因代码无效，必须在0-10之间"})
		return
	}

	username, _ := c.Get("username")
	actor := "anonymous"
	if u, ok := username.(string); ok {
		actor = u
	}

	if err := h.mgmtSvc.RevokeCertificate(c.Request.Context(), certID, req.Reason, req.ReasonText, actor, c.ClientIP()); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"code": "REVOKE_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书已吊销"})
}

// Renew 续期证书
func (h *CertificateHandler) Renew(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"code": "NOT_IMPLEMENTED", "message": "证书续期功能开发中"})
}
