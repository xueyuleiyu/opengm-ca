package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// KeyHandler 密钥管理Handler
type KeyHandler struct {
	exportSvc *service.KeyExportService
}

// NewKeyHandler 创建密钥Handler
func NewKeyHandler(exportSvc *service.KeyExportService) *KeyHandler {
	return &KeyHandler{exportSvc: exportSvc}
}

// Export 私钥导出（直接导出或审批通过后执行）
func (h *KeyHandler) Export(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用，可能由于主密钥未配置"})
		return
	}

	keyID := c.Param("key_id")
	if keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少密钥ID"})
		return
	}

	var req model.KeyExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}
	req.KeyID = keyID

	actor := getCurrentUser(c)

	resp, err := h.exportSvc.ExportKey(c.Request.Context(), &req, actor, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "EXPORT_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// CreateExportRequest 创建私钥导出申请
func (h *KeyHandler) CreateExportRequest(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	keyID := c.Param("key_id")
	if keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少密钥ID"})
		return
	}

	var req struct {
		Reason   string `json:"reason" binding:"required,min=10"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	actor := getCurrentUser(c)

	record, err := h.exportSvc.CreateExportRequest(c.Request.Context(), keyID, actor, req.Reason, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "EXPORT_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "导出申请已提交，请等待审批", "data": record})
}

// ApproveExportRequest 审批通过导出申请
func (h *KeyHandler) ApproveExportRequest(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	requestID := c.Param("request_id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少请求ID"})
		return
	}

	var req struct {
		Comment string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	actor := getCurrentUser(c)

	if err := h.exportSvc.ApproveExportRequest(c.Request.Context(), requestID, actor, req.Comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "APPROVAL_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "审批通过"})
}

// RejectExportRequest 拒绝导出申请
func (h *KeyHandler) RejectExportRequest(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	requestID := c.Param("request_id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少请求ID"})
		return
	}

	var req struct {
		Comment string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	actor := getCurrentUser(c)

	if err := h.exportSvc.RejectExportRequest(c.Request.Context(), requestID, actor, req.Comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "REJECT_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "已拒绝"})
}

// ListExportRequests 查询导出申请列表
func (h *KeyHandler) ListExportRequests(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	filters := make(map[string]interface{})
	if keyID := c.Query("key_id"); keyID != "" {
		filters["key_id"] = keyID
	}
	if requester := c.Query("requester"); requester != "" {
		filters["requester"] = requester
	}
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}

	page, pageSize, offset := parsePaginationParams(c, 20)

	reqs, total, err := h.exportSvc.ListExportRequests(c.Request.Context(), filters, offset, pageSize)
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
			"items":     reqs,
		},
	})
}

// GetExportRequest 获取单个导出申请详情
func (h *KeyHandler) GetExportRequest(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	requestID := c.Param("request_id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少请求ID"})
		return
	}

	req, approvals, err := h.exportSvc.GetExportRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "NOT_FOUND", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"request":   req,
			"approvals": approvals,
		},
	})
}

// ExecuteExportRequest 执行已审批的导出请求
func (h *KeyHandler) ExecuteExportRequest(c *gin.Context) {
	if h.exportSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "SERVICE_UNAVAILABLE", "message": "密钥导出服务暂不可用"})
		return
	}

	requestID := c.Param("request_id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "缺少请求ID"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// 获取请求详情以得到 key_id 和存储的密码
	exportReq, _, err := h.exportSvc.GetExportRequest(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "NOT_FOUND", "message": "导出请求不存在"})
		return
	}
	if exportReq.Status != model.ExportRequestApproved {
		c.JSON(http.StatusBadRequest, gin.H{"code": "EXPORT_DENIED", "message": "该导出请求尚未审批通过或已过期"})
		return
	}

	actor := getCurrentUser(c)

	// 构造导出请求，使用审批时存储的密码
	exportKeyReq := &model.KeyExportRequest{
		KeyID:           exportReq.KeyID,
		ExportFormat:    "PEM",
		Password:        exportReq.ExportPassword,
		CurrentPassword: req.CurrentPassword,
		Reason:          exportReq.Reason,
	}

	resp, err := h.exportSvc.ExportKey(c.Request.Context(), exportKeyReq, actor, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "EXPORT_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// List 密钥列表
func (h *KeyHandler) List(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "密钥列表功能开发中"})
}
