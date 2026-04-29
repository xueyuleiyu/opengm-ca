package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// AuditHandler 审计日志Handler
type AuditHandler struct {
	auditSvc *service.AuditService
}

// NewAuditHandler 创建审计Handler
func NewAuditHandler(auditSvc *service.AuditService) *AuditHandler {
	return &AuditHandler{auditSvc: auditSvc}
}

// List 审计日志列表
func (h *AuditHandler) List(c *gin.Context) {
	filters := make(map[string]interface{})
	if eventType := c.Query("event_type"); eventType != "" {
		filters["event_type"] = eventType
	}
	if actor := c.Query("actor"); actor != "" {
		filters["actor"] = actor
	}
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}
	if startTime := c.Query("start_time"); startTime != "" {
		filters["start_time"] = startTime
	}
	if endTime := c.Query("end_time"); endTime != "" {
		filters["end_time"] = endTime
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	logs, total, err := h.auditSvc.ListLogs(c.Request.Context(), filters, page, pageSize)
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
			"items":     logs,
		},
	})
}

// Verify 验证审计日志哈希链
func (h *AuditHandler) Verify(c *gin.Context) {
	startID, _ := strconv.ParseInt(c.DefaultQuery("start_id", "1"), 10, 64)
	endID, _ := strconv.ParseInt(c.DefaultQuery("end_id", "1000"), 10, 64)

	result, err := h.auditSvc.VerifyChain(c.Request.Context(), startID, endID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": result})
}
