package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// SystemHandler 系统管理Handler
type SystemHandler struct {
	mgmtSvc *service.ManagementService
}

// NewSystemHandler 创建系统Handler
func NewSystemHandler(mgmtSvc *service.ManagementService) *SystemHandler {
	return &SystemHandler{mgmtSvc: mgmtSvc}
}

// Status 获取系统状态
func (h *SystemHandler) Status(c *gin.Context) {
	ctx := c.Request.Context()
	stats, err := h.mgmtSvc.GetSystemStats(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    "INTERNAL_ERROR",
			"message": "获取系统状态失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"status":         "healthy",
			"version":        "1.0.0",
			"ca_initialized": true,
			"stats":          stats,
		},
	})
}

// ExpiringCerts 获取即将过期的证书列表
func (h *SystemHandler) ExpiringCerts(c *gin.Context) {
	ctx := c.Request.Context()
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 1 {
		days = 30
	}

	certs, err := h.mgmtSvc.ListExpiringCertificates(ctx, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    "INTERNAL_ERROR",
			"message": "查询即将过期证书失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"days":  days,
			"total": len(certs),
			"items": certs,
		},
	})
}
