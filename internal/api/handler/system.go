package handler

import (
	"net/http"

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
