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

// Export 私钥导出
func (h *KeyHandler) Export(c *gin.Context) {
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

	username, _ := c.Get("username")
	actor := "anonymous"
	if u, ok := username.(string); ok {
		actor = u
	}

	resp, err := h.exportSvc.ExportKey(c.Request.Context(), &req, actor, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"code": "EXPORT_DENIED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}

// List 密钥列表
func (h *KeyHandler) List(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "密钥列表功能开发中"})
}
