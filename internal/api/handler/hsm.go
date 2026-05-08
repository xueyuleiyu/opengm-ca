package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/hsm"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// HSMHandler HSM管理Handler
type HSMHandler struct {
	provider hsm.Provider
	auditSvc *service.AuditService
}

// NewHSMHandler 创建HSM Handler
func NewHSMHandler(provider hsm.Provider, auditSvc *service.AuditService) *HSMHandler {
	return &HSMHandler{provider: provider, auditSvc: auditSvc}
}

// Status 获取HSM状态
func (h *HSMHandler) Status(c *gin.Context) {
	status, err := h.provider.Status()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": status})
}

// ListKeys 列出所有密钥
func (h *HSMHandler) ListKeys(c *gin.Context) {
	keys, err := h.provider.ListKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": keys})
}

// GenerateKey 生成密钥对
func (h *HSMHandler) GenerateKey(c *gin.Context) {
	var req struct {
		Algorithm string `json:"algorithm" validate:"required"`
		KeySize   int    `json:"key_size"`
		KeyType   string `json:"key_type" validate:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	handle, pubKey, err := h.provider.GenerateKeyPair(req.Algorithm, req.KeySize, req.KeyType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	_ = pubKey
	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventKeyGenerate, model.SeverityInfo, c.GetString("username"), c.ClientIP(), "HSM_KEY", handle,
			"HSM生成密钥", map[string]interface{}{"algorithm": req.Algorithm, "key_type": req.KeyType}, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": gin.H{"handle": handle}})
}

// DeleteKey 删除密钥
func (h *HSMHandler) DeleteKey(c *gin.Context) {
	handle := c.Param("handle")
	if err := h.provider.DeleteKey(handle); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventKeyDelete, model.SeverityWarn, c.GetString("username"), c.ClientIP(), "HSM_KEY", handle,
			"HSM删除密钥", nil, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK"})
}
