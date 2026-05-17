package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/core"
)

// CAHandler CA证书链Handler
type CAHandler struct {
	caRepo core.CARepository
}

// NewCAHandler 创建CAHandler
func NewCAHandler(caRepo core.CARepository) *CAHandler {
	return &CAHandler{caRepo: caRepo}
}

// ListCAChain 获取CA证书链列表
func (h *CAHandler) ListCAChain(c *gin.Context) {
	cas, err := h.caRepo.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "获取CA链失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": cas})
}
