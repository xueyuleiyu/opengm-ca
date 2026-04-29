package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler 认证Handler
type AuthHandler struct {
	cfg        *config.AuthConfig
	operatorRepo *repository.OperatorRepository
}

// NewAuthHandler 创建认证Handler
func NewAuthHandler(cfg *config.AuthConfig, operatorRepo *repository.OperatorRepository) *AuthHandler {
	return &AuthHandler{
		cfg:          cfg,
		operatorRepo: operatorRepo,
	}
}

// Login 用户登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req model.OperatorLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// 查找用户
	op, err := h.operatorRepo.GetByUsername(c.Request.Context(), req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "用户名或密码错误"})
		return
	}

	// 检查账户状态
	if !op.IsActive || op.IsLocked() {
		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "账户已被禁用或锁定"})
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(req.Password)); err != nil {
		_ = h.operatorRepo.IncrementLoginFail(c.Request.Context(), op.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "用户名或密码错误"})
		return
	}

	// 生成JWT
	token, err := middleware.GenerateJWT(h.cfg, strconv.Itoa(op.ID), op.Username, string(op.Role), op.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "Token生成失败"})
		return
	}

	// 更新登录信息
	_ = h.operatorRepo.UpdateLoginInfo(c.Request.Context(), op.ID, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"access_token":  token,
			"refresh_token": "",
			"expires_in":    int(h.cfg.JWT.AccessTokenTTL.Seconds()),
			"token_type":    "Bearer",
			"operator": gin.H{
				"id":          op.ID,
				"username":    op.Username,
				"real_name":   op.RealName,
				"role":        op.Role,
				"permissions": op.Permissions,
			},
		},
	})
}

// RefreshToken 刷新Token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "Token刷新功能开发中"})
}