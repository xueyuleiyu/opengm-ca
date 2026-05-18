package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/service"
	"golang.org/x/crypto/bcrypt"
)

// OperatorHandler 操作员管理Handler
type OperatorHandler struct {
	opSvc    *service.OperatorService
	auditSvc *service.AuditService
}

// NewOperatorHandler 创建操作员管理Handler
func NewOperatorHandler(opSvc *service.OperatorService, auditSvc *service.AuditService) *OperatorHandler {
	return &OperatorHandler{opSvc: opSvc, auditSvc: auditSvc}
}

// List 列出所有操作员
func (h *OperatorHandler) List(c *gin.Context) {
	ops, err := h.opSvc.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": ops})
}

// Create 创建操作员
func (h *OperatorHandler) Create(c *gin.Context) {
	var req model.CreateOperatorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	if err := validatePasswordStrength(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "WEAK_PASSWORD", "message": err.Error()})
		return
	}

	if !model.IsValidRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的角色类型"})
		return
	}

	// 禁止创建超级管理员
	if req.Role == model.RoleSuperAdmin {
		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "禁止创建超级管理员角色"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "密码加密失败"})
		return
	}

	op := &model.Operator{
		Username:     req.Username,
		PasswordHash: string(hash),
		RealName:     req.RealName,
		Email:        req.Email,
		Phone:        req.Phone,
		Role:         req.Role,
		IsActive:     true,
	}

	if err := h.opSvc.Create(c.Request.Context(), op); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventAdminAction, model.SeverityInfo, getCurrentUser(c), c.ClientIP(), "OPERATOR", req.Username,
			"创建操作员", map[string]interface{}{"username": req.Username, "role": req.Role}, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": op})
}

// Update 更新操作员
func (h *OperatorHandler) Update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的ID"})
		return
	}

	var req model.UpdateOperatorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// MFA功能禁用检查（功能未实现）
	if req.MFAEnabled != nil && *req.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"code": "FEATURE_NOT_AVAILABLE", "message": "MFA功能尚未实现，暂不支持启用"})
		return
	}

	// 角色合法性校验
	if req.Role != nil {
		if !model.IsValidRole(*req.Role) {
			c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的角色类型"})
			return
		}
		if *req.Role == model.RoleSuperAdmin {
			c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "禁止提升为超级管理员角色"})
			return
		}
	}

	if err := h.opSvc.Update(c.Request.Context(), id, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventAdminAction, model.SeverityInfo, getCurrentUser(c), c.ClientIP(), "OPERATOR", strconv.Itoa(id),
			"更新操作员", map[string]interface{}{"operator_id": id}, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK"})
}

// Delete 删除操作员
func (h *OperatorHandler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的ID"})
		return
	}

	// 不能删除自己
	currentUserID, _ := strconv.Atoi(c.GetString("user_id"))
	if id == currentUserID {
		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "不能删除当前登录用户"})
		return
	}

	if err := h.opSvc.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventAdminAction, model.SeverityWarn, getCurrentUser(c), c.ClientIP(), "OPERATOR", strconv.Itoa(id),
			"删除操作员", map[string]interface{}{"operator_id": id}, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK"})
}

// ChangePassword 修改密码
func (h *OperatorHandler) ChangePassword(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的ID"})
		return
	}

	// 只能修改自己的密码（或安全管理员修改他人）
	currentUserID, _ := strconv.Atoi(c.GetString("user_id"))
	currentRole := model.OperatorRole(c.GetString("role"))
	if id != currentUserID && currentRole != model.RoleSecAdmin && currentRole != model.RoleSuperAdmin {
		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "只能修改自己的密码"})
		return
	}

	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	// 如果是安全管理员重置他人密码，不需要旧密码
	if id != currentUserID && (currentRole == model.RoleSecAdmin || currentRole == model.RoleSuperAdmin) {
		// 安全管理员直接设置新密码
		if err := validatePasswordStrength(req.NewPassword); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": "WEAK_PASSWORD", "message": err.Error()})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "密码加密失败"})
			return
		}
		if err := h.opSvc.UpdatePassword(c.Request.Context(), id, string(hash)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
			return
		}
		if h.auditSvc != nil {
			h.auditSvc.Log(c.Request.Context(), model.EventAdminAction, model.SeverityInfo, getCurrentUser(c), c.ClientIP(), "OPERATOR", strconv.Itoa(id),
				"安全管理员重置密码", map[string]interface{}{"operator_id": id}, model.ResultSuccess, "")
		}
		c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "密码已重置"})
		return
	}

	// 普通修改密码需要验证旧密码
	op, err := h.opSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "旧密码错误"})
		return
	}

	if err := validatePasswordStrength(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "WEAK_PASSWORD", "message": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "密码加密失败"})
		return
	}

	if err := h.opSvc.UpdatePassword(c.Request.Context(), id, string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "密码修改成功"})
}

// ToggleStatus 启用/禁用操作员
func (h *OperatorHandler) ToggleStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": "无效的ID"})
		return
	}

	// 不能禁用自己
	currentUserID, _ := strconv.Atoi(c.GetString("user_id"))
	if id == currentUserID {
		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "不能禁用当前登录用户"})
		return
	}

	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAMETER", "message": err.Error()})
		return
	}

	if err := h.opSvc.ToggleStatus(c.Request.Context(), id, req.IsActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	status := "禁用"
	if req.IsActive {
		status = "启用"
	}
	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventAdminAction, model.SeverityInfo, getCurrentUser(c), c.ClientIP(), "OPERATOR", strconv.Itoa(id),
			"切换操作员状态", map[string]interface{}{"operator_id": id, "is_active": req.IsActive}, model.ResultSuccess, "")
	}
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "操作员已" + status})
}
