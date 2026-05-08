package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler 认证Handler
type AuthHandler struct {
	cfg        *config.AuthConfig
	operatorRepo *repository.OperatorRepository
	auditSvc   *service.AuditService
}

// NewAuthHandler 创建认证Handler
func NewAuthHandler(cfg *config.AuthConfig, operatorRepo *repository.OperatorRepository, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{
		cfg:          cfg,
		operatorRepo: operatorRepo,
		auditSvc:     auditSvc,
	}
}

// getRolePermissions 根据角色获取默认权限列表
func getRolePermissions(role model.OperatorRole) []string {
	switch role {
	case model.RoleSysAdmin:
		return []string{"SYSTEM_CONFIG", "USER_MANAGE", "CERT_READ", "AUDIT_READ"}
	case model.RoleSecAdmin:
		return []string{"CERT_ISSUE", "CERT_REVOKE", "CERT_RENEW", "CA_MANAGE", "CRL_GENERATE", "OCSP_MANAGE", "CERT_POLICY_MANAGE", "KEY_MANAGE", "KEY_EXPORT", "HSM_MANAGE", "CERT_READ"}
	case model.RoleAuditor:
		return []string{"AUDIT_READ", "AUDIT_VERIFY", "CERT_READ"}
	case model.RoleSuperAdmin:
		return []string{"*"}
	}
	return []string{}
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
		if h.auditSvc != nil {
			h.auditSvc.Log(c.Request.Context(), model.EventAdminLogin, model.SeverityWarn, req.Username, c.ClientIP(), "OPERATOR", strconv.Itoa(op.ID),
				"登录失败: 密码错误", map[string]interface{}{"username": req.Username}, model.ResultFailed, "密码错误")
		}
		c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "用户名或密码错误"})
		return
	}

	// 生成权限列表（合并角色默认权限 + 自定义权限）
	perms := getRolePermissions(op.Role)
	if len(op.Permissions) > 0 {
		permSet := make(map[string]bool)
		for _, p := range perms {
			permSet[p] = true
		}
		for _, p := range op.Permissions {
			permSet[p] = true
		}
		perms = make([]string, 0, len(permSet))
		for p := range permSet {
			perms = append(perms, p)
		}
	}

	// 生成JWT
	token, err := middleware.GenerateJWT(h.cfg, strconv.Itoa(op.ID), op.Username, string(op.Role), perms)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "Token生成失败"})
		return
	}

	// 更新登录信息
	_ = h.operatorRepo.UpdateLoginInfo(c.Request.Context(), op.ID, c.ClientIP())

	if h.auditSvc != nil {
		h.auditSvc.Log(c.Request.Context(), model.EventAdminLogin, model.SeverityInfo, req.Username, c.ClientIP(), "OPERATOR", strconv.Itoa(op.ID),
			"登录成功", map[string]interface{}{"username": req.Username, "role": op.Role}, model.ResultSuccess, "")
	}

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

// InitDefaultAdmins 初始化三员管理员（允许补充创建缺失的角色）
func (h *AuthHandler) InitDefaultAdmins(c *gin.Context) {
	ctx := c.Request.Context()
	actor, _ := c.Get("username")
	actorStr, _ := actor.(string)

	ops, err := h.operatorRepo.ListAll(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "查询操作员失败"})
		return
	}

	// 检查已有角色，只创建缺失的
	var hasSecAdmin, hasAuditAdmin bool
	for _, op := range ops {
		if op.Role == model.RoleSecAdmin {
			hasSecAdmin = true
		}
		if op.Role == model.RoleAuditor {
			hasAuditAdmin = true
		}
	}
	if hasSecAdmin && hasAuditAdmin {
		c.JSON(http.StatusConflict, gin.H{"code": "ALREADY_INITIALIZED", "message": "三员管理员已完整初始化，不能重复设置"})
		return
	}

	// 创建缺失的管理员
	admins := []struct {
		username string
		password string
		realName string
		email    string
		role     model.OperatorRole
		skip     bool
	}{
		{"sys_admin", "iRqk5kj7WH9sBgMH", "系统管理员", "sys_admin@localhost", model.RoleSysAdmin, false},
		{"sec_admin", "wBqpVuGbqUuE6b2u", "安全管理员", "sec_admin@localhost", model.RoleSecAdmin, hasSecAdmin},
		{"audit_admin", "pa9bUFV4B9gPvAJi", "审计管理员", "audit_admin@localhost", model.RoleAuditor, hasAuditAdmin},
	}

	created := 0
	for _, a := range admins {
		if a.skip {
			continue
		}
		// 检查用户名是否已存在
		existing, _ := h.operatorRepo.GetByUsername(ctx, a.username)
		if existing != nil {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(a.password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "密码加密失败"})
			return
		}
		op := &model.Operator{
			Username:     a.username,
			PasswordHash: string(hash),
			RealName:     a.realName,
			Email:        a.email,
			Role:         a.role,
			IsActive:     true,
			CreatedBy:    func() *int { v := 1; return &v }(),
		}
		if err := h.operatorRepo.Create(ctx, op); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "创建管理员 " + a.username + " 失败: " + err.Error()})
			return
		}
		created++
	}

	if h.auditSvc != nil {
		h.auditSvc.Log(ctx, model.EventAdminAction, model.SeverityInfo, actorStr, c.ClientIP(), "SYSTEM", "init-admins",
			"初始化三员管理员", map[string]interface{}{"created": created}, model.ResultSuccess, "")
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "三员管理员初始化成功", "data": gin.H{"created": created}})
}