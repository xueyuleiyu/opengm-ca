package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler 认证Handler
type AuthHandler struct {
	cfg          *config.AuthConfig
	operatorRepo *repository.OperatorRepository
	auditSvc     *service.AuditService
}

// NewAuthHandler 创建认证Handler
func NewAuthHandler(cfg *config.AuthConfig, operatorRepo *repository.OperatorRepository, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{
		cfg:          cfg,
		operatorRepo: operatorRepo,
		auditSvc:     auditSvc,
	}
}

// getRolePermissions 根据角色获取默认权限列表（复用 model 层定义，避免重复）
func getRolePermissions(role model.OperatorRole) []string {
	return model.GetRolePermissions(role)
}

// dummyBcryptHash 用于用户不存在时的恒定时间比较（缓解时序攻击）
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMy.MqrqhmM6JGKpS4G3R1G2JH8YpfB0Bqy")

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
		// 用户不存在时执行虚拟bcrypt比较以保持时序恒定，缓解用户枚举攻击
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(req.Password))
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
		ctx := c.Request.Context()
		failCount, incErr := h.operatorRepo.IncrementLoginFail(ctx, op.ID)
		if incErr != nil {
			log.Warn().Err(incErr).Int("operator_id", op.ID).Msg("增加登录失败计数失败")
		} else {
			// 检查是否需要锁定账户（仅在计数成功时使用原子递增后的最新值）
			const maxLoginFail = 5
			const lockDuration = 30 * time.Minute
			if failCount >= maxLoginFail {
				lockUntil := time.Now().Add(lockDuration)
				if lockErr := h.operatorRepo.LockAccount(ctx, op.ID, lockUntil); lockErr != nil {
					log.Warn().Err(lockErr).Int("operator_id", op.ID).Msg("账户锁定失败")
				} else {
					log.Warn().Int("operator_id", op.ID).Time("locked_until", lockUntil).Msg("账户因多次登录失败被锁定")
					if h.auditSvc != nil {
						h.auditSvc.Log(ctx, model.EventAdminLogin, model.SeverityCritical, req.Username, c.ClientIP(), "OPERATOR", strconv.Itoa(op.ID),
							"账户因多次登录失败被锁定", map[string]interface{}{"username": req.Username, "fail_count": failCount}, model.ResultDenied, "")
					}
				}
			}
		}
		if h.auditSvc != nil {
			h.auditSvc.Log(ctx, model.EventAdminLogin, model.SeverityWarn, req.Username, c.ClientIP(), "OPERATOR", strconv.Itoa(op.ID),
				"登录失败: 密码错误", map[string]interface{}{"username": req.Username}, model.ResultFailed, "密码错误")
		}
		c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "用户名或密码错误"})
		return
	}

	// MFA校验（如已启用）
	if op.MFAEnabled {
		if req.MFACode == "" {
			c.JSON(http.StatusForbidden, gin.H{"code": "MFA_REQUIRED", "message": "需要MFA验证码"})
			return
		}
		// TODO: 实现TOTP/HOTP验证逻辑（当前系统缺少TOTP库）
		// 在实现前，启用MFA的账户无法登录，防止MFA被绕过
		c.JSON(http.StatusForbidden, gin.H{"code": "MFA_NOT_IMPLEMENTED", "message": "MFA验证功能尚未完全实现，请联系管理员"})
		return
	}

	// 生成权限列表（合并角色默认权限 + 自定义权限）
	perms := mergePermissions(getRolePermissions(op.Role), op.Permissions)

	// 生成JWT
	token, err := middleware.GenerateJWT(h.cfg, strconv.Itoa(op.ID), op.Username, string(op.Role), perms)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "Token生成失败"})
		return
	}

	// 更新登录信息
	if err := h.operatorRepo.UpdateLoginInfo(c.Request.Context(), op.ID, c.ClientIP()); err != nil {
		log.Warn().Err(err).Int("operator_id", op.ID).Msg("更新登录信息失败")
	}

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
				"permissions": perms,
			},
		},
	})
}

// RefreshToken 刷新Token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"code": "NOT_IMPLEMENTED", "message": "Token刷新功能尚未实现"})
}

// InitDefaultAdmins 初始化三员管理员（允许补充创建缺失的角色）
func (h *AuthHandler) InitDefaultAdmins(c *gin.Context) {
	ctx := c.Request.Context()
	actorStr := getCurrentUser(c)

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

	// 生成管理员密码
	sysPass, err := getEnvOrRandomPassword("CA_DEFAULT_SYS_ADMIN_PASSWORD")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "生成系统管理员密码失败: " + err.Error()})
		return
	}
	secPass, err := getEnvOrRandomPassword("CA_DEFAULT_SEC_ADMIN_PASSWORD")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "生成安全管理员密码失败: " + err.Error()})
		return
	}
	auditPass, err := getEnvOrRandomPassword("CA_DEFAULT_AUDIT_ADMIN_PASSWORD")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": "生成审计管理员密码失败: " + err.Error()})
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
		{"sys_admin", sysPass, "系统管理员", "sys_admin@localhost", model.RoleSysAdmin, false},
		{"sec_admin", secPass, "安全管理员", "sec_admin@localhost", model.RoleSecAdmin, hasSecAdmin},
		{"audit_admin", auditPass, "审计管理员", "audit_admin@localhost", model.RoleAuditor, hasAuditAdmin},
	}

	created := 0
	for _, a := range admins {
		if a.skip {
			continue
		}
		if err := validatePasswordStrength(a.password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": "WEAK_PASSWORD", "message": "管理员 " + a.username + " 密码强度不足: " + err.Error()})
			return
		}
		// 检查用户名是否已存在
		existing, err := h.operatorRepo.GetByUsername(ctx, a.username)
		if err != nil {
			log.Warn().Err(err).Str("username", a.username).Msg("查询用户名失败")
		}
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
			CreatedBy:    intPtr(1),
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

// validatePasswordStrength 校验密码强度
func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("密码长度至少8位")
	}
	var mask uint8
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			mask |= 1
		case ch >= 'a' && ch <= 'z':
			mask |= 2
		case ch >= '0' && ch <= '9':
			mask |= 4
		default:
			mask |= 8
		}
	}
	if mask != 15 {
		return fmt.Errorf("密码必须包含大小写字母、数字和特殊字符")
	}
	return nil
}

func mergePermissions(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	permSet := make(map[string]struct{}, len(base)+len(extra))
	for _, p := range base {
		permSet[p] = struct{}{}
	}
	for _, p := range extra {
		permSet[p] = struct{}{}
	}
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	return perms
}

func intPtr(v int) *int { return &v }

// getEnvOrRandomPassword 从环境变量读取密码，未设置则生成随机密码
func getEnvOrRandomPassword(envKey string) (string, error) {
	if pw := os.Getenv(envKey); pw != "" {
		return pw, nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// 熵源失败时直接返回错误，禁止回退到可预测的时间戳
		return "", fmt.Errorf("生成随机密码失败(熵源错误): %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
