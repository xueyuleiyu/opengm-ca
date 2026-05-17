package api

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/handler"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// Router API路由
type Router struct {
	cfg             *config.Config
	systemHandler   *handler.SystemHandler
	certHandler     *handler.CertificateHandler
	keyHandler      *handler.KeyHandler
	auditHandler    *handler.AuditHandler
	authHandler     *handler.AuthHandler
	operatorHandler *handler.OperatorHandler
	hsmHandler      *handler.HSMHandler
	crlHandler      *handler.CRLHandler
	ocspHandler     *handler.OCSPHandler
	operatorRepo    *repository.OperatorRepository
}

// NewRouter 创建路由
func NewRouter(
	cfg *config.Config,
	mgmtSvc *service.ManagementService,
	enrollSvc *service.EnrollmentService,
	exportSvc *service.KeyExportService,
	auditSvc *service.AuditService,
	authHandler *handler.AuthHandler,
	opHandler *handler.OperatorHandler,
	hsmHandler *handler.HSMHandler,
	crlHandler *handler.CRLHandler,
	ocspHandler *handler.OCSPHandler,
	operatorRepo *repository.OperatorRepository,
) *Router {
	return &Router{
		cfg:             cfg,
		systemHandler:   handler.NewSystemHandler(mgmtSvc),
		certHandler:     handler.NewCertificateHandler(enrollSvc, mgmtSvc),
		keyHandler:      handler.NewKeyHandler(exportSvc),
		auditHandler:    handler.NewAuditHandler(auditSvc),
		authHandler:     authHandler,
		operatorHandler: opHandler,
		hsmHandler:      hsmHandler,
		crlHandler:      crlHandler,
		ocspHandler:     ocspHandler,
		operatorRepo:    operatorRepo,
	}
}

// Register 注册所有路由
func (r *Router) Register(engine *gin.Engine) {
	// 全局中间件
	engine.Use(middleware.RequestIDMiddleware())
	engine.Use(middleware.RateLimitMiddleware(100, time.Minute))
	// 全局请求体大小限制 (10MB)
	engine.Use(middleware.RequestBodyLimitMiddleware(middleware.MaxRequestBodySize))

	// 健康检查（公开）
	engine.GET("/health", r.systemHandler.Status)

	// API v1
	v1 := engine.Group("/api/v1")
	{
		// 认证（公开）
		auth := v1.Group("/auth")
		{
			auth.POST("/login", r.authHandler.Login)
			auth.POST("/refresh", r.authHandler.RefreshToken)
		}

		// 需要认证的路由
		authorized := v1.Group("")
		authorized.Use(middleware.JWTMiddleware(&r.cfg.Auth, func(userID string) (bool, error) {
			id, err := strconv.Atoi(userID)
			if err != nil {
				return false, err
			}
			op, err := r.operatorRepo.GetByID(context.Background(), id)
			if err != nil {
				return false, err
			}
			return op.IsActive && !op.IsLocked(), nil
		}))
		{
			// 初始化管理员（仅限已认证且具有用户管理权限的操作员）
			authorized.POST("/auth/init-admins", middleware.RequirePermission("USER_MANAGE"), r.authHandler.InitDefaultAdmins)
			// 系统状态
			authorized.GET("/system/status", r.systemHandler.Status)
			authorized.GET("/system/expiring-certs", middleware.RequirePermission("CERT_READ"), r.systemHandler.ExpiringCerts)

			// 证书管理
			certs := authorized.Group("/certificates")
			// 证书申请接口使用更严格的请求体限制 (1MB)
			certs.Use(middleware.RequestBodyLimitMiddleware(middleware.MaxCertEnrollBodySize))
			{
				certs.POST("/enroll", middleware.RequirePermission("CERT_ISSUE"), r.certHandler.Enroll)
				certs.GET("", middleware.RequirePermission("CERT_READ"), r.certHandler.List)
				certs.GET("/:cert_id", middleware.RequirePermission("CERT_READ"), r.certHandler.Detail)
				certs.POST("/:cert_id/revoke", middleware.RequirePermission("CERT_REVOKE"), r.certHandler.Revoke)
				certs.POST("/:cert_id/renew", middleware.RequirePermission("CERT_RENEW"), r.certHandler.Renew)
			}

			// 密钥管理
			keys := authorized.Group("/keys")
			{
				keys.GET("", middleware.RequirePermission("KEY_MANAGE"), r.keyHandler.List)
				keys.POST("/:key_id/export", middleware.RequirePermission("KEY_EXPORT"), r.keyHandler.Export)
			}

			// 审计日志（仅审计管理员）
			audit := authorized.Group("/audit")
			{
				audit.GET("/logs", middleware.RequirePermission("AUDIT_READ"), r.auditHandler.List)
				audit.GET("/verify", middleware.RequirePermission("AUDIT_VERIFY"), r.auditHandler.Verify)
			}

			// 操作员管理
			operators := authorized.Group("/operators")
			{
				operators.GET("", middleware.RequirePermission("USER_MANAGE"), r.operatorHandler.List)
				operators.POST("", middleware.RequirePermission("USER_MANAGE"), r.operatorHandler.Create)
				operators.PUT("/:id", middleware.RequirePermission("USER_MANAGE"), r.operatorHandler.Update)
				operators.DELETE("/:id", middleware.RequirePermission("USER_MANAGE"), r.operatorHandler.Delete)
				// 密码修改接口：所有认证用户都可以修改自己的密码，SEC_ADMIN可以重置他人密码
				operators.POST("/:id/password", r.operatorHandler.ChangePassword)
				operators.POST("/:id/status", middleware.RequirePermission("USER_MANAGE"), r.operatorHandler.ToggleStatus)
			}

			// HSM管理（仅安全管理员）
			hsmGroup := authorized.Group("/hsm")
			{
				hsmGroup.GET("/status", middleware.RequirePermission("HSM_MANAGE"), r.hsmHandler.Status)
				hsmGroup.GET("/keys", middleware.RequirePermission("HSM_MANAGE"), r.hsmHandler.ListKeys)
				hsmGroup.POST("/keys", middleware.RequirePermission("HSM_MANAGE"), r.hsmHandler.GenerateKey)
				hsmGroup.DELETE("/keys/:handle", middleware.RequirePermission("HSM_MANAGE"), r.hsmHandler.DeleteKey)
			}

			// Prometheus Metrics（需要认证）
			authorized.GET("/metrics", metrics.MetricsHandler())
		}

		// CRL/OCSP（公开访问）
		v1.GET("/crl/:ca_name", r.crlHandler.GenerateCRL)
		v1.POST("/ocsp", r.ocspHandler.HandleRequest)
	}
}
