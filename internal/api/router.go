package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api/handler"
	"github.com/opengm-ca/opengm-ca/internal/api/middleware"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/service"
)

// Router API路由
type Router struct {
	cfg            *config.Config
	systemHandler  *handler.SystemHandler
	certHandler    *handler.CertificateHandler
	keyHandler     *handler.KeyHandler
	auditHandler   *handler.AuditHandler
	authHandler    *handler.AuthHandler
}

// NewRouter 创建路由
func NewRouter(
	cfg *config.Config,
	mgmtSvc *service.ManagementService,
	enrollSvc *service.EnrollmentService,
	exportSvc *service.KeyExportService,
	auditSvc *service.AuditService,
	authHandler *handler.AuthHandler,
) *Router {
	return &Router{
		cfg:           cfg,
		systemHandler: handler.NewSystemHandler(mgmtSvc),
		certHandler:   handler.NewCertificateHandler(enrollSvc, mgmtSvc),
		keyHandler:    handler.NewKeyHandler(exportSvc),
		auditHandler:  handler.NewAuditHandler(auditSvc),
		authHandler:   authHandler,
	}
}

// Register 注册所有路由
func (r *Router) Register(engine *gin.Engine) {
	// 全局中间件
	engine.Use(middleware.RequestIDMiddleware())
	engine.Use(middleware.RateLimitMiddleware(100, time.Minute))

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
		authorized.Use(middleware.JWTMiddleware(&r.cfg.Auth))
		{
			// 系统状态
			authorized.GET("/system/status", r.systemHandler.Status)

			// 证书管理
			certs := authorized.Group("/certificates")
			{
				certs.POST("/enroll", r.certHandler.Enroll)
				certs.GET("", r.certHandler.List)
				certs.GET("/:cert_id", r.certHandler.Detail)
				certs.POST("/:cert_id/revoke", middleware.RequirePermission("CERT_REVOKE"), r.certHandler.Revoke)
				certs.POST("/:cert_id/renew", r.certHandler.Renew)
			}

			// 密钥管理
			keys := authorized.Group("/keys")
			{
				keys.GET("", r.keyHandler.List)
				keys.POST("/:key_id/export", middleware.RequirePermission("KEY_EXPORT"), r.keyHandler.Export)
			}

			// 审计日志（仅AUDITOR和SUPER_ADMIN）
			audit := authorized.Group("/audit")
			{
				audit.GET("/logs", middleware.RequirePermission("AUDIT_READ"), r.auditHandler.List)
				audit.GET("/verify", middleware.RequirePermission("AUDIT_VERIFY"), r.auditHandler.Verify)
			}
		}

		// CRL/OCSP（公开访问）
		v1.GET("/crl/:ca_name.crl", func(c *gin.Context) {
			c.String(http.StatusOK, "CRL下载接口 - 待实现")
		})
		v1.GET("/crl/:ca_name.pem", func(c *gin.Context) {
			c.String(http.StatusOK, "CRL PEM下载接口 - 待实现")
		})
		v1.POST("/ocsp", func(c *gin.Context) {
			c.String(http.StatusOK, "OCSP接口 - 待实现")
		})
	}
}
