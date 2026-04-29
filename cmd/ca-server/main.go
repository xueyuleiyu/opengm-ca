package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configPath = flag.String("config", "./configs/config.yaml", "配置文件路径")
	initDB     = flag.Bool("init-db", false, "初始化数据库表")
	initCA     = flag.Bool("init-ca", false, "初始化CA根证书")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	setupLogger(cfg.Log)

	log.Info().Str("version", "1.0.0").Str("config", *configPath).Msg("openGM-CA 启动中")

	// 连接数据库
	db, err := repository.NewDB(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("数据库连接失败")
	}
	defer db.Close()

	// 初始化数据库(如指定--init-db)
	if *initDB {
		if err := runDBMigration(context.Background(), db); err != nil {
			log.Fatal().Err(err).Msg("数据库初始化失败")
		}
		log.Info().Msg("数据库初始化完成")
		if !*initCA {
			return
		}
	}

	// 初始化CA(如指定--init-ca)
	if *initCA {
		if err := runCAInitialization(context.Background(), cfg, db); err != nil {
			log.Fatal().Err(err).Msg("CA初始化失败")
		}
		log.Info().Msg("CA初始化完成")
		return
	}

	// 检查CA是否已初始化
	if err := checkCAInitialized(context.Background(), db); err != nil {
		log.Fatal().Err(err).Msg("CA未初始化，请先运行 --init-ca")
	}

	// 设置Gin模式
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建HTTP服务器
	router := setupRouter(cfg)
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: router,
	}

	// 优雅关闭
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Str("addr", server.Addr).Msg("HTTP服务启动失败")
		}
	}()

	log.Info().Str("addr", server.Addr).Msg("HTTP服务已启动")
	if cfg.Server.TLS.Enabled {
		log.Info().Msg("TLS 已启用")
	}
	if cfg.Server.TLS.GMTLS.Enabled {
		log.Info().Msg("国密TLS (GMTLS) 已启用")
	}

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("正在关闭服务...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("服务关闭异常")
	}

	log.Info().Msg("服务已安全退出")
}

// setupLogger 配置结构化日志
func setupLogger(cfg config.LogConfig) {
	// 设置日志级别
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// 输出格式
	if cfg.Format == "console" {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Timestamp().Caller().Logger()
	} else {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()
	}

	// 文件输出
	if cfg.Output == "file" && cfg.FilePath != "" {
		// TODO: 使用lumberjack实现日志轮转
		log.Info().Str("path", cfg.FilePath).Msg("日志文件输出")
	}
}

// setupRouter 配置HTTP路由
func setupRouter(cfg *config.Config) *gin.Engine {
	r := gin.New()

	// 中间件
	r.Use(gin.Recovery())
	r.Use(requestLogger())
	r.Use(corsMiddleware())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"version":   "1.0.0",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// API v1
	v1 := r.Group("/api/v1")
	{
		// 系统管理
		system := v1.Group("/system")
		{
			system.GET("/status", handleSystemStatus)
		}

		// 证书管理
		certs := v1.Group("/certificates")
		{
			certs.POST("/enroll", handleCertEnroll)
			certs.POST("/enroll/vpn", handleVPNCertEnroll)
			certs.GET("", handleCertList)
			certs.GET("/:cert_id", handleCertDetail)
			certs.POST("/:cert_id/revoke", handleCertRevoke)
			certs.POST("/:cert_id/renew", handleCertRenew)
		}

		// 密钥管理
		keys := v1.Group("/keys")
		{
			keys.POST("/:key_id/export", handleKeyExport)
			keys.GET("", handleKeyList)
		}

		// CRL/OCSP (公开访问)
		v1.GET("/crl/:ca_name.crl", handleCRLDownload)
		v1.GET("/crl/:ca_name.pem", handleCRLDownloadPEM)
		v1.POST("/ocsp", handleOCSP)

		// 审计日志
		audit := v1.Group("/audit")
		{
			audit.GET("/logs", handleAuditList)
			audit.GET("/verify", handleAuditVerify)
		}

		// 认证
		auth := v1.Group("/auth")
		{
			auth.POST("/login", handleLogin)
			auth.POST("/refresh", handleRefreshToken)
		}
	}

	return r
}

// requestLogger 请求日志中间件
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		log.Info().
			Str("client_ip", clientIP).
			Str("method", method).
			Str("path", path).
			Int("status", statusCode).
			Dur("latency", latency).
			Str("request_id", c.GetString("request_id")).
			Msg("HTTP请求")
	}
}

// corsMiddleware 跨域中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// runDBMigration 执行数据库迁移
func runDBMigration(ctx context.Context, db *repository.DB) error {
	// TODO: 使用bun迁移工具或手动执行SQL脚本
	log.Info().Msg("执行数据库迁移...")
	return nil
}

// runCAInitialization 初始化CA根证书和中间CA
func runCAInitialization(ctx context.Context, cfg *config.Config, db *repository.DB) error {
	log.Info().Msg("开始初始化CA...")
	// TODO: 调用core.CAInit初始化根CA和中间CA
	return nil
}

// checkCAInitialized 检查CA是否已初始化
func checkCAInitialized(ctx context.Context, db *repository.DB) error {
	// TODO: 查询ca_chain表，检查是否存在根CA
	return nil
}

// --- Handler占位符 ---

func handleSystemStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code": "OK",
		"data": gin.H{
			"status":         "healthy",
			"version":        "1.0.0",
			"ca_initialized": true,
		},
	})
}

func handleCertEnroll(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书申请接口 - 待实现"})
}

func handleVPNCertEnroll(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "VPN双证书申请接口 - 待实现"})
}

func handleCertList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书列表接口 - 待实现"})
}

func handleCertDetail(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书详情接口 - 待实现"})
}

func handleCertRevoke(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书吊销接口 - 待实现"})
}

func handleCertRenew(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "证书续期接口 - 待实现"})
}

func handleKeyExport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "私钥导出接口 - 待实现"})
}

func handleKeyList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "密钥列表接口 - 待实现"})
}

func handleCRLDownload(c *gin.Context) {
	c.String(http.StatusOK, "CRL下载接口 - 待实现")
}

func handleCRLDownloadPEM(c *gin.Context) {
	c.String(http.StatusOK, "CRL PEM下载接口 - 待实现")
}

func handleOCSP(c *gin.Context) {
	c.String(http.StatusOK, "OCSP接口 - 待实现")
}

func handleAuditList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "审计日志接口 - 待实现"})
}

func handleAuditVerify(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "审计验证接口 - 待实现"})
}

func handleLogin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "登录接口 - 待实现"})
}

func handleRefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": "OK", "message": "刷新Token接口 - 待实现"})
}
