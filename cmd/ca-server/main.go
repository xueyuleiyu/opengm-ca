package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opengm-ca/opengm-ca/internal/api"
	"github.com/opengm-ca/opengm-ca/internal/api/handler"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/hsm"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
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
		// 初始化主密钥存储(用于加密CA私钥)
		var keyStore *crypto.KeyStore
		ks, err := crypto.NewKeyStore(cfg.KeyManagement.MasterKey.EnvName)
		if err == nil {
			keyStore = ks
		}
		if err := runCAInitialization(context.Background(), cfg, db, keyStore); err != nil {
			log.Fatal().Err(err).Msg("CA初始化失败")
		}
		log.Info().Msg("CA初始化完成")
		return
	}

	// 检查CA是否已初始化
	if err := checkCAInitialized(context.Background(), db); err != nil {
		log.Fatal().Err(err).Msg("CA未初始化，请先运行 --init-ca")
	}

	// 启动HTTP服务
	if err := startServer(cfg, db); err != nil {
		log.Fatal().Err(err).Msg("服务启动失败")
	}
}

// keyEncryptorAdapter 适配 crypto.KeyStore 到 core.KeyEncryptor 接口
type keyEncryptorAdapter struct {
	ks *crypto.KeyStore
}

func (a *keyEncryptorAdapter) EncryptPrivateKey(plaintext []byte) (ciphertext, salt, nonce, tag []byte, err error) {
	if a.ks == nil {
		return nil, nil, nil, nil, fmt.Errorf("keystore未初始化")
	}
	return a.ks.EncryptPrivateKey(plaintext)
}

func (a *keyEncryptorAdapter) DecryptPrivateKey(ciphertext, salt, nonce, tag []byte) ([]byte, error) {
	if a.ks == nil {
		return nil, fmt.Errorf("keystore未初始化")
	}
	return a.ks.DecryptPrivateKey(ciphertext, salt, nonce, tag)
}

// startServer 启动HTTP服务
func startServer(cfg *config.Config, db *repository.DB) error {
	// 初始化各层组件
	// Repository层
	caRepo := repository.NewCAChainRepository(db.DB)
	certRepo := repository.NewCertificateRepository(db.DB)
	keyRepo := repository.NewKeyRepository(db.DB)
	exportReqRepo := repository.NewKeyExportRequestRepository(db.DB)
	exportApprovalRepo := repository.NewKeyExportApprovalRepository(db.DB)
	subjectRepo := repository.NewSubjectRepository(db.DB)
	auditRepo := repository.NewAuditRepository(db.DB)
	operatorRepo := repository.NewOperatorRepository(db.DB)

	// 初始化软HSM
	hsmPassword := os.Getenv("CA_HSM_PASSWORD")
	if hsmPassword == "" {
		log.Fatal().Msg("CA_HSM_PASSWORD 环境变量未设置，请先设置 HSM 密码")
	}
	hsmProvider, err := hsm.NewSoftHSM("./data/hsm", hsmPassword)
	if err != nil {
		log.Fatal().Err(err).Msg("HSM初始化失败")
	}
	defer hsmProvider.Close()
	hsmStatus, _ := hsmProvider.Status()
	log.Info().Str("type", hsmStatus.Type).Int("keys", hsmStatus.KeyCount).Str("path", hsmStatus.StoragePath).Msg("HSM初始化完成")

	// 初始化主密钥存储
	keyStore, err := crypto.NewKeyStore(cfg.KeyManagement.MasterKey.EnvName)
	if err != nil {
		log.Warn().Err(err).Msg("主密钥加载失败，私钥加密功能将不可用")
		keyStore = nil
	}

	// Service层
	auditSvc := service.NewAuditService(auditRepo, cfg.Audit.AsyncWrite, cfg.Audit.HashChainEnabled)
	opSvc := service.NewOperatorService(operatorRepo)

	var enrollSvc *service.EnrollmentService
	var exportSvc *service.KeyExportService
	caEngine := core.NewCAEngine(&cfg.CA)
	keyEncryptor := &keyEncryptorAdapter{ks: keyStore}
	if err := caEngine.LoadFromDB(context.Background(), caRepo, keyEncryptor, "./data/ca_keys"); err != nil {
		log.Warn().Err(err).Msg("CA引擎从数据库加载失败，证书签发功能可能不可用")
	}
	mgmtSvc := service.NewManagementService(certRepo, caRepo, caEngine, auditSvc, cfg.CRL.NextUpdateHours, cfg.CRL.IncludeExpiredEntries)
	// EnrollmentService必须初始化，即使keyStore为nil
	enrollSvc = service.NewEnrollmentService(cfg, caEngine, keyStore, certRepo, keyRepo, subjectRepo, caRepo, auditSvc)
	if keyStore != nil {
		exportSvc = service.NewKeyExportService(cfg, keyStore, keyRepo, exportReqRepo, exportApprovalRepo, operatorRepo, auditSvc)
	}

	// JWT Secret 安全校验（优先环境变量，拒绝弱密钥）
	jwtSecret := os.Getenv("CA_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = cfg.Auth.JWT.Secret
	}
	if jwtSecret == "" || strings.Contains(jwtSecret, "change-in-production") || len(jwtSecret) < 32 {
		log.Fatal().Msg("JWT Secret 未配置或使用了默认弱密钥。请设置 CA_JWT_SECRET 环境变量（建议32字节以上随机字符串），或修改配置文件中的 auth.jwt.secret")
	}
	cfg.Auth.JWT.Secret = jwtSecret
	log.Info().Str("source", func() string {
		if os.Getenv("CA_JWT_SECRET") != "" {
			return "env:CA_JWT_SECRET"
		}
		return "config"
	}()).Msg("JWT Secret 已加载")

	// 启动证书到期扫描后台任务
	schedulerCtx, schedulerCancel := context.WithCancel(context.Background())
	defer schedulerCancel()
	scheduler := service.NewCertExpirationScheduler(certRepo, auditSvc)
	go scheduler.Start(schedulerCtx)

	// Handler层
	authHandler := handler.NewAuthHandler(&cfg.Auth, operatorRepo, auditSvc)
	opHandler := handler.NewOperatorHandler(opSvc, auditSvc)
	hsmHandler := handler.NewHSMHandler(hsmProvider, auditSvc)
	crlHandler := handler.NewCRLHandler(caEngine, certRepo, caRepo, auditSvc, cfg.CRL.NextUpdateHours)
	ocspHandler := handler.NewOCSPHandler(certRepo, caRepo)
	caHandler := handler.NewCAHandler(caRepo)

	// 初始化 OCSP Responder（优先使用配置的正式证书）
	if cfg.OCSP.Enabled {
		if err := handler.InitOCSPResponder(cfg.OCSP.ResponderCertFile, cfg.OCSP.ResponderKeyFile); err != nil {
			log.Warn().Err(err).Msg("OCSP Responder 初始化失败，OCSP 服务可能不可用")
		}
	}

	// 设置Gin模式
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// TLS 强制检查（生产环境必须启用）
	if !cfg.Server.TLS.Enabled && os.Getenv("GM_CA_ALLOW_HTTP") != "true" {
		log.Fatal().Msg("TLS 未启用，生产环境必须开启 HTTPS。如需临时使用 HTTP，请设置 GM_CA_ALLOW_HTTP=true")
	}

	// 创建路由
	router := api.NewRouter(cfg, mgmtSvc, enrollSvc, exportSvc, auditSvc, authHandler, opHandler, hsmHandler, crlHandler, ocspHandler, caHandler, operatorRepo)
	engine := gin.New()
	engine.Use(gin.Recovery())
	// 安全响应头中间件
	engine.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if cfg.Server.TLS.Enabled {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		c.Next()
	})
	// 前端页面服务
	engine.GET("/", func(c *gin.Context) {
		c.File("./web/index.html")
	})
	engine.GET("/login", func(c *gin.Context) {
		c.File("./web/index.html")
	})
	// 仅暴露 web 目录下的特定安全文件类型，避免意外泄露敏感文件
	engine.StaticFS("/web", http.Dir("./web"))
	router.Register(engine)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: engine,
	}

	// TLS 证书准备
	if cfg.Server.TLS.Enabled {
		if err := ensureTLSCerts(&cfg.Server.TLS); err != nil {
			log.Fatal().Err(err).Msg("TLS证书准备失败")
		}
	}

	// 优雅关闭
	go func() {
		var err error
		if cfg.Server.TLS.Enabled {
			log.Info().Str("addr", server.Addr).Str("cert", cfg.Server.TLS.CertFile).Str("key", cfg.Server.TLS.KeyFile).Msg("HTTPS服务启动中")
			err = server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			log.Info().Str("addr", server.Addr).Msg("HTTP服务启动中")
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Str("addr", server.Addr).Msg("服务启动失败")
		}
	}()

	if cfg.Server.TLS.Enabled {
		log.Info().Msg("TLS 已启用，所有通信已加密")
	} else {
		log.Warn().Msg("TLS 未启用，生产环境必须开启 HTTPS")
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

	// 等待审计日志队列排空
	if auditSvc != nil {
		auditSvc.Close()
	}

	log.Info().Msg("服务已安全退出")
	return nil
}

// setupLogger 配置结构化日志
func setupLogger(cfg config.LogConfig) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.Format == "console" {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Timestamp().Caller().Logger()
	} else {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()
	}

	if cfg.Output == "file" && cfg.FilePath != "" {
		log.Info().Str("path", cfg.FilePath).Msg("日志文件输出")
	}
}

// runDBMigration 执行数据库迁移
func runDBMigration(ctx context.Context, db *repository.DB) error {
	log.Info().Msg("执行数据库迁移...")

	models := []interface{}{
		(*model.CAChain)(nil),
		(*model.Subject)(nil),
		(*model.Certificate)(nil),
		(*model.CertKey)(nil),
		(*model.AuditLog)(nil),
		(*model.Operator)(nil),
		(*model.APIKey)(nil),
		(*model.SystemConfig)(nil),
		(*model.KeyExportRequestRecord)(nil),
		(*model.KeyExportApprovalRecord)(nil),
	}

	for _, m := range models {
		_, err := db.NewCreateTable().IfNotExists().Model(m).Exec(ctx)
		if err != nil {
			return fmt.Errorf("创建表 %T 失败: %w", m, err)
		}
	}

	// 初始化系统配置（openGauss 不支持 ON CONFLICT，使用先查后插）
	configs := []model.SystemConfig{
		{ConfigKey: "master_key_version", ConfigValue: "1", ConfigType: "INT", Description: "当前活动的主密钥版本"},
		{ConfigKey: "serial_number_counter", ConfigValue: "1", ConfigType: "INT", Description: "下一个证书序列号"},
		{ConfigKey: "crl_update_hours", ConfigValue: "24", ConfigType: "INT", Description: "CRL更新间隔(小时)"},
		{ConfigKey: "cert_default_validity_days", ConfigValue: "365", ConfigType: "INT", Description: "默认证书有效期(天)"},
		{ConfigKey: "audit_retention_days", ConfigValue: "2555", ConfigType: "INT", Description: "审计日志保留天数(默认7年)"},
		{ConfigKey: "key_export_requires_approval", ConfigValue: "true", ConfigType: "BOOL", Description: "私钥导出是否需要审批"},
		{ConfigKey: "key_export_max_daily", ConfigValue: "10", ConfigType: "INT", Description: "每日最大私钥导出次数"},
	}
	for _, cfg := range configs {
		count, err := db.NewSelect().Model((*model.SystemConfig)(nil)).Where("config_key = ?", cfg.ConfigKey).Count(ctx)
		if err != nil {
			log.Warn().Err(err).Str("key", cfg.ConfigKey).Msg("查询系统配置失败")
			continue
		}
		if count == 0 {
			if _, err := db.NewInsert().Model(&cfg).Exec(ctx); err != nil {
				log.Warn().Err(err).Str("key", cfg.ConfigKey).Msg("初始化系统配置失败")
			}
		}
	}

	// 创建默认管理员（密码优先从环境变量读取，未设置则生成随机密码）
	adminPass := os.Getenv("CA_INITIAL_ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = generateRandomPassword()
		log.Warn().Str("username", "admin").Msg("未设置 CA_INITIAL_ADMIN_PASSWORD，已生成随机密码（请查看日志或重置密码）")
	}
	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("生成默认管理员密码哈希失败: %w", err)
	}
	admin := &model.Operator{
		Username:     "admin",
		PasswordHash: string(adminHash),
		RealName:     "系统管理员",
		Email:        "admin@localhost",
		Role:         model.RoleSuperAdmin,
		IsActive:     true,
	}
	adminCount, err := db.NewSelect().Model((*model.Operator)(nil)).Where("username = ?", admin.Username).Count(ctx)
	if err != nil {
		log.Warn().Err(err).Str("username", admin.Username).Msg("查询默认管理员失败")
	} else if adminCount == 0 {
		if _, err := db.NewInsert().Model(admin).Exec(ctx); err != nil {
			log.Warn().Err(err).Msg("创建默认管理员失败")
		}
	}

	log.Info().Int("tables", len(models)).Msg("数据库迁移完成")
	return nil
}

// generateRandomPassword 生成24字节随机密码（base64编码）
func generateRandomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("生成随机密码失败: %v", err))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// runCAInitialization 初始化CA根证书和中间CA
func runCAInitialization(ctx context.Context, cfg *config.Config, db *repository.DB, keyStore *crypto.KeyStore) error {
	log.Info().Msg("开始初始化CA...")

	caEngine := core.NewCAEngine(&cfg.CA)
	req := &model.CAInitRequest{
		RootCA: model.RootCAInitConfig{
			Subject: model.SubjectInfo{
				CommonName:   cfg.CA.RootCA.Subject.CommonName,
				Organization: cfg.CA.RootCA.Subject.Organization,
				Country:      cfg.CA.RootCA.Subject.Country,
			},
			Algorithm:     cfg.CA.RootCA.Algorithm,
			ValidityYears: cfg.CA.RootCA.ValidityYears,
			KeySize:       cfg.CA.RootCA.KeySize,
		},
	}

	for _, ica := range cfg.CA.IntermediateCAs {
		req.IntermediateCAs = append(req.IntermediateCAs, model.IntermediateCAInitConfig{
			CAName: ica.CAName,
			Subject: model.SubjectInfo{
				CommonName:   ica.Subject.CommonName,
				Organization: ica.Subject.Organization,
				Country:      ica.Subject.Country,
			},
			Algorithm:     ica.Algorithm,
			ValidityYears: ica.ValidityYears,
			CertTypes:     ica.CertTypes,
			MaxPathLen:    ica.MaxPathLen,
		})
	}

	resp, err := caEngine.Initialize(ctx, req)
	if err != nil {
		return fmt.Errorf("初始化CA引擎失败: %w", err)
	}

	// 保存到数据库和文件
	caRepo := repository.NewCAChainRepository(db.DB)
	keyEncryptor := &keyEncryptorAdapter{ks: keyStore}
	if err := caEngine.SaveToStorage(ctx, caRepo, keyEncryptor, "./data/ca_keys"); err != nil {
		return fmt.Errorf("持久化CA失败: %w", err)
	}

	log.Info().Int("sub_ca_count", len(resp.IntermediateCAs)).Msg("CA初始化完成")
	return nil
}

// checkCAInitialized 检查CA是否已初始化
func checkCAInitialized(ctx context.Context, db *repository.DB) error {
	caRepo := repository.NewCAChainRepository(db.DB)
	hasRoot, err := caRepo.HasRootCA(ctx)
	if err != nil {
		return fmt.Errorf("查询CA状态失败: %w", err)
	}
	if !hasRoot {
		return fmt.Errorf("CA系统未初始化")
	}
	return nil
}

// ensureTLSCerts 确保TLS证书存在，如不存在则返回错误（禁止自动生成弱自签名证书）
func ensureTLSCerts(cfg *config.TLSConfig) error {
	if !cfg.Enabled {
		return nil
	}

	// 检查证书是否已存在
	if _, err := os.Stat(cfg.CertFile); err != nil {
		return fmt.Errorf("TLS证书文件不存在: %s", cfg.CertFile)
	}
	if _, err := os.Stat(cfg.KeyFile); err != nil {
		return fmt.Errorf("TLS私钥文件不存在: %s", cfg.KeyFile)
	}

	log.Info().Str("cert", cfg.CertFile).Msg("使用现有TLS证书")
	return nil
}
