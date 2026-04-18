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
	"github.com/opengm-ca/opengm-ca/internal/api"
	"github.com/opengm-ca/opengm-ca/internal/api/handler"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/opengm-ca/opengm-ca/internal/service"
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

	// 启动HTTP服务
	if err := startServer(cfg, db); err != nil {
		log.Fatal().Err(err).Msg("服务启动失败")
	}
}

// startServer 启动HTTP服务
func startServer(cfg *config.Config, db *repository.DB) error {
	// 初始化各层组件
	// Repository层
	caRepo := repository.NewCAChainRepository(db.DB)
	certRepo := repository.NewCertificateRepository(db.DB)
	keyRepo := repository.NewKeyRepository(db.DB)
	subjectRepo := repository.NewSubjectRepository(db.DB)
	auditRepo := repository.NewAuditRepository(db.DB)
	operatorRepo := repository.NewOperatorRepository(db.DB)

	// 初始化主密钥存储
	keyStore, err := crypto.NewKeyStore(os.Getenv(cfg.KeyManagement.MasterKey.EnvName))
	if err != nil {
		log.Warn().Err(err).Msg("主密钥加载失败，私钥加密功能将不可用")
		keyStore = nil
	}

	// Service层
	auditSvc := service.NewAuditService(auditRepo, cfg.Audit.AsyncWrite, cfg.Audit.HashChainEnabled)
	mgmtSvc := service.NewManagementService(certRepo, auditSvc)

	var enrollSvc *service.EnrollmentService
	var exportSvc *service.KeyExportService
	if keyStore != nil {
		caEngine := core.NewCAEngine(&cfg.CA)
		_ = caEngine.LoadFromDB(context.Background(), caRepo)
		enrollSvc = service.NewEnrollmentService(cfg, caEngine, keyStore, certRepo, keyRepo, subjectRepo, caRepo, auditSvc)
		exportSvc = service.NewKeyExportService(cfg, keyStore, keyRepo, auditSvc)
	}

	// Handler层
	authHandler := handler.NewAuthHandler(&cfg.Auth, operatorRepo)

	// 设置Gin模式
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建路由
	router := api.NewRouter(cfg, mgmtSvc, enrollSvc, exportSvc, auditSvc, authHandler)
	engine := gin.New()
	// 前端页面服务
	engine.GET("/", func(c *gin.Context) {
		c.File("./web/index.html")
	})
	engine.GET("/login", func(c *gin.Context) {
		c.File("./web/index.html")
	})
	// API 静态资源（如证书下载等）
	engine.Static("/web", "./web")
	router.Register(engine)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: engine,
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
	}

	for _, m := range models {
		_, err := db.NewCreateTable().IfNotExists().Model(m).Exec(ctx)
		if err != nil {
			return fmt.Errorf("创建表 %T 失败: %w", m, err)
		}
	}

	// 初始化系统配置
	initSQL := `
	INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
	('master_key_version', '1', 'INT', '当前活动的主密钥版本'),
	('serial_number_counter', '1', 'INT', '下一个证书序列号'),
	('crl_update_hours', '24', 'INT', 'CRL更新间隔(小时)'),
	('cert_default_validity_days', '365', 'INT', '默认证书有效期(天)'),
	('audit_retention_days', '2555', 'INT', '审计日志保留天数(默认7年)'),
	('key_export_requires_approval', 'true', 'BOOL', '私钥导出是否需要审批'),
	('key_export_max_daily', '10', 'INT', '每日最大私钥导出次数')
	ON CONFLICT (config_key) DO NOTHING;
	`
	if _, err := db.ExecContext(ctx, initSQL); err != nil {
		log.Warn().Err(err).Msg("初始化系统配置失败(可能已存在)")
	}

	// 创建默认管理员
	defaultPassword := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" // bcrypt("changeme")
	adminSQL := `
	INSERT INTO operators (username, password_hash, real_name, email, role, created_by)
	VALUES ('admin', '` + defaultPassword + `', '系统管理员', 'admin@localhost', 'SUPER_ADMIN', 1)
	ON CONFLICT (username) DO NOTHING;
	`
	if _, err := db.ExecContext(ctx, adminSQL); err != nil {
		log.Warn().Err(err).Msg("创建默认管理员失败(可能已存在)")
	}

	log.Info().Int("tables", len(models)).Msg("数据库迁移完成")
	return nil
}

// runCAInitialization 初始化CA根证书和中间CA
func runCAInitialization(ctx context.Context, cfg *config.Config, db *repository.DB) error {
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
			CAName:        ica.CAName,
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

	// 保存到数据库
	caRepo := repository.NewCAChainRepository(db.DB)
	// TODO: 保存CA证书到数据库
	_ = caRepo
	_ = resp

	log.Info().Msg("CA初始化完成")
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


