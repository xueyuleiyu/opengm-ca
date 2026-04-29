package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Config 全局配置结构
type Config struct {
	Server          ServerConfig          `mapstructure:"server"`
	Database        DatabaseConfig        `mapstructure:"database"`
	CA              CAConfig                `mapstructure:"ca"`
	CertPolicy      CertPolicyConfig        `mapstructure:"cert_policy"`
	KeyManagement   KeyManagementConfig     `mapstructure:"key_management"`
	CRL             CRLConfig               `mapstructure:"crl"`
	OCSP            OCSPConfig              `mapstructure:"ocsp"`
	Audit           AuditConfig             `mapstructure:"audit"`
	Auth            AuthConfig              `mapstructure:"auth"`
	Log             LogConfig               `mapstructure:"log"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host string    `mapstructure:"host"`
	Port int       `mapstructure:"port"`
	TLS  TLSConfig `mapstructure:"tls"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	Enabled     bool       `mapstructure:"enabled"`
	CertFile    string     `mapstructure:"cert_file"`
	KeyFile     string     `mapstructure:"key_file"`
	GMTLS       GMTLSConfig `mapstructure:"gm_tls"`
}

// GMTLSConfig 国密TLS配置
type GMTLSConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	SignCertFile string `mapstructure:"sign_cert_file"`
	SignKeyFile  string `mapstructure:"sign_key_file"`
	EncCertFile  string `mapstructure:"enc_cert_file"`
	EncKeyFile   string `mapstructure:"enc_key_file"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Driver   string          `mapstructure:"driver"`
	Host     string          `mapstructure:"host"`
	Port     int             `mapstructure:"port"`
	User     string          `mapstructure:"user"`
	Password string          `mapstructure:"password"`
	DBName   string          `mapstructure:"dbname"`
	SSLMode  string          `mapstructure:"ssl_mode"`
	Pool     DBPoolConfig    `mapstructure:"pool"`
}

// DBPoolConfig 连接池配置
type DBPoolConfig struct {
	MaxOpen     int           `mapstructure:"max_open"`
	MaxIdle     int           `mapstructure:"max_idle"`
	MaxLifetime time.Duration `mapstructure:"max_lifetime"`
	MaxIdleTime time.Duration `mapstructure:"max_idle_time"`
}

// CAConfig CA引擎配置
type CAConfig struct {
	RootCA           RootCAConfig           `mapstructure:"root_ca"`
	IntermediateCAs  []IntermediateCAConfig `mapstructure:"intermediate_cas"`
}

// RootCAConfig 根CA配置
type RootCAConfig struct {
	Subject        SubjectConfig `mapstructure:"subject"`
	Algorithm      string        `mapstructure:"algorithm"`
	ValidityYears  int           `mapstructure:"validity_years"`
	KeySize        int           `mapstructure:"key_size"`
}

// IntermediateCAConfig 中间CA配置
type IntermediateCAConfig struct {
	CAName        string        `mapstructure:"ca_name"`
	Subject       SubjectConfig `mapstructure:"subject"`
	Algorithm     string        `mapstructure:"algorithm"`
	ValidityYears int           `mapstructure:"validity_years"`
	CertTypes     []string      `mapstructure:"cert_types"`
	MaxPathLen    int           `mapstructure:"max_path_len"`
}

// SubjectConfig 证书主题配置
type SubjectConfig struct {
	CommonName         string `mapstructure:"common_name"`
	Organization       string `mapstructure:"organization"`
	OrganizationalUnit string `mapstructure:"organizational_unit"`
	Country            string `mapstructure:"country"`
	State              string `mapstructure:"state"`
	Locality           string `mapstructure:"locality"`
}

// CertPolicyConfig 证书策略配置
type CertPolicyConfig struct {
	DefaultValidityDays   int               `mapstructure:"default_validity_days"`
	MaxValidityDays       int               `mapstructure:"max_validity_days"`
	MinKeySize            map[string]int    `mapstructure:"min_key_size"`
	AllowedAlgorithms     []string          `mapstructure:"allowed_algorithms"`
	AllowedHashAlgorithms []string          `mapstructure:"allowed_hash_algorithms"`
}

// KeyManagementConfig 密钥管理配置
type KeyManagementConfig struct {
	MasterKey MasterKeyConfig `mapstructure:"master_key"`
	Export    KeyExportConfig `mapstructure:"export"`
	Escrow    KeyEscrowConfig `mapstructure:"escrow"`
}

// MasterKeyConfig 主密钥配置
type MasterKeyConfig struct {
	Source  string `mapstructure:"source"`
	EnvName string `mapstructure:"env_name"`
	FilePath string `mapstructure:"file_path"`
	Version int    `mapstructure:"version"`
}

// KeyExportConfig 密钥导出配置
type KeyExportConfig struct {
	RequiresApproval  bool   `mapstructure:"requires_approval"`
	MaxDailyExports   int    `mapstructure:"max_daily_exports"`
	MaxExportsPerKey  int    `mapstructure:"max_exports_per_key"`
	ApprovalLevels    int    `mapstructure:"approval_levels"`
	AuditLevel        string `mapstructure:"audit_level"`
}

// KeyEscrowConfig 密钥托管配置
type KeyEscrowConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	EncryptionAlgorithm  string `mapstructure:"encryption_algorithm"`
	KeySplitThreshold    int    `mapstructure:"key_split_threshold"`
	KeySplitTotal        int    `mapstructure:"key_split_total"`
}

// CRLConfig CRL配置
type CRLConfig struct {
	UpdateIntervalHours  int      `mapstructure:"update_interval_hours"`
	NextUpdateHours      int      `mapstructure:"next_update_hours"`
	IncludeExpiredEntries bool    `mapstructure:"include_expired_entries"`
	DistributionPoints   []string `mapstructure:"distribution_points"`
}

// OCSPConfig OCSP配置
type OCSPConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	ResponderURL         string `mapstructure:"responder_url"`
	ResponseValidityHours int   `mapstructure:"response_validity_hours"`
}

// AuditConfig 审计配置
type AuditConfig struct {
	RetentionDays     int  `mapstructure:"retention_days"`
	AsyncWrite        bool `mapstructure:"async_write"`
	HashChainEnabled  bool `mapstructure:"hash_chain_enabled"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	JWT    JWTConfig    `mapstructure:"jwt"`
	APIKey APIKeyConfig `mapstructure:"api_key"`
}

// JWTConfig JWT配置
type JWTConfig struct {
	Secret           string        `mapstructure:"secret"`
	Issuer           string        `mapstructure:"issuer"`
	AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
}

// APIKeyConfig API密钥配置
type APIKeyConfig struct {
	HeaderName         string `mapstructure:"header_name"`
	RateLimitPerMinute int    `mapstructure:"rate_limit_per_minute"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	FilePath   string `mapstructure:"file_path"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAgeDays int    `mapstructure:"max_age_days"`
}

var globalConfig *Config

// Load 加载配置文件
func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetEnvPrefix("GM_CA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// 设置默认值
	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 处理环境变量引用，如 ${DB_PASSWORD}
	if err := resolveEnvVariables(&cfg); err != nil {
		return nil, fmt.Errorf("解析环境变量失败: %w", err)
	}

	globalConfig = &cfg
	log.Info().Str("config", configPath).Msg("配置文件加载成功")
	return &cfg, nil
}

// Get 获取全局配置
func Get() *Config {
	if globalConfig == nil {
		panic("配置未加载，请先调用 config.Load()")
	}
	return globalConfig
}

// setDefaults 设置默认值
func setDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8443)
	v.SetDefault("database.pool.max_open", 50)
	v.SetDefault("database.pool.max_idle", 10)
	v.SetDefault("cert_policy.default_validity_days", 365)
	v.SetDefault("crl.update_interval_hours", 24)
	v.SetDefault("audit.retention_days", 2555)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
}

// resolveEnvVariables 解析配置中的环境变量引用
func resolveEnvVariables(cfg *Config) error {
	// 数据库密码
	if strings.HasPrefix(cfg.Database.Password, "${") && strings.HasSuffix(cfg.Database.Password, "}") {
		envName := strings.TrimSuffix(strings.TrimPrefix(cfg.Database.Password, "${"), "}")
		cfg.Database.Password = os.Getenv(envName)
		if cfg.Database.Password == "" {
			return fmt.Errorf("环境变量 %s 未设置", envName)
		}
	}

	// JWT密钥
	if strings.HasPrefix(cfg.Auth.JWT.Secret, "${") && strings.HasSuffix(cfg.Auth.JWT.Secret, "}") {
		envName := strings.TrimSuffix(strings.TrimPrefix(cfg.Auth.JWT.Secret, "${"), "}")
		cfg.Auth.JWT.Secret = os.Getenv(envName)
		if cfg.Auth.JWT.Secret == "" {
			return fmt.Errorf("环境变量 %s 未设置", envName)
		}
	}

	// 主密钥
	if cfg.KeyManagement.MasterKey.Source == "env" {
		masterKey := os.Getenv(cfg.KeyManagement.MasterKey.EnvName)
		if masterKey == "" {
			log.Warn().Str("env", cfg.KeyManagement.MasterKey.EnvName).
				Msg("主密钥环境变量未设置，私钥加密功能将不可用")
		}
	}

	return nil
}

// DSN 构建数据库连接字符串
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}
