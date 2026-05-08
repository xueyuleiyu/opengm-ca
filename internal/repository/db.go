package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	_ "gitee.com/opengauss/openGauss-connector-go-pq"
)

// DB 全局数据库实例
type DB struct {
	*bun.DB
}

// NewDB 创建数据库连接
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	sqldb, err := sql.Open("opengauss", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}

	// 配置连接池
	sqldb.SetMaxOpenConns(cfg.Pool.MaxOpen)
	sqldb.SetMaxIdleConns(cfg.Pool.MaxIdle)
	sqldb.SetConnMaxLifetime(cfg.Pool.MaxLifetime)
	sqldb.SetConnMaxIdleTime(cfg.Pool.MaxIdleTime)

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqldb.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("数据库连接测试失败: %w", err)
	}

	db := bun.NewDB(sqldb, pgdialect.New())


	log.Info().Str("host", cfg.Host).Int("port", cfg.Port).Str("dbname", cfg.DBName).
		Msg("数据库连接成功")

	return &DB{db}, nil
}

// Close 关闭数据库连接
func (d *DB) Close() error {
	return d.DB.Close()
}
