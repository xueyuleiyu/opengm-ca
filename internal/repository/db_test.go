package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
)

// TestNewDBConnectsAndCountsCAChains 验证 openGauss sha256 认证下 NewDB 能在
// 5 秒内建立连接并查询到预期的 ca_chains 数据。口令仅从 DB_PASSWORD 环境变量读取。
func TestNewDBConnectsAndCountsCAChains(t *testing.T) {
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		t.Fatal("DB_PASSWORD 环境变量未设置，无法执行真实连接测试")
	}

	cfg := &config.DatabaseConfig{
		Driver:   "opengauss",
		Host:     "localhost",
		Port:     5432,
		User:     "ca_admin",
		Password: password,
		DBName:   "opengm_ca",
		SSLMode:  "prefer",
		Pool: config.DBPoolConfig{
			MaxOpen:     5,
			MaxIdle:     1,
			MaxLifetime: time.Hour,
			MaxIdleTime: 30 * time.Minute,
		},
	}

	type result struct {
		db  *DB
		err error
	}
	done := make(chan result, 1)
	go func() {
		db, err := NewDB(cfg)
		done <- result{db: db, err: err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NewDB 未在 5 秒内返回（sha256 认证迭代次数解析异常？）")
	}

	if res.err != nil {
		t.Fatalf("NewDB 连接失败: %v", res.err)
	}
	defer res.db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := res.db.PingContext(ctx); err != nil {
		t.Fatalf("数据库 Ping 失败: %v", err)
	}

	var count int
	if err := res.db.QueryRowContext(ctx, "SELECT count(*) FROM ca_chains").Scan(&count); err != nil {
		t.Fatalf("查询 ca_chains 数量失败: %v", err)
	}
	if count != 4 {
		t.Fatalf("ca_chains 数量 = %d, want 4", count)
	}
}
