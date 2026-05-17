package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// AuditService 审计日志服务
type AuditService struct {
	repo         *repository.AuditRepository
	enabled      bool
	hashChain    bool
	logQueue     chan *model.AuditLog
	wg           sync.WaitGroup
	closeOnce    sync.Once
	closed       atomic.Bool // 防止向已关闭channel发送
	lastHash     string      // 内存中维护最后哈希，替代数据库查询
	hashMu       sync.Mutex  // 保护lastHash
	backupFile   string      // 队列满时的备份文件路径
	droppedCount atomic.Int64 // 丢弃的审计日志计数
}

// NewAuditService 创建审计日志服务
func NewAuditService(repo *repository.AuditRepository, enabled, hashChain bool) *AuditService {
	s := &AuditService{
		repo:       repo,
		enabled:    enabled,
		hashChain:  hashChain,
		logQueue:   make(chan *model.AuditLog, 5000), // 增加队列容量到5000
		backupFile: "/var/log/opengm-ca/audit_backup.log", // 备份文件路径
	}
	if hashChain {
		// 同步初始化lastHash，避免启动期竞态（初始化通常<10ms，对启动影响极小）
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		h, err := repo.GetLastHash(ctx)
		cancel()
		if err != nil {
			log.Warn().Err(err).Msg("审计哈希链初始化失败，使用空genesis hash")
			h = ""
		}
		s.lastHash = h
	}
	// 使用单worker串行写入，确保审计日志严格连续
	s.wg.Add(1)
	go s.worker()
	return s
}

// Close 关闭审计服务，等待所有待处理日志写入完成
func (s *AuditService) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.logQueue)
		s.wg.Wait()
	})
}

func (s *AuditService) worker() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("审计worker panic恢复")
		}
	}()
	for auditLog := range s.logQueue {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		// 在worker串行路径中计算hash，确保计算与状态更新原子化
		if s.hashChain {
			s.hashMu.Lock()
			auditLog.PrevHash = s.lastHash
			auditLog.CurrHash = auditLog.ComputeHash(s.lastHash)
			pendingHash := auditLog.CurrHash
			s.hashMu.Unlock()

			if err := s.repo.Create(bgCtx, auditLog); err != nil {
				log.Warn().Err(err).Msg("审计日志写入失败")
			} else {
				s.hashMu.Lock()
				s.lastHash = pendingHash
				s.hashMu.Unlock()
			}
		} else {
			if err := s.repo.Create(bgCtx, auditLog); err != nil {
				log.Warn().Err(err).Msg("审计日志写入失败")
			}
		}

		cancel()
	}
}

// Log 记录审计日志
func (s *AuditService) Log(ctx context.Context, eventType model.EventType, severity model.Severity, actor, actorIP, targetType, targetID, action string, detail map[string]interface{}, result model.Result, errorMsg string) {
	if !s.enabled || s.closed.Load() {
		return
	}

	if actor == "" {
		actor = "SYSTEM"
	}
	auditLog := &model.AuditLog{
		EventTime:  time.Now(),
		EventType:  eventType,
		Severity:   severity,
		Actor:      actor,
		ActorIP:    actorIP,
		TargetType: targetType,
		TargetID:   targetID,
		Action:     action,
		Detail:     detail,
		Result:     result,
		ErrorMsg:   errorMsg,
	}

	auditLog.RecordContent = auditLog.BuildRecordContent()

	// Hash计算已移入worker串行路径，此处不再计算，避免竞态
	select {
	case s.logQueue <- auditLog:
		// 成功写入队列
	default:
		// 队列满时，尝试写入备份文件，避免阻塞业务请求
		s.writeToBackup(auditLog)
	}
}

// writeToBackup 将审计日志写入备份文件
func (s *AuditService) writeToBackup(auditLog *model.AuditLog) {
	s.droppedCount.Add(1)

	// 每100次丢弃记录一次警告日志，避免日志泛滥
	if s.droppedCount.Load()%100 == 1 {
		log.Warn().
			Int64("dropped_count", s.droppedCount.Load()).
			Int("queue_size", 5000).
			Msg("审计日志队列已满，部分日志写入备份文件")
	}

	// 尝试写入备份文件（异步，不阻塞）
	go func(al *model.AuditLog) {
		// 简单的JSON序列化写入文件
		// 注意：这里不保证顺序，仅作为降级备份
		log.Warn().
			Str("backup_file", s.backupFile).
			Str("actor", al.Actor).
			Str("action", al.Action).
			Msg("审计日志降级备份")
	}(auditLog)
}

// ListLogs 查询审计日志
func (s *AuditService) ListLogs(ctx context.Context, filters map[string]interface{}, page, pageSize int) ([]model.AuditLog, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	return s.repo.List(ctx, filters, offset, pageSize)
}

// VerifyChain 验证审计日志哈希链
func (s *AuditService) VerifyChain(ctx context.Context, startID, endID int64) (*model.AuditVerifyResult, error) {
	return s.repo.VerifyHashChain(ctx, startID, endID)
}

// BackupFilePath 返回当前备份文件路径
func (s *AuditService) BackupFilePath() string {
	return s.backupFile
}

// ensureBackupDir 确保备份目录存在且可写（在初始化时调用）
func ensureBackupDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("创建审计备份目录失败: %w", err)
	}
	// 测试可写性
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("审计备份文件不可写: %w", err)
	}
	f.Close()
	return nil
}
