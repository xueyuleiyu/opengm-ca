package service

import (
	"context"
	"sync"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// AuditService 审计日志服务
type AuditService struct {
	repo      *repository.AuditRepository
	enabled   bool
	hashChain bool
	logQueue  chan *model.AuditLog
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewAuditService 创建审计日志服务
func NewAuditService(repo *repository.AuditRepository, enabled, hashChain bool) *AuditService {
	s := &AuditService{
		repo:      repo,
		enabled:   enabled,
		hashChain: hashChain,
		logQueue:  make(chan *model.AuditLog, 1000),
	}
	workerCount := 4
	for i := 0; i < workerCount; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

// Close 关闭审计服务，等待所有待处理日志写入完成
func (s *AuditService) Close() {
	s.closeOnce.Do(func() {
		close(s.logQueue)
		s.wg.Wait()
	})
}

func (s *AuditService) worker() {
	defer s.wg.Done()
	for auditLog := range s.logQueue {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.repo.Create(bgCtx, auditLog); err != nil {
			log.Warn().Err(err).Msg("审计日志写入失败")
		}
		cancel()
	}
}

// Log 记录审计日志
func (s *AuditService) Log(ctx context.Context, eventType model.EventType, severity model.Severity, actor, actorIP, targetType, targetID, action string, detail map[string]interface{}, result model.Result, errorMsg string) {
	if !s.enabled {
		return
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

	// 构建记录内容
	auditLog.RecordContent = auditLog.BuildRecordContent()

	// 计算哈希链
	if s.hashChain {
		prevHash, _ := s.repo.GetLastHash(ctx)
		auditLog.PrevHash = prevHash
		auditLog.CurrHash = auditLog.ComputeHash(prevHash)
	} else {
		auditLog.CurrHash = auditLog.ComputeHash("")
	}

	// 写入队列（有界，避免无限goroutine增长）
	select {
	case s.logQueue <- auditLog:
	default:
		// 队列满时同步直写数据库，绝不丢弃审计日志
		if err := s.repo.Create(ctx, auditLog); err != nil {
			log.Error().Err(err).Str("actor", actor).Str("action", action).Msg("审计日志队列已满且同步写入失败")
		}
	}
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
