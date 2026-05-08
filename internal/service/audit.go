package service

import (
	"context"
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
}

// NewAuditService 创建审计日志服务
func NewAuditService(repo *repository.AuditRepository, enabled, hashChain bool) *AuditService {
	return &AuditService{
		repo:      repo,
		enabled:   enabled,
		hashChain: hashChain,
	}
}

// Log 记录审计日志
func (s *AuditService) Log(ctx context.Context, eventType model.EventType, severity model.Severity, actor, actorIP, targetType, targetID, action string, detail map[string]interface{}, result model.Result, errorMsg string) {
	if !s.enabled {
		return
	}

	auditLog := &model.AuditLog{
		EventTime:    time.Now(),
		EventType:    eventType,
		Severity:     severity,
		Actor:        actor,
		ActorIP:      actorIP,
		TargetType:   targetType,
		TargetID:     targetID,
		Action:       action,
		Detail:       detail,
		Result:       result,
		ErrorMsg:     errorMsg,
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

	// 异步写入（避免阻塞主流程）
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.repo.Create(bgCtx, auditLog); err != nil {
			// 审计日志写入失败不应影响主流程，但应记录到系统日志
			log.Warn().Err(err).Msg("审计日志写入失败")
		}
	}()
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
