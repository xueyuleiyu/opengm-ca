package repository

import (
	"context"
	"fmt"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// AuditRepository 审计日志仓库
type AuditRepository struct {
	db *bun.DB
}

// NewAuditRepository 创建审计日志仓库
func NewAuditRepository(db *bun.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create 创建审计日志记录
func (r *AuditRepository) Create(ctx context.Context, log *model.AuditLog) error {
	_, err := r.db.NewInsert().Model(log).Exec(ctx)
	return err
}

// GetByID 根据ID获取审计日志
func (r *AuditRepository) GetByID(ctx context.Context, id int64) (*model.AuditLog, error) {
	log := new(model.AuditLog)
	err := r.db.NewSelect().Model(log).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return log, nil
}

// List 查询审计日志列表
func (r *AuditRepository) List(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.AuditLog, int, error) {
	query := r.db.NewSelect().Model((*model.AuditLog)(nil))

	if eventType, ok := filters["event_type"].(string); ok && eventType != "" {
		query = query.Where("event_type = ?", eventType)
	}
	if actor, ok := filters["actor"].(string); ok && actor != "" {
		query = query.Where("actor = ?", actor)
	}
	if severity, ok := filters["severity"].(string); ok && severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if startTime, ok := filters["start_time"].(string); ok && startTime != "" {
		query = query.Where("event_time >= ?", startTime)
	}
	if endTime, ok := filters["end_time"].(string); ok && endTime != "" {
		query = query.Where("event_time <= ?", endTime)
	}

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var logs []model.AuditLog
	err = query.OrderExpr("event_time DESC").Limit(limit).Offset(offset).Scan(ctx, &logs)
	if err != nil {
		return nil, 0, err
	}

	return logs, count, nil
}

// GetLastHash 获取最后一条记录的哈希值（用于哈希链）
func (r *AuditRepository) GetLastHash(ctx context.Context) (string, error) {
	var result struct {
		CurrHash string `bun:"curr_hash"`
	}
	err := r.db.NewSelect().
		Model((*model.AuditLog)(nil)).
		ColumnExpr("curr_hash").
		OrderExpr("id DESC").
		Limit(1).
		Scan(ctx, &result)
	if err != nil {
		// 如果没有记录，返回空字符串作为 genesis hash
		return "", nil
	}
	return result.CurrHash, nil
}

// GetByRange 按ID范围获取审计日志（用于验证哈希链）
func (r *AuditRepository) GetByRange(ctx context.Context, startID, endID int64) ([]model.AuditLog, error) {
	var logs []model.AuditLog
	err := r.db.NewSelect().Model(&logs).
		Where("id >= ?", startID).
		Where("id <= ?", endID).
		OrderExpr("id ASC").
		Scan(ctx)
	return logs, err
}

// VerifyHashChain 验证审计日志哈希链完整性
func (r *AuditRepository) VerifyHashChain(ctx context.Context, startID, endID int64) (*model.AuditVerifyResult, error) {
	logs, err := r.GetByRange(ctx, startID, endID)
	if err != nil {
		return nil, fmt.Errorf("获取审计日志失败: %w", err)
	}

	result := &model.AuditVerifyResult{
		TotalRecords: int64(len(logs)),
		IsValid:      true,
	}

	if len(logs) == 0 {
		return result, nil
	}

	result.FirstHash = logs[0].CurrHash
	result.LastHash = logs[len(logs)-1].CurrHash

	var prevHash string
	for _, log := range logs {
		expectedHash := log.ComputeHash(prevHash)
		if expectedHash != log.CurrHash {
			result.IsValid = false
			result.Corrupted++
			result.CorruptedIDs = append(result.CorruptedIDs, log.ID)
		} else {
			result.Verified++
		}
		prevHash = log.CurrHash
	}

	return result, nil
}
