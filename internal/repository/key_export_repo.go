package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// KeyExportRequestRepository 私钥导出请求仓库
type KeyExportRequestRepository struct {
	db *bun.DB
}

// NewKeyExportRequestRepository 创建导出请求仓库
func NewKeyExportRequestRepository(db *bun.DB) *KeyExportRequestRepository {
	return &KeyExportRequestRepository{db: db}
}

// Create 创建导出请求
func (r *KeyExportRequestRepository) Create(ctx context.Context, req *model.KeyExportRequestRecord) error {
	_, err := r.db.NewInsert().Model(req).Exec(ctx)
	return err
}

// GetByRequestID 根据请求ID获取导出请求
func (r *KeyExportRequestRepository) GetByRequestID(ctx context.Context, requestID string) (*model.KeyExportRequestRecord, error) {
	req := new(model.KeyExportRequestRecord)
	err := r.db.NewSelect().Model(req).Where("request_id = ?", requestID).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// UpdateStatus 更新导出请求状态
func (r *KeyExportRequestRepository) UpdateStatus(ctx context.Context, requestID string, status model.KeyExportRequestStatus) error {
	_, err := r.db.NewUpdate().Model((*model.KeyExportRequestRecord)(nil)).
		Set("status = ?, updated_at = NOW()", status).
		Where("request_id = ?", requestID).
		Exec(ctx)
	return err
}

// List 查询导出请求列表
func (r *KeyExportRequestRepository) List(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.KeyExportRequestRecord, int, error) {
	query := r.db.NewSelect().Model((*model.KeyExportRequestRecord)(nil))

	if keyID, ok := filters["key_id"].(string); ok && keyID != "" {
		query = query.Where("key_id = ?", keyID)
	}
	if requester, ok := filters["requester"].(string); ok && requester != "" {
		query = query.Where("requester = ?", requester)
	}
	if status, ok := filters["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var reqs []model.KeyExportRequestRecord
	err = query.OrderExpr("created_at DESC").Limit(limit).Offset(offset).Scan(ctx, &reqs)
	if err != nil {
		return nil, 0, err
	}

	return reqs, count, nil
}

// KeyExportApprovalRepository 私钥导出审批记录仓库
type KeyExportApprovalRepository struct {
	db *bun.DB
}

// NewKeyExportApprovalRepository 创建审批记录仓库
func NewKeyExportApprovalRepository(db *bun.DB) *KeyExportApprovalRepository {
	return &KeyExportApprovalRepository{db: db}
}

// Create 创建审批记录
func (r *KeyExportApprovalRepository) Create(ctx context.Context, approval *model.KeyExportApprovalRecord) error {
	_, err := r.db.NewInsert().Model(approval).Exec(ctx)
	return err
}

// ListByRequestID 查询某请求的所有审批记录
func (r *KeyExportApprovalRepository) ListByRequestID(ctx context.Context, requestID string) ([]model.KeyExportApprovalRecord, error) {
	var approvals []model.KeyExportApprovalRecord
	err := r.db.NewSelect().Model((*model.KeyExportApprovalRecord)(nil)).
		Where("request_id = ?", requestID).
		OrderExpr("approved_at ASC").
		Scan(ctx, &approvals)
	return approvals, err
}

// CountByRequestID 统计某请求的审批数量
func (r *KeyExportApprovalRepository) CountByRequestID(ctx context.Context, requestID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*model.KeyExportApprovalRecord)(nil)).
		Where("request_id = ? AND approved = true", requestID).
		Count(ctx)
	return count, err
}

// HasApproved 检查某用户是否已审批某请求
func (r *KeyExportApprovalRepository) HasApproved(ctx context.Context, requestID, approver string) (bool, error) {
	exists, err := r.db.NewSelect().
		Model((*model.KeyExportApprovalRecord)(nil)).
		Where("request_id = ? AND approver = ?", requestID, approver).
		Exists(ctx)
	return exists, err
}

// CreateWithCheck 创建审批记录，利用数据库唯一索引防止重复审批
func (r *KeyExportApprovalRepository) CreateWithCheck(ctx context.Context, approval *model.KeyExportApprovalRecord) error {
	err := r.Create(ctx, approval)
	if err != nil {
		// 捕获唯一约束冲突（openGauss/PostgreSQL 错误码 23505）
		if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "unique constraint") || strings.Contains(err.Error(), "duplicate") {
			return fmt.Errorf("您已对该请求进行过审批，不能重复审批")
		}
		return err
	}
	return nil
}
