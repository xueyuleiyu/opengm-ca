package repository

import (
	"context"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// KeyRepository 密钥仓库
type KeyRepository struct {
	db *bun.DB
}

// NewKeyRepository 创建密钥仓库
func NewKeyRepository(db *bun.DB) *KeyRepository {
	return &KeyRepository{db: db}
}

// Create 创建密钥记录
func (r *KeyRepository) Create(ctx context.Context, key *model.CertKey) error {
	_, err := r.db.NewInsert().Model(key).Exec(ctx)
	return err
}

// GetByID 根据KeyID获取密钥
func (r *KeyRepository) GetByID(ctx context.Context, keyID string) (*model.CertKey, error) {
	key := new(model.CertKey)
	err := r.db.NewSelect().Model(key).Where("key_id = ?", keyID).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// List 查询密钥列表
func (r *KeyRepository) List(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.CertKey, int, error) {
	query := r.db.NewSelect().Model((*model.CertKey)(nil))

	if subjectID, ok := filters["subject_id"].(int); ok && subjectID > 0 {
		query = query.Where("subject_id = ?", subjectID)
	}
	if algorithm, ok := filters["algorithm"].(string); ok && algorithm != "" {
		query = query.Where("algorithm = ?", algorithm)
	}
	if exportable, ok := filters["exportable"].(bool); ok {
		query = query.Where("exportable = ?", exportable)
	}

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var keys []model.CertKey
	err = query.OrderExpr("created_at DESC").Limit(limit).Offset(offset).Scan(ctx, &keys)
	if err != nil {
		return nil, 0, err
	}

	return keys, count, nil
}

// IncrementExportCount 增加导出计数
func (r *KeyRepository) IncrementExportCount(ctx context.Context, keyID string) error {
	_, err := r.db.NewUpdate().Model((*model.CertKey)(nil)).
		Set("export_count = export_count + 1").
		Set("last_export_at = NOW()").
		Where("key_id = ?", keyID).
		Exec(ctx)
	return err
}

// GetDailyExportCount 获取当日导出次数
func (r *KeyRepository) GetDailyExportCount(ctx context.Context) (int, error) {
	var count int
	err := r.db.NewSelect().
		Model((*model.CertKey)(nil)).
		ColumnExpr("COALESCE(SUM(export_count), 0)").
		Where("DATE(last_export_at) = CURRENT_DATE").
		Scan(ctx, &count)
	return count, err
}
