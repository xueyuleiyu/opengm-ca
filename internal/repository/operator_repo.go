package repository

import (
	"context"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// OperatorRepository 操作员仓库
type OperatorRepository struct {
	db *bun.DB
}

// NewOperatorRepository 创建操作员仓库
func NewOperatorRepository(db *bun.DB) *OperatorRepository {
	return &OperatorRepository{db: db}
}

// Create 创建操作员
func (r *OperatorRepository) Create(ctx context.Context, op *model.Operator) error {
	_, err := r.db.NewInsert().Model(op).Exec(ctx)
	return err
}

// GetByID 根据ID获取操作员
func (r *OperatorRepository) GetByID(ctx context.Context, id int) (*model.Operator, error) {
	op := new(model.Operator)
	err := r.db.NewSelect().Model(op).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return op, nil
}

// GetByUsername 根据用户名获取操作员
func (r *OperatorRepository) GetByUsername(ctx context.Context, username string) (*model.Operator, error) {
	op := new(model.Operator)
	err := r.db.NewSelect().Model(op).Where("username = ?", username).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return op, nil
}

// UpdateLoginInfo 更新登录信息
func (r *OperatorRepository) UpdateLoginInfo(ctx context.Context, id int, loginIP string) error {
	_, err := r.db.NewUpdate().Model((*model.Operator)(nil)).
		Set("last_login_at = NOW()").
		Set("last_login_ip = ?", loginIP).
		Set("login_fail_count = 0").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// IncrementLoginFail 原子性增加登录失败次数并返回最新值
func (r *OperatorRepository) IncrementLoginFail(ctx context.Context, id int) (int, error) {
	var result struct {
		Count int `bun:"login_fail_count"`
	}
	_, err := r.db.NewUpdate().Model((*model.Operator)(nil)).
		Set("login_fail_count = login_fail_count + 1").
		Where("id = ?", id).
		Returning("login_fail_count").
		Exec(ctx, &result)
	return result.Count, err
}

// LockAccount 锁定账户
func (r *OperatorRepository) LockAccount(ctx context.Context, id int, lockedUntil interface{}) error {
	_, err := r.db.NewUpdate().Model((*model.Operator)(nil)).
		Set("locked_until = ?", lockedUntil).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// UpdateProfile 更新操作员基本信息（白名单列，防止敏感字段被覆盖）
func (r *OperatorRepository) UpdateProfile(ctx context.Context, op *model.Operator) error {
	_, err := r.db.NewUpdate().Model(op).
		Column("real_name", "email", "phone", "role", "is_active", "permissions", "updated_at").
		Where("id = ?", op.ID).
		Exec(ctx)
	return err
}

// UpdatePassword 更新密码并重置登录失败计数
func (r *OperatorRepository) UpdatePassword(ctx context.Context, id int, hash string) error {
	_, err := r.db.NewUpdate().Model((*model.Operator)(nil)).
		Set("password_hash = ?", hash).
		Set("login_fail_count = 0").
		Set("locked_until = NULL").
		Set("updated_at = NOW()").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// ToggleStatus 启用/禁用操作员
func (r *OperatorRepository) ToggleStatus(ctx context.Context, id int, isActive bool) error {
	_, err := r.db.NewUpdate().Model((*model.Operator)(nil)).
		Set("is_active = ?", isActive).
		Set("updated_at = NOW()").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// Delete 删除操作员
func (r *OperatorRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.NewDelete().Model((*model.Operator)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

// ListAll 查询所有操作员
func (r *OperatorRepository) ListAll(ctx context.Context) ([]*model.Operator, error) {
	var ops []*model.Operator
	err := r.db.NewSelect().Model((*model.Operator)(nil)).OrderExpr("created_at DESC").Scan(ctx, &ops)
	return ops, err
}

// List 查询操作员列表
func (r *OperatorRepository) List(ctx context.Context, offset, limit int) ([]model.Operator, int, error) {
	query := r.db.NewSelect().Model((*model.Operator)(nil))

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var ops []model.Operator
	err = query.OrderExpr("created_at DESC").Limit(limit).Offset(offset).Scan(ctx, &ops)
	if err != nil {
		return nil, 0, err
	}

	return ops, count, nil
}
