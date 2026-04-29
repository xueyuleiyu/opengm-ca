package repository

import (
	"context"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// CAChainRepository CA链仓库
type CAChainRepository struct {
	db *bun.DB
}

// NewCAChainRepository 创建CA链仓库
func NewCAChainRepository(db *bun.DB) *CAChainRepository {
	return &CAChainRepository{db: db}
}

// Create 创建CA记录
func (r *CAChainRepository) Create(ctx context.Context, ca *model.CAChain) error {
	_, err := r.db.NewInsert().Model(ca).Exec(ctx)
	return err
}

// GetByID 根据ID获取CA
func (r *CAChainRepository) GetByID(ctx context.Context, id int) (*model.CAChain, error) {
	ca := new(model.CAChain)
	err := r.db.NewSelect().Model(ca).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// GetByName 根据名称获取CA
func (r *CAChainRepository) GetByName(ctx context.Context, name string) (*model.CAChain, error) {
	ca := new(model.CAChain)
	err := r.db.NewSelect().Model(ca).Where("ca_name = ?", name).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// ListAll 获取所有CA
func (r *CAChainRepository) ListAll(ctx context.Context) ([]model.CAChain, error) {
	var cas []model.CAChain
	err := r.db.NewSelect().Model(&cas).OrderExpr("id ASC").Scan(ctx)
	return cas, err
}

// GetActiveCAs 获取所有活跃的中间CA
func (r *CAChainRepository) GetActiveCAs(ctx context.Context) ([]model.CAChain, error) {
	var cas []model.CAChain
	err := r.db.NewSelect().Model(&cas).
		Where("is_active = ?", true).
		Where("ca_type = ?", model.CATypeIntermediate).
		Scan(ctx)
	return cas, err
}

// HasRootCA 检查是否存在根CA
func (r *CAChainRepository) HasRootCA(ctx context.Context) (bool, error) {
	exists, err := r.db.NewSelect().Model((*model.CAChain)(nil)).
		Where("ca_type = ?", model.CATypeRoot).
		Exists(ctx)
	return exists, err
}
