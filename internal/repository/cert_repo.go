package repository

import (
	"context"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// CertificateRepository 证书仓库
type CertificateRepository struct {
	db *bun.DB
}

// NewCertificateRepository 创建证书仓库
func NewCertificateRepository(db *bun.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

// Create 创建证书记录
func (r *CertificateRepository) Create(ctx context.Context, cert *model.Certificate) error {
	_, err := r.db.NewInsert().Model(cert).Returning("*").Exec(ctx)
	return err
}

// GetByID 根据ID获取证书
func (r *CertificateRepository) GetByID(ctx context.Context, id int64) (*model.Certificate, error) {
	cert := new(model.Certificate)
	err := r.db.NewSelect().Model(cert).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// GetBySerialNumber 根据序列号获取证书
func (r *CertificateRepository) GetBySerialNumber(ctx context.Context, caID int, serialNumber string) (*model.Certificate, error) {
	cert := new(model.Certificate)
	err := r.db.NewSelect().Model(cert).
		Where("ca_id = ?", caID).
		Where("serial_number = ?", serialNumber).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// UpdateDualCertPairID 更新双证书配对关系
func (r *CertificateRepository) UpdateDualCertPairID(ctx context.Context, signCertID, encCertID int64) error {
	_, err := r.db.NewUpdate().Model((*model.Certificate)(nil)).
		Set("dual_cert_pair_id = ?", encCertID).
		Set("updated_at = NOW()").
		Where("id = ?", signCertID).
		Exec(ctx)
	if err != nil {
		return err
	}
	_, err = r.db.NewUpdate().Model((*model.Certificate)(nil)).
		Set("dual_cert_pair_id = ?", signCertID).
		Set("updated_at = NOW()").
		Where("id = ?", encCertID).
		Exec(ctx)
	return err
}

// List 查询证书列表
func (r *CertificateRepository) List(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.Certificate, int, error) {
	query := r.db.NewSelect().Model((*model.Certificate)(nil))

	if certType, ok := filters["cert_type"].(string); ok && certType != "" {
		query = query.Where("cert_type = ?", certType)
	}
	if status, ok := filters["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}
	if subjectCN, ok := filters["subject_cn"].(string); ok && subjectCN != "" {
		query = query.Where("subject_dn LIKE ?", "%"+subjectCN+"%")
	}
	if serialNumber, ok := filters["serial_number"].(string); ok && serialNumber != "" {
		query = query.Where("serial_number = ?", serialNumber)
	}
	if validToGte, ok := filters["valid_to_gte"].(time.Time); ok {
		query = query.Where("valid_to >= ?", validToGte)
	}

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var certs []model.Certificate
	query = query.OrderExpr("issued_at DESC").Offset(offset)
	if limit > 0 {
		query = query.Limit(limit)
	}
	err = query.Scan(ctx, &certs)
	if err != nil {
		return nil, 0, err
	}

	return certs, count, nil
}

// UpdateStatus 更新证书状态
func (r *CertificateRepository) UpdateStatus(ctx context.Context, id int64, status model.CertificateStatus, revokedAt interface{}, reason interface{}) error {
	query := r.db.NewUpdate().Model((*model.Certificate)(nil)).
		Set("status = ?", status).
		Where("id = ?", id)

	if revokedAt != nil {
		query = query.Set("revoked_at = ?", revokedAt)
	}
	if reason != nil {
		query = query.Set("revocation_reason = ?", reason)
	}

	_, err := query.Exec(ctx)
	return err
}

// CountByStatus 按状态统计证书数量
func (r *CertificateRepository) CountByStatus(ctx context.Context) (map[string]int64, error) {
	var results []struct {
		Status string `bun:"status"`
		Count  int64  `bun:"count"`
	}

	err := r.db.NewSelect().
		Model((*model.Certificate)(nil)).
		ColumnExpr("status, COUNT(*) as count").
		GroupExpr("status").
		Scan(ctx, &results)
	if err != nil {
		return nil, err
	}

	stats := make(map[string]int64)
	for _, r := range results {
		stats[r.Status] = r.Count
	}
	return stats, nil
}

// Delete 删除证书记录
func (r *CertificateRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().Model((*model.Certificate)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

// GetExpiringSoon 获取即将过期的证书
func (r *CertificateRepository) GetExpiringSoon(ctx context.Context, days int) ([]model.Certificate, error) {
	certs := make([]model.Certificate, 0)
	err := r.db.NewSelect().Model(&certs).
		Where("status = ?", model.CertStatusValid).
		Where("valid_to <= NOW() + INTERVAL '1 day' * ?", days).
		OrderExpr("valid_to ASC").
		Scan(ctx)
	return certs, err
}
