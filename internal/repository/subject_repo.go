package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/uptrace/bun"
)

// SubjectRepository 证书主体仓库
type SubjectRepository struct {
	db *bun.DB
}

// NewSubjectRepository 创建主体仓库
func NewSubjectRepository(db *bun.DB) *SubjectRepository {
	return &SubjectRepository{db: db}
}

// Create 创建主体记录
func (r *SubjectRepository) Create(ctx context.Context, subject *model.Subject) error {
	_, err := r.db.NewInsert().Model(subject).Exec(ctx)
	return err
}

// GetByID 根据ID获取主体
func (r *SubjectRepository) GetByID(ctx context.Context, id int) (*model.Subject, error) {
	subject := new(model.Subject)
	err := r.db.NewSelect().Model(subject).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return subject, nil
}

// buildSubject 根据SubjectInfo构建Subject模型
func buildSubject(info *model.SubjectInfo) *model.Subject {
	s := &model.Subject{
		CommonName:         info.CommonName,
		Organization:       info.Organization,
		OrganizationalUnit: info.OrganizationalUnit,
		Country:            info.Country,
		State:              info.State,
		Locality:           info.Locality,
		Email:              info.Email,
		IDCardNumber:       info.IDCardNumber,
		EmployeeID:         info.EmployeeID,
		DeviceID:           info.DeviceID,
		Department:         info.Department,
		VPNDomain:          info.VPNDomain,
	}
	if info.DeviceID != "" {
		s.SubjectType = model.SubjectTypeDevice
	} else if info.IDCardNumber != "" {
		s.SubjectType = model.SubjectTypePerson
	} else {
		s.SubjectType = model.SubjectTypeOrganization
	}
	return s
}

// GetOrCreate 根据身份标识获取或创建主体（使用事务避免TOCTOU竞态）
func (r *SubjectRepository) GetOrCreate(ctx context.Context, info *model.SubjectInfo) (*model.Subject, error) {
	subject := buildSubject(info)
	err := r.db.RunInTx(ctx, nil, func(txCtx context.Context, tx bun.Tx) error {
		found := new(model.Subject)
		err := tx.NewSelect().Model(found).
			Where("subject_type = ?", subject.SubjectType).
			Where("common_name = ?", subject.CommonName).
			Scan(txCtx)
		if err == nil {
			*subject = *found
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.NewInsert().Model(subject).Exec(txCtx)
		return err
	})
	return subject, err
}

// List 查询主体列表
func (r *SubjectRepository) List(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.Subject, int, error) {
	query := r.db.NewSelect().Model((*model.Subject)(nil))

	if subjectType, ok := filters["subject_type"].(string); ok && subjectType != "" {
		query = query.Where("subject_type = ?", subjectType)
	}
	if commonName, ok := filters["common_name"].(string); ok && commonName != "" {
		query = query.Where("common_name LIKE ?", "%"+commonName+"%")
	}

	count, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var subjects []model.Subject
	err = query.OrderExpr("created_at DESC").Limit(limit).Offset(offset).Scan(ctx, &subjects)
	if err != nil {
		return nil, 0, err
	}

	return subjects, count, nil
}
