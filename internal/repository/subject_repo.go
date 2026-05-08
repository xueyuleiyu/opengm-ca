package repository

import (
	"context"
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

// GetOrCreate 根据身份标识获取或创建主体
func (r *SubjectRepository) GetOrCreate(ctx context.Context, info *model.SubjectInfo) (*model.Subject, error) {
	subject := new(model.Subject)
	subjectType := model.SubjectTypeOrganization
	if info.IDCardNumber != "" {
		subjectType = model.SubjectTypePerson
	}
	err := r.db.NewSelect().Model(subject).
		Where("subject_type = ?", subjectType).
		Where("common_name = ?", info.CommonName).
		Scan(ctx)
	if err == nil {
		return subject, nil
	}

	// 不存在则创建
	subject = &model.Subject{
		SubjectType:        model.SubjectTypePerson,
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
		subject.SubjectType = model.SubjectTypeDevice
	} else if info.IDCardNumber != "" {
		subject.SubjectType = model.SubjectTypePerson
	} else {
		subject.SubjectType = model.SubjectTypeOrganization
	}

	_, err = r.db.NewInsert().Model(subject).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return subject, nil
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
