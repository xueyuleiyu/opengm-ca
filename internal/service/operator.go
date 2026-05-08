package service

import (
	"context"
	"fmt"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// OperatorService 操作员管理服务
type OperatorService struct {
	opRepo *repository.OperatorRepository
}

// NewOperatorService 创建操作员管理服务
func NewOperatorService(opRepo *repository.OperatorRepository) *OperatorService {
	return &OperatorService{opRepo: opRepo}
}

// List 列出所有操作员
func (s *OperatorService) List(ctx context.Context) ([]*model.Operator, error) {
	return s.opRepo.ListAll(ctx)
}

// Create 创建操作员
func (s *OperatorService) Create(ctx context.Context, op *model.Operator) error {
	// 检查用户名是否已存在
	existing, err := s.opRepo.GetByUsername(ctx, op.Username)
	if err == nil && existing != nil {
		return fmt.Errorf("用户名 %s 已存在", op.Username)
	}
	return s.opRepo.Create(ctx, op)
}

// Update 更新操作员
func (s *OperatorService) Update(ctx context.Context, id int, req *model.UpdateOperatorRequest) error {
	op, err := s.opRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("操作员不存在: %w", err)
	}

	if req.RealName != nil {
		op.RealName = *req.RealName
	}
	if req.Email != nil {
		op.Email = *req.Email
	}
	if req.Phone != nil {
		op.Phone = *req.Phone
	}
	if req.Role != nil {
		op.Role = *req.Role
	}
	if req.IsActive != nil {
		op.IsActive = *req.IsActive
	}
	if req.Permissions != nil {
		op.Permissions = req.Permissions
	}

	return s.opRepo.Update(ctx, op)
}

// Delete 删除操作员
func (s *OperatorService) Delete(ctx context.Context, id int) error {
	return s.opRepo.Delete(ctx, id)
}

// GetByID 根据ID获取操作员
func (s *OperatorService) GetByID(ctx context.Context, id int) (*model.Operator, error) {
	return s.opRepo.GetByID(ctx, id)
}

// UpdatePassword 更新密码
func (s *OperatorService) UpdatePassword(ctx context.Context, id int, hash string) error {
	op, err := s.opRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	op.PasswordHash = hash
	op.LoginFailCount = 0
	op.LockedUntil = nil
	return s.opRepo.Update(ctx, op)
}

// ToggleStatus 切换状态
func (s *OperatorService) ToggleStatus(ctx context.Context, id int, isActive bool) error {
	op, err := s.opRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	op.IsActive = isActive
	return s.opRepo.Update(ctx, op)
}

// UpdateLoginInfo 更新登录信息
func (s *OperatorService) UpdateLoginInfo(ctx context.Context, id int, ip string) error {
	return s.opRepo.UpdateLoginInfo(ctx, id, ip)
}

// IncrementLoginFail 增加登录失败次数
func (s *OperatorService) IncrementLoginFail(ctx context.Context, id int) error {
	return s.opRepo.IncrementLoginFail(ctx, id)
}

// InitializeThreeAdmins 初始化三员管理员（系统首次设置）
func (s *OperatorService) InitializeThreeAdmins(ctx context.Context, sysAdmin, secAdmin, auditor *model.Operator) error {
	// 检查是否已存在除超级管理员外的其他用户
	ops, err := s.opRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("查询操作员失败: %w", err)
	}

	// 过滤掉超级管理员
	var nonSuperAdmins int
	for _, op := range ops {
		if op.Role != model.RoleSuperAdmin {
			nonSuperAdmins++
		}
	}
	if nonSuperAdmins > 0 {
		return fmt.Errorf("三员管理员已初始化，不能重复设置")
	}

	// 创建三个管理员
	for _, op := range []*model.Operator{sysAdmin, secAdmin, auditor} {
		if err := s.Create(ctx, op); err != nil {
			log.Error().Err(err).Str("username", op.Username).Msg("创建三员管理员失败")
			return fmt.Errorf("创建 %s 失败: %w", op.Username, err)
		}
		log.Info().Str("username", op.Username).Str("role", string(op.Role)).Msg("三员管理员创建成功")
	}

	return nil
}
