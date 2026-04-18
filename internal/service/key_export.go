package service

import (
	"context"
	"fmt"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
)

// KeyExportService 私钥导出服务
type KeyExportService struct {
	cfg       *config.Config
	keyStore  *opengmcrypto.KeyStore
	keyRepo   *repository.KeyRepository
	auditSvc  *AuditService
}

// NewKeyExportService 创建私钥导出服务
func NewKeyExportService(cfg *config.Config, keyStore *opengmcrypto.KeyStore, keyRepo *repository.KeyRepository, auditSvc *AuditService) *KeyExportService {
	return &KeyExportService{
		cfg:      cfg,
		keyStore: keyStore,
		keyRepo:  keyRepo,
		auditSvc: auditSvc,
	}
}

// ExportKey 导出私钥
func (s *KeyExportService) ExportKey(ctx context.Context, req *model.KeyExportRequest, actor, actorIP string) (*model.KeyExportResponse, error) {
	// 1. 获取密钥记录
	keyModel, err := s.keyRepo.GetByID(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("密钥不存在: %w", err)
	}

	// 2. 权限检查
	if !keyModel.CanExport() {
		return nil, fmt.Errorf("密钥不允许导出")
	}

	// 3. 检查每日导出限制
	if s.cfg.KeyManagement.Export.MaxDailyExports > 0 {
		dailyCount, _ := s.keyRepo.GetDailyExportCount(ctx)
		if dailyCount >= s.cfg.KeyManagement.Export.MaxDailyExports {
			return nil, fmt.Errorf("今日私钥导出次数已达上限(%d次)", s.cfg.KeyManagement.Export.MaxDailyExports)
		}
	}

	// 4. 解密私钥
	plainKey, err := s.keyStore.RetrieveKey(keyModel)
	if err != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityCritical, actor, actorIP, "KEY", req.KeyID,
			"私钥导出失败: 解密失败", map[string]interface{}{"key_id": req.KeyID, "reason": req.Reason},
			model.ResultFailed, err.Error())
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	// 5. 更新导出计数
	if err := s.keyRepo.IncrementExportCount(ctx, req.KeyID); err != nil {
		return nil, fmt.Errorf("更新导出计数失败: %w", err)
	}

	// 6. 构建响应
	resp := &model.KeyExportResponse{
		KeyID:         req.KeyID,
		PrivateKeyPEM: string(plainKey),
		PublicKeyPEM:  keyModel.PublicKeyPEM,
		Algorithm:     string(keyModel.Algorithm),
		ExportedAt:    time.Now(),
		Warning:       "私钥已明文导出，请妥善保管，泄露将导致安全风险！",
	}

	remaining := keyModel.RemainingExports()
	if remaining >= 0 {
		resp.RemainingExports = &remaining
	}

	// 7. 审计日志（CRITICAL级别）
	s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityCritical, actor, actorIP, "KEY", req.KeyID,
		fmt.Sprintf("导出私钥: %s, 原因: %s", req.KeyID, req.Reason), map[string]interface{}{
			"key_id":            req.KeyID,
			"algorithm":         keyModel.Algorithm,
			"export_format":     req.ExportFormat,
			"reason":            req.Reason,
			"remaining_exports": remaining,
		}, model.ResultSuccess, "")

	return resp, nil
}
