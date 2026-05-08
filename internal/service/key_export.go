package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// KeyExportService 私钥导出服务
type KeyExportService struct {
	cfg          *config.Config
	keyStore     *opengmcrypto.KeyStore
	keyRepo      *repository.KeyRepository
	operatorRepo *repository.OperatorRepository
	auditSvc     *AuditService
}

// NewKeyExportService 创建私钥导出服务
func NewKeyExportService(cfg *config.Config, keyStore *opengmcrypto.KeyStore, keyRepo *repository.KeyRepository, operatorRepo *repository.OperatorRepository, auditSvc *AuditService) *KeyExportService {
	return &KeyExportService{
		cfg:          cfg,
		keyStore:     keyStore,
		keyRepo:      keyRepo,
		operatorRepo: operatorRepo,
		auditSvc:     auditSvc,
	}
}

// ExportKey 导出私钥（需要审批且必须密码加密）
func (s *KeyExportService) ExportKey(ctx context.Context, req *model.KeyExportRequest, actor, actorIP string) (*model.KeyExportResponse, error) {
	// 1. 获取密钥记录
	keyModel, err := s.keyRepo.GetByID(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("密钥不存在: %w", err)
	}

	// 2. 审批检查（如配置启用）
	if s.cfg.KeyManagement.Export.RequiresApproval {
		return nil, fmt.Errorf("私钥导出需要审批流程支持，当前系统未实现审批功能，导出被拒绝")
	}

	// 3. 权限检查
	if !keyModel.CanExport() {
		return nil, fmt.Errorf("密钥不允许导出")
	}

	// 4. 检查每日导出限制
	if s.cfg.KeyManagement.Export.MaxDailyExports > 0 {
		dailyCount, _ := s.keyRepo.GetDailyExportCount(ctx)
		if dailyCount >= s.cfg.KeyManagement.Export.MaxDailyExports {
			return nil, fmt.Errorf("今日私钥导出次数已达上限(%d次)", s.cfg.KeyManagement.Export.MaxDailyExports)
		}
	}

	// 5. 二次认证：验证当前用户密码
	if req.CurrentPassword == "" {
		return nil, fmt.Errorf("必须提供当前登录密码进行二次认证")
	}
	op, err := s.operatorRepo.GetByUsername(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("无法获取操作员信息: %w", err)
	}
	if err := verifyPassword(op.PasswordHash, req.CurrentPassword); err != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityWarn, actor, actorIP, "KEY", req.KeyID,
			"私钥导出失败: 二次认证密码错误", map[string]interface{}{"key_id": req.KeyID},
			model.ResultFailed, "二次认证失败")
		return nil, fmt.Errorf("二次认证失败: 密码错误")
	}

	// 6. 强制要求导出密码
	if req.Password == "" {
		return nil, fmt.Errorf("必须提供导出密码以保护私钥")
	}

	// 6. 解密私钥
	plainKey, err := s.keyStore.RetrieveKey(keyModel)
	if err != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityCritical, actor, actorIP, "KEY", req.KeyID,
			"私钥导出失败: 解密失败", map[string]interface{}{"key_id": req.KeyID, "reason": req.Reason},
			model.ResultFailed, err.Error())
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	// 7. 使用密码加密私钥 (PBKDF2 + AES-256-GCM)
	encryptedPEM, err := encryptPrivateKeyWithPassword(plainKey, req.Password)
	if err != nil {
		return nil, fmt.Errorf("加密导出私钥失败: %w", err)
	}

	// 8. 更新导出计数
	if err := s.keyRepo.IncrementExportCount(ctx, req.KeyID); err != nil {
		return nil, fmt.Errorf("更新导出计数失败: %w", err)
	}

	// 9. 构建响应
	resp := &model.KeyExportResponse{
		KeyID:         req.KeyID,
		PrivateKeyPEM: encryptedPEM,
		PublicKeyPEM:  keyModel.PublicKeyPEM,
		Algorithm:     string(keyModel.Algorithm),
		ExportedAt:    time.Now(),
		Warning:       "私钥已使用您提供的密码加密导出，请妥善保管密码和密文，泄露将导致安全风险！",
	}

	remaining := keyModel.RemainingExports()
	if remaining >= 0 {
		resp.RemainingExports = &remaining
	}

	// 10. 审计日志（CRITICAL级别）
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

// verifyPassword 校验密码（bcrypt）
func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// encryptPrivateKeyWithPassword 使用PBKDF2+AES-256-GCM加密私钥PEM
func encryptPrivateKeyWithPassword(plainKey []byte, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("生成盐值失败: %w", err)
	}
	derivedKey := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("创建AES密码器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM模式失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成nonce失败: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plainKey, nil)
	// 格式: base64(salt || ciphertext)
	result := base64.StdEncoding.EncodeToString(append(salt, ciphertext...))
	return result, nil
}
