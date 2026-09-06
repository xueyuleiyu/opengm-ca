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

	"github.com/google/uuid"
	"github.com/opengm-ca/opengm-ca/internal/config"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// KeyExportService 私钥导出服务
type KeyExportService struct {
	cfg                *config.Config
	keyStore           *opengmcrypto.KeyStore
	keyRepo            *repository.KeyRepository
	exportReqRepo      *repository.KeyExportRequestRepository
	exportApprovalRepo *repository.KeyExportApprovalRepository
	operatorRepo       *repository.OperatorRepository
	auditSvc           *AuditService
}

// NewKeyExportService 创建私钥导出服务
func NewKeyExportService(cfg *config.Config, keyStore *opengmcrypto.KeyStore, keyRepo *repository.KeyRepository, exportReqRepo *repository.KeyExportRequestRepository, exportApprovalRepo *repository.KeyExportApprovalRepository, operatorRepo *repository.OperatorRepository, auditSvc *AuditService) *KeyExportService {
	return &KeyExportService{
		cfg:                cfg,
		keyStore:           keyStore,
		keyRepo:            keyRepo,
		exportReqRepo:      exportReqRepo,
		exportApprovalRepo: exportApprovalRepo,
		operatorRepo:       operatorRepo,
		auditSvc:           auditSvc,
	}
}

// CreateExportRequest 创建私钥导出请求（需要审批时）
func (s *KeyExportService) CreateExportRequest(ctx context.Context, keyID, requester, reason, exportPassword string) (*model.KeyExportRequestRecord, error) {
	// 1. 获取密钥记录
	keyModel, err := s.keyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("密钥不存在: %w", err)
	}

	// 2. 权限检查
	if !keyModel.CanExport() {
		return nil, fmt.Errorf("密钥不允许导出")
	}

	// 3. 创建导出请求
	req := &model.KeyExportRequestRecord{
		RequestID:      uuid.New().String(),
		KeyID:          keyID,
		Requester:      requester,
		Reason:         reason,
		Status:         model.ExportRequestPending,
		ExportPassword: exportPassword,
		ExpiresAt:      ptr(time.Now().Add(24 * time.Hour)),
	}
	if err := s.exportReqRepo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("创建导出请求失败: %w", err)
	}

	// 4. 审计日志
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityInfo, requester, "", "KEY", keyID,
			fmt.Sprintf("提交私钥导出申请: %s", req.RequestID), map[string]interface{}{
				"request_id": req.RequestID,
				"key_id":     keyID,
				"reason":     reason,
			}, model.ResultSuccess, "")
	}

	return req, nil
}

// ApproveExportRequest 审批导出请求
func (s *KeyExportService) ApproveExportRequest(ctx context.Context, requestID, approver, comment string) error {
	req, err := s.exportReqRepo.GetByRequestID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("导出请求不存在: %w", err)
	}
	if req.Status != model.ExportRequestPending {
		return fmt.Errorf("请求状态为 %s，无法审批", req.Status)
	}
	if req.ExpiresAt != nil && time.Now().After(*req.ExpiresAt) {
		_ = s.exportReqRepo.UpdateStatus(ctx, requestID, model.ExportRequestExpired)
		return fmt.Errorf("导出请求已过期")
	}

	approval := &model.KeyExportApprovalRecord{
		RequestID: requestID,
		Approver:  approver,
		Comment:   comment,
		Approved:  true,
	}
	if err := s.exportApprovalRepo.CreateWithCheck(ctx, approval); err != nil {
		return fmt.Errorf("审批失败: %w", err)
	}

	// 检查是否达到审批人数
	count, _ := s.exportApprovalRepo.CountByRequestID(ctx, requestID)
	if count >= s.cfg.KeyManagement.Export.ApprovalLevels {
		if err := s.exportReqRepo.UpdateStatus(ctx, requestID, model.ExportRequestApproved); err != nil {
			return fmt.Errorf("更新请求状态失败: %w", err)
		}
	}

	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityInfo, approver, "", "KEY", req.KeyID,
			fmt.Sprintf("审批通过私钥导出申请: %s", requestID), map[string]interface{}{
				"request_id": requestID,
				"approver":   approver,
				"count":      count,
			}, model.ResultSuccess, "")
	}

	return nil
}

// RejectExportRequest 拒绝导出请求
func (s *KeyExportService) RejectExportRequest(ctx context.Context, requestID, approver, comment string) error {
	req, err := s.exportReqRepo.GetByRequestID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("导出请求不存在: %w", err)
	}
	if req.Status != model.ExportRequestPending {
		return fmt.Errorf("请求状态为 %s，无法拒绝", req.Status)
	}

	approval := &model.KeyExportApprovalRecord{
		RequestID: requestID,
		Approver:  approver,
		Comment:   comment,
		Approved:  false,
	}
	if err := s.exportApprovalRepo.CreateWithCheck(ctx, approval); err != nil {
		return fmt.Errorf("操作失败: %w", err)
	}

	if err := s.exportReqRepo.UpdateStatus(ctx, requestID, model.ExportRequestRejected); err != nil {
		return fmt.Errorf("更新请求状态失败: %w", err)
	}

	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityWarn, approver, "", "KEY", req.KeyID,
			fmt.Sprintf("拒绝私钥导出申请: %s", requestID), map[string]interface{}{
				"request_id": requestID,
				"approver":   approver,
				"comment":    comment,
			}, model.ResultFailed, "")
	}

	return nil
}

// ListExportRequests 查询导出请求列表
func (s *KeyExportService) ListExportRequests(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]model.KeyExportRequestRecord, int, error) {
	return s.exportReqRepo.List(ctx, filters, offset, limit)
}

// GetExportRequest 获取单个导出请求详情（含审批记录）
func (s *KeyExportService) GetExportRequest(ctx context.Context, requestID string) (*model.KeyExportRequestRecord, []model.KeyExportApprovalRecord, error) {
	req, err := s.exportReqRepo.GetByRequestID(ctx, requestID)
	if err != nil {
		return nil, nil, err
	}
	approvals, err := s.exportApprovalRepo.ListByRequestID(ctx, requestID)
	if err != nil {
		return nil, nil, err
	}
	return req, approvals, nil
}

// ExportKey 导出私钥（审批通过后执行，或无需审批时直接执行）
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

	// 3. 审批检查（如配置启用）
	if s.cfg.KeyManagement.Export.RequiresApproval {
		// 检查是否有已批准的导出请求
		filters := map[string]interface{}{
			"key_id":    req.KeyID,
			"requester": actor,
			"status":    string(model.ExportRequestApproved),
		}
		approvedReqs, _, err := s.exportReqRepo.List(ctx, filters, 0, 1)
		if err != nil {
			return nil, fmt.Errorf("查询审批状态失败: %w", err)
		}
		if len(approvedReqs) == 0 {
			// 没有已批准的请求，检查是否有待审批的
			filters["status"] = string(model.ExportRequestPending)
			pendingReqs, _, _ := s.exportReqRepo.List(ctx, filters, 0, 1)
			if len(pendingReqs) > 0 {
				return nil, fmt.Errorf("私钥导出申请 %s 正在审批中，请等待审批完成", pendingReqs[0].RequestID)
			}
			return nil, fmt.Errorf("私钥导出需要审批，请先提交导出申请并等待审批完成")
		}
		// 使用最新已批准的请求中的密码
		exportReq := approvedReqs[0]
		req.Password = exportReq.ExportPassword
		// 状态将在导出成功后更新为 EXECUTED
		defer func() {
			if err == nil {
				_ = s.exportReqRepo.UpdateStatus(ctx, exportReq.RequestID, model.ExportRequestExecuted)
			}
		}()
	}

	// 4. 二次认证：验证当前用户密码
	if req.CurrentPassword == "" {
		return nil, fmt.Errorf("必须提供当前登录密码进行二次认证")
	}
	op, err := s.operatorRepo.GetByUsername(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("无法获取操作员信息: %w", err)
	}
	if err := verifyPassword(op.PasswordHash, req.CurrentPassword); err != nil {
		if s.auditSvc != nil {
			s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityWarn, actor, actorIP, "KEY", req.KeyID,
				"私钥导出失败：二次认证密码错误", map[string]interface{}{"key_id": req.KeyID},
				model.ResultFailed, "二次认证失败")
		}
		return nil, fmt.Errorf("二次认证失败：密码错误")
	}

	// 5. 如果提供了导出密码，校验强度（允许为空，即明文导出）
	if req.Password != "" {
		if err := ValidateExportPasswordStrength(req.Password); err != nil {
			return nil, fmt.Errorf("导出密码强度不足: %w", err)
		}
	}

	// 6. 限额检查（在解密前执行，避免无效解密的性能和安全开销）
	if s.cfg.KeyManagement.Export.MaxDailyExports > 0 {
		dailyCount, err := s.keyRepo.GetDailyExportCount(ctx)
		if err != nil {
			return nil, fmt.Errorf("查询日导出计数失败: %w", err)
		}
		if dailyCount >= s.cfg.KeyManagement.Export.MaxDailyExports {
			return nil, fmt.Errorf("今日私钥导出次数已达上限(%d/%d)", dailyCount, s.cfg.KeyManagement.Export.MaxDailyExports)
		}
	}
	// 6b. 原子更新单密钥导出计数
	ok, err := s.keyRepo.IncrementExportCount(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("更新导出计数失败: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("该密钥导出次数已达上限")
	}

	// 7. 解密私钥
	plainKey, err := s.keyStore.RetrieveKey(keyModel)
	if err != nil {
		if s.auditSvc != nil {
			s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityCritical, actor, actorIP, "KEY", req.KeyID,
				"私钥导出失败：解密失败", map[string]interface{}{"key_id": req.KeyID, "reason": req.Reason},
				model.ResultFailed, err.Error())
		}
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}
	// 导出完成后安全擦除明文私钥
	defer func() {
		for i := range plainKey {
			plainKey[i] = 0
		}
	}()

	// 8. 使用密码加密私钥 (PBKDF2 + AES-256-GCM)，若密码为空则返回明文
	var encryptedPEM string
	if req.Password != "" {
		encryptedPEM, err = encryptPrivateKeyWithPassword(plainKey, req.Password)
		if err != nil {
			return nil, fmt.Errorf("加密导出私钥失败: %w", err)
		}
	} else {
		encryptedPEM = string(plainKey)
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
	if req.Password == "" {
		resp.Warning = "⚠️ 警告：您选择了明文导出私钥，私钥将以未加密形式呈现，请确保传输和存储环境安全！"
	}

	remaining := keyModel.RemainingExports()
	if remaining >= 0 {
		resp.RemainingExports = &remaining
	}

	// 10. 审计日志（CRITICAL级别）
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, model.EventKeyExport, model.SeverityCritical, actor, actorIP, "KEY", req.KeyID,
			fmt.Sprintf("导出私钥：%s，原因：%s", req.KeyID, req.Reason), map[string]interface{}{
				"key_id":            req.KeyID,
				"algorithm":         keyModel.Algorithm,
				"export_format":     req.ExportFormat,
				"reason":            req.Reason,
				"remaining_exports": remaining,
				"encrypted":         req.Password != "",
			}, model.ResultSuccess, "")
	}

	return resp, nil
}

// ValidateExportPasswordStrength 校验导出密码强度（最小12位）
func ValidateExportPasswordStrength(password string) error {
	return ValidatePasswordPolicy(password, 12)
}

// verifyPassword 校验密码（bcrypt）
func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// encryptPrivateKeyWithPassword 使用PBKDF2+AES-256-GCM加密私钥PEM
func encryptPrivateKeyWithPassword(plainKey []byte, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	derivedKey := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plainKey, nil)
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

func ptr(t time.Time) *time.Time {
	return &t
}
