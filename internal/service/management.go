package service

import (
	"context"
	"fmt"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
)

// ManagementService 证书管理服务
type ManagementService struct {
	certRepo *repository.CertificateRepository
	auditSvc *AuditService
}

// NewManagementService 创建证书管理服务
func NewManagementService(certRepo *repository.CertificateRepository, auditSvc *AuditService) *ManagementService {
	return &ManagementService{
		certRepo: certRepo,
		auditSvc: auditSvc,
	}
}

// GetCertificate 获取证书详情
func (s *ManagementService) GetCertificate(ctx context.Context, certID int64) (*model.Certificate, error) {
	return s.certRepo.GetByID(ctx, certID)
}

// ListCertificates 查询证书列表
func (s *ManagementService) ListCertificates(ctx context.Context, filters map[string]interface{}, page, pageSize int) ([]model.Certificate, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	return s.certRepo.List(ctx, filters, offset, pageSize)
}

// RevokeCertificate 吊销证书
func (s *ManagementService) RevokeCertificate(ctx context.Context, certID int64, reason int, reasonText, revokedBy string) error {
	cert, err := s.certRepo.GetByID(ctx, certID)
	if err != nil {
		return fmt.Errorf("证书不存在: %w", err)
	}

	if cert.Status != model.CertStatusValid {
		return fmt.Errorf("证书状态为 %s，无法吊销", cert.Status)
	}

	now := time.Now()
	if err := s.certRepo.UpdateStatus(ctx, certID, model.CertStatusRevoked, now, reason); err != nil {
		return fmt.Errorf("更新证书状态失败: %w", err)
	}

	// 审计日志
	s.auditSvc.Log(ctx, model.EventCertRevoke, model.SeverityWarn, revokedBy, "", "CERTIFICATE", cert.SerialNumber,
		fmt.Sprintf("吊销证书: %s, 原因: %s", cert.SubjectDN, reasonText), map[string]interface{}{
			"cert_id":  certID,
			"serial":   cert.SerialNumber,
			"reason":   reason,
			"reason_text": reasonText,
		}, model.ResultSuccess, "")

	return nil
}

// GetSystemStats 获取系统统计
func (s *ManagementService) GetSystemStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.certRepo.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("统计证书数量失败: %w", err)
	}

	total := int64(0)
	for _, v := range stats {
		total += v
	}

	return map[string]interface{}{
		"total_certificates":  total,
		"active_certificates": stats["VALID"],
		"revoked_certificates": stats["REVOKED"],
		"expired_certificates": stats["EXPIRED"],
	}, nil
}
