package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

const defaultCRLNextUpdateHours = 48

// ManagementService 证书管理服务
type ManagementService struct {
	certRepo        *repository.CertificateRepository
	caRepo          *repository.CAChainRepository
	caEngine        *core.CAEngine
	auditSvc        *AuditService
	nextUpdateHours int
}

// NewManagementService 创建证书管理服务
func NewManagementService(certRepo *repository.CertificateRepository, caRepo *repository.CAChainRepository, caEngine *core.CAEngine, auditSvc *AuditService, nextUpdateHours int) *ManagementService {
	if nextUpdateHours <= 0 {
		nextUpdateHours = defaultCRLNextUpdateHours
	}
	return &ManagementService{
		certRepo:        certRepo,
		caRepo:          caRepo,
		caEngine:        caEngine,
		auditSvc:        auditSvc,
		nextUpdateHours: nextUpdateHours,
	}
}

// GetCertificate 获取证书详情
func (s *ManagementService) GetCertificate(ctx context.Context, certID int64) (*model.Certificate, error) {
	return s.certRepo.GetByID(ctx, certID)
}

// ListExpiringCertificates 查询即将过期的证书
func (s *ManagementService) ListExpiringCertificates(ctx context.Context, days int) ([]model.Certificate, error) {
	if days < 1 {
		days = 30
	}
	return s.certRepo.GetExpiringSoon(ctx, days)
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
func (s *ManagementService) RevokeCertificate(ctx context.Context, certID int64, reason int, reasonText, revokedBy, actorIP string) error {
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

	// Metrics 埋点
	metrics.IncCertsRevoked()

	// 吊销成功后立即生成并保存CRL
	if err := s.generateAndSaveCRL(ctx, cert.CAID); err != nil {
		if rbErr := s.certRepo.UpdateStatus(ctx, certID, model.CertStatusValid, nil, 0); rbErr != nil {
			log.Error().Err(rbErr).Int64("cert_id", certID).Msg("吊销证书后CRL生成失败，回滚也失败")
		}
		return fmt.Errorf("吊销成功但CRL生成失败，已回滚: %w", err)
	}

	// 审计日志
	s.auditSvc.Log(ctx, model.EventCertRevoke, model.SeverityWarn, revokedBy, actorIP, "CERTIFICATE", cert.SerialNumber,
		fmt.Sprintf("吊销证书: %s, 原因: %s", cert.SubjectDN, reasonText), map[string]interface{}{
			"cert_id":     certID,
			"serial":      cert.SerialNumber,
			"reason":      reason,
			"reason_text": reasonText,
		}, model.ResultSuccess, "")

	return nil
}

// generateAndSaveCRL 为指定CA生成CRL并保存到文件
func (s *ManagementService) generateAndSaveCRL(ctx context.Context, caID int) error {
	ca, err := s.caRepo.GetByID(ctx, caID)
	if err != nil {
		return fmt.Errorf("获取CA失败: %w", err)
	}

	filters := map[string]interface{}{
		"status": string(model.CertStatusRevoked),
	}
	revokedCerts, _, err := s.certRepo.List(ctx, filters, 0, 0)
	if err != nil {
		return fmt.Errorf("查询吊销证书失败: %w", err)
	}

	revokedEntries := core.BuildRevokedEntries(revokedCerts, caID)

	thisUpdate := time.Now()
	nextUpdate := thisUpdate.Add(time.Duration(s.nextUpdateHours) * time.Hour)
	crlBytes, err := s.caEngine.GenerateCRL(ca.CAName, revokedEntries, thisUpdate, nextUpdate)
	if err != nil {
		return fmt.Errorf("生成CRL失败: %w", err)
	}

	crlDir := "./data/crls"
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		return fmt.Errorf("创建CRL目录失败: %w", err)
	}
	crlPath := filepath.Join(crlDir, ca.CAName+".crl")
	if err := os.WriteFile(crlPath, crlBytes, 0644); err != nil {
		return fmt.Errorf("保存CRL文件失败: %w", err)
	}

	log.Info().Str("ca", ca.CAName).Str("path", crlPath).Int("entries", len(revokedEntries)).Msg("CRL生成并保存成功")
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
		"total_certificates":   total,
		"active_certificates":  stats["VALID"],
		"revoked_certificates": stats["REVOKED"],
		"expired_certificates": stats["EXPIRED"],
	}, nil
}
