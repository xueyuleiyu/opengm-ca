package service

import (
	"context"
	"fmt"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/metrics"
	"github.com/opengm-ca/opengm-ca/internal/model"
	"github.com/opengm-ca/opengm-ca/internal/repository"
	"github.com/rs/zerolog/log"
)

// CertExpirationScheduler 证书到期扫描调度器
type CertExpirationScheduler struct {
	certRepo *repository.CertificateRepository
	auditSvc *AuditService
	interval time.Duration
}

// NewCertExpirationScheduler 创建调度器
func NewCertExpirationScheduler(certRepo *repository.CertificateRepository, auditSvc *AuditService) *CertExpirationScheduler {
	return &CertExpirationScheduler{
		certRepo: certRepo,
		auditSvc: auditSvc,
		interval: 24 * time.Hour,
	}
}

// Start 启动后台定时扫描
func (s *CertExpirationScheduler) Start(ctx context.Context) {
	// 立即执行一次
	s.scan(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Error().Interface("panic", r).Msg("证书扫描任务panic恢复")
					}
				}()
				s.scan(ctx)
			}()
		case <-ctx.Done():
			log.Info().Msg("证书到期扫描调度器已停止")
			return
		}
	}
}

// scan 执行扫描并分级告警
func (s *CertExpirationScheduler) scan(ctx context.Context) {
	log.Info().Msg("开始扫描即将过期的证书")

	thresholds := []struct {
		days     int
		severity model.Severity
	}{
		{1, model.SeverityCritical},
		{7, model.SeverityError},
		{15, model.SeverityWarn},
		{30, model.SeverityInfo},
	}

	var totalExpiring int
	for _, t := range thresholds {
		certs, err := s.certRepo.GetExpiringSoon(ctx, t.days)
		if err != nil {
			log.Error().Err(err).Int("days", t.days).Msg("查询即将过期证书失败")
			continue
		}

		if len(certs) > 0 {
			if t.days == 30 {
				totalExpiring = len(certs)
			}
			log.Log().
				Str("severity", string(t.severity)).
				Int("days", t.days).
				Int("count", len(certs)).
				Msg("发现即将过期证书")

			if s.auditSvc != nil {
				for _, cert := range certs {
					s.auditSvc.Log(ctx, model.EventCertExpireWarn, t.severity,
						"SYSTEM", "", "CERTIFICATE", cert.SerialNumber,
						fmt.Sprintf("证书将在%d天内过期: %s", t.days, cert.SubjectDN),
						map[string]interface{}{
							"cert_id":   cert.ID,
							"serial":    cert.SerialNumber,
							"subject":   cert.SubjectDN,
							"valid_to":  cert.ValidTo,
							"days_left": t.days,
						},
						model.ResultSuccess, "")
				}
			}
		}
	}
	// 更新 Prometheus Gauge
	metrics.SetCertsExpiringSoon(float64(totalExpiring))
}
