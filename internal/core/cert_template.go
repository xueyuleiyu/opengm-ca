package core

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/opengm-ca/opengm-ca/internal/config"
)

// keyUsageMap 字符串到 x509.KeyUsage 的映射
var keyUsageMap = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"certSign":          x509.KeyUsageCertSign,
	"crlSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
	"nonRepudiation":    x509.KeyUsageContentCommitment, // 别名
}

// extKeyUsageMap 字符串到 x509.ExtKeyUsage 的映射
var extKeyUsageMap = map[string]x509.ExtKeyUsage{
	"any":                            x509.ExtKeyUsageAny,
	"serverAuth":                     x509.ExtKeyUsageServerAuth,
	"clientAuth":                     x509.ExtKeyUsageClientAuth,
	"codeSigning":                    x509.ExtKeyUsageCodeSigning,
	"emailProtection":                x509.ExtKeyUsageEmailProtection,
	"ipsecEndSystem":                 x509.ExtKeyUsageIPSECEndSystem,
	"ipsecTunnel":                    x509.ExtKeyUsageIPSECTunnel,
	"ipsecUser":                      x509.ExtKeyUsageIPSECUser,
	"timeStamping":                   x509.ExtKeyUsageTimeStamping,
	"ocspSigning":                    x509.ExtKeyUsageOCSPSigning,
	"microsoftServerGatedCrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"microsoftCommercialCodeSigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
}

// ParseKeyUsage 将字符串数组解析为 x509.KeyUsage 位掩码
func ParseKeyUsage(usages []string) (x509.KeyUsage, error) {
	var result x509.KeyUsage
	for _, u := range usages {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		v, ok := keyUsageMap[u]
		if !ok {
			return 0, fmt.Errorf("未知的KeyUsage: %s", u)
		}
		result |= v
	}
	return result, nil
}

// ParseExtKeyUsage 将字符串数组解析为 x509.ExtKeyUsage 切片
func ParseExtKeyUsage(usages []string) ([]x509.ExtKeyUsage, error) {
	var result []x509.ExtKeyUsage
	for _, u := range usages {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		v, ok := extKeyUsageMap[u]
		if !ok {
			return nil, fmt.Errorf("未知的ExtKeyUsage: %s", u)
		}
		result = append(result, v)
	}
	return result, nil
}

// ApplyCertTemplate 将配置中的证书模板应用到 x509.Certificate
func ApplyCertTemplate(template *x509.Certificate, tmplCfg config.CertTemplateConfig) error {
	if len(tmplCfg.KeyUsage) > 0 {
		ku, err := ParseKeyUsage(tmplCfg.KeyUsage)
		if err != nil {
			return fmt.Errorf("解析KeyUsage失败: %w", err)
		}
		template.KeyUsage = ku
	}
	if len(tmplCfg.ExtKeyUsage) > 0 {
		eku, err := ParseExtKeyUsage(tmplCfg.ExtKeyUsage)
		if err != nil {
			return fmt.Errorf("解析ExtKeyUsage失败: %w", err)
		}
		template.ExtKeyUsage = eku
	}
	return nil
}
