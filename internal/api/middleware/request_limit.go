package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequestBodyLimitMiddleware 限制请求体大小中间件
// maxBytes: 最大请求体字节数
func RequestBodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 限制请求体大小
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// 常用请求体大小限制常量
const (
	// MaxRequestBodySize 默认最大请求体大小 (10MB)
	MaxRequestBodySize = 10 * 1024 * 1024

	// MaxCertEnrollBodySize 证书申请最大请求体大小 (1MB)
	MaxCertEnrollBodySize = 1 * 1024 * 1024

	// MaxCSRSize CSR PEM最大大小 (100KB)
	MaxCSRSize = 100 * 1024

	// MaxSubjectFieldLength Subject字段最大长度
	MaxSubjectFieldLength = 256

	// MaxSANCount SAN最大数量
	MaxSANCount = 100
)
