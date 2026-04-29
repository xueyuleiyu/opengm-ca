package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/rs/zerolog/log"
)

// JWTMiddleware JWT认证中间件
func JWTMiddleware(cfg *config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "缺少认证信息"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "认证格式错误"})
			c.Abort()
			return
		}

		tokenStr := parts[1]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWT.Secret), nil
		}, jwt.WithIssuer(cfg.JWT.Issuer))

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token无效或已过期"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token解析失败"})
			c.Abort()
			return
		}

		// 设置用户信息到上下文
		c.Set("user_id", claims["sub"])
		c.Set("username", claims["username"])
		c.Set("role", claims["role"])
		c.Set("permissions", claims["permissions"])

		c.Next()
	}
}

// RequirePermission 权限检查中间件
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		perms, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "无权限执行此操作"})
			c.Abort()
			return
		}

		permList, ok := perms.([]interface{})
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "权限解析失败"})
			c.Abort()
			return
		}

		hasPerm := false
		for _, p := range permList {
			if p == "*" || p == permission {
				hasPerm = true
				break
			}
		}

		if !hasPerm {
			c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "缺少权限: " + permission})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GenerateJWT 生成JWT Token
func GenerateJWT(cfg *config.AuthConfig, userID, username string, role string, permissions []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":         userID,
		"username":    username,
		"role":        role,
		"permissions": permissions,
		"iss":         cfg.JWT.Issuer,
		"iat":         now.Unix(),
		"exp":         now.Add(cfg.JWT.AccessTokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret))
}

// RateLimitMiddleware 简单限流中间件
func RateLimitMiddleware(maxRequests int, window time.Duration) gin.HandlerFunc {
	// 简化实现：使用内存map记录请求次数
	type clientInfo struct {
		count   int
		resetAt time.Time
	}
	clients := make(map[string]*clientInfo)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		info, exists := clients[clientIP]
		if !exists || now.After(info.resetAt) {
			clients[clientIP] = &clientInfo{
				count:   1,
				resetAt: now.Add(window),
			}
			c.Next()
			return
		}

		if info.count >= maxRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    "RATE_LIMITED",
				"message": "请求过于频繁，请稍后重试",
			})
			c.Abort()
			return
		}

		info.count++
		c.Next()
	}
}

// RequestIDMiddleware 请求ID中间件
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)
		c.Next()
	}
}

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}