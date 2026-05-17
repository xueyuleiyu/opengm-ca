package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/opengm-ca/opengm-ca/internal/config"
)

// UserStatusChecker 用户实时状态检查接口（在JWT中间件中校验账户是否仍有效）
type UserStatusChecker func(userID string) (bool, error)

// JWTMiddleware JWT认证中间件
func JWTMiddleware(cfg *config.AuthConfig, checker ...UserStatusChecker) gin.HandlerFunc {
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
		}, jwt.WithIssuer(cfg.JWT.Issuer), jwt.WithValidMethods([]string{"HS256"}))

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

		// 显式校验关键 claims
		if sub, _ := claims.GetSubject(); sub == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token缺少主体标识"})
			c.Abort()
			return
		}
		if exp, _ := claims.GetExpirationTime(); exp == nil || exp.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token已过期"})
			c.Abort()
			return
		}
		if iat, _ := claims.GetIssuedAt(); iat == nil || iat.After(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token签发时间无效"})
			c.Abort()
			return
		}

		// 设置用户信息到上下文（强制类型断言，防止客户端伪造非字符串sub）
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "Token主体格式无效"})
			c.Abort()
			return
		}

		// 校验用户实时状态（账户是否仍有效、未被锁定）
		if len(checker) > 0 && checker[0] != nil {
			if valid, checkErr := checker[0](sub); checkErr != nil || !valid {
				c.JSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "message": "账户已被禁用或锁定"})
				c.Abort()
				return
			}
		}

		c.Set("user_id", sub)
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

		for _, p := range permList {
			if p == "*" || p == permission {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"code": "FORBIDDEN", "message": "缺少权限: " + permission})
		c.Abort()
	}
}

// GenerateJWT 生成JWT Token
func GenerateJWT(cfg *config.AuthConfig, userID, username string, role string, permissions []string) (string, error) {
	// 校验JWT密钥长度（HS256需要至少32字节密钥）
	if len(cfg.JWT.Secret) < 32 {
		return "", fmt.Errorf("JWT密钥长度不足，至少需要32字节(256位)，当前: %d字节", len(cfg.JWT.Secret))
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":         userID,
		"username":    username,
		"role":        role,
		"permissions": permissions,
		"jti":         uuid.New().String(),
		"iss":         cfg.JWT.Issuer,
		"iat":         now.Unix(),
		"exp":         now.Add(cfg.JWT.AccessTokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret))
}

// RateLimitMiddleware 简单限流中间件（分片锁降低竞争，后台清理防止内存泄漏）
func RateLimitMiddleware(maxRequests int, window time.Duration) gin.HandlerFunc {
	type clientInfo struct {
		count   int
		resetAt time.Time
	}
	const shardCount = 8
	type shard struct {
		mu sync.Mutex
		m  map[string]*clientInfo
	}
	var shards [shardCount]shard
	for i := range shards {
		shards[i].m = make(map[string]*clientInfo)
	}

	// 后台定期清理过期条目
	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for i := range shards {
				s := &shards[i]
				s.mu.Lock()
				for ip, info := range s.m {
					if now.After(info.resetAt) {
						delete(s.m, ip)
					}
				}
				s.mu.Unlock()
			}
		}
	}()

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()
		idx := hashString(clientIP) % shardCount
		s := &shards[idx]

		s.mu.Lock()
		info, exists := s.m[clientIP]
		if !exists || now.After(info.resetAt) {
			s.m[clientIP] = &clientInfo{
				count:   1,
				resetAt: now.Add(window),
			}
			s.mu.Unlock()
			c.Next()
			return
		}

		if info.count >= maxRequests {
			s.mu.Unlock()
			c.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    "RATE_LIMITED",
				"message": "请求过于频繁，请稍后重试",
			})
			return
		}

		info.count++
		s.mu.Unlock()
		c.Next()
	}
}

func hashString(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return h
}

// RequestIDMiddleware 请求ID中间件
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" || len(requestID) > 64 || !isValidRequestID(requestID) {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)
		c.Next()
	}
}

func isValidRequestID(id string) bool {
	for _, ch := range id {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func generateRequestID() string {
	return uuid.New().String()
}
