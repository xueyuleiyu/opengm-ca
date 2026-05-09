package middleware

import (
	"testing"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateJWT(t *testing.T) {
	t.Run("valid JWT generation", func(t *testing.T) {
		cfg := &config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Issuer:          "opengm-ca-test",
				AccessTokenTTL:  time.Hour,
				RefreshTokenTTL: 24 * time.Hour,
			},
		}

		token, err := GenerateJWT(cfg, "user1", "testuser", "ADMIN", []string{"read", "write"})
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("JWT secret too short", func(t *testing.T) {
		cfg := &config.AuthConfig{
			JWT: config.JWTConfig{
				Secret: "shortsecret",
			},
		}

		_, err := GenerateJWT(cfg, "user1", "testuser", "ADMIN", []string{"read", "write"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "长度不足")
	})
}
