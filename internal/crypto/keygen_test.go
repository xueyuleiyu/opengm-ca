package crypto

import (
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	gen := NewKeyGenerator()

	t.Run("SM2 key generation", func(t *testing.T) {
		priv, pub, err := gen.GenerateKeyPair("SM2")
		require.NoError(t, err)
		assert.NotNil(t, priv)
		assert.NotNil(t, pub)

		_, ok := priv.(*sm2.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("RSA2048 key generation", func(t *testing.T) {
		priv, pub, err := gen.GenerateKeyPair("RSA2048")
		require.NoError(t, err)
		assert.NotNil(t, priv)
		assert.NotNil(t, pub)
	})

	t.Run("EC256 key generation", func(t *testing.T) {
		priv, pub, err := gen.GenerateKeyPair("EC256")
		require.NoError(t, err)
		assert.NotNil(t, priv)
		assert.NotNil(t, pub)
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		_, _, err := gen.GenerateKeyPair("INVALID")
		assert.Error(t, err)
	})
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	gen := NewKeyGenerator()

	testCases := []struct {
		name      string
		algorithm string
	}{
		{"SM2", "SM2"},
		{"RSA2048", "RSA2048"},
		{"EC256", "EC256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, _, err := gen.GenerateKeyPair(tc.algorithm)
			require.NoError(t, err)

			// 编码
			pemStr, err := EncodePrivateKey(priv, tc.algorithm)
			require.NoError(t, err)
			assert.NotEmpty(t, pemStr)

			// 解码
			decodedPriv, err := ParsePrivateKeyFromPEM(pemStr)
			require.NoError(t, err)
			assert.NotNil(t, decodedPriv)
		})
	}
}

func TestEncodePublicKey(t *testing.T) {
	gen := NewKeyGenerator()

	testCases := []struct {
		name      string
		algorithm string
	}{
		{"SM2", "SM2"},
		{"RSA2048", "RSA2048"},
		{"EC256", "EC256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, pub, err := gen.GenerateKeyPair(tc.algorithm)
			require.NoError(t, err)

			pemStr, err := EncodePublicKeyToPEM(pub)
			require.NoError(t, err)
			assert.NotEmpty(t, pemStr)
			assert.Contains(t, pemStr, "-----BEGIN PUBLIC KEY-----")
		})
	}
}
