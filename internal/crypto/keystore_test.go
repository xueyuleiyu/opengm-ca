package crypto

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveMasterKey(t *testing.T) {
	t.Run("hex format valid", func(t *testing.T) {
		hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		os.Setenv("TEST_HEX_KEY", hexKey)
		defer os.Unsetenv("TEST_HEX_KEY")

		key, err := ResolveMasterKey("TEST_HEX_KEY")
		require.NoError(t, err)
		assert.Len(t, key, 32)

		expected, _ := hex.DecodeString(hexKey)
		assert.Equal(t, expected, key)
	})

	t.Run("hex format invalid length", func(t *testing.T) {
		shortHexKey := "0123456789abcdef"
		os.Setenv("TEST_SHORT_KEY", shortHexKey)
		defer os.Unsetenv("TEST_SHORT_KEY")

		_, err := ResolveMasterKey("TEST_SHORT_KEY")
		assert.Error(t, err)
	})

	t.Run("base64 format valid", func(t *testing.T) {
		rawKey := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rawKey[i] = byte(i)
		}
		base64Key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		os.Setenv("TEST_B64_KEY", base64Key)
		defer os.Unsetenv("TEST_B64_KEY")

		key, err := ResolveMasterKey("TEST_B64_KEY")
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("raw bytes format valid", func(t *testing.T) {
		// 创建临时文件
		tmpFile, err := os.CreateTemp("", "test_key")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		rawKey := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rawKey[i] = byte(i)
		}
		_, err = tmpFile.Write(rawKey)
		require.NoError(t, err)
		tmpFile.Close()

		key, err := ResolveMasterKey(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, rawKey, key)
	})
}

func TestNewKeyStore(t *testing.T) {
	t.Run("valid master key", func(t *testing.T) {
		hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		os.Setenv("TEST_KS_KEY", hexKey)
		defer os.Unsetenv("TEST_KS_KEY")

		ks, err := NewKeyStore("TEST_KS_KEY")
		require.NoError(t, err)
		assert.NotNil(t, ks)
	})

	t.Run("invalid master key too short", func(t *testing.T) {
		shortKey := "0123456789abcdef"
		os.Setenv("TEST_SHORT_KS", shortKey)
		defer os.Unsetenv("TEST_SHORT_KS")

		_, err := NewKeyStore("TEST_SHORT_KS")
		assert.Error(t, err)
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	os.Setenv("TEST_RT_KEY", hexKey)
	defer os.Unsetenv("TEST_RT_KEY")

	ks, err := NewKeyStore("TEST_RT_KEY")
	require.NoError(t, err)

	plaintext := []byte("test secret data")

	ciphertext, salt, nonce, tag, err := ks.EncryptPrivateKey(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEmpty(t, salt)
	assert.NotEmpty(t, nonce)
	assert.NotEmpty(t, tag)

	decrypted, err := ks.DecryptPrivateKey(ciphertext, salt, nonce, tag)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
