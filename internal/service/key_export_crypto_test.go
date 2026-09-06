package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func TestVerifyPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}

	if err := verifyPassword(string(hash), "correct-password"); err != nil {
		t.Fatalf("verifyPassword(correct) error = %v, want nil", err)
	}
	if err := verifyPassword(string(hash), "wrong-password"); err == nil {
		t.Fatal("verifyPassword(wrong) = nil, want error")
	}
}

// decryptPrivateKeyWithPassword 与 encryptPrivateKeyWithPassword 对应的解密逻辑，
// 仅用于回环测试，验证加密结果可被还原。
func decryptPrivateKeyWithPassword(encoded, password string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < 16+12+16 {
		return nil, errors.New("ciphertext too short")
	}
	salt := raw[:16]
	nonce := raw[16:28]
	ciphertext := raw[28:]

	derivedKey := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestEncryptPrivateKeyWithPassword(t *testing.T) {
	plainKey := []byte("-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----")

	encrypted, err := encryptPrivateKeyWithPassword(plainKey, "export-password-123!")
	if err != nil {
		t.Fatalf("encryptPrivateKeyWithPassword() error = %v", err)
	}
	if encrypted == "" {
		t.Fatal("encryptPrivateKeyWithPassword() returned empty string")
	}
	if encrypted == string(plainKey) {
		t.Fatal("encryptPrivateKeyWithPassword() returned plaintext, not encrypted")
	}

	// 回环：正确口令能解密回原文
	decrypted, err := decryptPrivateKeyWithPassword(encrypted, "export-password-123!")
	if err != nil {
		t.Fatalf("decrypt with correct password error = %v", err)
	}
	if !bytes.Equal(decrypted, plainKey) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plainKey)
	}

	// 错误口令必须解密失败
	if _, err := decryptPrivateKeyWithPassword(encrypted, "wrong-password-456!"); err == nil {
		t.Fatal("decrypt with wrong password = nil, want error")
	}
}
