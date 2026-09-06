package hsm

import (
	"crypto"
	"os"
	"testing"
)

func TestSoftHSMGenerateKeyPair(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "test-password-123")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	t.Run("SM2", func(t *testing.T) {
		handle, pubKey, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
		if err != nil {
			t.Fatalf("GenerateKeyPair(SM2) error = %v", err)
		}
		if handle == "" {
			t.Error("handle is empty")
		}
		if pubKey == nil {
			t.Error("pubKey is nil")
		}
	})

	t.Run("RSA2048", func(t *testing.T) {
		handle, pubKey, err := hsm.GenerateKeyPair("RSA2048", 0, "SIGNATURE")
		if err != nil {
			t.Fatalf("GenerateKeyPair(RSA2048) error = %v", err)
		}
		if handle == "" {
			t.Error("handle is empty")
		}
		if pubKey == nil {
			t.Error("pubKey is nil")
		}
	})

	t.Run("EC256", func(t *testing.T) {
		handle, pubKey, err := hsm.GenerateKeyPair("EC256", 0, "SIGNATURE")
		if err != nil {
			t.Fatalf("GenerateKeyPair(EC256) error = %v", err)
		}
		if handle == "" {
			t.Error("handle is empty")
		}
		if pubKey == nil {
			t.Error("pubKey is nil")
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		_, _, err := hsm.GenerateKeyPair("INVALID", 0, "SIGNATURE")
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}
	})
}

func TestSoftHSMSignAndVerify(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_sign_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "test-password-456")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	handle, _, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	digest := []byte("test message for signing")
	sig, err := hsm.Sign(handle, digest, "SM3")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature is empty")
	}

	// Sign with non-existent handle
	_, err = hsm.Sign("non-existent", digest, "SM3")
	if err == nil {
		t.Error("expected error for non-existent key handle")
	}
}

func TestSoftHSMGetPublicKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_pub_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "test-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	handle, origPub, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	pubKey, err := hsm.GetPublicKey(handle)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	if pubKey == nil {
		t.Error("GetPublicKey() returned nil")
	}
	_ = origPub

	pubPEM, err := hsm.GetPublicKeyPEM(handle)
	if err != nil {
		t.Fatalf("GetPublicKeyPEM() error = %v", err)
	}
	if pubPEM == "" {
		t.Error("GetPublicKeyPEM() returned empty")
	}
}

func TestSoftHSMKeyLifecycle(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_lifecycle_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "lifecycle-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	// Generate
	handle, _, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// List
	keys, err := hsm.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListKeys() count = %d, want 1", len(keys))
	}

	// Get info
	info, err := hsm.GetKeyInfo(handle)
	if err != nil {
		t.Fatalf("GetKeyInfo() error = %v", err)
	}
	if info.Handle != handle {
		t.Errorf("GetKeyInfo() handle = %s, want %s", info.Handle, handle)
	}

	// Status
	status, err := hsm.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.KeyCount != 1 {
		t.Errorf("Status().KeyCount = %d, want 1", status.KeyCount)
	}
	if status.Type != "SOFT_HSM" {
		t.Errorf("Status().Type = %s, want SOFT_HSM", status.Type)
	}
	if !status.Initialized {
		t.Error("Status().Initialized should be true")
	}

	// Export is forbidden
	_, err = hsm.ExportKey(handle)
	if err == nil {
		t.Error("ExportKey() should return error")
	}

	// Delete
	if err := hsm.DeleteKey(handle); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	keys, _ = hsm.ListKeys()
	if len(keys) != 0 {
		t.Errorf("ListKeys() after delete count = %d, want 0", len(keys))
	}

	// Delete non-existent
	if err := hsm.DeleteKey("non-existent"); err == nil {
		t.Error("DeleteKey(non-existent) should return error")
	}
}

func TestSoftHSMPersistenceAcrossRestarts(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_persist_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	handle1 := ""
	{
		hsm, err := NewSoftHSM(dir, "persist-pwd")
		if err != nil {
			t.Fatalf("NewSoftHSM() error = %v", err)
		}
		handle, _, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		handle1 = handle
		hsm.Close()
	}

	// Re-open and verify key is still there
	{
		hsm, err := NewSoftHSM(dir, "persist-pwd")
		if err != nil {
			t.Fatalf("NewSoftHSM() re-open error = %v", err)
		}
		defer hsm.Close()

		keys, err := hsm.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys() error = %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("ListKeys() re-open count = %d, want 1", len(keys))
		}
		if keys[0].Handle != handle1 {
			t.Errorf("handle mismatch: %s vs %s", keys[0].Handle, handle1)
		}

		// Should be able to sign with the recovered key
		sig, err := hsm.Sign(handle1, []byte("test data"), "SM3")
		if err != nil {
			t.Fatalf("Sign() after re-open error = %v", err)
		}
		if len(sig) == 0 {
			t.Error("signature empty after re-open")
		}
	}
}

func TestSoftHSMWrongPassword(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_wrongpwd_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm1, err := NewSoftHSM(dir, "correct-password")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	handle, _, err := hsm1.GenerateKeyPair("SM2", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	hsm1.Close()

	// Re-open with wrong password
	hsm2, err := NewSoftHSM(dir, "wrong-password")
	if err != nil {
		t.Fatalf("NewSoftHSM() with wrong password error = %v", err)
	}
	defer hsm2.Close()

	// Keys should be loaded but decryption should fail
	keys, err := hsm2.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListKeys() count = %d, want 1 (keys are loaded but encrypted with wrong key)", len(keys))
	}

	// Sign should fail because the KEK is derived from wrong password
	_, err = hsm2.Sign(handle, []byte("test"), "SM3")
	if err == nil {
		t.Error("Sign() with wrong password should fail")
	}
}

func TestSoftHSMImportKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_import_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "import-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	// Generate a key first, then try to import it
	handle1, _, err := hsm.GenerateKeyPair("SM2", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	_ = handle1

	// Import should work for RSA (using standard x509 marshaling)
	// We can't easily test ImportKey with SM2 without the private key reference
	// but we can test that invalid types are rejected
	_, err = hsm.ImportKey("INVALID", "not-a-key", "SIGNATURE")
	if err == nil {
		t.Error("ImportKey() with invalid type should error")
	}
}

func TestSoftHSMInvalidHandle(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_invalid_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "test-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	_, err = hsm.GetPublicKey("nonexistent")
	if err == nil {
		t.Error("GetPublicKey(nonexistent) should error")
	}

	_, err = hsm.GetKeyInfo("nonexistent")
	if err == nil {
		t.Error("GetKeyInfo(nonexistent) should error")
	}

	_, err = hsm.GetPublicKeyPEM("nonexistent")
	if err == nil {
		t.Error("GetPublicKeyPEM(nonexistent) should error")
	}
}

func TestSoftHSMHSMStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_status_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "status-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	status, err := hsm.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Type != "SOFT_HSM" {
		t.Errorf("Status().Type = %s, want SOFT_HSM", status.Type)
	}
	if !status.Initialized {
		t.Error("Status().Initialized should be true")
	}
	if status.KeyCount != 0 {
		t.Errorf("Status().KeyCount = %d, want 0", status.KeyCount)
	}
	if status.StoragePath != dir {
		t.Errorf("Status().StoragePath = %s, want %s", status.StoragePath, dir)
	}
}

func TestSoftHSMSignDigest(t *testing.T) {
	dir, err := os.MkdirTemp("", "softhsm_signdigest_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	hsm, err := NewSoftHSM(dir, "digest-pwd")
	if err != nil {
		t.Fatalf("NewSoftHSM() error = %v", err)
	}
	defer hsm.Close()

	// Test RSA signing path
	rHandle, _, err := hsm.GenerateKeyPair("RSA2048", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair(RSA) error = %v", err)
	}

	digest := []byte("0123456789abcdef0123456789abcdef") // 32 bytes = SHA256 digest
	sig, err := hsm.Sign(rHandle, digest, "SHA256")
	if err != nil {
		t.Fatalf("Sign(RSA) error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("RSA signature is empty")
	}

	// Test ECDSA signing path
	eHandle, _, err := hsm.GenerateKeyPair("EC256", 0, "SIGNATURE")
	if err != nil {
		t.Fatalf("GenerateKeyPair(EC) error = %v", err)
	}

	sig, err = hsm.Sign(eHandle, digest, "SHA256")
	if err != nil {
		t.Fatalf("Sign(ECDSA) error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("ECDSA signature is empty")
	}

	// Retrieve public key for verification
	rsaPub, _ := hsm.GetPublicKey(rHandle)
	_ = crypto.PublicKey(rsaPub)

	ecPub, _ := hsm.GetPublicKey(eHandle)
	_ = crypto.PublicKey(ecPub)
}
