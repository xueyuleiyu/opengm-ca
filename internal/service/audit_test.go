package service

import (
	"testing"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/model"
)

func TestComputeHash(t *testing.T) {
	auditLog := &model.AuditLog{
		RecordContent: `{"action":"test","actor":"admin"}`,
	}

	h1 := auditLog.ComputeHash("")
	if h1 == "" {
		t.Error("ComputeHash() returned empty string")
	}
	if len(h1) != 64 {
		t.Errorf("ComputeHash() length = %d, want 64 (SHA-256 hex)", len(h1))
	}

	// Same input should produce same hash
	h2 := auditLog.ComputeHash("")
	if h1 != h2 {
		t.Error("ComputeHash() not deterministic")
	}

	// Different prevHash should produce different hash
	h3 := auditLog.ComputeHash("abc123")
	if h1 == h3 {
		t.Error("ComputeHash() should produce different hashes for different prevHash")
	}
}

func TestComputeHashChain(t *testing.T) {
	// Simulate a hash chain
	logs := []*model.AuditLog{
		{RecordContent: `{"action":"a1"}`},
		{RecordContent: `{"action":"a2"}`},
		{RecordContent: `{"action":"a3"}`},
	}

	var prevHash string
	hashes := make([]string, len(logs))

	for i, l := range logs {
		h := l.ComputeHash(prevHash)
		if h == "" {
			t.Fatalf("log[%d] hash is empty", i)
		}
		hashes[i] = h
		prevHash = h
	}

	// All hashes should be unique
	seen := make(map[string]bool)
	for i, h := range hashes {
		if seen[h] {
			t.Errorf("log[%d] hash collision: %s", i, h)
		}
		seen[h] = true
	}
}

func TestComputeHashWithoutRecordContent(t *testing.T) {
	auditLog := &model.AuditLog{
		EventTime: time.Now(),
		EventType: model.EventCertIssue,
		Severity:  model.SeverityInfo,
		Actor:     "admin",
		Action:    "test action",
	}

	h := auditLog.ComputeHash("genesis")
	if h == "" {
		t.Error("ComputeHash() returned empty when RecordContent is not set")
	}
}
