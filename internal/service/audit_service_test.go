package service

import (
	"path/filepath"
	"testing"

	"github.com/opengm-ca/opengm-ca/internal/model"
)

func TestBackupFilePath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit_backup.log")

	s := &AuditService{backupFile: path}

	if got := s.BackupFilePath(); got != path {
		t.Fatalf("BackupFilePath() = %q, want %q", got, path)
	}
}

func TestWriteToBackup(t *testing.T) {
	tmp := t.TempDir()
	s := &AuditService{backupFile: filepath.Join(tmp, "audit_backup.log")}

	s.writeToBackup(&model.AuditLog{Actor: "admin", Action: "test action"})

	if got := s.droppedCount.Load(); got != 1 {
		t.Fatalf("droppedCount = %d, want 1", got)
	}
}
