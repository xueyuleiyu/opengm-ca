package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// EventType 审计事件类型
type EventType string

const (
	EventCertIssue      EventType = "CERT_ISSUE"
	EventCertRevoke     EventType = "CERT_REVOKE"
	EventCertRenew      EventType = "CERT_RENEW"
	EventCertHold       EventType = "CERT_HOLD"
	EventKeyGenerate    EventType = "KEY_GENERATE"
	EventKeyExport      EventType = "KEY_EXPORT"
	EventKeyDelete      EventType = "KEY_DELETE"
	EventKeyImport      EventType = "KEY_IMPORT"
	EventCAInit         EventType = "CA_INIT"
	EventCARotate       EventType = "CA_ROTATE"
	EventCRLGenerate    EventType = "CRL_GENERATE"
	EventAdminLogin     EventType = "ADMIN_LOGIN"
	EventAdminAction    EventType = "ADMIN_ACTION"
	EventConfigChange   EventType = "CONFIG_CHANGE"
	EventBackupCreate   EventType = "BACKUP_CREATE"
	EventBackupRestore  EventType = "BACKUP_RESTORE"
)

// Severity 日志严重级别
type Severity string

const (
	SeverityDebug     Severity = "DEBUG"
	SeverityInfo      Severity = "INFO"
	SeverityWarn      Severity = "WARN"
	SeverityError     Severity = "ERROR"
	SeverityCritical  Severity = "CRITICAL"
)

// Result 操作结果
type Result string

const (
	ResultSuccess Result = "SUCCESS"
	ResultFailed  Result = "FAILED"
	ResultDenied  Result = "DENIED"
	ResultTimeout Result = "TIMEOUT"
)

// AuditLog 审计日志领域模型
type AuditLog struct {
	ID              int64       `bun:"id,pk,autoincrement" json:"id"`
	EventTime       time.Time   `bun:"event_time,notnull,default:current_timestamp" json:"event_time"`
	EventType       EventType   `bun:"event_type,notnull" json:"event_type"`
	Severity        Severity    `bun:"severity,default:'INFO'" json:"severity"`

	Actor           string      `bun:"actor,notnull" json:"actor"`
	ActorType       string      `bun:"actor_type,default:'USER'" json:"actor_type"`
	ActorIP         string      `bun:"actor_ip" json:"actor_ip,omitempty"`
	ActorFingerprint string     `bun:"actor_fingerprint" json:"actor_fingerprint,omitempty"`

	TargetType      string      `bun:"target_type" json:"target_type,omitempty"`
	TargetID        string      `bun:"target_id" json:"target_id,omitempty"`

	Action          string      `bun:"action,notnull" json:"action"`
	Detail          map[string]interface{} `bun:"detail,type:jsonb,default:'{}'" json:"detail"`
	Result          Result      `bun:"result" json:"result"`
	ErrorMsg        string      `bun:"error_msg" json:"error_msg,omitempty"`

	// 哈希链完整性保护
	PrevHash        string      `bun:"prev_hash" json:"prev_hash,omitempty"`
	RecordContent   string      `bun:"record_content,notnull" json:"record_content"`
	CurrHash        string      `bun:"curr_hash,notnull" json:"curr_hash"`

	// 时间戳签名
	TSSignature     []byte      `bun:"ts_signature" json:"ts_signature,omitempty"`
}

// TableName 返回表名
func (a *AuditLog) TableName() string {
	return "audit_log"
}

// ComputeHash 计算当前记录的哈希值
func (a *AuditLog) ComputeHash(prevHash string) string {
	content, _ := json.Marshal(map[string]interface{}{
		"event_time":    a.EventTime.Format(time.RFC3339Nano),
		"event_type":    a.EventType,
		"severity":      a.Severity,
		"actor":         a.Actor,
		"actor_type":    a.ActorType,
		"actor_ip":      a.ActorIP,
		"target_type":   a.TargetType,
		"target_id":     a.TargetID,
		"action":        a.Action,
		"detail":        a.Detail,
		"result":        a.Result,
		"error_msg":     a.ErrorMsg,
	})

	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// BuildRecordContent 构建记录内容JSON
func (a *AuditLog) BuildRecordContent() string {
	content, _ := json.Marshal(map[string]interface{}{
		"event_time":    a.EventTime.Format(time.RFC3339Nano),
		"event_type":    a.EventType,
		"severity":      a.Severity,
		"actor":         a.Actor,
		"actor_type":    a.ActorType,
		"actor_ip":      a.ActorIP,
		"target_type":   a.TargetType,
		"target_id":     a.TargetID,
		"action":        a.Action,
		"detail":        a.Detail,
		"result":        a.Result,
		"error_msg":     a.ErrorMsg,
	})
	return string(content)
}

// AuditVerifyResult 审计验证结果
type AuditVerifyResult struct {
	TotalRecords  int64  `json:"total_records"`
	Verified      int64  `json:"verified"`
	Corrupted     int64  `json:"corrupted"`
	FirstHash     string `json:"first_hash"`
	LastHash      string `json:"last_hash"`
	IsValid       bool   `json:"is_valid"`
	CorruptedIDs  []int64 `json:"corrupted_ids,omitempty"`
}
