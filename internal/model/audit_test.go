package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestComputeHashDeterministic(t *testing.T) {
	log := &AuditLog{RecordContent: `{"action":"issue","actor":"admin"}`}

	h1 := log.ComputeHash("")
	h2 := log.ComputeHash("")

	if h1 != h2 {
		t.Fatalf("ComputeHash() not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("ComputeHash() length = %d, want 64 (sha256 hex)", len(h1))
	}
}

func TestComputeHashPrevHashParticipates(t *testing.T) {
	log := &AuditLog{RecordContent: `{"action":"issue"}`}

	hEmpty := log.ComputeHash("")
	hGenesis := log.ComputeHash("genesis")
	hOther := log.ComputeHash("other-prev-hash")

	if hEmpty == hGenesis {
		t.Fatal("ComputeHash() should differ between empty and non-empty prevHash")
	}
	if hGenesis == hOther {
		t.Fatal("ComputeHash() should differ between different prevHash values")
	}
}

// TestComputeHashFieldPerturbation 逐字段扰动：任何业务字段变化都必须导致哈希变化。
func TestComputeHashFieldPerturbation(t *testing.T) {
	base := &AuditLog{
		EventTime:  time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		EventType:  EventCertIssue,
		Severity:   SeverityInfo,
		Actor:      "admin",
		ActorType:  "USER",
		ActorIP:    "10.0.0.1",
		TargetType: "CERTIFICATE",
		TargetID:   "abc123",
		Action:     "签发证书",
		Detail:     map[string]interface{}{"serial": "01"},
		Result:     ResultSuccess,
		ErrorMsg:   "",
	}

	baseHash := base.ComputeHash("")

	mutations := []struct {
		name   string
		mutate func(*AuditLog)
	}{
		{"event_time", func(a *AuditLog) { a.EventTime = a.EventTime.Add(time.Second) }},
		{"event_type", func(a *AuditLog) { a.EventType = EventCertRevoke }},
		{"severity", func(a *AuditLog) { a.Severity = SeverityWarn }},
		{"actor", func(a *AuditLog) { a.Actor = "other-admin" }},
		{"actor_type", func(a *AuditLog) { a.ActorType = "SYSTEM" }},
		{"actor_ip", func(a *AuditLog) { a.ActorIP = "10.0.0.2" }},
		{"target_type", func(a *AuditLog) { a.TargetType = "KEY" }},
		{"target_id", func(a *AuditLog) { a.TargetID = "xyz789" }},
		{"action", func(a *AuditLog) { a.Action = "吊销证书" }},
		{"detail", func(a *AuditLog) { a.Detail = map[string]interface{}{"serial": "02"} }},
		{"result", func(a *AuditLog) { a.Result = ResultFailed }},
		{"error_msg", func(a *AuditLog) { a.ErrorMsg = "boom" }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			// 逐字段复制，避免 map 共享
			cloned := *base
			cloned.Detail = map[string]interface{}{}
			for k, v := range base.Detail {
				cloned.Detail[k] = v
			}
			m.mutate(&cloned)

			if got := cloned.ComputeHash(""); got == baseHash {
				t.Fatalf("field %q changed but hash did not change: %s", m.name, got)
			}
		})
	}
}

// TestComputeHashChainIntegrity 三条记录串成链，篡改中间一条后链校验必须失败。
func TestComputeHashChainIntegrity(t *testing.T) {
	logs := []*AuditLog{
		{RecordContent: `{"action":"a1"}`},
		{RecordContent: `{"action":"a2"}`},
		{RecordContent: `{"action":"a3"}`},
	}

	prevHashes := make([]string, len(logs))
	currHashes := make([]string, len(logs))
	prev := ""
	for i, l := range logs {
		prevHashes[i] = prev
		currHashes[i] = l.ComputeHash(prev)
		prev = currHashes[i]
	}

	verify := func() int {
		for i := range logs {
			if logs[i].ComputeHash(prevHashes[i]) != currHashes[i] {
				return i
			}
		}
		return -1
	}

	if i := verify(); i != -1 {
		t.Fatalf("valid chain failed verification at index %d", i)
	}

	// 篡改中间一条记录
	logs[1].RecordContent = `{"action":"a2-tampered"}`

	tamperedIdx := verify()
	if tamperedIdx != 1 {
		t.Fatalf("tampered chain verification returned index %d, want 1", tamperedIdx)
	}

	// 证明后续记录的前驱哈希不再衔接：第 2 条重算哈希 != 篡改前存储的 currHash
	if recomputed := logs[1].ComputeHash(prevHashes[1]); recomputed == currHashes[1] {
		t.Fatal("tampered record still produces its original hash")
	}
	// 第 3 条记录存的前驱哈希是篡改前第 2 条的哈希，与第 2 条重算哈希不一致，链已断
	if prevHashes[2] == logs[1].ComputeHash(prevHashes[1]) {
		t.Fatal("tampered record recomputed hash still matches next record prevHash")
	}
}

func TestBuildRecordContent(t *testing.T) {
	log := &AuditLog{
		EventTime: time.Date(2026, 9, 6, 12, 0, 0, 123456789, time.UTC),
		EventType: EventCertIssue,
		Severity:  SeverityInfo,
		Actor:     "admin",
		Action:    "签发证书",
	}

	content := log.BuildRecordContent()

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		t.Fatalf("BuildRecordContent() produced invalid JSON: %v", err)
	}

	if m["actor"] != "admin" {
		t.Errorf("BuildRecordContent() actor = %v, want admin", m["actor"])
	}
	if m["action"] != "签发证书" {
		t.Errorf("BuildRecordContent() action = %v, want 签发证书", m["action"])
	}
	// 时间必须截断到微秒精度，保证存储后哈希一致
	if got := log.EventTime.Nanosecond() % 1000; got != 0 {
		t.Errorf("BuildRecordContent() EventTime not truncated to microsecond: ns=%d", log.EventTime.Nanosecond())
	}
}

func TestToMapIncludesHashChainFields(t *testing.T) {
	log := &AuditLog{
		EventTime: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		EventType: EventCertIssue,
		Severity:  SeverityInfo,
		Actor:     "admin",
		ActorType: "USER",
		Action:    "test",
		Detail:    map[string]interface{}{"k": "v"},
		Result:    ResultSuccess,
	}

	m := log.toMap()

	if m["event_time"] == "" {
		t.Error("toMap() missing event_time")
	}
	if m["actor"] != "admin" {
		t.Errorf("toMap() actor = %v, want admin", m["actor"])
	}
	if m["detail"].(map[string]interface{})["k"] != "v" {
		t.Errorf("toMap() detail = %v", m["detail"])
	}
}
