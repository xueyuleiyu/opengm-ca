package model

import (
	"testing"
	"time"
)

func TestAPIKeyIsValid(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name string
		key  APIKey
		ip   string
		want bool
	}{
		{
			name: "active no expiry no whitelist",
			key:  APIKey{IsActive: true},
			ip:   "1.2.3.4",
			want: true,
		},
		{
			name: "inactive",
			key:  APIKey{IsActive: false},
			want: false,
		},
		{
			name: "revoked",
			key:  APIKey{IsActive: true, RevokedAt: &future},
			want: false,
		},
		{
			name: "expired",
			key:  APIKey{IsActive: true, ValidTo: &past},
			want: false,
		},
		{
			name: "valid future expiry",
			key:  APIKey{IsActive: true, ValidTo: &future},
			want: true,
		},
		{
			name: "whitelist match",
			key:  APIKey{IsActive: true, IPWhitelist: []string{"1.2.3.4", "5.6.7.8"}},
			ip:   "5.6.7.8",
			want: true,
		},
		{
			name: "whitelist mismatch",
			key:  APIKey{IsActive: true, IPWhitelist: []string{"1.2.3.4"}},
			ip:   "9.9.9.9",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsValid(tt.ip); got != tt.want {
				t.Fatalf("IsValid(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestAPIKeyHasPermission(t *testing.T) {
	key := APIKey{Permissions: []string{"CERT_ISSUE", "CERT_READ"}}

	if !key.HasPermission("CERT_ISSUE") {
		t.Error("HasPermission(exact) = false, want true")
	}
	if key.HasPermission("NO_SUCH_PERM") {
		t.Error("HasPermission(missing) = true, want false")
	}

	wildcard := APIKey{Permissions: []string{"*"}}
	if !wildcard.HasPermission("ANYTHING") {
		t.Error("HasPermission(*) = false, want true")
	}
}

func TestCAChainMethods(t *testing.T) {
	now := time.Now()
	valid := CAChain{
		CAType:    CATypeIntermediate,
		IsActive:  true,
		ValidFrom: now.Add(-time.Hour),
		ValidTo:   now.Add(time.Hour),
	}

	if valid.IsRoot() {
		t.Error("IsRoot() = true for INTERMEDIATE, want false")
	}
	if !valid.IsValid() {
		t.Error("IsValid() = false, want true")
	}
	if !valid.CanIssueCertificates() {
		t.Error("CanIssueCertificates() = false, want true")
	}

	root := CAChain{CAType: CATypeRoot}
	if !root.IsRoot() {
		t.Error("IsRoot() = false for ROOT, want true")
	}
	if root.CanIssueCertificates() {
		t.Error("CanIssueCertificates() = true for ROOT, want false")
	}

	inactive := CAChain{CAType: CATypeIntermediate, IsActive: false}
	if inactive.IsValid() {
		t.Error("IsValid() = true for inactive CA, want false")
	}

	expired := CAChain{CAType: CATypeIntermediate, IsActive: true, ValidFrom: now.Add(-2 * time.Hour), ValidTo: now.Add(-time.Hour)}
	if expired.IsValid() {
		t.Error("IsValid() = true for expired CA, want false")
	}
}

func TestCertificateMethods(t *testing.T) {
	now := time.Now()

	active := Certificate{Status: CertStatusValid, ValidTo: now.Add(time.Hour)}
	if active.IsExpired() {
		t.Error("IsExpired() = true, want false")
	}
	if !active.IsActive() {
		t.Error("IsActive() = false, want true")
	}

	expired := Certificate{Status: CertStatusValid, ValidTo: now.Add(-time.Hour)}
	if !expired.IsExpired() {
		t.Error("IsExpired() = false for past ValidTo, want true")
	}
	if expired.IsActive() {
		t.Error("IsActive() = true for expired cert, want false")
	}

	revoked := Certificate{Status: CertStatusRevoked, ValidTo: now.Add(time.Hour)}
	if revoked.IsActive() {
		t.Error("IsActive() = true for revoked cert, want false")
	}
}

func TestCertificateGetSubjectAltNames(t *testing.T) {
	if got := (&Certificate{}).GetSubjectAltNames(); got != nil {
		t.Fatalf("GetSubjectAltNames(nil extensions) = %v, want nil", got)
	}

	cert := &Certificate{
		Extensions: map[string]interface{}{
			"subject_alt_names": []interface{}{
				map[string]interface{}{"type": "dns", "value": "a.example.com"},
				map[string]interface{}{"type": "ip", "value": "1.2.3.4"},
			},
		},
	}
	sans := cert.GetSubjectAltNames()
	if len(sans) != 2 {
		t.Fatalf("GetSubjectAltNames() len = %d, want 2", len(sans))
	}
	if sans[0].Type != "dns" || sans[0].Value != "a.example.com" {
		t.Errorf("GetSubjectAltNames()[0] = %+v", sans[0])
	}
	if sans[1].Type != "ip" || sans[1].Value != "1.2.3.4" {
		t.Errorf("GetSubjectAltNames()[1] = %+v", sans[1])
	}
}

func TestCertKeyExportControl(t *testing.T) {
	deleted := time.Now()

	if got := (&CertKey{Exportable: false}).CanExport(); got {
		t.Error("CanExport() = true for non-exportable key, want false")
	}
	if got := (&CertKey{Exportable: true}).CanExport(); !got {
		t.Error("CanExport() = false for exportable key, want true")
	}
	if got := (&CertKey{Exportable: true, MaxExports: 3, ExportCount: 3}).CanExport(); got {
		t.Error("CanExport() = true when export count reached max, want false")
	}
	if got := (&CertKey{Exportable: true, DeletedAt: &deleted}).CanExport(); got {
		t.Error("CanExport() = true for deleted key, want false")
	}
}

func TestCertKeyRemainingExports(t *testing.T) {
	if got := (&CertKey{Exportable: true, MaxExports: 0}).RemainingExports(); got != -1 {
		t.Errorf("RemainingExports() = %d, want -1 (unlimited)", got)
	}
	if got := (&CertKey{Exportable: false, MaxExports: 5}).RemainingExports(); got != -1 {
		t.Errorf("RemainingExports() = %d, want -1 (not exportable)", got)
	}
	if got := (&CertKey{Exportable: true, MaxExports: 5, ExportCount: 2}).RemainingExports(); got != 3 {
		t.Errorf("RemainingExports() = %d, want 3", got)
	}
	if got := (&CertKey{Exportable: true, MaxExports: 5, ExportCount: 8}).RemainingExports(); got != 0 {
		t.Errorf("RemainingExports() = %d, want 0 (clamped)", got)
	}
}

func TestCertKeyIsSoftKey(t *testing.T) {
	if !(&CertKey{StorageType: KeyStorageSoftware}).IsSoftKey() {
		t.Error("IsSoftKey() = false for SOFTWARE, want true")
	}
	if !(&CertKey{StorageType: KeyStorageEscrow}).IsSoftKey() {
		t.Error("IsSoftKey() = false for ESCROW, want true")
	}
	if (&CertKey{StorageType: KeyStorageHSM}).IsSoftKey() {
		t.Error("IsSoftKey() = true for HSM, want false")
	}
}

func TestIsValidRole(t *testing.T) {
	valid := []OperatorRole{RoleSysAdmin, RoleSecAdmin, RoleAuditor, RoleSuperAdmin}
	for _, r := range valid {
		if !IsValidRole(r) {
			t.Errorf("IsValidRole(%s) = false, want true", r)
		}
	}
	if IsValidRole("NOT_A_ROLE") {
		t.Error("IsValidRole(NOT_A_ROLE) = true, want false")
	}
}

func TestOperatorIsLocked(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	if (&Operator{}).IsLocked() {
		t.Error("IsLocked() = true for nil LockedUntil, want false")
	}
	if !(&Operator{LockedUntil: &future}).IsLocked() {
		t.Error("IsLocked() = false for future LockedUntil, want true")
	}
	if (&Operator{LockedUntil: &past}).IsLocked() {
		t.Error("IsLocked() = true for past LockedUntil, want false")
	}
}

func TestOperatorHasPermission(t *testing.T) {
	super := Operator{Role: RoleSuperAdmin}
	if !super.HasPermission("WHATEVER") {
		t.Error("HasPermission() = false for SUPER_ADMIN, want true")
	}

	explicit := Operator{Role: RoleAuditor, Permissions: []string{"CUSTOM_PERM"}}
	if !explicit.HasPermission("CUSTOM_PERM") {
		t.Error("HasPermission() = false for explicit permission, want true")
	}

	role := Operator{Role: RoleSysAdmin}
	if !role.HasPermission("USER_MANAGE") {
		t.Error("HasPermission() = false for role default permission, want true")
	}
	if role.HasPermission("HSM_MANAGE") {
		t.Error("HasPermission() = true for non-owned permission, want false")
	}
}

func TestOperatorRoleHelpers(t *testing.T) {
	sec := Operator{Role: RoleSecAdmin}
	if sec.CanManageOperators() {
		t.Error("CanManageOperators() = true for SEC_ADMIN, want false")
	}
	aud := Operator{Role: RoleAuditor}
	if !aud.CanAudit() {
		t.Error("CanAudit() = false for AUDITOR, want true")
	}
	sys := Operator{Role: RoleSysAdmin}
	if !sys.CanManageSystem() {
		t.Error("CanManageSystem() = false for SYS_ADMIN, want true")
	}
}

func TestOperatorRoleNames(t *testing.T) {
	tests := []struct {
		role OperatorRole
		want string
	}{
		{RoleSysAdmin, "系统管理员"},
		{RoleSecAdmin, "安全保密管理员"},
		{RoleAuditor, "安全审计员"},
		{RoleSuperAdmin, "超级管理员"},
		{"UNKNOWN", "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.role.RoleDisplayName(); got != tt.want {
			t.Errorf("RoleDisplayName(%s) = %q, want %q", tt.role, got, tt.want)
		}
	}

	if got := RoleSysAdmin.RoleDescription(); got == "" {
		t.Error("RoleDescription(SYS_ADMIN) = empty, want non-empty")
	}
	if got := OperatorRole("UNKNOWN").RoleDescription(); got != "" {
		t.Errorf("RoleDescription(UNKNOWN) = %q, want empty", got)
	}
}

func TestGetRolePermissions(t *testing.T) {
	perms := GetRolePermissions(RoleAuditor)
	if len(perms) == 0 {
		t.Fatal("GetRolePermissions(AUDITOR) returned empty")
	}
	if perms[0] != "AUDIT_READ" {
		t.Errorf("GetRolePermissions(AUDITOR)[0] = %q, want AUDIT_READ", perms[0])
	}

	if got := GetRolePermissions("UNKNOWN"); len(got) != 0 {
		t.Errorf("GetRolePermissions(UNKNOWN) = %v, want empty", got)
	}

	// 返回副本，修改返回值不影响内部映射
	perms[0] = "MUTATED"
	again := GetRolePermissions(RoleAuditor)
	if again[0] != "AUDIT_READ" {
		t.Error("GetRolePermissions() returned shared slice, mutation leaked")
	}
}

func TestCheckRolePermission(t *testing.T) {
	if !checkRolePermission(RoleSecAdmin, "KEY_MANAGE") {
		t.Error("checkRolePermission(SEC_ADMIN, KEY_MANAGE) = false, want true")
	}
	if checkRolePermission(RoleAuditor, "KEY_MANAGE") {
		t.Error("checkRolePermission(AUDITOR, KEY_MANAGE) = true, want false")
	}
	if checkRolePermission("UNKNOWN", "ANY") {
		t.Error("checkRolePermission(UNKNOWN) = true, want false")
	}
}

func TestSubjectGetIdentityKey(t *testing.T) {
	person := Subject{SubjectType: SubjectTypePerson, IDCardNumber: "110101199001011234", CommonName: "张三"}
	if got := person.GetIdentityKey(); got != "110101199001011234" {
		t.Errorf("GetIdentityKey(person with id) = %q, want id card number", got)
	}

	personNoID := Subject{SubjectType: SubjectTypePerson, CommonName: "李四"}
	if got := personNoID.GetIdentityKey(); got != "李四" {
		t.Errorf("GetIdentityKey(person without id) = %q, want common name", got)
	}

	device := Subject{SubjectType: SubjectTypeDevice, DeviceID: "dev-001", CommonName: "device-cn"}
	if got := device.GetIdentityKey(); got != "dev-001" {
		t.Errorf("GetIdentityKey(device with id) = %q, want device id", got)
	}

	org := Subject{SubjectType: SubjectTypeOrganization, CommonName: "Org"}
	if got := org.GetIdentityKey(); got != "Org" {
		t.Errorf("GetIdentityKey(org) = %q, want common name", got)
	}
}

func TestSubjectToSubjectInfo(t *testing.T) {
	s := Subject{
		CommonName:         "cn",
		Organization:       "org",
		OrganizationalUnit: "ou",
		Country:            "CN",
		State:              "state",
		Locality:           "city",
		Email:              "a@example.com",
		IDCardNumber:       "110101199001011234",
		EmployeeID:         "E001",
		DeviceID:           "D001",
		Department:         "dept",
		VPNDomain:          "vpn.example.com",
	}

	info := s.ToSubjectInfo()
	if info.CommonName != "cn" || info.Organization != "org" || info.Country != "CN" {
		t.Errorf("ToSubjectInfo() = %+v", info)
	}
	if info.Email != "a@example.com" || info.EmployeeID != "E001" || info.DeviceID != "D001" {
		t.Errorf("ToSubjectInfo() = %+v", info)
	}
	if info.Department != "dept" || info.VPNDomain != "vpn.example.com" {
		t.Errorf("ToSubjectInfo() = %+v", info)
	}
}
