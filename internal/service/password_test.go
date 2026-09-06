package service

import "testing"

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		minLength int
		wantErr   string
	}{
		{
			name:      "valid with all character classes",
			password:  "Abcd1234!",
			minLength: 8,
			wantErr:   "",
		},
		{
			name:      "too short",
			password:  "Ab1!",
			minLength: 8,
			wantErr:   "密码长度至少8位",
		},
		{
			name:      "missing uppercase",
			password:  "abcd1234!",
			minLength: 8,
			wantErr:   "密码必须包含大写字母",
		},
		{
			name:      "missing lowercase",
			password:  "ABCD1234!",
			minLength: 8,
			wantErr:   "密码必须包含小写字母",
		},
		{
			name:      "missing number",
			password:  "Abcdefgh!",
			minLength: 8,
			wantErr:   "密码必须包含数字",
		},
		{
			name:      "missing special",
			password:  "Abcd1234",
			minLength: 8,
			wantErr:   "密码必须包含特殊字符",
		},
		{
			name:      "exactly min length",
			password:  "Ab1!ef",
			minLength: 6,
			wantErr:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tt.password, tt.minLength)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePasswordPolicy(%q, %d) error = %v, want nil", tt.password, tt.minLength, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePasswordPolicy(%q, %d) = nil, want error containing %q", tt.password, tt.minLength, tt.wantErr)
			}
			if got := err.Error(); got != tt.wantErr {
				t.Fatalf("ValidatePasswordPolicy(%q, %d) error = %q, want %q", tt.password, tt.minLength, got, tt.wantErr)
			}
		})
	}
}
