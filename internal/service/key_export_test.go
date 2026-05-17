package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateExportPasswordStrength(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "password too short",
			password: "Short1!",
			wantErr:  true,
			errMsg:   "至少12位",
		},
		{
			name:     "missing uppercase",
			password: "password123!@#",
			wantErr:  true,
			errMsg:   "大写字母",
		},
		{
			name:     "missing lowercase",
			password: "PASSWORD123!@#",
			wantErr:  true,
			errMsg:   "小写字母",
		},
		{
			name:     "missing number",
			password: "Password!@#$%",
			wantErr:  true,
			errMsg:   "数字",
		},
		{
			name:     "missing special char",
			password: "Password12345",
			wantErr:  true,
			errMsg:   "特殊字符",
		},
		{
			name:     "valid password",
			password: "Password123!@#",
			wantErr:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExportPasswordStrength(tc.password)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
