package service

import "fmt"

// ValidatePasswordPolicy 统一密码强度校验，接受可配置的最小长度
func ValidatePasswordPolicy(password string, minLength int) error {
	if len(password) < minLength {
		return fmt.Errorf("密码长度至少%d位", minLength)
	}
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasNumber = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("密码必须包含大写字母")
	}
	if !hasLower {
		return fmt.Errorf("密码必须包含小写字母")
	}
	if !hasNumber {
		return fmt.Errorf("密码必须包含数字")
	}
	if !hasSpecial {
		return fmt.Errorf("密码必须包含特殊字符")
	}
	return nil
}
