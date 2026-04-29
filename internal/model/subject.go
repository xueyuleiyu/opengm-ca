package model

import (
	"time"
)

// SubjectType 主体类型
type SubjectType string

const (
	SubjectTypePerson       SubjectType = "PERSON"
	SubjectTypeOrganization SubjectType = "ORGANIZATION"
	SubjectTypeDevice       SubjectType = "DEVICE"
)

// Subject 证书主体领域模型
type Subject struct {
	ID               int                    `bun:"id,pk,autoincrement" json:"id"`
	SubjectType      SubjectType            `bun:"subject_type,notnull" json:"subject_type"`
	CommonName       string                 `bun:"common_name,notnull" json:"common_name"`
	Organization     string                 `bun:"organization" json:"organization,omitempty"`
	OrganizationalUnit string               `bun:"organizational_unit" json:"organizational_unit,omitempty"`
	Country          string                 `bun:"country,default:'CN'" json:"country,omitempty"`
	State            string                 `bun:"state" json:"state,omitempty"`
	Locality         string                 `bun:"locality" json:"locality,omitempty"`
	Email            string                 `bun:"email" json:"email,omitempty"`
	IDCardNumber     string                 `bun:"id_card_number" json:"id_card_number,omitempty"`
	EmployeeID       string                 `bun:"employee_id" json:"employee_id,omitempty"`
	DeviceID         string                 `bun:"device_id" json:"device_id,omitempty"`
	DomainNames      []string               `bun:"domain_names,array" json:"domain_names,omitempty"`
	IPAddresses      []string               `bun:"ip_addresses,array" json:"ip_addresses,omitempty"`
	Department       string                 `bun:"department" json:"department,omitempty"`
	VPNDomain        string                 `bun:"vpn_domain" json:"vpn_domain,omitempty"`
	Metadata         map[string]interface{} `bun:"metadata,type:jsonb,default:'{}'" json:"metadata,omitempty"`
	CreatedAt        time.Time              `bun:"created_at,default:current_timestamp" json:"created_at"`
	UpdatedAt        time.Time              `bun:"updated_at,default:current_timestamp" json:"updated_at"`

	// 关联对象
	Certificates []Certificate `bun:"rel:has-many,join:id=subject_id" json:"certificates,omitempty"`
	Keys         []CertKey     `bun:"rel:has-many,join:id=subject_id" json:"keys,omitempty"`
}

// TableName 返回表名
func (s *Subject) TableName() string {
	return "subjects"
}

// GetIdentityKey 获取主体唯一标识键
func (s *Subject) GetIdentityKey() string {
	switch s.SubjectType {
	case SubjectTypePerson:
		if s.IDCardNumber != "" {
			return s.IDCardNumber
		}
		return s.CommonName
	case SubjectTypeDevice:
		if s.DeviceID != "" {
			return s.DeviceID
		}
		return s.CommonName
	default:
		return s.CommonName
	}
}

// ToSubjectInfo 转换为SubjectInfo
func (s *Subject) ToSubjectInfo() SubjectInfo {
	return SubjectInfo{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		State:              s.State,
		Locality:           s.Locality,
		Email:              s.Email,
		IDCardNumber:       s.IDCardNumber,
		EmployeeID:         s.EmployeeID,
		DeviceID:           s.DeviceID,
		Department:         s.Department,
		VPNDomain:          s.VPNDomain,
	}
}
