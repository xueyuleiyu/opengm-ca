package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// 国密扩展OID定义
var (
	// OID国密身份标识扩展 (1.2.156.112562.2.1.1.23)
	// 用于标识国密证书的身份信息
	OIDGMIdentity = asn1.ObjectIdentifier{1, 2, 156, 112562, 2, 1, 1, 23}

	// OID国密特有扩展 (2.16.840.1.113732.5)
	// 用于国密证书的特定标识
	OIDGMExtension = asn1.ObjectIdentifier{2, 16, 840, 1, 113732, 5}

	// OID Netscape证书类型
	OIDNetscapeCertType = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}

	// OID CRL分发点
	OIDCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// GMExtension 国密扩展配置
type GMExtension struct {
	// 是否启用国密身份标识扩展
	EnableIdentityExtension bool
	// 身份标识值 (可选，默认使用主题CN)
	IdentityValue string
	// 是否启用国密特有扩展
	EnableGMExtension bool
	// 国密扩展值 (可选)
	GMExtensionValue string
}

// CRLDistributionPoint CRL分发点配置
type CRLDistributionPoint struct {
	// CRL分发点URI
	URI string
	// CRL分发点目录名称 (可选)
	DirName string
}

// AddGMExtensions 添加国密扩展字段到证书模板
func AddGMExtensions(template *x509.Certificate, gmExt *GMExtension) error {
	if gmExt == nil {
		return nil
	}

	// 添加国密身份标识扩展
	if gmExt.EnableIdentityExtension {
		identityValue := gmExt.IdentityValue
		if identityValue == "" {
			// 默认使用主题CN作为身份标识
			identityValue = template.Subject.CommonName
		}

		// 将身份标识转换为ASN1编码
		identityBytes, err := asn1.Marshal(identityValue)
		if err != nil {
			return fmt.Errorf("编码国密身份标识失败: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       OIDGMIdentity,
			Critical: false,
			Value:    identityBytes,
		})
	}

	// 添加国密特有扩展
	if gmExt.EnableGMExtension {
		gmValue := gmExt.GMExtensionValue
		if gmValue == "" {
			// 默认值
			gmValue = "GM_CERTIFICATE"
		}

		gmBytes, err := asn1.Marshal(gmValue)
		if err != nil {
			return fmt.Errorf("编码国密扩展失败: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       OIDGMExtension,
			Critical: false,
			Value:    gmBytes,
		})
	}

	return nil
}

// AddCRLDistributionPoints 添加CRL分发点到证书模板
func AddCRLDistributionPoints(template *x509.Certificate, crlDP *CRLDistributionPoint) error {
	if crlDP == nil || crlDP.URI == "" {
		return nil
	}

	// 构建CRL分发点
	type DistributionPoint struct {
		DistributionPoint asn1.RawValue `asn1:"tag:0,optional,explicit"`
	}

	// 创建URI分发点
	uriValue := fmt.Sprintf("URI:%s", crlDP.URI)
	uriBytes, err := asn1.Marshal(uriValue)
	if err != nil {
		return fmt.Errorf("编码CRL URI失败: %w", err)
	}

	// 构建分发点结构
	dp := DistributionPoint{
		DistributionPoint: asn1.RawValue{
			FullBytes: uriBytes,
		},
	}

	dpBytes, err := asn1.Marshal(dp)
	if err != nil {
		return fmt.Errorf("编码CRL分发点失败: %w", err)
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OIDCRLDistributionPoints,
		Critical: false,
		Value:    dpBytes,
	})

	return nil
}

// AddNetscapeCertType 添加Netscape证书类型扩展
func AddNetscapeCertType(template *x509.Certificate, certType string) error {
	if certType == "" {
		return nil
	}

	// Netscape证书类型位掩码
	// SSL Client: 0x80
	// SSL Server: 0x40
	// S/MIME: 0x20
	// Object Signing: 0x10
	// SSL CA: 0x04
	// S/MIME CA: 0x02
	// Object Signing CA: 0x01

	var certTypeByte byte
	switch certType {
	case "SSL Client":
		certTypeByte = 0x80
	case "SSL Server":
		certTypeByte = 0x40
	case "S/MIME":
		certTypeByte = 0x20
	case "Object Signing":
		certTypeByte = 0x10
	case "SSL CA":
		certTypeByte = 0x04
	case "S/MIME CA":
		certTypeByte = 0x02
	case "Object Signing CA":
		certTypeByte = 0x01
	default:
		// 默认SSL Client
		certTypeByte = 0x80
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OIDNetscapeCertType,
		Critical: false,
		Value:    []byte{certTypeByte},
	})

	return nil
}

// GenerateIdentityValue 生成国密身份标识值
// 基于证书主题信息生成唯一身份标识
func GenerateIdentityValue(template *x509.Certificate) string {
	// 使用主题CN + 组织 + 国家生成身份标识
	parts := []string{}

	if template.Subject.CommonName != "" {
		parts = append(parts, template.Subject.CommonName)
	}
	if len(template.Subject.Organization) > 0 {
		parts = append(parts, template.Subject.Organization[0])
	}
	if len(template.Subject.Country) > 0 {
		parts = append(parts, template.Subject.Country[0])
	}

	// 如果没有主题信息，使用序列号
	if len(parts) == 0 {
		return hex.EncodeToString(template.SerialNumber.Bytes())
	}

	// 组合身份标识
	identity := ""
	for i, part := range parts {
		if i > 0 {
			identity += "-"
		}
		identity += part
	}

	return identity
}

// EnhanceCertificateWithGMExtensions 使用国密扩展增强证书
// 这是一个便捷函数，一次性添加所有国密相关扩展
func EnhanceCertificateWithGMExtensions(template *x509.Certificate, certType string, crlURI string) error {
	// 生成身份标识值
	identityValue := GenerateIdentityValue(template)

	// 添加国密扩展
	gmExt := &GMExtension{
		EnableIdentityExtension: true,
		IdentityValue:           identityValue,
		EnableGMExtension:       true,
		GMExtensionValue:        "GM_CERTIFICATE",
	}
	if err := AddGMExtensions(template, gmExt); err != nil {
		return err
	}

	// 添加Netscape证书类型
	if err := AddNetscapeCertType(template, certType); err != nil {
		return err
	}

	// 添加CRL分发点
	if crlURI != "" {
		crlDP := &CRLDistributionPoint{
			URI: crlURI,
		}
		if err := AddCRLDistributionPoints(template, crlDP); err != nil {
			return err
		}
	}

	return nil
}
