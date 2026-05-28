package certs

import (
    "crypto/rand"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "math/big"
    "net"           
    "strings"       
    "time"
)

// CertificateType определяет тип сертификата
type CertificateType string

const (
    ServerCert   CertificateType = "server"
    ClientCert   CertificateType = "client"
    CodeSigning  CertificateType = "code-signing"
    OCSPResponder CertificateType = "ocsp"
)

// TemplateConfig конфигурация для создания шаблона сертификата
type TemplateConfig struct {
    Type          CertificateType
    Subject       *pkix.Name
    DNSNames      []string
    IPAddresses   []net.IP
    ValidityDays  int
    KeyUsage      x509.KeyUsage
    ExtKeyUsage   []x509.ExtKeyUsage
}

// CreateCertificateTemplate создает шаблон сертификата на основе типа
func CreateCertificateTemplate(certType string, subject *pkix.Name, sanList []string, validityDays int) (*x509.Certificate, error) {
    // Генерируем серийный номер
    serialBytes := make([]byte, 20)
    if _, err := rand.Read(serialBytes); err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    serial := new(big.Int).SetBytes(serialBytes)
    
    now := time.Now().UTC()
    
    // Парсим SAN
    var dnsNames []string
    var ipAddresses []net.IP
    
    for _, san := range sanList {
        if strings.HasPrefix(san, "dns:") {
            dnsNames = append(dnsNames, strings.TrimPrefix(san, "dns:"))
        } else if strings.HasPrefix(san, "ip:") {
            ip := net.ParseIP(strings.TrimPrefix(san, "ip:"))
            if ip != nil {
                ipAddresses = append(ipAddresses, ip)
            }
        } else {
            // По умолчанию считаем DNS
            dnsNames = append(dnsNames, san)
        }
    }
    
    template := &x509.Certificate{
        SerialNumber: serial,
        Subject:      *subject,
        NotBefore:    now,
        NotAfter:     now.AddDate(0, 0, validityDays),
        DNSNames:     dnsNames,
        IPAddresses:  ipAddresses,
        IsCA:         false,
    }
    
    // Настраиваем KeyUsage и ExtKeyUsage в зависимости от типа
    switch certType {
    case "server":
        template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
        template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
        
    case "client":
        template.KeyUsage = x509.KeyUsageDigitalSignature
        template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
        
    case "code-signing":
        template.KeyUsage = x509.KeyUsageDigitalSignature
        template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
        
    case "ocsp":
        template.KeyUsage = x509.KeyUsageDigitalSignature
        template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
        
    default:
        return nil, fmt.Errorf("unknown certificate type: %s", certType)
    }
    
    return template, nil
}

// CreateIntermediateCATemplate создает шаблон для Intermediate CA
func CreateIntermediateCATemplate(subject *pkix.Name, parentCert *x509.Certificate, publicKey interface{}, validityDays int, maxPathLen int) (*x509.Certificate, error) {
    serialBytes := make([]byte, 20)
    if _, err := rand.Read(serialBytes); err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    serial := new(big.Int).SetBytes(serialBytes)
    
    now := time.Now().UTC()
    
    // Вычисляем Subject Key Identifier
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    ski := sha1Sum(pubKeyBytes)
    
    template := &x509.Certificate{
        SerialNumber: serial,
        Subject:      *subject,
        Issuer:       parentCert.Subject,
        NotBefore:    now,
        NotAfter:     now.AddDate(0, 0, validityDays),
        
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLen:            maxPathLen,
        
        SubjectKeyId:   ski,
        AuthorityKeyId: parentCert.SubjectKeyId,
    }
    
    return template, nil
}

// sha1Sum вычисляет SHA-1 хеш
func sha1Sum(data []byte) []byte {
    hash := sha1.Sum(data)
    return hash[:]
}