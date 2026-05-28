package certs

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "time"
)

// VerifyCertificateChain проверяет цепочку сертификатов
func VerifyCertificateChain(certPath string, caPaths []string) error {
    // Загружаем сертификат для проверки
    cert, err := LoadCertificate(certPath)
    if err != nil {
        return fmt.Errorf("failed to load certificate: %w", err)
    }
    
    // Загружаем CA сертификаты
    roots := x509.NewCertPool()
    intermediates := x509.NewCertPool()
    
    for _, caPath := range caPaths {
        caCert, err := LoadCertificate(caPath)
        if err != nil {
            return fmt.Errorf("failed to load CA certificate %s: %w", caPath, err)
        }
        
        if caCert.IsCA {
            roots.AddCert(caCert)
        } else {
            intermediates.AddCert(caCert)
        }
    }
    
    // Проверяем с опциями
    opts := x509.VerifyOptions{
        Roots:         roots,
        Intermediates: intermediates,
        CurrentTime:   time.Now(),
        KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
    }
    
    if _, err := cert.Verify(opts); err != nil {
        return fmt.Errorf("certificate verification failed: %w", err)
    }
    
    return nil
}

// LoadCertificate загружает сертификат из файла
func LoadCertificate(path string) (*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    
    return x509.ParseCertificate(block.Bytes)
}