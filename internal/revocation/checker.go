package revocation

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

// RevocationStatus represents the status of a certificate
type RevocationStatus struct {
    Status           string
    RevocationTime   string
    RevocationReason string
    Method           string
}

// Checker handles revocation checking
type Checker struct {
    ocspFirst bool
}

// NewChecker creates a new revocation checker
func NewChecker() *Checker {
    return &Checker{
        ocspFirst: true,
    }
}

// CheckStatus checks revocation status using OCSP first, then CRL fallback
func (c *Checker) CheckStatus(certPath, issuerPath string, crlURL, ocspURL string) (*RevocationStatus, error) {
    cert, err := loadCertificate(certPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load certificate: %w", err)
    }

    issuer, err := loadCertificate(issuerPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load issuer certificate: %w", err)
    }

    if ocspURL == "" && len(cert.OCSPServer) > 0 {
        ocspURL = cert.OCSPServer[0]
    }

    // Try OCSP first
    if ocspURL != "" && c.ocspFirst {
        status, err := checkOCSP(cert, issuer, ocspURL)
        if err == nil && status.Status != "unknown" {
            status.Method = "ocsp"
            return status, nil
        }
    }

    // Fallback to CRL
    if crlURL != "" {
        status, err := checkCRL(cert, issuer, crlURL)
        if err == nil {
            status.Method = "crl"
            return status, nil
        }
    }

    return &RevocationStatus{
        Status: "unknown",
        Method: "none",
    }, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
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