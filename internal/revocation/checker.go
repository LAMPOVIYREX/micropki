package revocation

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "time"
)

// RevocationStatus represents the status of a certificate
type RevocationStatus struct {
    Status          string // good, revoked, unknown
    RevocationTime  time.Time
    RevocationReason string
    Method          string // ocsp, crl, fallback
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
    // Load certificate
    cert, err := loadCertificate(certPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load certificate: %w", err)
    }
    
    // Load issuer certificate
    issuer, err := loadCertificate(issuerPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load issuer certificate: %w", err)
    }
    
    // Get OCSP URL from certificate if not provided
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

// checkOCSP performs OCSP check (simplified)
func checkOCSP(cert, issuer *x509.Certificate, ocspURL string) (*RevocationStatus, error) {
    // Simplified OCSP check - in production use crypto/ocsp
    return &RevocationStatus{
        Status: "good",
    }, nil
}

// checkCRL performs CRL check (simplified)
func checkCRL(cert, issuer *x509.Certificate, crlURL string) (*RevocationStatus, error) {
    // Simplified CRL check
    return &RevocationStatus{
        Status: "good",
    }, nil
}

// loadCertificate loads certificate from PEM file
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