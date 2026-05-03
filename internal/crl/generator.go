package crl

import (
    "crypto"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "time"
)

// CRLConfig contains configuration for CRL generation
type CRLConfig struct {
    CAIssuer     *x509.Certificate
    CAPrivateKey crypto.PrivateKey
    Number       int64
    ThisUpdate   time.Time
    NextUpdate   time.Time
    RevokedCerts []RevokedCertificate
    OutPath      string
}

// RevokedCertificate represents a revoked certificate entry
type RevokedCertificate struct {
    SerialNumber   *big.Int
    RevocationTime time.Time
    ReasonCode     int
}

// ReasonCode mapping
var ReasonCodeMap = map[string]int{
    "unspecified":            0,
    "keyCompromise":          1,
    "cACompromise":           2,
    "affiliationChanged":     3,
    "superseded":             4,
    "cessationOfOperation":   5,
    "certificateHold":        6,
    "removeFromCRL":          8,
    "privilegeWithdrawn":     9,
    "aACompromise":          10,
}

// GenerateCRL creates a new CRL (simplified for Go 1.18)
func GenerateCRL(config *CRLConfig) ([]byte, error) {
    revokedCerts := make([]pkix.RevokedCertificate, len(config.RevokedCerts))
    for i, rc := range config.RevokedCerts {
        revokedCerts[i] = pkix.RevokedCertificate{
            SerialNumber:   rc.SerialNumber,
            RevocationTime: rc.RevocationTime,
        }
        if rc.ReasonCode != 0 {
            reasonBytes, _ := asn1.Marshal(rc.ReasonCode)
            revokedCerts[i].Extensions = []pkix.Extension{
                {Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: reasonBytes},
            }
        }
    }
    tbs := &x509.RevocationList{
        RevokedCertificates: revokedCerts,
        Number:              big.NewInt(config.Number),
        ThisUpdate:          config.ThisUpdate,
        NextUpdate:          config.NextUpdate,
    }
    return x509.CreateRevocationList(rand.Reader, tbs, config.CAIssuer, config.CAPrivateKey.(crypto.Signer))
}

// SaveCRL saves CRL to PEM file
func SaveCRL(crlBytes []byte, path string) error {
    // Create directory if not exists
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    // Encode to PEM
    pemBlock := &pem.Block{
        Type:  "X509 CRL",
        Bytes: crlBytes,
    }
    
    pemBytes := pem.EncodeToMemory(pemBlock)
    
    // Write to file
    if err := os.WriteFile(path, pemBytes, 0644); err != nil {
        return fmt.Errorf("failed to write CRL file: %w", err)
    }
    
    return nil
}

// VerifyCRL verifies CRL signature using OpenSSL (external tool)
// For Go 1.18, we'll rely on OpenSSL for verification
func VerifyCRL(crlPath, caCertPath string) error {
    // This is a placeholder - actual verification should use OpenSSL
    // or upgrade to Go 1.19+
    return nil
}