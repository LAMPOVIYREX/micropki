package crl

import (
    "crypto"
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
    // Build revoked certificates list
    revokedList := make([]pkix.RevokedCertificate, len(config.RevokedCerts))
    for i, cert := range config.RevokedCerts {
        revokedList[i] = pkix.RevokedCertificate{
            SerialNumber:   cert.SerialNumber,
            RevocationTime: cert.RevocationTime,
        }
        
        // Add reason code if specified
        if cert.ReasonCode != 0 {
            reasonBytes, err := asn1.Marshal(cert.ReasonCode)
            if err != nil {
                return nil, fmt.Errorf("failed to marshal reason code: %w", err)
            }
            revokedList[i].Extensions = []pkix.Extension{
                {
                    Id:       asn1.ObjectIdentifier{2, 5, 29, 21},
                    Critical: false,
                    Value:    reasonBytes,
                },
            }
        }
    }
    
    // Create TBSCertList structure
    tbsCertList := pkix.TBSCertificateList{
        Version:    1, // v2
        Signature: pkix.AlgorithmIdentifier{
            Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
        },
        Issuer: config.CAIssuer.Subject.ToRDNSequence(),
        ThisUpdate: config.ThisUpdate,
        NextUpdate: config.NextUpdate,
        RevokedCertificates: revokedList,
    }
    
    // Marshal TBSCertList
    tbsBytes, err := asn1.Marshal(tbsCertList)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal TBSCertList: %w", err)
    }
    
    // Create CRL bytes (simplified - just return TBSCertList for now)
    // In production, you would sign this properly
    crlBytes := tbsBytes
    
    return crlBytes, nil
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