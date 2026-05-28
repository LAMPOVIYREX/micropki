package client

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "os"
)

// GenerateCSR generates a private key and CSR
func GenerateCSR(subject, keyType string, keySize int, sans []string, outKey, outCSR string) error {
    // Generate private key
    var privKey interface{}
    var err error
    
    if keyType == "rsa" {
        if keySize != 2048 && keySize != 4096 {
            keySize = 2048
        }
        privKey, err = rsa.GenerateKey(rand.Reader, keySize)
        if err != nil {
            return fmt.Errorf("failed to generate RSA key: %w", err)
        }
    } else {
        return fmt.Errorf("ECC not yet implemented for CSR")
    }
    
    // Save private key (unencrypted)
    keyBytes := x509.MarshalPKCS1PrivateKey(privKey.(*rsa.PrivateKey))
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
    
    if err := os.WriteFile(outKey, keyPEM, 0600); err != nil {
        return fmt.Errorf("failed to save private key: %w", err)
    }
    
    // Create CSR template
    template := &x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName: subject,
        },
        DNSNames: sans,
    }
    
    // Create CSR
    csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
    if err != nil {
        return fmt.Errorf("failed to create CSR: %w", err)
    }
    
    // Save CSR
    csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
    if err := os.WriteFile(outCSR, csrPEM, 0644); err != nil {
        return fmt.Errorf("failed to save CSR: %w", err)
    }
    
    return nil
}