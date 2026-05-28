package certs

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "path/filepath"
    "testing"
)

func TestParseDN(t *testing.T) {
    tests := []struct {
        name    string
        dn      string
        wantCN  string
        wantErr bool
    }{
        {"Slash format", "/CN=Test CA", "Test CA", false},
        {"Comma format", "CN=Test CA", "Test CA", false},
        {"Empty", "", "", true},
        {"Missing CN", "O=Org", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            name, err := ParseDN(tt.dn)
            if tt.wantErr && err == nil {
                t.Error("Expected error, got nil")
            }
            if !tt.wantErr {
                if err != nil {
                    t.Errorf("Unexpected error: %v", err)
                }
                if name.CommonName != tt.wantCN {
                    t.Errorf("Expected CN=%s, got %s", tt.wantCN, name.CommonName)
                }
            }
        })
    }
}

func TestGenerateSelfSignedCert(t *testing.T) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    subject, err := ParseDN("/CN=Test CA")
    if err != nil {
        t.Fatal(err)
    }

    certBytes, err := GenerateSelfSignedCert(privKey, subject, 365)
    if err != nil {
        t.Fatalf("Failed to generate cert: %v", err)
    }

    cert, err := x509.ParseCertificate(certBytes)
    if err != nil {
        t.Fatalf("Failed to parse cert: %v", err)
    }

    if cert.Subject.CommonName != "Test CA" {
        t.Errorf("Expected CN=Test CA, got %s", cert.Subject.CommonName)
    }
    if !cert.IsCA {
        t.Error("Expected IsCA=true")
    }
}

func TestSaveAndLoadCertificate(t *testing.T) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    subject, _ := ParseDN("/CN=Test Cert")
    certBytes, err := GenerateSelfSignedCert(privKey, subject, 365)
    if err != nil {
        t.Fatal(err)
    }

    tmpDir := t.TempDir()
    certPath := filepath.Join(tmpDir, "cert.pem")

    err = SaveCertificateToPEM(certBytes, certPath)
    if err != nil {
        t.Fatalf("Failed to save cert: %v", err)
    }

    loadedCert, err := LoadCertificate(certPath)
    if err != nil {
        t.Fatalf("Failed to load cert: %v", err)
    }

    if loadedCert.Subject.CommonName != "Test Cert" {
        t.Errorf("Expected CN=Test Cert, got %s", loadedCert.Subject.CommonName)
    }
}

func TestVerifyCertificate(t *testing.T) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    subject, _ := ParseDN("/CN=Test CA")
    certBytes, err := GenerateSelfSignedCert(privKey, subject, 365)
    if err != nil {
        t.Fatal(err)
    }

    tmpDir := t.TempDir()
    certPath := filepath.Join(tmpDir, "ca.pem")
    SaveCertificateToPEM(certBytes, certPath)

    err = VerifyCertificate(certPath)
    if err != nil {
        t.Errorf("Verification failed: %v", err)
    }
}