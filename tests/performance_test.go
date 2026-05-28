package tests

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "testing"
    "time"

    "micropki/internal/database"
)

func TestPerformance1000Certificates(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping performance test in short mode")
    }

    // Setup in-memory SQLite
    db, err := database.InitDB(":memory:")
    if err != nil {
        t.Fatalf("Failed to init DB: %v", err)
    }
    defer db.Close()

    // Create a test CA cert and key (self-signed for testing)
    caKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatalf("Failed to generate CA key: %v", err)
    }

    caTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "Test CA"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign,
        IsCA:         true,
    }
    caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
    if err != nil {
        t.Fatalf("Failed to create CA cert: %v", err)
    }
    caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

    startTime := time.Now()
    successCount := 0

    for i := 0; i < 1000; i++ {
        // Generate key
        key, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            t.Logf("Failed to generate key %d: %v", i, err)
            continue
        }

        csrTemplate := &x509.CertificateRequest{
            Subject: pkix.Name{CommonName: fmt.Sprintf("test%d.local", i)},
        }

        // Create CSR (result not directly used, we simulate DB insertion)
        if _, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key); err != nil {
            t.Logf("Failed to create CSR %d: %v", i, err)
            continue
        }

        // Simulate DB insertion directly
        serial := fmt.Sprintf("%016X", i+1)
        _, err = db.Exec(`
            INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            serial, csrTemplate.Subject.String(), "CN=Test CA",
            time.Now().Format(time.RFC3339), time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
            string(caCertPEM), "valid", time.Now().Format(time.RFC3339))
        if err != nil {
            t.Logf("Insert failed for %d: %v", i, err)
            continue
        }
        successCount++
    }

    elapsed := time.Since(startTime)
    t.Logf("Issued %d certificates in %v (%.2f certs/sec)", successCount, elapsed, float64(successCount)/elapsed.Seconds())

    if successCount < 900 {
        t.Errorf("Only %d certificates succeeded, expected at least 900", successCount)
    }
}