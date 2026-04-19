package tests

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "path/filepath"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "micropki/internal/client"
    "micropki/internal/validation"
)

// TEST-38: CSR Generation Test
func TestCSRGeneration(t *testing.T) {
    tempDir := t.TempDir()
    keyPath := filepath.Join(tempDir, "test.key.pem")
    csrPath := filepath.Join(tempDir, "test.csr.pem")
    
    err := client.GenerateCSR("test.example.com", "rsa", 2048, []string{"dns:test.example.com"}, keyPath, csrPath)
    require.NoError(t, err)
    
    info, err := os.Stat(keyPath)
    require.NoError(t, err)
    assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
    
    csrData, err := os.ReadFile(csrPath)
    require.NoError(t, err)
    
    block, _ := pem.Decode(csrData)
    require.NotNil(t, block)
    assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
    
    csr, err := x509.ParseCertificateRequest(block.Bytes)
    require.NoError(t, err)
    
    err = csr.CheckSignature()
    assert.NoError(t, err)
    
    assert.Contains(t, csr.Subject.String(), "test.example.com")
}

// TEST-40: Chain Validation – Valid Chain
func TestChainValidationValid(t *testing.T) {
    // Create certificate chain
    rootCert, rootKey := createTestCA(t, "Test Root CA", true, -1)
    intermediateCert, interKey := createIntermediateCA(t, "Test Intermediate CA", rootCert, rootKey)
    leafCert, _ := createTestLeaf(t, "test.example.com", intermediateCert, interKey)
    
    tempDir := t.TempDir()
    rootPath := filepath.Join(tempDir, "root.pem")
    interPath := filepath.Join(tempDir, "intermediate.pem")
    leafPath := filepath.Join(tempDir, "leaf.pem")
    
    saveCert(t, rootPath, rootCert)
    saveCert(t, interPath, intermediateCert)
    saveCert(t, leafPath, leafCert)
    
    // Create validator
    validator, err := validation.NewValidator(rootPath, time.Now())
    require.NoError(t, err)
    
    // Validate with intermediates
    result, err := validator.ValidateCertificate(leafPath, []string{interPath})
    require.NoError(t, err)
    
    t.Logf("Validation result: %v", result.Passed)
    for _, step := range result.Steps {
        t.Logf("  Step: %s - Passed: %v - %s", step.Name, step.Passed, step.Message)
    }
    
    assert.True(t, result.Passed, "Validation should pass")
}

// TEST-41: Chain Validation – Expired Certificate
func TestChainValidationExpired(t *testing.T) {
    rootCert, rootPrivKey := createTestCA(t, "Test Root CA", true, -1)
    expiredCert := createExpiredCertificate(t, "expired.example.com", rootCert, rootPrivKey)
    
    tempDir := t.TempDir()
    rootPath := filepath.Join(tempDir, "root.pem")
    leafPath := filepath.Join(tempDir, "leaf.pem")
    
    saveCert(t, rootPath, rootCert)
    saveCert(t, leafPath, expiredCert)
    
    validator, err := validation.NewValidator(rootPath, time.Now())
    require.NoError(t, err)
    
    result, err := validator.ValidateCertificate(leafPath, []string{})
    require.NoError(t, err)
    assert.False(t, result.Passed, "Expired certificate should fail validation")
}

// TEST-46: Chain Building – Missing Intermediate
func TestChainBuildingMissingIntermediate(t *testing.T) {
    rootCert, _ := createTestCA(t, "Test Root CA", true, -1)
    intermediateCert, interPrivKey := createTestCA(t, "Test Intermediate CA", true, 0)
    leafCert, _ := createTestLeaf(t, "test.example.com", intermediateCert, interPrivKey)
    
    tempDir := t.TempDir()
    rootPath := filepath.Join(tempDir, "root.pem")
    leafPath := filepath.Join(tempDir, "leaf.pem")
    
    saveCert(t, rootPath, rootCert)
    saveCert(t, leafPath, leafCert)
    
    validator, err := validation.NewValidator(rootPath, time.Now())
    require.NoError(t, err)
    
    result, err := validator.ValidateCertificate(leafPath, []string{})
    require.NoError(t, err)
    assert.False(t, result.Passed, "Validation without intermediate should fail")
}

// Helper functions
// createTestCA создаёт самоподписанный корневой сертификат
func createTestCA(t *testing.T, subject string, isCA bool, maxPathLen int) (*x509.Certificate, *rsa.PrivateKey) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    
    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject:      pkix.Name{CommonName: subject},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:         isCA,
        MaxPathLen:   maxPathLen,
    }
    
    // Self-signed
    certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
    require.NoError(t, err)
    
    cert, err := x509.ParseCertificate(certBytes)
    require.NoError(t, err)
    
    return cert, privKey
}

// createIntermediateCA создаёт промежуточный сертификат, подписанный корневым
func createIntermediateCA(t *testing.T, subject string, rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    
    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject:      pkix.Name{CommonName: subject},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(5, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:         true,
        MaxPathLen:   0,
    }
    
    certBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, &privKey.PublicKey, rootKey)
    require.NoError(t, err)
    
    cert, err := x509.ParseCertificate(certBytes)
    require.NoError(t, err)
    
    return cert, privKey
}

// createTestLeaf создаёт листовой сертификат, подписанный промежуточным
func createTestLeaf(t *testing.T, subject string, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    
    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject:      pkix.Name{CommonName: subject},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    
    certBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &privKey.PublicKey, issuerKey)
    require.NoError(t, err)
    
    cert, err := x509.ParseCertificate(certBytes)
    require.NoError(t, err)
    
    return cert, privKey
}

// createExpiredCertificate создаёт просроченный сертификат
func createExpiredCertificate(t *testing.T, subject string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) *x509.Certificate {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    
    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject:      pkix.Name{CommonName: subject},
        NotBefore:    time.Now().AddDate(-2, 0, 0),
        NotAfter:     time.Now().AddDate(-1, 0, 0),
        KeyUsage:     x509.KeyUsageDigitalSignature,
    }
    
    certBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, &privKey.PublicKey, issuerKey)
    require.NoError(t, err)
    
    cert, err := x509.ParseCertificate(certBytes)
    require.NoError(t, err)
    
    return cert
}

func saveCert(t *testing.T, path string, cert *x509.Certificate) {
    pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
    err := os.WriteFile(path, pemBytes, 0644)
    require.NoError(t, err)
}

func loadCertForTest(path string) (*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, nil
    }
    return x509.ParseCertificate(block.Bytes)
}