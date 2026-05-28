package validation

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
)

func createTestCert(t *testing.T, subject string, isCA bool, days int) (string, *rsa.PrivateKey) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    template := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().Unix()),
        Subject:      pkix.Name{CommonName: subject},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(0, 0, days),
        KeyUsage:     x509.KeyUsageDigitalSignature,
        IsCA:         isCA,
    }

    certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
    if err != nil {
        t.Fatal(err)
    }

    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
    return string(certPEM), privKey
}

func saveCert(t *testing.T, path string, pemData string) {
    if err := os.WriteFile(path, []byte(pemData), 0644); err != nil {
        t.Fatal(err)
    }
}

func TestNewValidator(t *testing.T) {
    _, err := NewValidator("", time.Now())
    if err != nil {
        t.Errorf("Failed to create validator: %v", err)
    }
}

func TestValidateSelfSignedCert(t *testing.T) {
    tmpDir := t.TempDir()
    certPath := filepath.Join(tmpDir, "cert.pem")
    certPEM, _ := createTestCert(t, "Test Cert", false, 365)
    saveCert(t, certPath, certPEM)

    // Для самоподписанного сертификата нужно доверять этому же сертификату
    // Но NewValidator принимает путь к корневому сертификату. Создадим временный файл с этим же сертификатом
    rootPath := filepath.Join(tmpDir, "root.pem")
    saveCert(t, rootPath, certPEM)

    validator, err := NewValidator(rootPath, time.Now())
    if err != nil {
        t.Fatal(err)
    }

    result, err := validator.ValidateCertificate(certPath, []string{})
    if err != nil {
        t.Fatalf("Validation error: %v", err)
    }
    // Самоподписанный сертификат с указанным root должен пройти валидацию
    if !result.Passed {
        t.Error("Self-signed certificate should pass validation when root is itself")
    }
}

func TestAddIntermediate(t *testing.T) {
    validator, err := NewValidator("", time.Now())
    if err != nil {
        t.Fatal(err)
    }
    certPEM, _ := createTestCert(t, "Intermediate", true, 1825)
    // Парсим сертификат из PEM
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        t.Fatal("Failed to decode PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }
    validator.AddIntermediate(cert)
    t.Log("Intermediate added successfully")
}