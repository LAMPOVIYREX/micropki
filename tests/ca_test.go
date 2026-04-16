package tests

import (
    "crypto/x509"
    "os"
    "path/filepath"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "micropki/internal/certs"
    "micropki/internal/crypto"
    "micropki/internal/logger"
)

func TestGenerateKeyPair(t *testing.T) {
    t.Run("RSA 4096", func(t *testing.T) {
        keyPair, err := crypto.GenerateKeyPair("rsa", 4096)
        require.NoError(t, err)
        assert.Equal(t, "rsa", string(keyPair.KeyType))
        assert.Equal(t, 4096, keyPair.KeySize)
        assert.NotNil(t, keyPair.PrivateKey)
        assert.NotNil(t, keyPair.PublicKey)
    })

    t.Run("ECC P-384", func(t *testing.T) {
        keyPair, err := crypto.GenerateKeyPair("ecc", 384)
        require.NoError(t, err)
        assert.Equal(t, "ecc", string(keyPair.KeyType))
        assert.Equal(t, 384, keyPair.KeySize)
        assert.NotNil(t, keyPair.PrivateKey)
        assert.NotNil(t, keyPair.PublicKey)
    })
}

func TestParseDN(t *testing.T) {
    name, err := certs.ParseDN("/CN=Test CA/O=MicroPKI")
    require.NoError(t, err)
    assert.Equal(t, "Test CA", name.CommonName)
}

func TestGenerateSelfSignedCert(t *testing.T) {
    keyPair, err := crypto.GenerateKeyPair("rsa", 4096)
    require.NoError(t, err)

    subject, err := certs.ParseDN("/CN=Test Root CA")
    require.NoError(t, err)

    certBytes, err := certs.GenerateSelfSignedCert(keyPair.PrivateKey, subject, 365)
    require.NoError(t, err)
    assert.NotNil(t, certBytes)

    cert, err := x509.ParseCertificate(certBytes)
    require.NoError(t, err)
    assert.Equal(t, "Test Root CA", cert.Subject.CommonName)
    assert.True(t, cert.IsCA)
}

func TestEncryptAndSavePrivateKey(t *testing.T) {
    tempDir := t.TempDir()
    keyPath := filepath.Join(tempDir, "private", "test.key.pem")

    keyPair, err := crypto.GenerateKeyPair("rsa", 4096)
    require.NoError(t, err)

    passphrase := []byte("TestPass123!") // Strong passphrase
    err = crypto.EncryptAndSavePrivateKey(keyPair, passphrase, keyPath)
    require.NoError(t, err)

    _, err = os.Stat(keyPath)
    assert.NoError(t, err)

    loadedKey, err := crypto.LoadAndDecryptPrivateKey(keyPath, passphrase)
    require.NoError(t, err)
    assert.NotNil(t, loadedKey)
}

func TestLogger(t *testing.T) {
    tempDir := t.TempDir()
    logPath := filepath.Join(tempDir, "test.log")

    log, err := logger.NewLogger(logPath)
    require.NoError(t, err)
    defer log.Close()

    log.Info("Test info message")
    log.Warning("Test warning message")
    log.Error("Test error message")

    _, err = os.Stat(logPath)
    assert.NoError(t, err)

    content, err := os.ReadFile(logPath)
    require.NoError(t, err)
    assert.Contains(t, string(content), "INFO")
    assert.Contains(t, string(content), "WARNING")
    assert.Contains(t, string(content), "ERROR")
}
