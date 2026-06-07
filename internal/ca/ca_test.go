package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"micropki/internal/logger"
	"micropki/pkg/types"

	myCrypto "micropki/internal/crypto"

	"github.com/stretchr/testify/require"
)

func TestNewCA(t *testing.T) {
	config := &types.CAConfig{
		OutDir:  t.TempDir(),
		Subject: "CN=Test",
	}
	log, _ := logger.NewLogger("")
	ca := NewCA(config, log)
	if ca == nil {
		t.Error("NewCA returned nil")
	}
}

func TestInitRootCA(t *testing.T) {
	tempDir := t.TempDir()
	passFile := filepath.Join(tempDir, "pass.txt")
	err := os.WriteFile(passFile, []byte("TestPass123!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	config := &types.CAConfig{
		Subject:      "/CN=Test Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("TestPass123!"),
		OutDir:       tempDir,
		ValidityDays: 365,
	}
	log, _ := logger.NewLogger("")
	ca := NewCA(config, log)
	files, err := ca.InitRootCA()
	if err != nil {
		t.Fatalf("InitRootCA failed: %v", err)
	}
	// Проверяем, что файлы созданы
	if _, err := os.Stat(files.CertPath); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
	if _, err := os.Stat(files.PrivateKeyPath); os.IsNotExist(err) {
		t.Error("Private key file not created")
	}
	if _, err := os.Stat(files.PolicyPath); os.IsNotExist(err) {
		t.Log("Policy file not created (optional)")
	}
}

func TestGenerateIntermediateCSR(t *testing.T) {
	keyPair, err := myCrypto.GenerateKeyPair("rsa", 4096)
	require.NoError(t, err)

	subject := &pkix.Name{CommonName: "Intermediate CA"}
	csrBytes, err := GenerateIntermediateCSR(subject, keyPair)
	require.NoError(t, err)
	require.NotEmpty(t, csrBytes)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)
	require.Equal(t, "Intermediate CA", csr.Subject.CommonName)
}

func TestSignIntermediateCSR(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	interKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	subject := &pkix.Name{CommonName: "Intermediate CA"}
	csrBytes, err := GenerateIntermediateCSR(subject, &myCrypto.KeyPair{PrivateKey: interKey, PublicKey: &interKey.PublicKey})
	require.NoError(t, err)

	certDER, err := SignIntermediateCSR(csrBytes, rootCert, rootKey, 365, 1)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.Equal(t, "Intermediate CA", cert.Subject.CommonName)
	require.True(t, cert.IsCA)
	require.Equal(t, 1, cert.MaxPathLen)
}

func TestGetSignatureAlgorithmFromKey(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	require.Equal(t, x509.SHA256WithRSA, getSignatureAlgorithmFromKey(rsaKey))

	eccKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.Equal(t, x509.ECDSAWithSHA384, getSignatureAlgorithmFromKey(eccKey))
}

func TestGetSignatureAlgorithmFromKey_CA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	require.Equal(t, x509.SHA256WithRSA, getSignatureAlgorithmFromKey(rsaKey))
}

func TestInitIntermediateCA_ECC(t *testing.T) {
	// Создаём Root CA RSA
	tmpRoot := t.TempDir()
	passFile := filepath.Join(tmpRoot, "pass.txt")
	os.WriteFile(passFile, []byte("RootPass123"), 0600)

	log, _ := logger.NewLogger("")
	rootConfig := &types.CAConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("RootPass123"),
		OutDir:       tmpRoot,
		ValidityDays: 3650,
	}
	rootCA := NewCA(rootConfig, log)
	_, err := rootCA.InitRootCA()
	require.NoError(t, err)

	// Intermediate CA с ECC
	tmpInt := t.TempDir()
	intPassFile := filepath.Join(tmpInt, "intpass.txt")
	os.WriteFile(intPassFile, []byte("IntPass123"), 0600)

	intConfig := &IntermediateCAConfig{
		Subject:          "/CN=Intermediate ECC CA",
		KeyType:          "ecc",
		KeySize:          384,
		Passphrase:       []byte("IntPass123"),
		OutDir:           tmpInt,
		ValidityDays:     1825,
		RootCAPassphrase: []byte("RootPass123"),
		RootCADir:        tmpRoot,
		MaxPathLen:       1,
	}
	caInstance := NewCA(&types.CAConfig{Subject: intConfig.Subject}, log)
	files, err := caInstance.InitIntermediateCA(intConfig)
	require.NoError(t, err)
	require.FileExists(t, files.CertPath)
	require.FileExists(t, files.PrivateKeyPath)
}

func TestSignIntermediateCSR_Error(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootCert := &x509.Certificate{} // невалидный сертификат
	_, err := SignIntermediateCSR([]byte("invalid csr"), rootCert, rootKey, 365, 1)
	require.Error(t, err)
}

func TestLoadCertificate_Error(t *testing.T) {
	_, err := loadCertificate("nonexistent.pem")
	require.Error(t, err)
}

func TestInitRootCA_ECC(t *testing.T) {
	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "pass.txt")
	os.WriteFile(passFile, []byte("EccPass123!"), 0600)

	config := &types.CAConfig{
		Subject:      "/CN=ECC Root CA",
		KeyType:      "ecc",
		KeySize:      384,
		Passphrase:   []byte("EccPass123!"),
		OutDir:       tmpDir,
		ValidityDays: 3650,
	}
	log, _ := logger.NewLogger("")
	caInstance := NewCA(config, log)
	files, err := caInstance.InitRootCA()
	require.NoError(t, err)
	require.FileExists(t, files.CertPath)
	require.FileExists(t, files.PrivateKeyPath)
}

func TestInitIntermediateCA_BadPassphrase(t *testing.T) {
	tmpRoot := t.TempDir()
	passFile := filepath.Join(tmpRoot, "pass.txt")
	os.WriteFile(passFile, []byte("RootPass123"), 0600)
	log, _ := logger.NewLogger("")
	rootConfig := &types.CAConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("RootPass123"),
		OutDir:       tmpRoot,
		ValidityDays: 3650,
	}
	rootCA := NewCA(rootConfig, log)
	_, err := rootCA.InitRootCA()
	require.NoError(t, err)

	tmpInt := t.TempDir()
	intConfig := &IntermediateCAConfig{
		Subject:          "/CN=Intermediate CA",
		KeyType:          "rsa",
		KeySize:          4096,
		Passphrase:       []byte("IntPass123"),
		OutDir:           tmpInt,
		ValidityDays:     1825,
		RootCAPassphrase: []byte("WrongPass"),
		RootCADir:        tmpRoot,
		MaxPathLen:       1,
	}
	caInstance := NewCA(&types.CAConfig{Subject: intConfig.Subject}, log)
	_, err = caInstance.InitIntermediateCA(intConfig)
	require.Error(t, err)
}

func TestGetSignatureAlgorithmFromKey_ECC(t *testing.T) {
	eccKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.Equal(t, x509.ECDSAWithSHA384, getSignatureAlgorithmFromKey(eccKey))
}

func TestInitIntermediateCA_WrongRootKey(t *testing.T) {
	tmpRoot := t.TempDir()
	passFile := filepath.Join(tmpRoot, "pass.txt")
	os.WriteFile(passFile, []byte("RootPass123"), 0600)
	log, _ := logger.NewLogger("")
	rootConfig := &types.CAConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("RootPass123"),
		OutDir:       tmpRoot,
		ValidityDays: 3650,
	}
	rootCA := NewCA(rootConfig, log)
	_, err := rootCA.InitRootCA()
	require.NoError(t, err)

	tmpInt := t.TempDir()
	intConfig := &IntermediateCAConfig{
		Subject:          "/CN=Intermediate CA",
		KeyType:          "rsa",
		KeySize:          4096,
		Passphrase:       []byte("IntPass123"),
		OutDir:           tmpInt,
		ValidityDays:     1825,
		RootCAPassphrase: []byte("WrongPass"),
		RootCADir:        tmpRoot,
		MaxPathLen:       1,
	}
	caInstance := NewCA(&types.CAConfig{Subject: intConfig.Subject}, log)
	_, err = caInstance.InitIntermediateCA(intConfig)
	require.Error(t, err)
}

func TestInitRootCA_ErrorPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "pass.txt")
	os.WriteFile(passFile, []byte("RootPass123"), 0600)
	config := &types.CAConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		KeySize:      2048, // нарушение политики (должно быть 4096)
		Passphrase:   []byte("RootPass123"),
		OutDir:       tmpDir,
		ValidityDays: 3650,
	}
	log, _ := logger.NewLogger("")
	caInstance := NewCA(config, log)
	_, err := caInstance.InitRootCA()
	require.Error(t, err)
}

func TestIntermediateCA_WithECC(t *testing.T) {
	tmpRoot := t.TempDir()
	passFile := filepath.Join(tmpRoot, "pass.txt")
	os.WriteFile(passFile, []byte("RootPass123"), 0600)
	log, _ := logger.NewLogger("")
	rootConfig := &types.CAConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("RootPass123"),
		OutDir:       tmpRoot,
		ValidityDays: 3650,
	}
	rootCA := NewCA(rootConfig, log)
	_, err := rootCA.InitRootCA()
	require.NoError(t, err)

	tmpInt := t.TempDir()
	intConfig := &IntermediateCAConfig{
		Subject:          "/CN=Intermediate ECC CA",
		KeyType:          "ecc",
		KeySize:          384,
		Passphrase:       []byte("IntPass123"),
		OutDir:           tmpInt,
		ValidityDays:     1825,
		RootCAPassphrase: []byte("RootPass123"),
		RootCADir:        tmpRoot,
		MaxPathLen:       1,
	}
	caInstance := NewCA(&types.CAConfig{Subject: intConfig.Subject}, log)
	files, err := caInstance.InitIntermediateCA(intConfig)
	require.NoError(t, err)
	require.FileExists(t, files.CertPath)
	require.FileExists(t, files.PrivateKeyPath)
}
