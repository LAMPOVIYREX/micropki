package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/stretchr/testify/require"
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
		{"With O", "/CN=Test CA/O=Org", "Test CA", false},
		{"Empty", "", "", true},
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
	if cert.NotAfter.Sub(cert.NotBefore) != 365*24*time.Hour {
		t.Errorf("Expected validity 365 days, got %v", cert.NotAfter.Sub(cert.NotBefore))
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

func TestLoadCertificateNotFound(t *testing.T) {
	_, err := LoadCertificate("/nonexistent.pem")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestSignCertificate(t *testing.T) {
	// Create root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootSubject, _ := ParseDN("/CN=Root CA")
	rootCertBytes, err := GenerateSelfSignedCert(rootKey, rootSubject, 3650)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create intermediate CSR
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interSubject, _ := ParseDN("/CN=Intermediate CA")
	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      *interSubject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	interCertBytes, err := SignCertificate(interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to sign intermediate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interCertBytes)
	if err != nil {
		t.Fatal(err)
	}
	if interCert.Issuer.CommonName != "Root CA" {
		t.Errorf("Expected issuer Root CA, got %s", interCert.Issuer.CommonName)
	}
}

func TestCreateIntermediateCATemplate(t *testing.T) {
	rootCert, _, _ := createTestCert(t, "Root CA", true, 3650)
	subject, _ := ParseDN("/CN=Intermediate CA")

	// Создаём временный ключ для публичного ключа
	tempKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template, err := CreateIntermediateCATemplate(subject, rootCert, &tempKey.PublicKey, 365, 0)
	if err != nil {
		t.Fatalf("Failed to create template: %v", err)
	}

	if !template.IsCA {
		t.Error("Expected IsCA=true")
	}
	if template.MaxPathLen != 0 {
		t.Errorf("Expected MaxPathLen=0, got %d", template.MaxPathLen)
	}
}

func createTestCert(t *testing.T, name string, isCA bool, days int) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         isCA,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, privKey, certBytes
}

func TestEncodeCertificatePEM(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := ParseDN("/CN=Test")
	certBytes, err := GenerateSelfSignedCert(privKey, subject, 365)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := EncodeCertificatePEM(certBytes)
	if len(pemBytes) == 0 {
		t.Error("Encoded PEM is empty")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("Invalid PEM encoding")
	}
}

func TestSaveCertificatePEM(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := ParseDN("/CN=Test")
	certBytes, err := GenerateSelfSignedCert(privKey, subject, 365)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cert.pem")
	err = SaveCertificatePEM(certBytes, path, 0644)
	if err != nil {
		t.Fatalf("Failed to save: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("File not created")
	}
}

func TestSignCertificate_Valid(t *testing.T) {
	// Create root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootSubject, _ := ParseDN("/CN=Root CA")
	rootCertBytes, err := GenerateSelfSignedCert(rootKey, rootSubject, 3650)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create leaf template
	leafSubject, _ := ParseDN("/CN=Leaf")
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      *leafSubject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafCertBytes, err := SignCertificate(leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		t.Fatal(err)
	}
	if leafCert.Issuer.CommonName != "Root CA" {
		t.Errorf("Expected issuer Root CA, got %s", leafCert.Issuer.CommonName)
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	serial, err := GenerateSerialNumber()
	require.NoError(t, err)
	require.NotNil(t, serial)
}

func TestComputeSubjectKeyIdentifier(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ski, err := ComputeSubjectKeyIdentifier(&key.PublicKey)
	require.NoError(t, err)
	require.Len(t, ski, 20)
}

func TestGetPublicKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, err := GetPublicKey(key)
	require.NoError(t, err)
	require.Equal(t, &key.PublicKey, pub)
}

func TestCreateSelfSignedRootCA(t *testing.T) {
	serial, _ := GenerateSerialNumber()
	config := &CertificateConfig{
		Subject:      "/CN=Root CA",
		KeyType:      "rsa",
		ValidityDays: 365,
		SerialNumber: serial,
		PublicKey:    &rsa.PublicKey{}, // mock
	}
	// Мы не можем реально создать, потому что нужен реальный ключ, но вызов ParseDN проверим
	// Просто проверим, что функция возвращает ошибку при плохом ключе
	_, err := CreateSelfSignedRootCA(config)
	require.Error(t, err) // не сможет замаршалить публичный ключ
}

func TestVerifyCertificateChain(t *testing.T) {
	tmpDir := t.TempDir()
	// Генерируем Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true, // <-- добавить
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCertPath := filepath.Join(tmpDir, "root.cert.pem")
	os.WriteFile(rootCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER}), 0644)

	// Генерируем Leaf, подписанный Root
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCertPath := filepath.Join(tmpDir, "leaf.cert.pem")
	os.WriteFile(leafCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER}), 0644)

	// Проверяем цепочку
	err := VerifyCertificateChain(leafCertPath, []string{rootCertPath})
	require.NoError(t, err)
}

func TestGetSignatureAlgorithm(t *testing.T) {
	require.Equal(t, x509.SHA256WithRSA, getSignatureAlgorithm("rsa"))
	require.Equal(t, x509.ECDSAWithSHA384, getSignatureAlgorithm("ecc"))
}

func TestGetSignatureAlgorithmFromKey(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	require.Equal(t, x509.SHA256WithRSA, getSignatureAlgorithmFromKey(rsaKey))
	eccKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.Equal(t, x509.ECDSAWithSHA384, getSignatureAlgorithmFromKey(eccKey))
}

func TestVerifyCertificate_SelfSigned(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)

	err := VerifyCertificate(certPath)
	require.NoError(t, err)
}

func TestLoadCertificate_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
	cert, err := LoadCertificate(certPath)
	require.NoError(t, err)
	require.Equal(t, "test", cert.Subject.CommonName)
}

func TestVerifyCertificateChain_Error(t *testing.T) {
	tmpDir := t.TempDir()
	// Создаём самоподписанный сертификат
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)

	// Проверяем цепочку без доверенных корней — должна быть ошибка
	err := VerifyCertificateChain(certPath, nil)
	require.Error(t, err)
}

func TestVerifyCertificate_Invalid(t *testing.T) {
	err := VerifyCertificate("nonexistent.pem")
	require.Error(t, err)
}

func TestParseDN_Empty(t *testing.T) {
	_, err := ParseDN("")
	require.Error(t, err)
}

func TestLoadCertificate_Error(t *testing.T) {
	_, err := LoadCertificate("nonexistent.pem")
	require.Error(t, err)
}

func TestVerifyCertificate_SelfSigned_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
	err := VerifyCertificate(certPath)
	require.NoError(t, err)
}

func TestGetPublicKey_ECC(t *testing.T) {
	eccKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pub, err := GetPublicKey(eccKey)
	require.NoError(t, err)
	require.NotNil(t, pub)
}

func TestCreateSelfSignedRootCA_ECC(t *testing.T) {
	eccKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	serial, _ := GenerateSerialNumber()
	config := &CertificateConfig{
		Subject:      "/CN=ECC Root CA",
		KeyType:      "ecc",
		ValidityDays: 365,
		SerialNumber: serial,
		PublicKey:    &eccKey.PublicKey,
	}
	template, err := CreateSelfSignedRootCA(config)
	require.NoError(t, err)
	require.True(t, template.IsCA)
	require.Equal(t, "ECC Root CA", template.Subject.CommonName)
}

func TestParseDN_Complex(t *testing.T) {
	name, err := ParseDN("/CN=Test Server/O=MyOrg/OU=Dev/C=US/ST=California/L=San Jose")
	require.NoError(t, err)
	require.Equal(t, "Test Server", name.CommonName)
	require.Equal(t, []string{"MyOrg"}, name.Organization)
	require.Equal(t, []string{"Dev"}, name.OrganizationalUnit)
	require.Equal(t, []string{"US"}, name.Country)
	require.Equal(t, []string{"California"}, name.Province)
	require.Equal(t, []string{"San Jose"}, name.Locality)
}

func TestCreateCertificateTemplate_CodeSigning(t *testing.T) {
	subj := &pkix.Name{CommonName: "codesign.example.com"}
	tmpl, err := CreateCertificateTemplate("code-signing", subj, []string{"dns:example.com"}, 365)
	require.NoError(t, err)
	require.False(t, tmpl.IsCA)
	require.Equal(t, x509.KeyUsageDigitalSignature, tmpl.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, tmpl.ExtKeyUsage)
}
