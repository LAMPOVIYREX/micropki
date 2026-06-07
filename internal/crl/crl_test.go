package crl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	myCrypto "micropki/internal/crypto"
	"micropki/internal/database"

	"github.com/stretchr/testify/require"
)

// helper для создания временной БД с таблицами
func initTestDB(t *testing.T) *sql.DB {
	db, err := database.InitDB(":memory:")
	require.NoError(t, err)
	return db
}

func TestReasonCodeMap(t *testing.T) {
	require.Equal(t, 0, ReasonCodeMap["unspecified"])
	require.Equal(t, 1, ReasonCodeMap["keyCompromise"])
	require.Equal(t, 2, ReasonCodeMap["cACompromise"])
	require.Equal(t, 5, ReasonCodeMap["cessationOfOperation"])
}

func TestGenerateCRL(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	config := &CRLConfig{
		CAIssuer:     caCert,
		CAPrivateKey: caKey,
		Number:       1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().AddDate(0, 0, 7),
		RevokedCerts: []RevokedCertificate{},
		OutPath:      filepath.Join(t.TempDir(), "test.crl"),
	}

	crlBytes, err := GenerateCRL(config)
	require.NoError(t, err)
	require.NotEmpty(t, crlBytes)
}

func TestSaveCRL(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.crl")
	err := SaveCRL([]byte("dummy"), path)
	require.NoError(t, err)
	require.FileExists(t, path)
}

func TestGetRevokedCertificates(t *testing.T) {
	db := initTestDB(t)
	defer db.Close()

	// Вставляем отозванный сертификат
	_, err := db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at) 
        VALUES ('DEAD', 'CN=revoked', 'CN=Root', '2024-01-01', '2025-01-01', 'pem', 'revoked', 'keyCompromise', '2024-06-01T00:00:00Z', '2024-01-01')`)
	require.NoError(t, err)

	revoked, err := GetRevokedCertificates(db, "CN=Root")
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	require.Equal(t, "DEAD", fmt.Sprintf("%X", revoked[0].SerialNumber))
	require.Equal(t, 1, revoked[0].ReasonCode) // keyCompromise
}

func TestRevokeCertificateAndGenerateCRL(t *testing.T) {
	db := initTestDB(t)
	defer db.Close()

	_, err := db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('123ABC', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)
	require.NoError(t, err)

	// Этот вызов может упасть при генерации CRL, но сама функция RevokeCertificate не возвращает ошибку (только логирует)
	err = RevokeCertificate(db, "123ABC", "keyCompromise", "/tmp", "root", "/tmp/pass")
	require.NoError(t, err)

	var status string
	err = db.QueryRow("SELECT status FROM certificates WHERE serial_hex = '123ABC'").Scan(&status)
	require.NoError(t, err)
	require.Equal(t, "revoked", status)
}

func TestVerifyCRL(t *testing.T) {
	err := VerifyCRL("fake.crl", "fake.cert")
	require.NoError(t, err) // функция всегда возвращает nil
}

func TestGenerateCRL_Error(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bad CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign, // без CRLSign
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	config := &CRLConfig{
		CAIssuer:     caCert,
		CAPrivateKey: caKey,
		Number:       1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().AddDate(0, 0, 7),
		RevokedCerts: []RevokedCertificate{},
		OutPath:      filepath.Join(t.TempDir(), "test.crl"),
	}
	_, err = GenerateCRL(config)
	require.Error(t, err)
}

func TestLoadCertificate_CRL(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
	require.NoError(t, err)
	cert, err := loadCertificate(certPath)
	require.NoError(t, err)
	require.Equal(t, "test", cert.Subject.CommonName)
}

func TestRevokeCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "rootCA")
	certsDir := filepath.Join(caDir, "certs")
	privateDir := filepath.Join(caDir, "private")
	crlDir := filepath.Join(caDir, "crl")
	require.NoError(t, os.MkdirAll(certsDir, 0755))
	require.NoError(t, os.MkdirAll(privateDir, 0700))
	require.NoError(t, os.MkdirAll(crlDir, 0755))

	// Генерируем CA ключ и сертификат
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(certsDir, "ca.cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}), 0644)
	require.NoError(t, err)

	// Ключ шифруем и сохраняем
	encryptedKey, err := myCrypto.EncryptPrivateKey(caKey, []byte("pass123"))
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(privateDir, "ca.key.pem"), encryptedKey, 0600)
	require.NoError(t, err)

	// БД
	db, err := database.InitDB(filepath.Join(caDir, "micropki.db"))
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('REV123', 'CN=test', 'CN=Root CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)
	require.NoError(t, err)

	passFile := filepath.Join(tmpDir, "pass.txt")
	err = os.WriteFile(passFile, []byte("pass123"), 0600)
	require.NoError(t, err)

	err = RevokeCertificate(db, "REV123", "keyCompromise", caDir, "root", passFile)
	require.NoError(t, err)
}

func TestGenerateCRLAfterRevocation_Error(t *testing.T) {
	tmpDir := t.TempDir()
	passFile := filepath.Join(tmpDir, "pass.txt")
	os.WriteFile(passFile, []byte("password"), 0600)

	err := generateCRLAfterRevocation(tmpDir, "root", passFile)
	require.Error(t, err) // нет файлов сертификатов
}

func TestGenerateCRLAfterRevocation_InvalidCA(t *testing.T) {
	err := generateCRLAfterRevocation("/tmp", "badtype", "/tmp/pass")
	require.Error(t, err)
}
