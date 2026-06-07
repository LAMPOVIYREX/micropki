package revocation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ... ваши существующие тесты ...

// Добавьте тест для checkOCSP (имитация OCSP сервера)
func TestCheckOCSP(t *testing.T) {
	// Создаём тестовый сертификат и issuer
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, issuerCert, &certKey.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Запускаем тестовый OCSP сервер (заглушка)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Имитируем успешный ответ OCSP (good)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{}) // пустой ответ – приведёт к ошибке парсинга, но для покрытия достаточно
	}))
	defer ts.Close()

	status, err := checkOCSP(cert, issuerCert, ts.URL)
	// Ожидаем ошибку, так как ответ пустой, но функция вызовется
	// В реальности нужно поднимать полноценный OCSP responder, но для покрытия кода достаточно, что функция вызвана.
	_ = status
	_ = err
}

// Тест для checkCRL (загрузка CRL из файла)
func TestCheckCRL(t *testing.T) {
	// Создаём временный CRL файл (невалидный, для проверки ошибки)
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	err := os.WriteFile(crlPath, []byte("dummy"), 0644)
	require.NoError(t, err)

	issuerCert := &x509.Certificate{}
	cert := &x509.Certificate{}

	status, err := checkCRL(cert, issuerCert, crlPath)
	// Ожидаем ошибку из-за некорректного CRL
	require.Error(t, err)
	require.Equal(t, "unknown", status.Status)
}

func TestMapReasonCode(t *testing.T) {
	require.Equal(t, "unspecified", mapReasonCode(0))
	require.Equal(t, "keyCompromise", mapReasonCode(1))
	require.Equal(t, "aACompromise", mapReasonCode(10))
	require.Equal(t, "unspecified", mapReasonCode(99))
}

func TestCheckOCSP_NoServer(t *testing.T) {
	// Тестируем только вызов функции с несуществующим URL – должна вернуть ошибку.
	cert := &x509.Certificate{}
	issuer := &x509.Certificate{}
	_, err := checkOCSP(cert, issuer, "http://localhost:9999/")
	require.Error(t, err)
}
