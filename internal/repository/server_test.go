package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	myCrypto "micropki/internal/crypto"
	"micropki/internal/database"
	"micropki/internal/logger"

	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) (*Server, *sql.DB, func()) {
	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "a", "b", "certs")
	intermediateDir := filepath.Join(tmpDir, "a", "pki-intermediate")
	intermediateCertsDir := filepath.Join(intermediateDir, "certs")
	intermediatePrivateDir := filepath.Join(intermediateDir, "private")

	os.MkdirAll(certDir, 0755)
	os.MkdirAll(intermediateCertsDir, 0755)
	os.MkdirAll(intermediatePrivateDir, 0700)

	testPass := []byte("test123")

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	os.WriteFile(filepath.Join(intermediateCertsDir, "intermediate.cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}), 0644)

	encryptedKey, err := myCrypto.EncryptPrivateKey(caKey, testPass)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(intermediatePrivateDir, "intermediate.key.pem"), encryptedKey, 0600)
	require.NoError(t, err)

	db, _ := database.InitDB(filepath.Join(tmpDir, "test.db"))
	log, _ := logger.NewLogger("")
	s := &Server{
		db:           db,
		certDir:      certDir,
		host:         "127.0.0.1",
		port:         0,
		logger:       log,
		caPassphrase: testPass,
	}
	return s, db, func() { db.Close() }
}

// ------------------ Успешные запросы ------------------

func TestHandleRequestCert_ValidCSR(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	expectedCAPath := filepath.Join(s.certDir, "..", "..", "pki-intermediate", "certs", "intermediate.cert.pem")
	_, err := os.Stat(expectedCAPath)
	require.NoError(t, err)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	req := httptest.NewRequest("POST", "/request-cert?template=server", bytes.NewReader(csrPEM))
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestHandleGetCertificate_Existing(t *testing.T) {
	s, db, cleanup := setupTestServer(t)
	defer cleanup()

	pemCert := "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
	_, err := db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=Test', 'CN=CA', '2024-01-01T00:00:00Z', '2025-01-01T00:00:00Z', ?, 'valid', '2024-01-01T00:00:00Z')`, pemCert)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/certificate/ABCD", nil)
	w := httptest.NewRecorder()
	s.handleGetCertificate(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, pemCert, w.Body.String())
}

func TestHandleGetCA_Root(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	rootCertPath := filepath.Join(s.certDir, "ca.cert.pem")
	err := os.WriteFile(rootCertPath, []byte("root-cert-data"), 0644)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/ca/root", nil)
	w := httptest.NewRecorder()
	s.handleGetCA(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "root-cert-data", w.Body.String())
}

func TestHandleGetCA_Intermediate(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	err := os.WriteFile(filepath.Join(s.certDir, "intermediate.cert.pem"), []byte("intermediate-cert"), 0644)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/ca/intermediate", nil)
	w := httptest.NewRecorder()
	s.handleGetCA(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "intermediate-cert", w.Body.String())
}

func TestHandleGetCRL_Intermediate(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	crlDir := filepath.Join(filepath.Dir(s.certDir), "crl")
	os.MkdirAll(crlDir, 0755)
	crlPath := filepath.Join(crlDir, "intermediate.crl.pem")
	err := os.WriteFile(crlPath, []byte("crl-data"), 0644)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/crl?ca=intermediate", nil)
	w := httptest.NewRecorder()
	s.handleGetCRL(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "crl-data", w.Body.String())
}

func TestHandleGetCRL_Root(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	crlDir := filepath.Join(filepath.Dir(s.certDir), "crl")
	os.MkdirAll(crlDir, 0755)
	err := os.WriteFile(filepath.Join(crlDir, "root.crl.pem"), []byte("root-crl"), 0644)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/crl?ca=root", nil)
	w := httptest.NewRecorder()
	s.handleGetCRL(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "root-crl", w.Body.String())
}

func TestHandleGetCRL_DefaultCA(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()

	crlDir := filepath.Join(filepath.Dir(s.certDir), "crl")
	os.MkdirAll(crlDir, 0755)
	os.WriteFile(filepath.Join(crlDir, "intermediate.crl.pem"), []byte("crl-data"), 0644)

	req := httptest.NewRequest("GET", "/crl", nil)
	w := httptest.NewRecorder()
	s.handleGetCRL(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "crl-data", w.Body.String())
}

// ------------------ Ошибки запросов ------------------

func TestHandleRequestCert_InvalidCSR(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("POST", "/request-cert", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRequestCert_InvalidMethod(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/request-cert", nil)
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRequestCert_InvalidTemplate(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	req := httptest.NewRequest("POST", "/request-cert?template=invalid", bytes.NewReader(csrPEM))
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusCreated, w.Code) // по умолчанию server
}

func TestHandleRequestCert_CompromisedKey(t *testing.T) {
	s, db, cleanup := setupTestServer(t)
	defer cleanup()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	hash := sha256.Sum256(pubDER)
	pubKeyHash := hex.EncodeToString(hash[:])
	db.Exec(`INSERT INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason) VALUES (?, 'test', '2024-01-01', 'keyCompromise')`, pubKeyHash)

	req := httptest.NewRequest("POST", "/request-cert?template=server", bytes.NewReader(csrPEM))
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleGetCertificate_InvalidSerial(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/certificate/ZZZ", nil)
	w := httptest.NewRecorder()
	s.handleGetCertificate(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetCertificate_NotFound(t *testing.T) {
	s, db, cleanup := setupTestServer(t)
	defer cleanup()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('1234', 'CN=Test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)
	req := httptest.NewRequest("GET", "/certificate/DEADBEEF", nil)
	w := httptest.NewRecorder()
	s.handleGetCertificate(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleGetCertificate_DBError(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	s.db.Close()
	req := httptest.NewRequest("GET", "/certificate/ABCD", nil)
	w := httptest.NewRecorder()
	s.handleGetCertificate(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleGetCA_InvalidLevel(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/ca/bad", nil)
	w := httptest.NewRecorder()
	s.handleGetCA(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetCA_MissingLevel(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/ca/", nil)
	w := httptest.NewRecorder()
	s.handleGetCA(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetCRL_InvalidCA(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/crl?ca=bad", nil)
	w := httptest.NewRecorder()
	s.handleGetCRL(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ------------------ Middleware и Health ------------------

func TestLoggingMiddleware(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := s.loggingMiddleware(next)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleHealth(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "ok")
}

// ------------------ Утилиты загрузки ------------------

func TestLoadPrivateKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(keyPath, keyPEM, 0600)
	priv, err := loadPrivateKeyFile(keyPath, "")
	require.NoError(t, err)
	require.NotNil(t, priv)
}

func TestLoadPrivateKeyFile_Error(t *testing.T) {
	_, err := loadPrivateKeyFile("nonexistent.pem", "")
	require.Error(t, err)
}

func TestLoadCertFile(t *testing.T) {
	tmpDir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPath := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
	cert, err := loadCertFile(certPath)
	require.NoError(t, err)
	require.Equal(t, "test", cert.Subject.CommonName)
}

func TestLoadCertFile_Error(t *testing.T) {
	_, err := loadCertFile("nonexistent.pem")
	require.Error(t, err)
}

// ------------------ Старт/Стоп сервера ------------------

func TestServer_StartAndStop(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	s.port = port
	go func() {
		_ = s.Start()
	}()
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	s.Stop()
}

func TestServer_Close(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	err := s.Close()
	require.NoError(t, err)
}

func TestServer_CloseWithPassphrase(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	s.caPassphrase = []byte("test123")
	err := s.Close()
	require.NoError(t, err)
}

// ------------------ NewServer с ошибками ------------------

func TestNewServer_InvalidDB(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{
		DBPath:  "/invalid/path/test.db",
		CertDir: t.TempDir(),
	}
	_, err := NewServer(config, log)
	require.Error(t, err)
}

func TestNewServer_InvalidPassphrase(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{
		DBPath:           ":memory:",
		CertDir:          t.TempDir(),
		CAPassphraseFile: "/nonexistent/pass",
	}
	_, err := NewServer(config, log)
	require.Error(t, err)
}

// ------------------ Интеграционный тест (полный цикл) ------------------

func TestServer_FullIntegration(t *testing.T) {
	s, db, cleanup := setupTestServer(t)
	defer cleanup()

	pemCert := "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=Test', 'CN=CA', '2024-01-01', '2025-01-01', ?, 'valid', '2024-01-01')`, pemCert)

	os.MkdirAll(filepath.Join(filepath.Dir(s.certDir), "crl"), 0755)
	os.WriteFile(filepath.Join(filepath.Dir(s.certDir), "crl", "root.crl.pem"), []byte("root-crl"), 0644)
	os.WriteFile(filepath.Join(s.certDir, "ca.cert.pem"), []byte("root-ca"), 0644)
	os.WriteFile(filepath.Join(s.certDir, "intermediate.cert.pem"), []byte("intermediate-ca"), 0644)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	s.port = port
	go s.Start()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	resp, err := client.Get(baseURL + "/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/certificate/ABCD")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/ca/root")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/ca/intermediate")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/crl?ca=root")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	resp, err = client.Post(baseURL+"/request-cert?template=server", "application/x-pem-file", bytes.NewReader(csrPEM))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	s.Stop()
}

func TestRepo_NewServer_BadDB(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{
		DBPath:  "/nonexistent/dir/test.db",
		CertDir: t.TempDir(),
	}
	_, err := NewServer(config, log)
	require.Error(t, err)
}

func TestHandleRequestCert_CAError(t *testing.T) {
	s, _, cleanup := setupTestServer(t)
	defer cleanup()
	// Удалим CA, чтобы handleRequestCert не смог его загрузить
	caPath := filepath.Join(filepath.Dir(s.certDir), "..", "pki-intermediate", "certs", "intermediate.cert.pem")
	os.Remove(caPath)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	req := httptest.NewRequest("POST", "/request-cert?template=server", bytes.NewReader(csrPEM))
	w := httptest.NewRecorder()
	s.handleRequestCert(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
