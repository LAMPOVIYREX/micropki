package ocsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"micropki/internal/database"
	"micropki/internal/logger"
)

// ------------------ Вспомогательные функции ------------------

func TestLoadCertificateOCSP(t *testing.T) {
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
	cert, err := loadCertificate(certPath)
	require.NoError(t, err)
	require.Equal(t, "test", cert.Subject.CommonName)
}

func TestLoadPrivateKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	tmpFile := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(tmpFile, keyPEM, 0600)
	priv, err := loadPrivateKey(tmpFile, "")
	require.NoError(t, err)
	require.NotNil(t, priv)
}

func TestLoadPrivateKey_Encrypted(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pass := []byte("secret")
	block, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), pass, x509.PEMCipherAES256)
	keyPEM := pem.EncodeToMemory(block)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(keyFile, keyPEM, 0600)
	passFile := filepath.Join(tmpDir, "pass.txt")
	os.WriteFile(passFile, pass, 0600)

	priv, err := loadPrivateKey(keyFile, passFile)
	require.NoError(t, err)
	require.NotNil(t, priv)
}

func TestGetReasonCode(t *testing.T) {
	require.Equal(t, 0, getReasonCode("unspecified"))
	require.Equal(t, 1, getReasonCode("keyCompromise"))
	require.Equal(t, 2, getReasonCode("cACompromise"))
	require.Equal(t, 3, getReasonCode("affiliationChanged"))
	require.Equal(t, 4, getReasonCode("superseded"))
	require.Equal(t, 5, getReasonCode("cessationOfOperation"))
	require.Equal(t, 6, getReasonCode("certificateHold"))
	require.Equal(t, 8, getReasonCode("removeFromCRL"))
	require.Equal(t, 9, getReasonCode("privilegeWithdrawn"))
	require.Equal(t, 10, getReasonCode("aACompromise"))
	require.Equal(t, 0, getReasonCode("unknown"))
}

// ------------------ Конструктор ------------------

func TestNewOCSPResponder_RealFiles(t *testing.T) {
	tmpDir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCertPath := filepath.Join(tmpDir, "ca.cert.pem")
	os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}), 0644)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caTmpl, &respKey.PublicKey, caKey)
	respCertPath := filepath.Join(tmpDir, "resp.cert.pem")
	os.WriteFile(respCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: respCertDER}), 0644)

	keyBytes := x509.MarshalPKCS1PrivateKey(respKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	respKeyPath := filepath.Join(tmpDir, "resp.key.pem")
	os.WriteFile(respKeyPath, keyPEM, 0600)

	log, _ := logger.NewLogger("")
	_, err := NewOCSPResponder(filepath.Join(tmpDir, "test.db"), caCertPath, respCertPath, respKeyPath, "", 60, log, 0, 0)
	require.NoError(t, err)
}

func TestNewOCSPResponder_MissingFiles(t *testing.T) {
	log, _ := logger.NewLogger("")
	_, err := NewOCSPResponder(":memory:", "/nonexistent.pem", "/nonexistent.pem", "/nonexistent.pem", "", 60, log, 0, 0)
	require.Error(t, err)
}

// ------------------ GetCertificateStatus ------------------

func TestGetCertificateStatus_Good(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	_, err := db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('3039', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)
	require.NoError(t, err)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
		logger:        log,
		cacheTTL:      60,
	}
	status, revTime, reason := responder.getCertificateStatus("3039")
	require.Equal(t, "good", status)
	require.Zero(t, revTime)
	require.Zero(t, reason)
}

func TestGetCertificateStatus_Revoked(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at) 
        VALUES ('FFFF', 'CN=revoked', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'revoked', 'keyCompromise', '2024-06-01T00:00:00Z', '2024-01-01')`)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
		logger:        log,
		cacheTTL:      60,
	}
	status, revTime, reason := responder.getCertificateStatus("FFFF")
	require.Equal(t, "revoked", status)
	require.Equal(t, 1, reason)
	require.NotZero(t, revTime)
}

func TestGetCertificateStatus_Unknown(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		logger:        log,
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
		cacheTTL:      60,
	}
	status, revTime, reason := responder.getCertificateStatus("BOGUS")
	require.Equal(t, "unknown", status)
	require.Zero(t, revTime)
	require.Zero(t, reason)
}

// ------------------ HandleOCSPRequest ------------------

func TestHandleOCSPRequest_MethodNotAllowed(t *testing.T) {
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{logger: log}
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleOCSPRequest_InvalidContentType(t *testing.T) {
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{logger: log}
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleOCSPRequest_EmptyBody(t *testing.T) {
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{logger: log}
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleOCSPRequest_BadBody(t *testing.T) {
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            &sql.DB{},
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
		logger:        log,
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{0x00}))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleOCSPRequest_NonSignerKey(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	badKey := &rsa.PublicKey{}
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  badKey,
		logger:        log,
		cacheTTL:      60,
	}
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(caCert, caCert, opts)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleOCSPRequest_IssuerHashMismatch(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('FFFF', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	otherCAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "OtherCA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	otherCACertDER, _ := x509.CreateCertificate(rand.Reader, otherCATmpl, otherCATmpl, &otherCAKey.PublicKey, otherCAKey)
	otherCACert, _ := x509.ParseCertificate(otherCACertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  respKey,
		logger:        log,
		cacheTTL:      60,
	}
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(otherCACert, otherCACert, opts)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleOCSPRequest_Good(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  respKey,
		logger:        log,
		cacheTTL:      60,
	}
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(caCert, caCert, opts)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleOCSPRequest_Revoked(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at) 
        VALUES ('BBBB', 'CN=revoked', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'revoked', 'keyCompromise', '2024-06-01T00:00:00Z', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  respKey,
		logger:        log,
		cacheTTL:      60,
	}
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(caCert, caCert, opts)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

// ------------------ Start / Stop ------------------

func TestOCSPResponder_StartStop(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	log, _ := logger.NewLogger("")
	r := &OCSPResponder{
		db:            db,
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
		responderKey: func() crypto.PrivateKey {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			return k
		}(),
		logger:   log,
		cacheTTL: 60,
	}
	go func() { _ = r.Start("127.0.0.1", 19997) }()
	time.Sleep(50 * time.Millisecond)
	err := r.Stop()
	require.NoError(t, err)
	err = r.Close()
	require.NoError(t, err)
}

func TestOCSPResponder_StartIntegration(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  respKey,
		logger:        log,
		cacheTTL:      60,
	}
	go func() { _ = responder.Start("127.0.0.1", 19999) }()
	time.Sleep(100 * time.Millisecond)

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(caCert, caCert, opts)
	resp, err := http.Post("http://127.0.0.1:19999/", "application/ocsp-request", bytes.NewReader(reqBytes))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	responder.Stop()
}

func TestOCSPResponder_FullIntegration(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	defer db.Close()
	db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) 
        VALUES ('ABCD', 'CN=test', 'CN=CA', '2024-01-01', '2025-01-01', 'pem', 'valid', '2024-01-01')`)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	respKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	respTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respCertDER, _ := x509.CreateCertificate(rand.Reader, respTmpl, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respCertDER)

	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: respCert,
		responderKey:  respKey,
		logger:        log,
		cacheTTL:      60,
	}
	go func() { _ = responder.Start("127.0.0.1", 19998) }()
	time.Sleep(50 * time.Millisecond)

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	reqBytes, _ := ocsp.CreateRequest(caCert, caCert, opts)
	resp, err := http.Post("http://127.0.0.1:19998/", "application/ocsp-request", bytes.NewReader(reqBytes))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NotEmpty(t, respBody)

	responder.Stop()
}

func TestOCSPResponder_CloseWithDB(t *testing.T) {
	db, _ := database.InitDB(":memory:")
	r := &OCSPResponder{db: db}
	err := r.Close()
	require.NoError(t, err)
}

func TestLoadPrivateKey_EncryptedWrongPass(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pass := []byte("correct")
	block, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), pass, x509.PEMCipherAES256)
	keyPEM := pem.EncodeToMemory(block)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(keyFile, keyPEM, 0600)

	// Передаём неверный пароль через файл
	wrongPassFile := filepath.Join(tmpDir, "wrongpass.txt")
	os.WriteFile(wrongPassFile, []byte("wrongpass"), 0600)

	_, err := loadPrivateKey(keyFile, wrongPassFile)
	require.Error(t, err)
}

func TestHandleOCSPRequest_InvalidBody(t *testing.T) {
	log, _ := logger.NewLogger("")
	responder := &OCSPResponder{
		logger:        log,
		caCert:        &x509.Certificate{},
		responderCert: &x509.Certificate{},
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{0x30, 0x01, 0x00}))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.HandleOCSPRequest(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOCSPResponder_Close_NilDB(t *testing.T) {
	r := &OCSPResponder{db: nil}
	err := r.Close()
	require.NoError(t, err)
}

func TestLoadCertificate_Error(t *testing.T) {
	_, err := loadCertificate("/nonexistent/cert.pem")
	require.Error(t, err)
}
func TestNewOCSPResponder_DBError(t *testing.T) {
	log, _ := logger.NewLogger("")
	// Передаём путь к БД в несуществующей директории — InitDB вернёт ошибку
	_, err := NewOCSPResponder("/nonexistent/path/test.db", "/nonexistent.pem", "/nonexistent.pem", "/nonexistent.pem", "", 60, log, 0, 0)
	require.Error(t, err)
}
