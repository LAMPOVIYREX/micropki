package ocsp

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"

	myCrypto "micropki/internal/crypto"
	"micropki/internal/database"
	"micropki/internal/logger"
	"micropki/internal/ratelimit"
)

// OCSPResponder handles OCSP requests
type OCSPResponder struct {
	db            *sql.DB
	caCert        *x509.Certificate
	responderCert *x509.Certificate
	responderKey  crypto.PrivateKey
	logger        *logger.Logger
	rateLimiter   *ratelimit.RateLimiter
	cacheTTL      int
}

// NewOCSPResponder creates a new OCSP responder
func NewOCSPResponder(dbPath, caCertPath, responderCertPath, responderKeyPath, passphraseFile string, cacheTTL int, log *logger.Logger, rateLimit, rateBurst int) (*OCSPResponder, error) {
	db, err := database.InitDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	caCert, err := loadCertificate(caCertPath)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	responderCert, err := loadCertificate(responderCertPath)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load responder certificate: %w", err)
	}

	responderKey, err := loadPrivateKey(responderKeyPath, passphraseFile)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load responder private key: %w", err)
	}

	var rl *ratelimit.RateLimiter
	if rateLimit > 0 {
		rl = ratelimit.NewRateLimiter(rateLimit, rateBurst)
	}
	return &OCSPResponder{
		db:            db,
		caCert:        caCert,
		responderCert: responderCert,
		responderKey:  responderKey,
		logger:        log,
		rateLimiter:   rl,
		cacheTTL:      cacheTTL,
	}, nil
}

func (r *OCSPResponder) Start(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.HandleOCSPRequest)

	var finalHandler http.Handler = mux
	if r.rateLimiter != nil {
		finalHandler = r.rateLimiter.Middleware(finalHandler)
	}

	r.logger.Info("Starting OCSP responder on %s", addr)
	return http.ListenAndServe(addr, finalHandler)
}

// HandleOCSPRequest processes OCSP requests
func (r *OCSPResponder) HandleOCSPRequest(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Content-Type") != "application/ocsp-request" {
		http.Error(w, "Invalid Content-Type", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		r.logger.Error("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Parse OCSP request (old API)
	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		r.logger.Error("Failed to parse OCSP request: %v", err)
		http.Error(w, "Invalid OCSP request", http.StatusBadRequest)
		return
	}

	// Проверка issuer hash
	expectedNameHash := sha1Hash(r.caCert.RawSubject)
	expectedKeyHash := sha1Hash(r.caCert.RawSubjectPublicKeyInfo)

	if !bytes.Equal(ocspReq.IssuerNameHash, expectedNameHash) || !bytes.Equal(ocspReq.IssuerKeyHash, expectedKeyHash) {
		r.logger.Info("Issuer hash mismatch - returning unknown")
		// Формируем ответ unknown
		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(time.Duration(r.cacheTTL) * time.Second),
			ProducedAt:   time.Now(),
		}
		signer, ok := r.responderKey.(crypto.Signer)
		if !ok {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		respBytes, err := ocsp.CreateResponse(r.responderCert, r.caCert, template, signer)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
		return
	}

	serial := ocspReq.SerialNumber
	serialHex := fmt.Sprintf("%X", serial)
	status, revokedAt, reasonCode := r.getCertificateStatus(serialHex)

	template := ocsp.Response{
		SerialNumber: serial,
		IssuerHash:   crypto.SHA1,
		ProducedAt:   time.Now(),
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Duration(r.cacheTTL) * time.Second),
	}

	switch status {
	case "good":
		template.Status = ocsp.Good
	case "revoked":
		template.Status = ocsp.Revoked
		template.RevokedAt = revokedAt
		template.RevocationReason = reasonCode
	default:
		template.Status = ocsp.Unknown
	}

	// Nonce не обрабатываем в старой версии

	signer, ok := r.responderKey.(crypto.Signer)
	if !ok {
		r.logger.Error("Responder key does not implement crypto.Signer")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	respBytes, err := ocsp.CreateResponse(r.responderCert, r.caCert, template, signer)
	if err != nil {
		r.logger.Error("Failed to create OCSP response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	r.logger.Info("OCSP request: serial=%s, status=%s, client=%s, time=%dms",
		serialHex, status, req.RemoteAddr, time.Since(startTime).Milliseconds())

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// sha1Hash возвращает SHA-1 хеш слайса байтов
func sha1Hash(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

// getCertificateStatus determines certificate status from database
func (r *OCSPResponder) getCertificateStatus(serialHex string) (status string, revocationTime time.Time, revocationReason int) {
	var certStatus string
	var reason sql.NullString
	var revDate sql.NullString

	err := r.db.QueryRow(
		"SELECT status, revocation_reason, revocation_date FROM certificates WHERE serial_hex = ?",
		serialHex,
	).Scan(&certStatus, &reason, &revDate)

	if err == sql.ErrNoRows {
		return "unknown", time.Time{}, 0
	}
	if err != nil {
		r.logger.Error("Database error for serial %s: %v", serialHex, err)
		return "unknown", time.Time{}, 0
	}

	switch certStatus {
	case "revoked":
		if revDate.Valid {
			revocationTime, _ = time.Parse(time.RFC3339, revDate.String)
		}
		reasonCode := 0
		if reason.Valid {
			reasonCode = getReasonCode(reason.String)
		}
		return "revoked", revocationTime, reasonCode
	case "valid":
		return "good", time.Time{}, 0
	default:
		return "unknown", time.Time{}, 0
	}
}

// loadCertificate loads certificate from PEM file
func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

// loadPrivateKey loads private key from PEM file
func loadPrivateKey(path, passphraseFile string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if x509.IsEncryptedPEMBlock(block) {
		if passphraseFile == "" {
			return nil, fmt.Errorf("encrypted key requires passphrase")
		}
		passphrase, err := myCrypto.LoadPassphraseFromFile(passphraseFile)
		if err != nil {
			return nil, err
		}
		defer myCrypto.SecureZero(passphrase)

		keyBytes, err := x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, err
		}

		return x509.ParsePKCS1PrivateKey(keyBytes)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// getReasonCode maps reason string to integer
func getReasonCode(reason string) int {
	codes := map[string]int{
		"unspecified":          0,
		"keyCompromise":        1,
		"cACompromise":         2,
		"affiliationChanged":   3,
		"superseded":           4,
		"cessationOfOperation": 5,
		"certificateHold":      6,
		"removeFromCRL":        8,
		"privilegeWithdrawn":   9,
		"aACompromise":         10,
	}
	if code, ok := codes[reason]; ok {
		return code
	}
	return 0
}

// Stop останавливает OCSP сервер
func (r *OCSPResponder) Stop() error {
	return nil
}

// Close закрывает соединение с базой данных
func (r *OCSPResponder) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}
