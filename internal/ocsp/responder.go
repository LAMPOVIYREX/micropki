package ocsp

import (
    "crypto"
    "crypto/x509"
    "database/sql"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
    
    "micropki/internal/database"
    "micropki/internal/logger"
    myCrypto "micropki/internal/crypto"
)

// OCSPResponder handles OCSP requests
type OCSPResponder struct {
    db             *sql.DB
    caCert         *x509.Certificate
    responderCert  *x509.Certificate
    responderKey   crypto.PrivateKey
    logger         *logger.Logger
}

// NewOCSPResponder creates a new OCSP responder
func NewOCSPResponder(dbPath, caCertPath, responderCertPath, responderKeyPath, passphraseFile string, cacheTTL int, log *logger.Logger) (*OCSPResponder, error) {
    // Open database
    db, err := database.InitDB(dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Load CA certificate
    caCert, err := loadCertificate(caCertPath)
    if err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to load CA certificate: %w", err)
    }
    
    // Load responder certificate
    responderCert, err := loadCertificate(responderCertPath)
    if err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to load responder certificate: %w", err)
    }
    
    // Load responder private key
    responderKey, err := loadPrivateKey(responderKeyPath, passphraseFile)
    if err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to load responder private key: %w", err)
    }
    
    return &OCSPResponder{
        db:            db,
        caCert:        caCert,
        responderCert: responderCert,
        responderKey:  responderKey,
        logger:        log,
    }, nil
}

// Close closes database connection
func (r *OCSPResponder) Close() error {
    return r.db.Close()
}

// HandleOCSPRequest processes OCSP requests
// HandleOCSPRequest processes OCSP requests
func (r *OCSPResponder) HandleOCSPRequest(w http.ResponseWriter, req *http.Request) {
    startTime := time.Now()
    
    var serialHex string
    
    // Handle GET requests with query parameter
    if req.Method == http.MethodGet {
        serialHex = req.URL.Query().Get("serial")
        if serialHex == "" {
            serialHex = req.URL.Query().Get("serialNumber")
        }
    } else if req.Method == http.MethodPost {
        // Read request body
        body, err := io.ReadAll(req.Body)
        if err != nil {
            r.logger.Error("Failed to read request body: %v", err)
            http.Error(w, "Failed to read request", http.StatusBadRequest)
            return
        }
        serialHex = extractSerialFromRequest(body)
    } else {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Get certificate status
    status, _, _ := r.getCertificateStatus(serialHex)
    
    r.logger.Info("OCSP request: serial=%s, status=%s, client=%s, time=%dms",
        serialHex, status, req.RemoteAddr, time.Since(startTime).Milliseconds())
    
    // Return simple response
    w.Header().Set("Content-Type", "application/ocsp-response")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(fmt.Sprintf("OCSP Response: %s", status)))
}

// extractSerialFromRequest extracts serial number from OCSP request (simplified)
func extractSerialFromRequest(body []byte) string {
    // Try to parse as form data
    bodyStr := string(body)
    
    // Check for serial= parameter
    if len(bodyStr) > 7 && bodyStr[:7] == "serial=" {
        return bodyStr[7:]
    }
    
    // Check for JSON format
    if len(bodyStr) > 0 && bodyStr[0] == '{' {
        // Simple JSON parsing
        var data map[string]interface{}
        if err := json.Unmarshal(body, &data); err == nil {
            if serial, ok := data["serial"].(string); ok {
                return serial
            }
        }
    }
    
    // If body looks like hex, assume it's the serial
    if len(bodyStr) > 0 {
        // Check if it's a valid hex string
        valid := true
        for _, c := range bodyStr {
            if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                valid = false
                break
            }
        }
        if valid && len(bodyStr) >= 8 {
            return bodyStr
        }
    }
    
    return "unknown"
}

// getCertificateStatus determines certificate status from database
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
    
    // Check if encrypted
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
    
    // Unencrypted
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// getReasonCode maps reason string to integer
func getReasonCode(reason string) int {
    codes := map[string]int{
        "unspecified":         0,
        "keyCompromise":       1,
        "cACompromise":        2,
        "affiliationChanged":  3,
        "superseded":          4,
        "cessationOfOperation":5,
        "certificateHold":     6,
        "removeFromCRL":       8,
        "privilegeWithdrawn":  9,
        "aACompromise":       10,
    }
    if code, ok := codes[reason]; ok {
        return code
    }
    return 0
}