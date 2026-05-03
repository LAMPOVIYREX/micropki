package repository

import (
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/x509"
    "strings"
    "database/sql"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "time"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "math/big"

    "micropki/internal/audit"
    "micropki/internal/database"
    "micropki/internal/logger"
    "micropki/internal/policy"
    myCrypto "micropki/internal/crypto"
    "micropki/internal/ratelimit"
    "micropki/internal/transparency"
)

type ServerConfig struct {
    DBPath     string
    CertDir    string
    Host       string
    Port       int
    LogFile    string
    RateLimit  int
    RateBurst  int
    CAPassphraseFile string
}

type Server struct {
    db          *sql.DB
    certDir     string
    host        string
    port        int
    logger      *logger.Logger
    httpSrv     *http.Server
    rateLimiter *ratelimit.RateLimiter
    caPassphrase []byte
}

func NewServer(config *ServerConfig, log *logger.Logger) (*Server, error) {
    db, err := database.InitDB(config.DBPath)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize database: %w", err)
    }

    var rl *ratelimit.RateLimiter
    if config.RateLimit > 0 {
        rl = ratelimit.NewRateLimiter(config.RateLimit, config.RateBurst)
    }

    // Загружаем пароль для Intermediate CA (если указан)
    var caPassphrase []byte
    if config.CAPassphraseFile != "" {
        pass, err := myCrypto.LoadPassphraseFromFile(config.CAPassphraseFile)
        if err != nil {
            db.Close()
            return nil, fmt.Errorf("failed to load CA passphrase: %w", err)
        }
        caPassphrase = pass
    }

    return &Server{
        db:           db,
        certDir:      config.CertDir,
        host:         config.Host,
        port:         config.Port,
        logger:       log,
        rateLimiter:  rl,
        caPassphrase: caPassphrase,
    }, nil
}

func (s *Server) Start() error {
    addr := fmt.Sprintf("%s:%d", s.host, s.port)
    mux := http.NewServeMux()
    mux.HandleFunc("/certificate/", s.handleGetCertificate)
    mux.HandleFunc("/ca/", s.handleGetCA)
    mux.HandleFunc("/crl", s.handleGetCRL)
    mux.HandleFunc("/health", s.handleHealth)
    mux.HandleFunc("/request-cert", s.handleRequestCert)

    // Создание директории для аудита, если её нет
    auditDir := filepath.Dir(filepath.Dir(s.certDir)) + "/audit"
    if err := os.MkdirAll(auditDir, 0700); err != nil {
        s.logger.Warning("Failed to create audit directory: %v", err)
    }

    handler := s.loggingMiddleware(mux)
    if s.rateLimiter != nil {
        handler = s.rateLimiter.Middleware(handler)
    }

    s.httpSrv = &http.Server{Addr: addr, Handler: handler}
    s.logger.Info("Starting repository server on %s", addr)
    return s.httpSrv.ListenAndServe()
}

func (s *Server) handleRequestCert(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request", http.StatusBadRequest)
        return
    }

    templateName := r.URL.Query().Get("template")
    if templateName == "" {
        templateName = "server"
    }

    // Парсинг CSR
    block, _ := pem.Decode(body)
    if block == nil || block.Type != "CERTIFICATE REQUEST" {
        http.Error(w, "Invalid CSR format", http.StatusBadRequest)
        return
    }

    csr, err := x509.ParseCertificateRequest(block.Bytes)
    if err != nil {
        http.Error(w, "Failed to parse CSR", http.StatusBadRequest)
        return
    }

    if err := csr.CheckSignature(); err != nil {
        http.Error(w, "Invalid CSR signature", http.StatusBadRequest)
        return
    }

    // === Policy checks ===
    keyAlgo := "rsa"
    keySize := 0
    if pub := csr.PublicKey; pub != nil {
        switch k := pub.(type) {
        case *rsa.PublicKey:
            keyAlgo = "rsa"
            keySize = k.Size() * 8
        case *ecdsa.PublicKey:
            keyAlgo = "ecc"
            keySize = k.Curve.Params().BitSize
        }
    }

    var certType policy.CertificateType
    switch templateName {
    case "server":
        certType = policy.Server
    case "client":
        certType = policy.Client
    case "code_signing":
        certType = policy.CodeSigning
    default:
        certType = policy.Server
    }

    validityDays := 365
    if v := r.URL.Query().Get("validity_days"); v != "" {
        fmt.Sscanf(v, "%d", &validityDays)
    }

    if err := policy.ValidateKeySize(certType, keySize, keyAlgo); err != nil {
        s.logger.Error("Policy violation: %v", err)
        http.Error(w, fmt.Sprintf("Policy violation: %v", err), http.StatusBadRequest)
        return
    }
    if err := policy.ValidateValidity(certType, validityDays); err != nil {
        s.logger.Error("Policy violation: %v", err)
        http.Error(w, fmt.Sprintf("Policy violation: %v", err), http.StatusBadRequest)
        return
    }

    // Извлекаем DNS имена
    var sans []string
    for _, dns := range csr.DNSNames {
        sans = append(sans, "dns:"+dns)
    }
    if err := policy.ValidateSAN(certType, sans); err != nil {
        s.logger.Error("SAN policy violation: %v", err)
        http.Error(w, fmt.Sprintf("SAN policy violation: %v", err), http.StatusBadRequest)
        return
    }

    // Проверка компрометации ключа
    pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
    if err == nil {
        hash := sha256.Sum256(pubDER)
        pubKeyHash := hex.EncodeToString(hash[:])
        compromised, _ := database.IsKeyCompromised(s.db, pubKeyHash)
        if compromised {
            s.logger.Error("Public key is compromised")
            http.Error(w, "Public key is compromised, issuance rejected", http.StatusForbidden)
            return
        }
    }

    // Загрузка CA сертификата и ключа
    caCertPath := filepath.Join(s.certDir, "..", "..", "pki-intermediate", "certs", "intermediate.cert.pem")
    caKeyPath := filepath.Join(s.certDir, "..", "..", "pki-intermediate", "private", "intermediate.key.pem")
    caCert, err := loadCertFile(caCertPath)
    if err != nil {
        s.logger.Error("Failed to load CA cert: %v", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }

    // Загрузка закрытого ключа CA с использованием пароля
    caKey, err := myCrypto.LoadAndDecryptPrivateKey(caKeyPath, s.caPassphrase)
    if err != nil {
        s.logger.Error("Failed to load CA private key: %v", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }

    // Генерация серийного номера
    serialBytes := make([]byte, 20)
    _, err = rand.Read(serialBytes)
    if err != nil {
        s.logger.Error("Failed to generate serial: %v", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }
    serialNumber := new(big.Int).SetBytes(serialBytes)

    // Создание сертификата
    certTemplate := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject:      csr.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(0, 0, validityDays),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames:     csr.DNSNames,
    }

    certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caKey)
    if err != nil {
        s.logger.Error("Failed to sign certificate: %v", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }

    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
    serialHex := fmt.Sprintf("%X", serialNumber)

    // Сохранение в БД
    _, err = s.db.Exec(`INSERT INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        serialHex, csr.Subject.String(), caCert.Subject.String(),
        certTemplate.NotBefore.Format(time.RFC3339), certTemplate.NotAfter.Format(time.RFC3339),
        string(certPEM), "valid", time.Now().Format(time.RFC3339))
    if err != nil {
        s.logger.Warning("Failed to insert certificate into DB: %v", err)
    }

    // Аудит и CT log
    outDir := filepath.Dir(filepath.Dir(s.certDir))
    if auditLogger, err := audit.NewAuditLogger(outDir); err == nil {
        _ = auditLogger.Log("AUDIT", "issue_certificate", "success", "Certificate issued from CSR", map[string]interface{}{
            "serial":   serialHex,
            "subject":  csr.Subject.String(),
            "template": templateName,
            "client_ip": r.RemoteAddr,
        })
        auditLogger.Close()
    }
    if ctLog, err := transparency.NewCTLog(outDir); err == nil {
        _ = ctLog.Append(serialHex, csr.Subject.String(), "")
        ctLog.Close()
    }

    // Отправка ответа
    w.Header().Set("Content-Type", "application/x-pem-file")
    w.WriteHeader(http.StatusCreated)
    w.Write(certPEM)
}

// остальные методы (handleGetCertificate, handleGetCA, handleGetCRL, handleHealth, loggingMiddleware) остаются без изменений.

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Extract serial from path: /certificate/{serial}
    serial := strings.TrimPrefix(r.URL.Path, "/certificate/")
    if serial == "" {
        http.Error(w, "Serial number required", http.StatusBadRequest)
        return
    }
    
    // Validate hex format
    for _, c := range serial {
        if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
            http.Error(w, "Invalid serial number format (hex expected)", http.StatusBadRequest)
            return
        }
    }
    
    record, err := database.GetCertificateBySerial(s.db, strings.ToUpper(serial))
    if err != nil {
        s.logger.Error("Database error: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    if record == nil {
        http.Error(w, "Certificate not found", http.StatusNotFound)
        return
    }
    
    w.Header().Set("Content-Type", "application/x-pem-file")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(record.CertPEM))
}

func (s *Server) handleGetCA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Extract level from path: /ca/{level}
    level := strings.TrimPrefix(r.URL.Path, "/ca/")
    if level == "" {
        http.Error(w, "CA level required (root or intermediate)", http.StatusBadRequest)
        return
    }
    
    var certFile string
    switch level {
    case "root":
        certFile = filepath.Join(s.certDir, "ca.cert.pem")
    case "intermediate":
        certFile = filepath.Join(s.certDir, "intermediate.cert.pem")
    default:
        http.Error(w, "Invalid CA level. Use 'root' or 'intermediate'", http.StatusBadRequest)
        return
    }
    
    certPEM, err := os.ReadFile(certFile)
    if err != nil {
        http.Error(w, "CA certificate not found", http.StatusNotFound)
        return
    }
    
    w.Header().Set("Content-Type", "application/x-pem-file")
    w.WriteHeader(http.StatusOK)
    w.Write(certPEM)
}

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Parse query parameter
    caType := r.URL.Query().Get("ca")
    if caType == "" {
        caType = "intermediate" // Default to intermediate
    }
    
    var crlPath string
    switch caType {
    case "root":
        crlPath = filepath.Join(s.certDir, "..", "crl", "root.crl.pem")
    case "intermediate":
        crlPath = filepath.Join(s.certDir, "..", "crl", "intermediate.crl.pem")
    default:
        http.Error(w, "Invalid CA type. Use 'root' or 'intermediate'", http.StatusBadRequest)
        return
    }
    
    // Check if CRL file exists
    crlData, err := os.ReadFile(crlPath)
    if err != nil {
        http.Error(w, "CRL not found", http.StatusNotFound)
        return
    }
    
    w.Header().Set("Content-Type", "application/pkix-crl")
    w.Header().Set("Cache-Control", "max-age=3600")
    w.WriteHeader(http.StatusOK)
    w.Write(crlData)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        s.logger.Info("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
        next.ServeHTTP(w, r)
    })
}

func loadCertFile(path string) (*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM")
    }
    return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKeyFile(path, passphrase string) (interface{}, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM")
    }
    // Для простоты предполагаем, что ключ не зашифрован
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Stop останавливает HTTP сервер
func (s *Server) Stop() error {
    if s.httpSrv != nil {
        return s.httpSrv.Close()
    }
    return nil
}

// Close закрывает соединение с базой данных
func (s *Server) Close() error {
    if s.caPassphrase != nil {
        myCrypto.SecureZero(s.caPassphrase)
    }
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}