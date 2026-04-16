package repository

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    
    "micropki/internal/database"
    "micropki/internal/logger"
)

type Server struct {
    db       *sql.DB
    certDir  string
    host     string
    port     int
    logger   *logger.Logger
    httpSrv  *http.Server
}

type ServerConfig struct {
    DBPath   string
    CertDir  string
    Host     string
    Port     int
    LogFile  string
}

func NewServer(config *ServerConfig, log *logger.Logger) (*Server, error) {
    // Initialize database
    db, err := database.InitDB(config.DBPath)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize database: %w", err)
    }
    
    return &Server{
        db:      db,
        certDir: config.CertDir,
        host:    config.Host,
        port:    config.Port,
        logger:  log,
    }, nil
}

func (s *Server) Start() error {
    addr := fmt.Sprintf("%s:%d", s.host, s.port)
    
    mux := http.NewServeMux()
    mux.HandleFunc("/certificate/", s.handleGetCertificate)
    mux.HandleFunc("/ca/", s.handleGetCA)
    mux.HandleFunc("/crl", s.handleGetCRL)
    mux.HandleFunc("/health", s.handleHealth)
    
    s.httpSrv = &http.Server{
        Addr:    addr,
        Handler: s.loggingMiddleware(mux),
    }
    
    s.logger.Info("Starting repository server on %s", addr)
    s.logger.Info("Database path: %s", s.db)
    s.logger.Info("Certificate directory: %s", s.certDir)
    
    return s.httpSrv.ListenAndServe()
}

func (s *Server) Stop() error {
    if s.httpSrv != nil {
        return s.httpSrv.Close()
    }
    return nil
}

func (s *Server) Close() error {
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}

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