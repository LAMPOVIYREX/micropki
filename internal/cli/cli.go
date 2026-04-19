package cli

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "math/big"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "syscall"
    "time"
    
    "github.com/spf13/cobra"
    "micropki/internal/ca"
    "micropki/internal/certs"
    "micropki/internal/client"
    "micropki/internal/crl"
    myCrypto "micropki/internal/crypto"
    "micropki/internal/database"
    "micropki/internal/logger"
    "micropki/internal/ocsp"
    "micropki/internal/repository"
    "micropki/internal/revocation"
    "micropki/internal/validation"
    "micropki/pkg/types"
)

var (
    // Root CA flags
    subject        string
    keyType        string
    keySize        int
    passphraseFile string
    outDir         string
    validityDays   int
    logFile        string
    force          bool
    certPath       string
    
    // Intermediate CA flags
    intermediateSubject   string
    intermediateKeyType   string
    intermediateKeySize   int
    intermediateOutDir    string
    intermediateValidity  int
    rootCADir             string
    rootCAPassphraseFile  string
    maxPathLen            int
)

func NewRootCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "micropki",
        Short: "MicroPKI - A minimal Public Key Infrastructure",
        Long:  `A lightweight PKI implementation for educational purposes.`,
    }
    
    cmd.AddCommand(newCACmd())
    cmd.AddCommand(newVerifyCmd())
    cmd.AddCommand(newCertCmd())
    cmd.AddCommand(newDBCmd())    
    cmd.AddCommand(newRepoCmd()) 
    cmd.AddCommand(newOCSPCmd())
    cmd.AddCommand(newClientCmd()) 
    
    return cmd
}

// ==================== CA COMMANDS ====================

func newCACmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "ca",
        Short: "Certificate Authority operations",
    }
    
    cmd.AddCommand(newCAInitCmd())
    cmd.AddCommand(newCAInitIntermediateCmd())
    cmd.AddCommand(newCARevokeCmd())      
    cmd.AddCommand(newCAGenCRLCmd()) 
    cmd.AddCommand(newCAIssueOCSPCertCmd())
    
    return cmd
}

func newCAInitCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "init",
        Short: "Initialize a new Root CA",
        Long:  `Create a self-signed Root CA certificate and encrypted private key.`,
        RunE:  runCAInit,
    }
    
    cmd.Flags().StringVar(&subject, "subject", "", "Distinguished Name")
    cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type: rsa or ecc")
    cmd.Flags().IntVar(&keySize, "key-size", 4096, "Key size (4096 for RSA, 384 for ECC)")
    cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Path to passphrase file")
    cmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Output directory")
    cmd.Flags().IntVar(&validityDays, "validity-days", 3650, "Validity period in days")
    cmd.Flags().StringVar(&logFile, "log-file", "", "Log file path")
    cmd.Flags().BoolVar(&force, "force", false, "Force overwrite")
    
    cmd.MarkFlagRequired("subject")
    cmd.MarkFlagRequired("passphrase-file")
    
    return cmd
}

func newCAInitIntermediateCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "init-intermediate",
        Short: "Initialize a new Intermediate CA",
        Long:  `Create an Intermediate CA certificate signed by the Root CA.`,
        RunE:  runCAInitIntermediate,
    }
    
    cmd.Flags().StringVar(&intermediateSubject, "subject", "", "Distinguished Name")
    cmd.Flags().StringVar(&intermediateKeyType, "key-type", "rsa", "Key type: rsa or ecc")
    cmd.Flags().IntVar(&intermediateKeySize, "key-size", 4096, "Key size")
    cmd.Flags().StringVar(&intermediateOutDir, "out-dir", "./intermediate-pki", "Output directory")
    cmd.Flags().IntVar(&intermediateValidity, "validity-days", 1825, "Validity period")
    cmd.Flags().StringVar(&rootCADir, "root-ca-dir", "./pki", "Root CA directory")
    cmd.Flags().StringVar(&rootCAPassphraseFile, "root-passphrase-file", "", "Root CA passphrase")
    cmd.Flags().IntVar(&maxPathLen, "max-path-len", 0, "Max path length")
    cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Intermediate CA passphrase")
    
    cmd.MarkFlagRequired("subject")
    cmd.MarkFlagRequired("passphrase-file")
    cmd.MarkFlagRequired("root-passphrase-file")
    
    return cmd
}

func newVerifyCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "verify",
        Short: "Verify a certificate",
        RunE:  runVerify,
    }
    
    cmd.Flags().StringVar(&certPath, "cert", "", "Path to certificate")
    cmd.MarkFlagRequired("cert")
    
    return cmd
}

// ==================== CERT COMMANDS ====================

func newCertCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "cert",
        Short: "Certificate operations",
    }
    
    cmd.AddCommand(newCertIssueCmd())
    
    return cmd
}

func newCertIssueCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "issue",
        Short: "Issue a new certificate",
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Println("Certificate issuance will be implemented in Sprint 3")
            return nil
        },
    }
    
    cmd.Flags().StringVar(&subject, "subject", "", "Certificate subject")
    cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type")
    cmd.MarkFlagRequired("subject")
    
    return cmd
}

// ==================== DATABASE COMMANDS ====================

func newDBCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "db",
        Short: "Database operations",
    }
    
    cmd.AddCommand(newDBInitCmd())
    cmd.AddCommand(newDBListCertsCmd())
    cmd.AddCommand(newDBShowCertCmd())
    
    return cmd
}

func newDBInitCmd() *cobra.Command {
    var dbPath string
    
    cmd := &cobra.Command{
        Use:   "init",
        Short: "Initialize certificate database",
        RunE: func(cmd *cobra.Command, args []string) error {
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            log.Info("Initializing database at %s", dbPath)
            
            _, err = database.InitDB(dbPath)
            if err != nil {
                log.Error("Failed to initialize database: %v", err)
                return err
            }
            
            fmt.Printf("Database successfully initialized at %s\n", dbPath)
            return nil
        },
    }
    
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Path to SQLite database")
    return cmd
}

func newDBListCertsCmd() *cobra.Command {
    var dbPath string
    var status string
    var format string
    
    cmd := &cobra.Command{
        Use:   "list",
        Short: "List certificates in database",
        RunE: func(cmd *cobra.Command, args []string) error {
            db, err := database.InitDB(dbPath)
            if err != nil {
                return fmt.Errorf("failed to open database: %w", err)
            }
            defer db.Close()
            
            records, err := database.ListCertificates(db, status, 100)
            if err != nil {
                return err
            }
            
            if format == "json" {
                output := make([]map[string]interface{}, len(records))
                for i, r := range records {
                    output[i] = map[string]interface{}{
                        "serial":   r.SerialHex,
                        "subject":  r.Subject,
                        "issuer":   r.Issuer,
                        "status":   r.Status,
                        "not_before": r.NotBefore,
                        "not_after":  r.NotAfter,
                    }
                }
                data, _ := json.MarshalIndent(output, "", "  ")
                fmt.Println(string(data))
            } else {
                fmt.Printf("\n%-40s | %-40s | %-12s\n", "SERIAL", "SUBJECT", "STATUS")
                fmt.Println(strings.Repeat("-", 100))
                for _, r := range records {
                    serial := r.SerialHex
                    if len(serial) > 40 {
                        serial = serial[:37] + "..."
                    }
                    subject := r.Subject
                    if len(subject) > 40 {
                        subject = subject[:37] + "..."
                    }
                    fmt.Printf("%-40s | %-40s | %-12s\n", serial, subject, r.Status)
                }
                fmt.Printf("\nTotal: %d certificates\n", len(records))
            }
            return nil
        },
    }
    
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Database path")
    cmd.Flags().StringVar(&status, "status", "", "Filter by status")
    cmd.Flags().StringVar(&format, "format", "table", "Output format (table, json)")
    return cmd
}

func newDBShowCertCmd() *cobra.Command {
    var dbPath string
    
    cmd := &cobra.Command{
        Use:   "show <serial>",
        Short: "Show certificate by serial number",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            serialHex := strings.ToUpper(args[0])
            
            db, err := database.InitDB(dbPath)
            if err != nil {
                return fmt.Errorf("failed to open database: %w", err)
            }
            defer db.Close()
            
            record, err := database.GetCertificateBySerial(db, serialHex)
            if err != nil {
                return err
            }
            
            if record == nil {
                return fmt.Errorf("certificate with serial %s not found", serialHex)
            }
            
            fmt.Print(record.CertPEM)
            return nil
        },
    }
    
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Database path")
    return cmd
}

// ==================== REPOSITORY COMMANDS ====================

func newRepoCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "repo",
        Short: "Repository operations",
    }
    
    cmd.AddCommand(newRepoServeCmd())
    
    return cmd
}

func newRepoServeCmd() *cobra.Command {
    var (
        repoHost    string
        repoPort    int
        repoDBPath  string
        repoCertDir string
    )
    
    cmd := &cobra.Command{
        Use:   "serve",
        Short: "Start repository HTTP server",
        RunE: func(cmd *cobra.Command, args []string) error {
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            config := &repository.ServerConfig{
                DBPath:  repoDBPath,
                CertDir: repoCertDir,
                Host:    repoHost,
                Port:    repoPort,
                LogFile: logFile,
            }
            
            server, err := repository.NewServer(config, log)
            if err != nil {
                return fmt.Errorf("failed to create server: %w", err)
            }
            defer server.Close()
            
            sigChan := make(chan os.Signal, 1)
            signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
            
            go func() {
                <-sigChan
                log.Info("Shutting down server...")
                server.Stop()
            }()
            
            return server.Start()
        },
    }
    
    cmd.Flags().StringVar(&repoHost, "host", "127.0.0.1", "Bind address")
    cmd.Flags().IntVar(&repoPort, "port", 8080, "TCP port")
    cmd.Flags().StringVar(&repoDBPath, "db-path", "./pki/micropki.db", "Database path")
    cmd.Flags().StringVar(&repoCertDir, "cert-dir", "./pki/certs", "Certificate directory")
    
    return cmd
}

// ==================== RUN FUNCTIONS ====================

func runCAInit(cmd *cobra.Command, args []string) error {
    if err := validateInputs(); err != nil {
        return err
    }
    
    log, err := logger.NewLogger(logFile)
    if err != nil {
        return fmt.Errorf("failed to initialize logger: %w", err)
    }
    defer log.Close()
    
    if err := checkOutputDirectory(outDir, force, log); err != nil {
        return err
    }
    
    passphrase, err := myCrypto.LoadPassphraseFromFile(passphraseFile)
    if err != nil {
        return err
    }
    defer myCrypto.SecureZero(passphrase)
    
    if err := myCrypto.ValidatePassphrase(passphrase); err != nil {
        return fmt.Errorf("weak passphrase: %w", err)
    }
    
    config := &types.CAConfig{
        Subject:      subject,
        KeyType:      keyType,
        KeySize:      keySize,
        Passphrase:   passphrase,
        OutDir:       outDir,
        ValidityDays: validityDays,
        LogFile:      logFile,
    }
    
    caInstance := ca.NewCA(config, log)
    
    _, err = caInstance.InitRootCA()
    if err != nil {
        return err
    }
    
    fmt.Printf("Root CA successfully initialized in %s\n", outDir)
    return nil
}

func runCAInitIntermediate(cmd *cobra.Command, args []string) error {
    if intermediateSubject == "" {
        return fmt.Errorf("subject cannot be empty")
    }
    
    log, err := logger.NewLogger(logFile)
    if err != nil {
        return fmt.Errorf("failed to initialize logger: %w", err)
    }
    defer log.Close()
    
    passphrase, err := myCrypto.LoadPassphraseFromFile(passphraseFile)
    if err != nil {
        return err
    }
    defer myCrypto.SecureZero(passphrase)
    
    rootPassphrase, err := myCrypto.LoadPassphraseFromFile(rootCAPassphraseFile)
    if err != nil {
        return err
    }
    defer myCrypto.SecureZero(rootPassphrase)
    
    config := &ca.IntermediateCAConfig{
        Subject:          intermediateSubject,
        KeyType:          intermediateKeyType,
        KeySize:          intermediateKeySize,
        Passphrase:       passphrase,
        OutDir:           intermediateOutDir,
        ValidityDays:     intermediateValidity,
        RootCAPassphrase: rootPassphrase,
        RootCADir:        rootCADir,
        MaxPathLen:       maxPathLen,
    }
    
    caInstance := ca.NewCA(&types.CAConfig{
        Subject: intermediateSubject,
        KeyType: intermediateKeyType,
        KeySize: intermediateKeySize,
        OutDir:  intermediateOutDir,
    }, log)
    
    files, err := caInstance.InitIntermediateCA(config)
    if err != nil {
        return err
    }
    
    fmt.Printf("Intermediate CA successfully initialized in %s\n", intermediateOutDir)
    fmt.Printf("Private key: %s\n", files.PrivateKeyPath)
    fmt.Printf("Certificate: %s\n", files.CertPath)
    
    return nil
}

func runVerify(cmd *cobra.Command, args []string) error {
    fmt.Printf("Verifying certificate: %s\n", certPath)
    return nil
}

func validateInputs() error {
    if subject == "" {
        return fmt.Errorf("subject cannot be empty")
    }
    if keyType != "rsa" && keyType != "ecc" {
        return fmt.Errorf("key-type must be 'rsa' or 'ecc'")
    }
    if keyType == "rsa" && keySize != 4096 {
        return fmt.Errorf("RSA key size must be 4096")
    }
    if keyType == "ecc" && keySize != 384 {
        return fmt.Errorf("ECC key size must be 384")
    }
    return nil
}

func checkOutputDirectory(dir string, force bool, log *logger.Logger) error {
    keyPath := filepath.Join(dir, "private", "ca.key.pem")
    certPath := filepath.Join(dir, "certs", "ca.cert.pem")
    policyPath := filepath.Join(dir, "policy.txt")
    
    var existingFiles []string
    if fileExists(keyPath) {
        existingFiles = append(existingFiles, keyPath)
    }
    if fileExists(certPath) {
        existingFiles = append(existingFiles, certPath)
    }
    if fileExists(policyPath) {
        existingFiles = append(existingFiles, policyPath)
    }
    
    if len(existingFiles) > 0 && !force {
        log.Warning("The following files already exist:")
        for _, f := range existingFiles {
            log.Warning("  - %s", f)
        }
        
        fmt.Print("Do you want to overwrite them? [y/N]: ")
        var response string
        fmt.Scanln(&response)
        
        if response != "y" && response != "Y" && response != "yes" {
            return fmt.Errorf("operation cancelled by user")
        }
    }
    
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("cannot create directory: %w", err)
    }
    
    return nil
}

// ==================== REVOCATION COMMANDS ====================

func newCARevokeCmd() *cobra.Command {
    var reason string
    var force bool
    var dbPath string
    
    cmd := &cobra.Command{
        Use:   "revoke <serial>",
        Short: "Revoke a certificate",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            serialHex := strings.ToUpper(args[0])
            
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            // Validate reason
            if _, ok := crl.ReasonCodeMap[reason]; !ok {
                return fmt.Errorf("invalid reason: %s", reason)
            }
            
            if !force {
                fmt.Printf("Are you sure you want to revoke certificate %s? [y/N]: ", serialHex)
                var response string
                fmt.Scanln(&response)
                if response != "y" && response != "Y" && response != "yes" {
                    return fmt.Errorf("revocation cancelled")
                }
            }
            
            // Open database
            db, err := database.InitDB(dbPath)
            if err != nil {
                return fmt.Errorf("failed to open database: %w", err)
            }
            defer db.Close()
            
            // Revoke certificate
            if err := crl.RevokeCertificate(db, serialHex, reason); err != nil {
                log.Error("Revocation failed: %v", err)
                return err
            }
            
            log.Info("Certificate %s revoked with reason: %s", serialHex, reason)
            fmt.Printf("Certificate %s successfully revoked\n", serialHex)
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&reason, "reason", "unspecified", "Revocation reason")
    cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation")
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Database path")
    
    return cmd
}

func newCAGenCRLCmd() *cobra.Command {
    var caType string
    var nextUpdateDays int
    var outFile string
    var dbPath string
    var caDir string
    
    cmd := &cobra.Command{
        Use:   "gen-crl",
        Short: "Generate Certificate Revocation List",
        RunE: func(cmd *cobra.Command, args []string) error {
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            if caType != "root" && caType != "intermediate" {
                return fmt.Errorf("ca must be 'root' or 'intermediate'")
            }
            
            // Determine paths
            var caCertPath, caKeyPath, crlPath string
            
            if caType == "root" {
                caCertPath = filepath.Join(caDir, "certs", "ca.cert.pem")
                caKeyPath = filepath.Join(caDir, "private", "ca.key.pem")
                if outFile == "" {
                    crlPath = filepath.Join(caDir, "crl", "root.crl.pem")
                }
            } else {
                caCertPath = filepath.Join(caDir, "certs", "intermediate.cert.pem")
                caKeyPath = filepath.Join(caDir, "private", "intermediate.key.pem")
                if outFile == "" {
                    crlPath = filepath.Join(caDir, "crl", "intermediate.crl.pem")
                }
            }
            
            if outFile != "" {
                crlPath = outFile
            }
            
            // Load CA certificate
            caCert, err := loadCertificate(caCertPath)
            if err != nil {
                return fmt.Errorf("failed to load CA certificate: %w", err)
            }
            
            // Load CA private key
            passphrase, err := myCrypto.LoadPassphraseFromFile(passphraseFile)
            if err != nil {
                return fmt.Errorf("failed to load passphrase: %w", err)
            }
            defer myCrypto.SecureZero(passphrase)
            
            caKey, err := myCrypto.LoadAndDecryptPrivateKey(caKeyPath, passphrase)
            if err != nil {
                return fmt.Errorf("failed to load CA private key: %w", err)
            }
            
            // Open database
            db, err := database.InitDB(dbPath)
            if err != nil {
                return fmt.Errorf("failed to open database: %w", err)
            }
            defer db.Close()
            
            // Get revoked certificates
            revokedCerts, err := crl.GetRevokedCertificates(db, caCert.Subject.String())
            if err != nil {
                return fmt.Errorf("failed to get revoked certificates: %w", err)
            }
            
            // Get CRL number (simple approach - use timestamp)
            crlNumber := time.Now().Unix()
            
            // Generate CRL
            config := &crl.CRLConfig{
                CAIssuer:     caCert,
                CAPrivateKey: caKey,
                Number:       crlNumber,
                ThisUpdate:   time.Now().UTC(),
                NextUpdate:   time.Now().UTC().AddDate(0, 0, nextUpdateDays),
                RevokedCerts: revokedCerts,
                OutPath:      crlPath,
            }
            
            crlBytes, err := crl.GenerateCRL(config)
            if err != nil {
                log.Error("Failed to generate CRL: %v", err)
                return err
            }
            
            // Save CRL
            if err := crl.SaveCRL(crlBytes, crlPath); err != nil {
                return fmt.Errorf("failed to save CRL: %w", err)
            }
            
            log.Info("CRL generated successfully for %s CA", caType)
            log.Info("  Number of revoked certificates: %d", len(revokedCerts))
            log.Info("  This update: %s", config.ThisUpdate.Format(time.RFC3339))
            log.Info("  Next update: %s", config.NextUpdate.Format(time.RFC3339))
            log.Info("  Output file: %s", crlPath)
            
            fmt.Printf("CRL successfully generated at %s\n", crlPath)
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&caType, "ca", "", "CA type: root or intermediate")
    cmd.Flags().IntVar(&nextUpdateDays, "next-update", 7, "Days until next CRL update")
    cmd.Flags().StringVar(&outFile, "out-file", "", "Output file path")
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Database path")
    cmd.Flags().StringVar(&caDir, "ca-dir", "./pki", "CA directory")
    cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Passphrase for CA private key")
    
    cmd.MarkFlagRequired("ca")
    cmd.MarkFlagRequired("passphrase-file")
    
    return cmd
}

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

func fileExists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}


// ==================== OCSP COMMANDS ====================

func newOCSPCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "ocsp",
        Short: "OCSP responder operations",
    }
    
    cmd.AddCommand(newOCSPServeCmd())
    
    return cmd
}

func newOCSPServeCmd() *cobra.Command {
    var (
        host          string
        port          int
        dbPath        string
        responderCert string
        responderKey  string
        caCert        string
        cacheTTL      int
    )
    
    cmd := &cobra.Command{
        Use:   "serve",
        Short: "Start OCSP responder server",
        RunE: func(cmd *cobra.Command, args []string) error {
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            responder, err := ocsp.NewOCSPResponder(
                dbPath, caCert, responderCert, responderKey, passphraseFile, cacheTTL, log,
            )
            if err != nil {
                return fmt.Errorf("failed to create OCSP responder: %w", err)
            }
            defer responder.Close()
            
            addr := fmt.Sprintf("%s:%d", host, port)
            http.HandleFunc("/", responder.HandleOCSPRequest)
            
            log.Info("Starting OCSP responder on %s", addr)
            log.Info("  Database: %s", dbPath)
            log.Info("  CA Certificate: %s", caCert)
            log.Info("  Responder Certificate: %s", responderCert)
            
            return http.ListenAndServe(addr, nil)
        },
    }
    
    cmd.Flags().StringVar(&host, "host", "127.0.0.1", "Bind address")
    cmd.Flags().IntVar(&port, "port", 8081, "TCP port")
    cmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Database path")
    cmd.Flags().StringVar(&responderCert, "responder-cert", "", "OCSP responder certificate (PEM)")
    cmd.Flags().StringVar(&responderKey, "responder-key", "", "OCSP responder private key (PEM)")
    cmd.Flags().StringVar(&caCert, "ca-cert", "", "Issuer CA certificate (PEM)")
    cmd.Flags().IntVar(&cacheTTL, "cache-ttl", 60, "Cache TTL in seconds")
    
    cmd.MarkFlagRequired("responder-cert")
    cmd.MarkFlagRequired("responder-key")
    cmd.MarkFlagRequired("ca-cert")
    
    return cmd
}

func newCAIssueOCSPCertCmd() *cobra.Command {
    var (
        caCertPath    string
        caKeyPath     string
        caPassFile    string
        ocspSubject   string
        ocspKeyType   string
        ocspKeySize   int
        ocspSAN       string
        ocspOutDir    string
        ocspValidity  int
    )
    
    cmd := &cobra.Command{
        Use:   "issue-ocsp-cert",
        Short: "Issue OCSP responder certificate",
        RunE: func(cmd *cobra.Command, args []string) error {
            log, err := logger.NewLogger(logFile)
            if err != nil {
                return fmt.Errorf("failed to initialize logger: %w", err)
            }
            defer log.Close()
            
            log.Info("Issuing OCSP responder certificate...")
            
            // Load CA certificate
            caCert, err := loadCertificate(caCertPath)
            if err != nil {
                return fmt.Errorf("failed to load CA certificate: %w", err)
            }
            
            // Load CA private key
            caKey, err := loadPrivateKey(caKeyPath, caPassFile)
            if err != nil {
                return fmt.Errorf("failed to load CA private key: %w", err)
            }
            
            // Generate key pair for OCSP responder
            keyPair, err := myCrypto.GenerateKeyPair(ocspKeyType, ocspKeySize)
            if err != nil {
                return fmt.Errorf("failed to generate key pair: %w", err)
            }
            
            // Parse subject
            subject, err := certs.ParseDN(ocspSubject)
            if err != nil {
                return fmt.Errorf("invalid subject: %w", err)
            }
            
            // Create template with OCSP extensions
            template := &x509.Certificate{
                SerialNumber: big.NewInt(time.Now().Unix()),
                Subject:      *subject,
                NotBefore:    time.Now(),
                NotAfter:     time.Now().AddDate(0, 0, ocspValidity),
                KeyUsage:     x509.KeyUsageDigitalSignature,
                ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
                BasicConstraintsValid: true,
                IsCA: false,
            }
            
            // Add SAN if provided
            if ocspSAN != "" {
                template.DNSNames = []string{ocspSAN}
            }
            
            // Sign certificate
            certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, keyPair.PublicKey, caKey)
            if err != nil {
                return fmt.Errorf("failed to create certificate: %w", err)
            }
            
            // Save certificate
            certPath := filepath.Join(ocspOutDir, "ocsp.cert.pem")
            if err := certs.SaveCertificateToPEM(certBytes, certPath); err != nil {
                return fmt.Errorf("failed to save certificate: %w", err)
            }
            
            // Save private key (unencrypted for OCSP responder)
            keyPath := filepath.Join(ocspOutDir, "ocsp.key.pem")
            keyBytes := x509.MarshalPKCS1PrivateKey(keyPair.PrivateKey.(*rsa.PrivateKey))
            keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
            if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
                return fmt.Errorf("failed to save private key: %w", err)
            }
            
            log.Info("OCSP responder certificate issued successfully")
            fmt.Printf("OCSP certificate: %s\n", certPath)
            fmt.Printf("OCSP private key: %s (unencrypted, permissions 0600)\n", keyPath)
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&caCertPath, "ca-cert", "", "CA certificate file")
    cmd.Flags().StringVar(&caKeyPath, "ca-key", "", "CA private key file")
    cmd.Flags().StringVar(&caPassFile, "ca-pass-file", "", "CA passphrase file")
    cmd.Flags().StringVar(&ocspSubject, "subject", "", "OCSP responder subject")
    cmd.Flags().StringVar(&ocspKeyType, "key-type", "rsa", "Key type: rsa or ecc")
    cmd.Flags().IntVar(&ocspKeySize, "key-size", 2048, "Key size (2048 for RSA, 256 for ECC)")
    cmd.Flags().StringVar(&ocspSAN, "san", "", "Subject Alternative Name (DNS)")
    cmd.Flags().StringVar(&ocspOutDir, "out-dir", "./pki/certs", "Output directory")
    cmd.Flags().IntVar(&ocspValidity, "validity-days", 365, "Validity period in days")
    
    cmd.MarkFlagRequired("ca-cert")
    cmd.MarkFlagRequired("ca-key")
    cmd.MarkFlagRequired("subject")
    
    return cmd
}

func loadPrivateKey(path, passphraseFile string) (interface{}, error) {
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


// ==================== CLIENT COMMANDS ====================

func newClientCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "client",
        Short: "Client operations (CSR, validation, revocation check)",
    }
    
    cmd.AddCommand(newClientGenCSRCmd())
    cmd.AddCommand(newClientRequestCertCmd())
    cmd.AddCommand(newClientValidateCmd())
    cmd.AddCommand(newClientCheckStatusCmd())
    
    return cmd
}

func newClientGenCSRCmd() *cobra.Command {
    var subject, keyType, outKey, outCSR string
    var keySize int
    var sans []string
    
    cmd := &cobra.Command{
        Use:   "gen-csr",
        Short: "Generate private key and CSR",
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Printf("Generating CSR for subject: %s\n", subject)
            
            err := client.GenerateCSR(subject, keyType, keySize, sans, outKey, outCSR)
            if err != nil {
                return err
            }
            
            fmt.Printf("Private key saved to: %s (unencrypted, permissions 0600)\n", outKey)
            fmt.Printf("CSR saved to: %s\n", outCSR)
            return nil
        },
    }
    
    cmd.Flags().StringVar(&subject, "subject", "", "Certificate subject")
    cmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa, ecc)")
    cmd.Flags().IntVar(&keySize, "key-size", 2048, "Key size (2048/4096 for RSA, 256/384 for ECC)")
    cmd.Flags().StringSliceVar(&sans, "san", []string{}, "Subject Alternative Names")
    cmd.Flags().StringVar(&outKey, "out-key", "./key.pem", "Output private key file")
    cmd.Flags().StringVar(&outCSR, "out-csr", "./request.csr.pem", "Output CSR file")
    
    cmd.MarkFlagRequired("subject")
    
    return cmd
}

func newClientRequestCertCmd() *cobra.Command {
    var csrPath, template, caURL, outCert string
    
    cmd := &cobra.Command{
        Use:   "request-cert",
        Short: "Submit CSR to CA and get certificate",
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Printf("Submitting CSR to CA at %s\n", caURL)
            
            csrData, err := os.ReadFile(csrPath)
            if err != nil {
                return fmt.Errorf("failed to read CSR: %w", err)
            }
            
            resp, err := http.Post(caURL+"/request-cert?template="+template, "application/x-pem-file", bytes.NewReader(csrData))
            if err != nil {
                return fmt.Errorf("failed to submit CSR: %w", err)
            }
            defer resp.Body.Close()
            
            if resp.StatusCode != http.StatusCreated {
                body, _ := io.ReadAll(resp.Body)
                return fmt.Errorf("CA returned error: %s", string(body))
            }
            
            certData, err := io.ReadAll(resp.Body)
            if err != nil {
                return fmt.Errorf("failed to read response: %w", err)
            }
            
            if err := os.WriteFile(outCert, certData, 0644); err != nil {
                return fmt.Errorf("failed to save certificate: %w", err)
            }
            
            fmt.Printf("Certificate saved to: %s\n", outCert)
            return nil
        },
    }
    
    cmd.Flags().StringVar(&csrPath, "csr", "", "Path to CSR file")
    cmd.Flags().StringVar(&template, "template", "server", "Certificate template (server, client, code_signing)")
    cmd.Flags().StringVar(&caURL, "ca-url", "http://localhost:8080", "CA repository URL")
    cmd.Flags().StringVar(&outCert, "out-cert", "./cert.pem", "Output certificate file")
    
    cmd.MarkFlagRequired("csr")
    
    return cmd
}

func newClientValidateCmd() *cobra.Command {
    var certPath, trustedPath, mode string
    var crlURL, ocspURL string
    var untrustedPaths []string
    
    cmd := &cobra.Command{
        Use:   "validate",
        Short: "Validate certificate chain",
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Printf("Validating certificate: %s\n", certPath)
            fmt.Printf("Mode: %s\n", mode)
            
            // Create validator
            validator, err := validation.NewValidator(trustedPath, time.Now())
            if err != nil {
                return err
            }
            
            // Load intermediates
            for _, path := range untrustedPaths {
                cert, err := loadCertificate(path)
                if err != nil {
                    return fmt.Errorf("failed to load intermediate: %w", err)
                }
                validator.AddIntermediate(cert)
            }
            
            // Validate
            result, err := validator.ValidateCertificate(certPath, untrustedPaths)
            if err != nil {
                return err
            }
            
            // Print results
            fmt.Println("\n=== Validation Results ===")
            for _, step := range result.Steps {
                status := "✓"
                if !step.Passed {
                    status = "✗"
                }
                fmt.Printf("%s %s: %s\n", status, step.Name, step.Message)
            }
            
            if result.Passed {
                fmt.Println("\n✓ Certificate chain is VALID")
            } else {
                fmt.Printf("\n✗ Certificate chain is INVALID: %s\n", result.ErrorMsg)
                return fmt.Errorf("validation failed")
            }
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&certPath, "cert", "", "Path to leaf certificate")
    cmd.Flags().StringSliceVar(&untrustedPaths, "untrusted", []string{}, "Intermediate certificate paths")
    cmd.Flags().StringVar(&trustedPath, "trusted", "./pki/certs/ca.cert.pem", "Trusted root certificate")
    cmd.Flags().StringVar(&crlURL, "crl", "", "CRL URL for revocation check")
    cmd.Flags().StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL")
    cmd.Flags().StringVar(&mode, "mode", "full", "Validation mode (chain, full)")
    
    cmd.MarkFlagRequired("cert")
    
    return cmd
}

func newClientCheckStatusCmd() *cobra.Command {
    var certPath, issuerPath, crlURL, ocspURL string
    
    cmd := &cobra.Command{
        Use:   "check-status",
        Short: "Check certificate revocation status",
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Printf("Checking revocation status for: %s\n", certPath)
            
            checker := revocation.NewChecker()
            status, err := checker.CheckStatus(certPath, issuerPath, crlURL, ocspURL)
            if err != nil {
                return err
            }
            
            fmt.Printf("\n=== Revocation Status ===\n")
            fmt.Printf("Status: %s\n", status.Status)
            fmt.Printf("Method: %s\n", status.Method)
            if status.Status == "revoked" {
                fmt.Printf("Revocation time: %s\n", status.RevocationTime.Format(time.RFC3339))
                fmt.Printf("Revocation reason: %s\n", status.RevocationReason)
            }
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&certPath, "cert", "", "Path to certificate")
    cmd.Flags().StringVar(&issuerPath, "ca-cert", "", "Issuer CA certificate")
    cmd.Flags().StringVar(&crlURL, "crl", "", "CRL file or URL")
    cmd.Flags().StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL")
    
    cmd.MarkFlagRequired("cert")
    cmd.MarkFlagRequired("ca-cert")
    
    return cmd
}