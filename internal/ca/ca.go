package ca

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "path/filepath"
    "time"
    
    "micropki/internal/certs"
    "micropki/internal/crypto"
    "micropki/internal/logger"
    "micropki/pkg/types"
    
)

type CertificateAuthority struct {
    Config *types.CAConfig
    Logger *logger.Logger
}

func NewCA(config *types.CAConfig, log *logger.Logger) *CertificateAuthority {
    return &CertificateAuthority{
        Config: config,
        Logger: log,
    }
}

// InitRootCA инициализирует Root CA
func (ca *CertificateAuthority) InitRootCA() (*types.CAFiles, error) {
    ca.Logger.Info("Starting Root CA initialization")
    
    // Генерируем ключевую пару
    ca.Logger.Info("Generating key pair: type=%s, size=%d", ca.Config.KeyType, ca.Config.KeySize)
    keyPair, err := crypto.GenerateKeyPair(ca.Config.KeyType, ca.Config.KeySize)
    if err != nil {
        ca.Logger.Error("Key generation failed: %v", err)
        return nil, fmt.Errorf("key generation failed: %w", err)
    }
    ca.Logger.Info("Key generation completed successfully")
    
    // Парсим Distinguished Name
    ca.Logger.Info("Parsing subject: %s", ca.Config.Subject)
    subject, err := certs.ParseDN(ca.Config.Subject)
    if err != nil {
        ca.Logger.Error("Failed to parse subject: %v", err)
        return nil, fmt.Errorf("invalid subject: %w", err)
    }
    
    // Генерируем самоподписанный сертификат
    ca.Logger.Info("Generating self-signed certificate (validity: %d days)", ca.Config.ValidityDays)
    certBytes, err := certs.GenerateSelfSignedCert(keyPair.PrivateKey, subject, ca.Config.ValidityDays)
    if err != nil {
        ca.Logger.Error("Certificate generation failed: %v", err)
        return nil, fmt.Errorf("certificate generation failed: %w", err)
    }
    ca.Logger.Info("Certificate generation completed successfully")
    
    /* Insert into database if available
    if db, err := database.InitDB(filepath.Join(ca.Config.OutDir, "micropki.db")); err == nil {
        defer db.Close()
        
        // Parse certificate
        cert, err := certs.LoadCertificate(certPath)
        if err == nil {
            if err := database.InsertCertificate(db, cert, string(certPEM)); err != nil {
                ca.Logger.Warning("Failed to insert certificate into database: %v", err)
            } else {
                ca.Logger.Info("Certificate inserted into database")
            }
        }
    }*/

    // Создаем структуру директорий
    privateDir := filepath.Join(ca.Config.OutDir, "private")
    certsDir := filepath.Join(ca.Config.OutDir, "certs")
    
    if err := os.MkdirAll(privateDir, 0700); err != nil {
        ca.Logger.Error("Failed to create private directory: %v", err)
        return nil, fmt.Errorf("failed to create private directory: %w", err)
    }
    
    if err := os.MkdirAll(certsDir, 0755); err != nil {
        ca.Logger.Error("Failed to create certs directory: %v", err)
        return nil, fmt.Errorf("failed to create certs directory: %w", err)
    }
    
    // Сохраняем зашифрованный приватный ключ
    keyPath := filepath.Join(privateDir, "ca.key.pem")
    ca.Logger.Info("Saving encrypted private key to: %s", keyPath)
    if err := crypto.EncryptAndSavePrivateKey(keyPair, ca.Config.Passphrase, keyPath); err != nil {
        ca.Logger.Error("Failed to save private key: %v", err)
        return nil, fmt.Errorf("failed to save private key: %w", err)
    }
    ca.Logger.Info("Private key saved successfully")
    
    certPath := filepath.Join(certsDir, "ca.cert.pem")
    ca.Logger.Info("Saving certificate to: %s", certPath)
    if err := certs.SaveCertificateToPEM(certBytes, certPath); err != nil {
        ca.Logger.Error("Failed to save certificate: %v", err)
        return nil, fmt.Errorf("failed to save certificate: %w", err)
    }
    ca.Logger.Info("Certificate saved successfully")

    // Прочитайте PEM для вставки в БД
    //certPEMBytes, err := os.ReadFile(certPath)
    if err != nil {
        ca.Logger.Warning("Failed to read certificate for DB: %v", err)
    } else {
        //certPEM := string(certPEMBytes)
        
    }
    
    // Создаем policy файл
    policyPath := filepath.Join(ca.Config.OutDir, "policy.txt")
    ca.Logger.Info("Creating policy document: %s", policyPath)
    if err := ca.createPolicyFile(policyPath, keyPair); err != nil {
        ca.Logger.Error("Failed to create policy file: %v", err)
        return nil, fmt.Errorf("failed to create policy file: %w", err)
    }
    ca.Logger.Info("Policy document created successfully")
    
    ca.Logger.Info("Root CA initialization completed successfully")
    
    return &types.CAFiles{
        PrivateKeyPath: keyPath,
        CertPath:       certPath,
        PolicyPath:     policyPath,
    }, nil
}

// createPolicyFile создает файл политики
func (ca *CertificateAuthority) createPolicyFile(path string, keyPair *crypto.KeyPair) error {
    // Загружаем созданный сертификат для получения информации
    certPath := filepath.Join(ca.Config.OutDir, "certs", "ca.cert.pem")
    certInfo, err := ca.getCertificateInfo(certPath)
    if err != nil {
        return fmt.Errorf("failed to get certificate info: %w", err)
    }
    
    content := fmt.Sprintf(`Certificate Policy Document
===========================
CA Name: %s
Certificate Serial Number (hex): %s
Validity Period:
  Not Before: %s
  Not After:  %s
Key Algorithm: %s-%d

Purpose:
This Root CA is part of the MicroPKI demonstration project.
It serves as the trust anchor for all certificates issued
by this PKI implementation.

Policy Version: 1.0
Creation Date: %s

Security Considerations:
- Private key is stored encrypted with AES-256
- Key can only be accessed with the correct passphrase
- All operations are logged for audit purposes

Usage Constraints:
- This CA is for educational/demonstration purposes only
- Not intended for production use
- Certificate validity: %d days

Generated by MicroPKI - A Single-Handed PKI Implementation
`,
        certInfo.Subject,
        certInfo.Serial,
        certInfo.NotBefore.Format(time.RFC3339),
        certInfo.NotAfter.Format(time.RFC3339),
        certInfo.KeyAlgo,
        certInfo.KeySize,
        time.Now().Format(time.RFC3339),
        ca.Config.ValidityDays,
    )
    
    return os.WriteFile(path, []byte(content), 0644)
}

// getCertificateInfo получает информацию о сертификате
func (ca *CertificateAuthority) getCertificateInfo(certPath string) (*types.CertificateInfo, error) {
    certBytes, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }
    
    block, _ := pem.Decode(certBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate: %w", err)
    }
    
    return &types.CertificateInfo{
        Subject:   cert.Subject.String(),
        Serial:    fmt.Sprintf("%x", cert.SerialNumber),
        NotBefore: cert.NotBefore,
        NotAfter:  cert.NotAfter,
        KeyAlgo:   ca.Config.KeyType,
        KeySize:   ca.Config.KeySize,
    }, nil
}