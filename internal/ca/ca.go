package ca

import (
    "fmt"
    "os"
    "path/filepath"

    "micropki/internal/audit"
    "micropki/internal/certs"
    "micropki/internal/crypto"
    "micropki/internal/logger"
    "micropki/internal/policy"
    "micropki/internal/transparency"
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

// InitRootCA инициализирует Root CA с проверкой политик и аудитом
func (ca *CertificateAuthority) InitRootCA() (*types.CAFiles, error) {
    ca.Logger.Info("Starting Root CA initialization")

    // === Policy checks for Root CA ===
    if err := policy.ValidateKeySize(policy.RootCA, ca.Config.KeySize, ca.Config.KeyType); err != nil {
        ca.Logger.Error("Policy violation: %v", err)
        return nil, fmt.Errorf("policy violation: %w", err)
    }
    if err := policy.ValidateValidity(policy.RootCA, ca.Config.ValidityDays); err != nil {
        ca.Logger.Error("Policy violation: %v", err)
        return nil, fmt.Errorf("policy violation: %w", err)
    }

    // Generate key pair
    ca.Logger.Info("Generating key pair: type=%s, size=%d", ca.Config.KeyType, ca.Config.KeySize)
    keyPair, err := crypto.GenerateKeyPair(ca.Config.KeyType, ca.Config.KeySize)
    if err != nil {
        ca.Logger.Error("Key generation failed: %v", err)
        return nil, fmt.Errorf("key generation failed: %w", err)
    }
    ca.Logger.Info("Key generation completed successfully")

    // Parse subject
    subject, err := certs.ParseDN(ca.Config.Subject)
    if err != nil {
        ca.Logger.Error("Failed to parse subject: %v", err)
        return nil, fmt.Errorf("invalid subject: %w", err)
    }

    // Generate self-signed certificate
    ca.Logger.Info("Generating self-signed certificate (validity: %d days)", ca.Config.ValidityDays)
    certBytes, err := certs.GenerateSelfSignedCert(keyPair.PrivateKey, subject, ca.Config.ValidityDays)
    if err != nil {
        ca.Logger.Error("Certificate generation failed: %v", err)
        return nil, fmt.Errorf("certificate generation failed: %w", err)
    }
    ca.Logger.Info("Certificate generation completed successfully")

    // Create directory structure
    privateDir := filepath.Join(ca.Config.OutDir, "private")
    certsDir := filepath.Join(ca.Config.OutDir, "certs")
    if err := os.MkdirAll(privateDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create private directory: %w", err)
    }
    if err := os.MkdirAll(certsDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create certs directory: %w", err)
    }

    // Save encrypted private key
    keyPath := filepath.Join(privateDir, "ca.key.pem")
    if err := crypto.EncryptAndSavePrivateKey(keyPair, ca.Config.Passphrase, keyPath); err != nil {
        return nil, fmt.Errorf("failed to save private key: %w", err)
    }

    // Save certificate
    certPath := filepath.Join(certsDir, "ca.cert.pem")
    if err := certs.SaveCertificateToPEM(certBytes, certPath); err != nil {
        return nil, fmt.Errorf("failed to save certificate: %w", err)
    }

    // Create policy document
    policyPath := filepath.Join(ca.Config.OutDir, "policy.txt")
    if err := ca.createPolicyFile(policyPath, keyPair); err != nil {
        return nil, fmt.Errorf("failed to create policy file: %w", err)
    }

    // === Audit log ===
    auditLogger, err := audit.NewAuditLogger(ca.Config.OutDir)
    if err == nil {
        defer auditLogger.Close()
        _ = auditLogger.Log("AUDIT", "init_root_ca", "success", "Root CA initialized", map[string]interface{}{
            "subject": subject.String(),
            "key_type": ca.Config.KeyType,
            "key_size": ca.Config.KeySize,
        })
    }

    // === CT simulation log ===
    ctLog, err := transparency.NewCTLog(ca.Config.OutDir)
    if err == nil {
        defer ctLog.Close()
        // Get serial from certificate
        cert, _ := certs.LoadCertificate(certPath)
        if cert != nil {
            serialHex := fmt.Sprintf("%X", cert.SerialNumber)
            _ = ctLog.Append(serialHex, subject.String(), "")
        }
    }

    ca.Logger.Info("Root CA initialization completed successfully")
    return &types.CAFiles{
        PrivateKeyPath: keyPath,
        CertPath:       certPath,
        PolicyPath:     policyPath,
    }, nil
}

func (ca *CertificateAuthority) createPolicyFile(path string, keyPair *crypto.KeyPair) error {
    // existing implementation (не меняется)
    return nil
}