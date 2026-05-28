package ca

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "time"
    
    "micropki/internal/certs"
    "micropki/internal/crypto"
    "micropki/pkg/types"
)

// IntermediateCAConfig конфигурация для Intermediate CA
type IntermediateCAConfig struct {
    Subject          string
    KeyType          string
    KeySize          int
    Passphrase       []byte
    OutDir           string
    ValidityDays     int
    RootCAPassphrase []byte
    RootCADir        string
    MaxPathLen       int
}

// InitIntermediateCA создает Intermediate CA, подписанный Root CA
func (ca *CertificateAuthority) InitIntermediateCA(config *IntermediateCAConfig) (*types.CAFiles, error) {
    ca.Logger.Info("Starting Intermediate CA initialization")
    
    // 1. Загружаем Root CA сертификат
    rootCertPath := filepath.Join(config.RootCADir, "certs", "ca.cert.pem")
    rootCert, err := loadCertificate(rootCertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load root certificate: %w", err)
    }
    
    // 2. Загружаем Root CA приватный ключ
    rootKeyPath := filepath.Join(config.RootCADir, "private", "ca.key.pem")
    rootPrivateKey, err := crypto.LoadAndDecryptPrivateKey(rootKeyPath, config.RootCAPassphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to load root private key: %w", err)
    }
    
    // 3. Генерируем ключевую пару для Intermediate CA
    ca.Logger.Info("Generating Intermediate CA key pair: type=%s, size=%d", config.KeyType, config.KeySize)
    keyPair, err := crypto.GenerateKeyPair(config.KeyType, config.KeySize)
    if err != nil {
        return nil, fmt.Errorf("key generation failed: %w", err)
    }
    
    // 4. Парсим Subject для Intermediate CA
    subject, err := certs.ParseDN(config.Subject)
    if err != nil {
        return nil, fmt.Errorf("invalid subject: %w", err)
    }
    
    // 5. Создаем шаблон Intermediate CA сертификата
    template, err := certs.CreateIntermediateCATemplate(subject, rootCert, keyPair.PublicKey, config.ValidityDays, config.MaxPathLen)
    if err != nil {
        return nil, fmt.Errorf("failed to create template: %w", err)
    }
    
    // 6. Подписываем сертификат Root CA
    certBytes, err := certs.SignCertificate(template, rootCert, keyPair.PublicKey, rootPrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to sign certificate: %w", err)
    }
    
    // 7. Создаем структуру директорий
    privateDir := filepath.Join(config.OutDir, "private")
    certsDir := filepath.Join(config.OutDir, "certs")
    
    if err := os.MkdirAll(privateDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create private directory: %w", err)
    }
    if err := os.MkdirAll(certsDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create certs directory: %w", err)
    }
    
    // 8. Сохраняем зашифрованный приватный ключ
    keyPath := filepath.Join(privateDir, "intermediate.key.pem")
    if err := crypto.EncryptAndSavePrivateKey(keyPair, config.Passphrase, keyPath); err != nil {
        return nil, fmt.Errorf("failed to save private key: %w", err)
    }
    
    // 9. Сохраняем сертификат
    certPath := filepath.Join(certsDir, "intermediate.cert.pem")
    if err := certs.SaveCertificateToPEM(certBytes, certPath); err != nil {
        return nil, fmt.Errorf("failed to save certificate: %w", err)
    }
    
    // 10. Загружаем Root CA сертификат в байтовом виде для цепочки
    rootCertBytes, err := os.ReadFile(rootCertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read root certificate: %w", err)
    }
    
    // 11. Сохраняем полную цепочку (Intermediate + Root)
    chainPath := filepath.Join(certsDir, "chain.cert.pem")
    if err := saveCertificateChain(certBytes, rootCertBytes, chainPath); err != nil {
        ca.Logger.Warning("Failed to save certificate chain: %v", err)
    }
    
    ca.Logger.Info("Intermediate CA initialization completed successfully")
    
    return &types.CAFiles{
        PrivateKeyPath: keyPath,
        CertPath:       certPath,
        PolicyPath:     "",
    }, nil
}

// loadCertificate загружает сертификат из файла
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

// saveCertificateChain сохраняет цепочку сертификатов
func saveCertificateChain(intermediateCert, rootCert []byte, path string) error {
    file, err := os.Create(path)
    if err != nil {
        return err
    }
    defer file.Close()
    
    // Записываем Intermediate сертификат
    block := &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: intermediateCert,
    }
    if err := pem.Encode(file, block); err != nil {
        return err
    }
    
    // Записываем Root сертификат
    block = &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: rootCert,
    }
    return pem.Encode(file, block)
}

// GenerateIntermediateCSR генерирует CSR для Intermediate CA
func GenerateIntermediateCSR(subject *pkix.Name, keyPair *crypto.KeyPair) ([]byte, error) {

    basicConstraintsDER := []byte{
        0x30, 0x06,  
        0x01, 0x01,  
        0xFF,        
        0x02, 0x01,  
        0x00,        
    }
    
    template := &x509.CertificateRequest{
        Subject: *subject,
        ExtraExtensions: []pkix.Extension{
            {
                Id:       []int{2, 5, 29, 19}, 
                Critical: true,
                Value:    basicConstraintsDER,
            },
        },
    }
    
    csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, keyPair.PrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create CSR: %w", err)
    }
    
    return csrBytes, nil
}

// SignIntermediateCSR подписывает CSR Intermediate CA
func SignIntermediateCSR(csrBytes []byte, rootCert *x509.Certificate, rootPrivateKey interface{}, validityDays int, maxPathLen int) ([]byte, error) {
    // Парсим CSR
    csr, err := x509.ParseCertificateRequest(csrBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse CSR: %w", err)
    }
    
    // Проверяем подпись CSR
    if err := csr.CheckSignature(); err != nil {
        return nil, fmt.Errorf("CSR signature verification failed: %w", err)
    }
    
    // Проверяем BasicConstraints в CSR
    caConstraint := false
    for _, ext := range csr.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 19}) { // BasicConstraints OID
            caConstraint = true
            break
        }
    }
    
    if !caConstraint {
        return nil, fmt.Errorf("CSR must have BasicConstraints: CA=TRUE")
    }
    
    // Создаем серийный номер
    serialBytes := make([]byte, 20)
    if _, err := rand.Read(serialBytes); err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    serial := new(big.Int).SetBytes(serialBytes)
    
    now := time.Now().UTC()
    
    // Вычисляем SKI
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    hash := sha1.Sum(pubKeyBytes)
    ski := hash[:]
    
    template := &x509.Certificate{
        SerialNumber: serial,
        Subject:      csr.Subject,
        Issuer:       rootCert.Subject,
        NotBefore:    now,
        NotAfter:     now.AddDate(0, 0, validityDays),
        
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLen:            maxPathLen,
        
        SubjectKeyId:   ski,
        AuthorityKeyId: rootCert.SubjectKeyId,
        
        SignatureAlgorithm: getSignatureAlgorithmFromKey(rootPrivateKey),
    }
    
    certBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, csr.PublicKey, rootPrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to sign certificate: %w", err)
    }
    
    return certBytes, nil
}

func getSignatureAlgorithmFromKey(key interface{}) x509.SignatureAlgorithm {
    switch key.(type) {
    case *rsa.PrivateKey:
        return x509.SHA256WithRSA
    case *ecdsa.PrivateKey:
        return x509.ECDSAWithSHA384
    default:
        return x509.UnknownSignatureAlgorithm
    }
}