package certs

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
)

type CertificateConfig struct {
    Subject       string
    KeyType       string
    ValidityDays  int
    SerialNumber  *big.Int
    PublicKey     interface{}
}

func ParseDN(dn string) (*pkix.Name, error) {
    name := &pkix.Name{}
    
    // Try to parse both formats: slash-notation and comma-separated
    // This is a simplified parser - in production, use a proper DN parser
    if len(dn) == 0 {
        return nil, fmt.Errorf("empty DN string")
    }
    
    // Basic parsing for demo purposes
    // Format: "/CN=Common Name/O=Organization/C=US" or "CN=Common Name,O=Organization"
    current := ""
    for i := 0; i < len(dn); i++ {
        if dn[i] == '/' && i == 0 {
            continue
        }
        if dn[i] == '/' || dn[i] == ',' {
            if current != "" {
                parts := splitRDN(current)
                if len(parts) == 2 {
                    switch parts[0] {
                    case "CN":
                        name.CommonName = parts[1]
                    case "O":
                        name.Organization = []string{parts[1]}
                    case "OU":
                        name.OrganizationalUnit = []string{parts[1]}
                    case "C":
                        name.Country = []string{parts[1]}
                    case "ST":
                        name.Province = []string{parts[1]}
                    case "L":
                        name.Locality = []string{parts[1]}
                    }
                }
            }
            current = ""
        } else {
            current += string(dn[i])
        }
    }
    
    if current != "" {
        parts := splitRDN(current)
        if len(parts) == 2 {
            switch parts[0] {
            case "CN":
                name.CommonName = parts[1]
            case "O":
                name.Organization = []string{parts[1]}
            case "OU":
                name.OrganizationalUnit = []string{parts[1]}
            case "C":
                name.Country = []string{parts[1]}
            case "ST":
                name.Province = []string{parts[1]}
            case "L":
                name.Locality = []string{parts[1]}
            }
        }
    }
    
    if name.CommonName == "" {
        return nil, fmt.Errorf("DN must contain a Common Name (CN)")
    }
    
    return name, nil
}

func splitRDN(rdn string) []string {
    for i := 0; i < len(rdn); i++ {
        if rdn[i] == '=' {
            return []string{rdn[:i], rdn[i+1:]}
        }
    }
    return []string{rdn}
}

func GenerateSerialNumber() (*big.Int, error) {
    serial := make([]byte, 20) // 160 bits of randomness
    if _, err := rand.Read(serial); err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    return new(big.Int).SetBytes(serial), nil
}

func CreateSelfSignedRootCA(config *CertificateConfig) (*x509.Certificate, error) {
    name, err := ParseDN(config.Subject)
    if err != nil {
        return nil, err
    }
    
    notBefore := time.Now().UTC()
    notAfter := notBefore.AddDate(0, 0, config.ValidityDays)
    
    // Compute Subject Key Identifier (SHA-1 of public key)
    var pubKeyBytes []byte
    switch pub := config.PublicKey.(type) {
    case *rsa.PublicKey:
        pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
    case *ecdsa.PublicKey:
        pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
    default:
        return nil, fmt.Errorf("unsupported public key type")
    }
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    
    hash := sha1.Sum(pubKeyBytes)
    ski := hash[:]
    
    template := &x509.Certificate{
        SerialNumber: config.SerialNumber,
        Subject:      *name,
        Issuer:       *name, // Self-signed, so issuer = subject
        NotBefore:    notBefore,
        NotAfter:     notAfter,
        
        KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLen:            0, // No path length constraint
        
        SubjectKeyId:   ski,
        AuthorityKeyId: ski, // Same as SKI for self-signed
        
        SignatureAlgorithm: getSignatureAlgorithm(config.KeyType),
    }
    
    return template, nil
}

func getSignatureAlgorithm(keyType string) x509.SignatureAlgorithm {
    if keyType == "rsa" {
        return x509.SHA256WithRSA
    }
    return x509.ECDSAWithSHA384
}

func SignCertificate(template, parent *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
    certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to sign certificate: %w", err)
    }
    return certDER, nil
}

func EncodeCertificatePEM(certDER []byte) []byte {
    return pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certDER,
    })
}

func SaveCertificatePEM(certDER []byte, path string, perm os.FileMode) error {
    pemBytes := EncodeCertificatePEM(certDER)
    return os.WriteFile(path, pemBytes, perm)
}

func VerifyCertificate(certPath string) error {
    certPEM, err := os.ReadFile(certPath)
    if err != nil {
        return fmt.Errorf("failed to read certificate: %w", err)
    }
    
    block, _ := pem.Decode(certPEM)
    if block == nil {
        return fmt.Errorf("failed to decode PEM certificate")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse certificate: %w", err)
    }
    
    // Verify self-signed certificate
    roots := x509.NewCertPool()
    roots.AddCert(cert)
    
    opts := x509.VerifyOptions{
        Roots: roots,
    }
    
    if _, err := cert.Verify(opts); err != nil {
        return fmt.Errorf("certificate verification failed: %w", err)
    }
    
    return nil
}

// GenerateSelfSignedCert создает самоподписанный сертификат
func GenerateSelfSignedCert(privateKey interface{}, subject *pkix.Name, validityDays int) ([]byte, error) {
    // Генерируем серийный номер
    serialBytes := make([]byte, 20)
    if _, err := rand.Read(serialBytes); err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    serial := new(big.Int).SetBytes(serialBytes)
    
    now := time.Now().UTC()
    
    // Получаем публичный ключ
    var publicKey interface{}
    switch k := privateKey.(type) {
    case *rsa.PrivateKey:
        publicKey = &k.PublicKey
    case *ecdsa.PrivateKey:
        publicKey = &k.PublicKey
    default:
        return nil, fmt.Errorf("unsupported private key type")
    }
    
    // Вычисляем Subject Key Identifier
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    hash := sha1.Sum(pubKeyBytes)
    ski := hash[:]
    
    template := &x509.Certificate{
        SerialNumber: serial,
        Subject:      *subject,
        Issuer:       *subject,
        NotBefore:    now,
        NotAfter:     now.AddDate(0, 0, validityDays),
        
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        
        SubjectKeyId:   ski,
        AuthorityKeyId: ski,
        
        SignatureAlgorithm: getSignatureAlgorithmFromKey(privateKey),
    }
    
    certBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create certificate: %w", err)
    }
    
    return certBytes, nil
}

// getSignatureAlgorithmFromKey определяет алгоритм подписи по типу ключа
func getSignatureAlgorithmFromKey(privateKey interface{}) x509.SignatureAlgorithm {
    switch privateKey.(type) {
    case *rsa.PrivateKey:
        return x509.SHA256WithRSA
    case *ecdsa.PrivateKey:
        return x509.ECDSAWithSHA384
    default:
        return x509.UnknownSignatureAlgorithm
    }
}

// SaveCertificateToPEM сохраняет сертификат в PEM формате
func SaveCertificateToPEM(certBytes []byte, path string) error {
    // Создаем директорию, если не существует
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    pemBlock := &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certBytes,
    }
    
    pemBytes := pem.EncodeToMemory(pemBlock)
    return os.WriteFile(path, pemBytes, 0644)
}

// ComputeSubjectKeyIdentifier вычисляет SKI для публичного ключа
func ComputeSubjectKeyIdentifier(pubKey interface{}) ([]byte, error) {
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    
    hash := sha1.Sum(pubKeyBytes)
    return hash[:], nil
}

// GetPublicKey извлекает публичный ключ из приватного
func GetPublicKey(privateKey interface{}) (interface{}, error) {
    switch k := privateKey.(type) {
    case *rsa.PrivateKey:
        return &k.PublicKey, nil
    case *ecdsa.PrivateKey:
        return &k.PublicKey, nil
    default:
        return nil, fmt.Errorf("unsupported key type")
    }
}