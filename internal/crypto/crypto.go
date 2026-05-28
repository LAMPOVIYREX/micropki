package crypto

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "path/filepath"
)

type KeyType string

const (
    RSA KeyType = "rsa"
    ECC KeyType = "ecc"
)

type KeyPair struct {
    PrivateKey interface{}
    PublicKey  interface{}
    KeyType    KeyType
    KeySize    int
}

func GenerateKeyPair(keyTypeStr string, keySize int) (*KeyPair, error) {
    switch keyTypeStr {
    case "rsa":
        
        if keySize != 2048 && keySize != 4096 {
            return nil, fmt.Errorf("RSA key size must be 2048 or 4096 bits")
        }
        privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
        if err != nil {
            return nil, fmt.Errorf("failed to generate RSA key: %w", err)
        }
        return &KeyPair{
            PrivateKey: privateKey,
            PublicKey:  &privateKey.PublicKey,
            KeyType:    RSA,
            KeySize:    keySize,
        }, nil
        
    case "ecc":
        if keySize != 384 {
            return nil, fmt.Errorf("ECC key size must be 384 bits (P-384)")
        }
        privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
        if err != nil {
            return nil, fmt.Errorf("failed to generate ECC key: %w", err)
        }
        return &KeyPair{
            PrivateKey: privateKey,
            PublicKey:  &privateKey.PublicKey,
            KeyType:    ECC,
            KeySize:    keySize,
        }, nil
        
    default:
        return nil, fmt.Errorf("unsupported key type: %s", keyTypeStr)
    }
}

func EncryptPrivateKey(privateKey interface{}, passphrase []byte) ([]byte, error) {
    var keyBytes []byte
    var err error
    
    switch k := privateKey.(type) {
    case *rsa.PrivateKey:
        keyBytes = x509.MarshalPKCS1PrivateKey(k)
    case *ecdsa.PrivateKey:
        keyBytes, err = x509.MarshalECPrivateKey(k)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal ECC private key: %w", err)
        }
    default:
        return nil, fmt.Errorf("unsupported private key type")
    }
    
    // Create encrypted PEM block
    block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyBytes, passphrase, x509.PEMCipherAES256)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt private key: %w", err)
    }
    
    return pem.EncodeToMemory(block), nil
}

func SaveEncryptedKey(keyPair *KeyPair, passphrase []byte, path string, perm os.FileMode) error {
    encryptedKey, err := EncryptPrivateKey(keyPair.PrivateKey, passphrase)
    if err != nil {
        return err
    }
    
    return os.WriteFile(path, encryptedKey, perm)
}

func LoadPassphraseFromFile(path string) ([]byte, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read passphrase file: %w", err)
    }
    
    // Remove trailing newline if present
    if len(data) > 0 && data[len(data)-1] == '\n' {
        data = data[:len(data)-1]
    }
    
    return data, nil
}

// GenerateSerialNumber генерирует серийный номер
func GenerateSerialNumber() ([]byte, error) {
    serial := make([]byte, 20)
    _, err := rand.Read(serial)
    if err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }
    return serial, nil
}

// EncryptAndSavePrivateKey сохраняет зашифрованный приватный ключ
func EncryptAndSavePrivateKey(keyPair *KeyPair, passphrase []byte, path string) error {
    encryptedKey, err := EncryptPrivateKey(keyPair.PrivateKey, passphrase)
    if err != nil {
        return err
    }
    
    // Создаем директорию, если не существует
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    return os.WriteFile(path, encryptedKey, 0600)
}

// LoadAndDecryptPrivateKey загружает и расшифровывает приватный ключ
func LoadAndDecryptPrivateKey(path string, passphrase []byte) (interface{}, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read key file: %w", err)
    }
    
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    
    // Try to decrypt
    keyBytes, err := x509.DecryptPEMBlock(block, passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt private key: %w", err)
    }
    
    // Try to parse as RSA
    if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
        return key, nil
    }
    
    // Try to parse as ECC
    if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
        return key, nil
    }
    
    // Try to parse as PKCS8
    if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
        return key, nil
    }
    
    return nil, fmt.Errorf("unsupported private key format")
}

// ValidatePassphrase проверяет качество пароля
func ValidatePassphrase(passphrase []byte) error {
    if len(passphrase) < 8 {
        return fmt.Errorf("passphrase must be at least 8 characters")
    }
    
    hasUpper := false
    hasLower := false
    hasDigit := false
    
    for _, b := range passphrase {
        c := rune(b)
        if c >= 'A' && c <= 'Z' {
            hasUpper = true
        } else if c >= 'a' && c <= 'z' {
            hasLower = true
        } else if c >= '0' && c <= '9' {
            hasDigit = true
        }
    }
    
    if !hasUpper {
        return fmt.Errorf("passphrase must contain at least one uppercase letter")
    }
    if !hasLower {
        return fmt.Errorf("passphrase must contain at least one lowercase letter")
    }
    if !hasDigit {
        return fmt.Errorf("passphrase must contain at least one digit")
    }
    
    return nil
}