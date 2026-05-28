package crypto

import (
    "os"
    "testing"
)

func TestGenerateKeyPair(t *testing.T) {
    // RSA 4096
    kp, err := GenerateKeyPair("rsa", 4096)
    if err != nil {
        t.Fatalf("Failed to generate RSA 4096: %v", err)
    }
    if kp.KeyType != RSA {
        t.Errorf("Expected RSA, got %v", kp.KeyType)
    }
    if kp.KeySize != 4096 {
        t.Errorf("Expected 4096, got %d", kp.KeySize)
    }

    // ECC P-384
    kp, err = GenerateKeyPair("ecc", 384)
    if err != nil {
        t.Fatalf("Failed to generate ECC 384: %v", err)
    }
    if kp.KeyType != ECC {
        t.Errorf("Expected ECC, got %v", kp.KeyType)
    }
    if kp.KeySize != 384 {
        t.Errorf("Expected 384, got %d", kp.KeySize)
    }

    // Invalid key type
    _, err = GenerateKeyPair("invalid", 0)
    if err == nil {
        t.Error("Expected error for invalid key type")
    }

    // Invalid RSA size
    _, err = GenerateKeyPair("rsa", 1024)
    if err == nil {
        t.Error("Expected error for RSA 1024")
    }
}

func TestEncryptAndSavePrivateKey(t *testing.T) {
    kp, err := GenerateKeyPair("rsa", 4096)
    if err != nil {
        t.Fatal(err)
    }

    tmpFile := t.TempDir() + "/key.pem"
    passphrase := []byte("test123")

    err = EncryptAndSavePrivateKey(kp, passphrase, tmpFile)
    if err != nil {
        t.Fatalf("Failed to save encrypted key: %v", err)
    }

    // Check file exists
    if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
        t.Error("Key file not created")
    }

    // Load and decrypt
    loadedKey, err := LoadAndDecryptPrivateKey(tmpFile, passphrase)
    if err != nil {
        t.Fatalf("Failed to load key: %v", err)
    }
    if loadedKey == nil {
        t.Error("Loaded key is nil")
    }
}

func TestLoadAndDecryptPrivateKeyWrongPassphrase(t *testing.T) {
    kp, err := GenerateKeyPair("rsa", 4096)
    if err != nil {
        t.Fatal(err)
    }

    tmpFile := t.TempDir() + "/key.pem"
    passphrase := []byte("test123")
    wrongPassphrase := []byte("wrong")

    err = EncryptAndSavePrivateKey(kp, passphrase, tmpFile)
    if err != nil {
        t.Fatal(err)
    }

    _, err = LoadAndDecryptPrivateKey(tmpFile, wrongPassphrase)
    if err == nil {
        t.Error("Expected error for wrong passphrase")
    }
}

func TestLoadPassphraseFromFile(t *testing.T) {
    tmpFile := t.TempDir() + "/pass.txt"
    content := []byte("mysecretpass\n")
    if err := os.WriteFile(tmpFile, content, 0600); err != nil {
        t.Fatal(err)
    }

    passphrase, err := LoadPassphraseFromFile(tmpFile)
    if err != nil {
        t.Fatalf("Failed to load passphrase: %v", err)
    }

    if string(passphrase) != "mysecretpass" {
        t.Errorf("Expected 'mysecretpass', got '%s'", passphrase)
    }

    // Non-existent file
    _, err = LoadPassphraseFromFile("/nonexistent")
    if err == nil {
        t.Error("Expected error for non-existent file")
    }
}

func TestValidatePassphrase(t *testing.T) {
    tests := []struct {
        name      string
        passphrase []byte
        shouldErr bool
    }{
        {"Too short", []byte("Short1!"), true},
        {"No uppercase", []byte("nouppercase123!"), true},
        {"No lowercase", []byte("NOLOWERCASE123!"), true},
        {"No digit", []byte("NoDigit!"), true},
        {"Valid", []byte("ValidPass123!"), false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidatePassphrase(tt.passphrase)
            if tt.shouldErr && err == nil {
                t.Error("Expected error, got nil")
            }
            if !tt.shouldErr && err != nil {
                t.Errorf("Expected no error, got %v", err)
            }
        })
    }
}

func TestSecureZero(t *testing.T) {
    data := []byte("secret")
    SecureZero(data)
    for i := range data {
        if data[i] != 0 {
            t.Errorf("Byte %d not zeroed: %d", i, data[i])
        }
    }
}

func TestConstantTimeCompare(t *testing.T) {
    a := "secret"
    b := "secret"
    c := "different"

    if !ConstantTimeCompare(a, b) {
        t.Error("Expected true for equal strings")
    }
    if ConstantTimeCompare(a, c) {
        t.Error("Expected false for different strings")
    }
}

func TestGenerateSerialNumber(t *testing.T) {
    serial, err := GenerateSerialNumber()
    if err != nil {
        t.Fatalf("Failed to generate serial: %v", err)
    }
    if len(serial) != 20 {
        t.Errorf("Expected 20 bytes, got %d", len(serial))
    }
}