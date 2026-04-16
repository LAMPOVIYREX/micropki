package tests

import (
    "os"
    "path/filepath"
    "testing"
    
    "micropki/internal/crypto"
)

func TestEncryptedKeyStorage(t *testing.T) {
    // Generate key pair
    keyPair, err := crypto.GenerateKeyPair("rsa", 4096)
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }
    
    // Create temporary directory
    tmpDir, err := os.MkdirTemp("", "micropki-crypto-test-*")
    if err != nil {
        t.Fatalf("Failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tmpDir)
    
    passphrase := []byte("testpass123")
    keyPath := filepath.Join(tmpDir, "test.key.pem")
    
    // Save encrypted key
    if err := crypto.EncryptAndSavePrivateKey(keyPair, passphrase, keyPath); err != nil {
        t.Fatalf("Failed to save encrypted key: %v", err)
    }
    
    // Check file permissions
    info, err := os.Stat(keyPath)
    if err != nil {
        t.Fatalf("Failed to stat key file: %v", err)
    }
    
    // Check if permissions are 0600 (Unix-like systems)
    if info.Mode().Perm() != 0600 {
        t.Logf("Warning: Expected permissions 0600, got %v", info.Mode().Perm())
    }
}

func TestInvalidKeySizes(t *testing.T) {
    // Test invalid RSA key size
    _, err := crypto.GenerateKeyPair("rsa", 2048)
    if err == nil {
        t.Error("Expected error for RSA 2048, got nil")
    }
    
    // Test invalid ECC key size
    _, err = crypto.GenerateKeyPair("ecc", 256)
    if err == nil {
        t.Error("Expected error for ECC 256, got nil")
    }
}

func TestPassphraseLoading(t *testing.T) {
    // Create temporary passphrase file
    tmpDir, err := os.MkdirTemp("", "micropki-pass-test-*")
    if err != nil {
        t.Fatalf("Failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tmpDir)
    
    passFile := filepath.Join(tmpDir, "pass.txt")
    passContent := []byte("securepass123\n")
    
    if err := os.WriteFile(passFile, passContent, 0600); err != nil {
        t.Fatalf("Failed to write passphrase file: %v", err)
    }
    
    // Load passphrase
    passphrase, err := crypto.LoadPassphraseFromFile(passFile)
    if err != nil {
        t.Fatalf("Failed to load passphrase: %v", err)
    }
    
    // Check that trailing newline was stripped
    expected := []byte("securepass123")
    if string(passphrase) != string(expected) {
        t.Errorf("Expected passphrase '%s', got '%s'", expected, passphrase)
    }
    
    // Test non-existent file
    _, err = crypto.LoadPassphraseFromFile("/nonexistent/file")
    if err == nil {
        t.Error("Expected error for non-existent file, got nil")
    }
}