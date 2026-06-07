package ca

import (
	"os"
	"path/filepath"
	"testing"

	"micropki/internal/logger"
	"micropki/pkg/types"
)

func TestInitIntermediateCA(t *testing.T) {
	// 1. Создаём Root CA
	tempDir := t.TempDir()
	passFile := filepath.Join(tempDir, "pass.txt")
	err := os.WriteFile(passFile, []byte("TestPass123!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	rootConfig := &types.CAConfig{
		Subject:      "/CN=Test Root CA",
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("TestPass123!"),
		OutDir:       tempDir,
		ValidityDays: 365,
	}
	log, _ := logger.NewLogger("")
	ca := NewCA(rootConfig, log)
	_, err = ca.InitRootCA()
	if err != nil {
		t.Fatalf("InitRootCA failed: %v", err)
	}

	// 2. Создаём Intermediate CA
	interOutDir := filepath.Join(tempDir, "intermediate")
	interConfig := &IntermediateCAConfig{
		Subject:          "/CN=Test Intermediate CA",
		KeyType:          "rsa",
		KeySize:          4096,
		Passphrase:       []byte("TestPass123!"),
		OutDir:           interOutDir,
		ValidityDays:     365,
		RootCAPassphrase: []byte("TestPass123!"),
		RootCADir:        tempDir,
		MaxPathLen:       0,
	}
	files, err := ca.InitIntermediateCA(interConfig)
	if err != nil {
		t.Fatalf("InitIntermediateCA failed: %v", err)
	}
	// Проверяем, что сертификат создан
	if _, err := os.Stat(files.CertPath); os.IsNotExist(err) {
		t.Error("Intermediate certificate not created")
	}
	if _, err := os.Stat(files.PrivateKeyPath); os.IsNotExist(err) {
		t.Error("Intermediate private key not created")
	}
}
