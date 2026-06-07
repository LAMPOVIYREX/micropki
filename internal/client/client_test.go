package client

import (
	"os"
	"testing"
)

func TestGenerateCSR(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := tempDir + "/key.pem"
	csrPath := tempDir + "/csr.pem"
	err := GenerateCSR("CN=test", "rsa", 2048, []string{"dns:test"}, keyPath, csrPath)
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}
	// Проверяем, что файлы созданы
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Private key not created")
	}
	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Error("CSR not created")
	}
}
