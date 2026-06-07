package transparency

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCTLog(t *testing.T) {
	tmpDir := t.TempDir()
	ct, err := NewCTLog(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ct.Close()

	err = ct.Append("123456", "CN=test", "fingerprint")
	if err != nil {
		t.Fatalf("Failed to append: %v", err)
	}

	logPath := filepath.Join(tmpDir, "audit", "ct.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("CT log not created")
	}
}
