package logger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	log, err := NewLogger("")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()
	log.Info("test")
}

func TestLoggerFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	log, err := NewLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	log.Info("test message")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("Log file empty")
	}
}

func TestLoggerLevels(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	l, _ := NewLogger(logPath)
	defer l.Close()

	l.Warning("warning msg")
	l.Error("error msg")

	data, _ := os.ReadFile(logPath)
	content := string(data)
	require.Contains(t, content, "WARNING")
	require.Contains(t, content, "ERROR")
}

func TestLogger_Close_File(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.log")
	l, _ := NewLogger(tmpFile)
	err := l.Close()
	require.NoError(t, err)
}
