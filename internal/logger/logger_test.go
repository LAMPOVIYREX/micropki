package logger

import (
    "os"
    "path/filepath"
    "testing"
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