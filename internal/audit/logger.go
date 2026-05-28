package audit

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
)

// LogEntry represents a single audit log entry
type LogEntry struct {
    Timestamp string                 `json:"timestamp"`
    Level     string                 `json:"level"`
    Operation string                 `json:"operation"`
    Status    string                 `json:"status"`
    Message   string                 `json:"message"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
    Integrity IntegrityInfo          `json:"integrity"`
}

type IntegrityInfo struct {
    PrevHash string `json:"prev_hash"`
    Hash     string `json:"hash"`
}

type AuditLogger struct {
    file      *os.File
    mu        sync.Mutex
    lastHash  string
}

// NewAuditLogger creates or opens the audit log and initialises hash chain
func NewAuditLogger(outDir string) (*AuditLogger, error) {
    auditDir := filepath.Join(outDir, "audit")
    if err := os.MkdirAll(auditDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create audit directory: %w", err)
    }

    logPath := filepath.Join(auditDir, "audit.log")
    file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return nil, fmt.Errorf("failed to open audit log: %w", err)
    }

    al := &AuditLogger{
        file:     file,
        lastHash: "0000000000000000000000000000000000000000000000000000000000000000",
    }

    // Get the hash of the last entry if file is not empty
    info, err := file.Stat()
    if err != nil {
        return nil, err
    }
    if info.Size() > 0 {
        // Read the last line and extract its hash (simplified: we'll store lastHash separately)
        // For simplicity, we'll read the whole file and compute chain? Or store last hash in a separate file.
        // Implementing separate chain file as recommended.
        chainPath := filepath.Join(auditDir, "chain.dat")
        data, err := os.ReadFile(chainPath)
        if err == nil && len(data) > 0 {
            al.lastHash = string(data)
        }
    }

    return al, nil
}

// Log writes an audit entry
func (al *AuditLogger) Log(level, operation, status, message string, metadata map[string]interface{}) error {
    al.mu.Lock()
    defer al.mu.Unlock()

    entry := LogEntry{
        Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
        Level:     level,
        Operation: operation,
        Status:    status,
        Message:   message,
        Metadata:  metadata,
    }

    // Compute previous hash
    entry.Integrity.PrevHash = al.lastHash

    // Compute hash of the entry excluding the 'hash' field itself
    // We need canonical JSON without the hash field
    entryCopy := entry
    entryCopy.Integrity.Hash = "" // temporary
    data, err := json.Marshal(entryCopy)
    if err != nil {
        return err
    }
    h := sha256.Sum256(data)
    entry.Integrity.Hash = hex.EncodeToString(h[:])

    // Final JSON with hash
    finalData, err := json.Marshal(entry)
    if err != nil {
        return err
    }
    if _, err := al.file.Write(append(finalData, '\n')); err != nil {
        return err
    }
    al.lastHash = entry.Integrity.Hash

    // Update chain.dat
    auditDir := filepath.Dir(al.file.Name())
    chainPath := filepath.Join(auditDir, "chain.dat")
    if err := os.WriteFile(chainPath, []byte(al.lastHash), 0600); err != nil {
        // non-fatal
    }
    return nil
}

// Close closes the log file
func (al *AuditLogger) Close() error {
    return al.file.Close()
}