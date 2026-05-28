package transparency

import (
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type CTLog struct {
    file *os.File
}

func NewCTLog(outDir string) (*CTLog, error) {
    auditDir := filepath.Join(outDir, "audit")
    if err := os.MkdirAll(auditDir, 0755); err != nil {
        return nil, err
    }
    path := filepath.Join(auditDir, "ct.log")
    f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }
    return &CTLog{file: f}, nil
}

func (ct *CTLog) Append(serial, subject, fingerprint string) error {
    line := fmt.Sprintf("%s serial=%s subject=%s fingerprint=%s\n",
        time.Now().UTC().Format(time.RFC3339), serial, subject, fingerprint)
    _, err := ct.file.WriteString(line)
    return err
}

func (ct *CTLog) Close() error {
    return ct.file.Close()
}