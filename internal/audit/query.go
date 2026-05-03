package audit

import (
    "bufio"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"
)

// QueryLog читает audit.log, фильтрует записи по параметрам и возвращает их
func QueryLog(logPath string, from, to time.Time, level, operation, serial string, limit int) ([]LogEntry, error) {
    file, err := os.Open(logPath)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    var entries []LogEntry
    for scanner.Scan() {
        var entry LogEntry
        if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
            continue
        }
        ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
        if err != nil {
            continue
        }
        if !from.IsZero() && ts.Before(from) {
            continue
        }
        if !to.IsZero() && ts.After(to) {
            continue
        }
        if level != "" && entry.Level != level {
            continue
        }
        if operation != "" && entry.Operation != operation {
            continue
        }
        if serial != "" {
            if entry.Metadata == nil {
                continue
            }
            s, ok := entry.Metadata["serial"]
            if !ok || s != serial {
                continue
            }
        }
        entries = append(entries, entry)
        if limit > 0 && len(entries) >= limit {
            break
        }
    }
    return entries, scanner.Err()
}

// VerifyIntegrity проверяет хеш-цепочку audit.log
func VerifyIntegrity(logPath, chainPath string) (bool, string, error) {
    file, err := os.Open(logPath)
    if err != nil {
        return false, "", err
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    var prevHash string
    first := true
    lineNum := 0
    for scanner.Scan() {
        lineNum++
        line := scanner.Bytes()
        var entry LogEntry
        if err := json.Unmarshal(line, &entry); err != nil {
            return false, fmt.Sprintf("line %d: invalid JSON", lineNum), nil
        }
        if first {
            if entry.Integrity.PrevHash != "0000000000000000000000000000000000000000000000000000000000000000" {
                return false, fmt.Sprintf("first entry prev_hash not zero: %s", entry.Integrity.PrevHash), nil
            }
            first = false
        } else if entry.Integrity.PrevHash != prevHash {
            return false, fmt.Sprintf("entry %d: prev_hash mismatch (expected %s, got %s)", lineNum, prevHash, entry.Integrity.PrevHash), nil
        }
        // Вычисляем hash текущей записи (без поля integrity.hash)
        entryCopy := entry
        entryCopy.Integrity.Hash = ""
        data, err := json.Marshal(entryCopy)
        if err != nil {
            return false, fmt.Sprintf("entry %d: failed to marshal for hash", lineNum), nil
        }
        hash := sha256.Sum256(data)
        computed := hex.EncodeToString(hash[:])
        if entry.Integrity.Hash != computed {
            return false, fmt.Sprintf("entry %d: hash mismatch (computed %s, stored %s)", lineNum, computed, entry.Integrity.Hash), nil
        }
        prevHash = entry.Integrity.Hash
    }
    chainData, err := os.ReadFile(chainPath)
    if err == nil && len(chainData) > 0 {
        lastHash := strings.TrimSpace(string(chainData))
        if lastHash != prevHash {
            return false, fmt.Sprintf("last hash mismatch with chain.dat (expected %s, got %s)", lastHash, prevHash), nil
        }
    }
    return true, "", scanner.Err()
}