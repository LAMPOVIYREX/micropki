package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := tmpDir
	al, err := NewAuditLogger(outDir)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer al.Close()

	err = al.Log("AUDIT", "test", "success", "test message", nil)
	if err != nil {
		t.Fatalf("Failed to log: %v", err)
	}

	// Check file exists
	logPath := filepath.Join(outDir, "audit", "audit.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Audit log not created")
	}
}

func TestAuditLogQuery(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := tmpDir
	al, err := NewAuditLogger(outDir)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	al.Log("AUDIT", "test_op", "success", "message", map[string]interface{}{"key": "value"})
	al.Log("INFO", "another", "failure", "error", nil)

	logPath := filepath.Join(outDir, "audit", "audit.log")
	entries, err := QueryLog(logPath, time.Time{}, time.Time{}, "", "", "", 0)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
}

func TestAuditVerify(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := tmpDir
	al, err := NewAuditLogger(outDir)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	al.Log("AUDIT", "op1", "success", "msg1", nil)
	al.Log("AUDIT", "op2", "success", "msg2", nil)

	logPath := filepath.Join(outDir, "audit", "audit.log")
	ok, errMsg, err := VerifyIntegrity(logPath, filepath.Join(outDir, "audit", "chain.dat"))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Errorf("Integrity check failed: %s", errMsg)
	}
}

func TestAuditLogQueryWithFilters(t *testing.T) {
	tmpDir := t.TempDir()
	al, err := NewAuditLogger(tmpDir)
	require.NoError(t, err)
	defer al.Close()

	al.Log("AUDIT", "op1", "success", "msg1", map[string]interface{}{"serial": "123"})
	al.Log("ERROR", "op2", "failure", "msg2", nil)

	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	entries, err := QueryLog(logPath, time.Time{}, time.Time{}, "ERROR", "", "", 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "ERROR", entries[0].Level)
}

func TestAuditLogQuery_BySerial(t *testing.T) {
	tmpDir := t.TempDir()
	al, _ := NewAuditLogger(tmpDir)
	defer al.Close()
	al.Log("AUDIT", "issue", "success", "cert", map[string]interface{}{"serial": "SERIAL1"})
	al.Log("AUDIT", "revoke", "success", "cert", map[string]interface{}{"serial": "SERIAL2"})
	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	entries, err := QueryLog(logPath, time.Time{}, time.Time{}, "", "", "SERIAL1", 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "SERIAL1", entries[0].Metadata["serial"])
}

func TestAuditLogQuery_DateRange(t *testing.T) {
	tmpDir := t.TempDir()
	al, _ := NewAuditLogger(tmpDir)
	defer al.Close()
	al.Log("AUDIT", "test", "success", "old", nil)
	time.Sleep(10 * time.Millisecond)
	mid := time.Now()
	time.Sleep(10 * time.Millisecond)
	al.Log("AUDIT", "test", "success", "new", nil)

	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	entries, _ := QueryLog(logPath, mid, time.Time{}, "", "", "", 0)
	require.Len(t, entries, 1)
	require.Equal(t, "new", entries[0].Message)
}

func TestAuditVerifyTampered(t *testing.T) {
	tmpDir := t.TempDir()
	al, _ := NewAuditLogger(tmpDir)
	al.Log("AUDIT", "op1", "success", "msg1", nil)
	al.Close()

	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write([]byte("tampered\n"))
	f.Close()

	ok, errMsg, err := VerifyIntegrity(logPath, filepath.Join(tmpDir, "audit", "chain.dat"))
	require.NoError(t, err)
	require.False(t, ok)
	require.NotEmpty(t, errMsg)
}

func TestAuditLogQuery_NoResults(t *testing.T) {
	tmpDir := t.TempDir()
	al, _ := NewAuditLogger(tmpDir)
	al.Log("AUDIT", "test", "success", "msg", nil)
	al.Close()
	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	entries, err := QueryLog(logPath, time.Now().Add(time.Hour), time.Time{}, "", "", "", 0)
	require.NoError(t, err)
	require.Len(t, entries, 0)
}

func TestNewAuditLogger_ExistingChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0700)
	// Создаём chain.dat с некоторым хешем
	chainPath := filepath.Join(auditDir, "chain.dat")
	os.WriteFile(chainPath, []byte("abcdef1234567890"), 0600)

	al, err := NewAuditLogger(tmpDir)
	require.NoError(t, err)
	defer al.Close()
	require.NotNil(t, al)
	// Проверим, что lastHash загружен (косвенно: следующий лог будет использовать этот хеш)
	err = al.Log("AUDIT", "test", "success", "msg", nil)
	require.NoError(t, err)
}

func TestNewAuditLogger_WithExistingChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0700)
	// Создаём chain.dat с некоторым хешем
	chainPath := filepath.Join(auditDir, "chain.dat")
	os.WriteFile(chainPath, []byte("abcdef1234567890"), 0600)

	al, err := NewAuditLogger(tmpDir)
	require.NoError(t, err)
	defer al.Close()
	require.NotNil(t, al)
	// Косвенно проверяем: lastHash должен быть загружен, лог должен продолжаться
	err = al.Log("AUDIT", "test", "success", "msg", nil)
	require.NoError(t, err)
}

func TestVerifyIntegrity_BrokenChain(t *testing.T) {
	tmpDir := t.TempDir()
	al, _ := NewAuditLogger(tmpDir)
	al.Log("AUDIT", "test", "ok", "msg1", nil)
	al.Log("AUDIT", "test", "ok", "msg2", nil)
	al.Close()

	// портим лог
	logPath := filepath.Join(tmpDir, "audit", "audit.log")
	data, _ := os.ReadFile(logPath)
	data[len(data)-10] ^= 0xFF // инвертируем байт
	os.WriteFile(logPath, data, 0600)

	ok, _, err := VerifyIntegrity(logPath, filepath.Join(tmpDir, "audit", "chain.dat"))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestNewAuditLogger_NoExistingDir(t *testing.T) {
	tmpDir := t.TempDir()
	// Директория audit не существует, NewAuditLogger должна создать её
	al, err := NewAuditLogger(tmpDir)
	require.NoError(t, err)
	defer al.Close()
	require.DirExists(t, filepath.Join(tmpDir, "audit"))
}

func TestNewAuditLogger_OpenError(t *testing.T) {
	// Создаём директорию без прав на запись
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0555) // только чтение и выполнение
	defer os.Chmod(auditDir, 0755)

	_, err := NewAuditLogger(tmpDir)
	require.Error(t, err)
}

func TestQueryLog_FileNotFound(t *testing.T) {
	_, err := QueryLog("/nonexistent/path", time.Time{}, time.Time{}, "", "", "", 0)
	require.Error(t, err)
}

func TestNewAuditLogger_CreateDirError(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit")
	// Создаём файл вместо директории, чтобы os.MkdirAll вернула ошибку
	os.WriteFile(auditPath, []byte("block"), 0444)
	_, err := NewAuditLogger(tmpDir)
	require.Error(t, err)
}
