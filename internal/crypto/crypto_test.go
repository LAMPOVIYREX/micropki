package crypto

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	// RSA 4096
	kp, err := GenerateKeyPair("rsa", 4096)
	if err != nil {
		t.Fatalf("Failed to generate RSA 4096: %v", err)
	}
	if kp.KeyType != RSA {
		t.Errorf("Expected RSA, got %v", kp.KeyType)
	}
	if kp.KeySize != 4096 {
		t.Errorf("Expected 4096, got %d", kp.KeySize)
	}

	// ECC P-384
	kp, err = GenerateKeyPair("ecc", 384)
	if err != nil {
		t.Fatalf("Failed to generate ECC 384: %v", err)
	}
	if kp.KeyType != ECC {
		t.Errorf("Expected ECC, got %v", kp.KeyType)
	}
	if kp.KeySize != 384 {
		t.Errorf("Expected 384, got %d", kp.KeySize)
	}

	// Invalid key type
	_, err = GenerateKeyPair("invalid", 0)
	if err == nil {
		t.Error("Expected error for invalid key type")
	}

	// Invalid RSA size
	_, err = GenerateKeyPair("rsa", 1024)
	if err == nil {
		t.Error("Expected error for RSA 1024")
	}
}

func TestEncryptAndSavePrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair("rsa", 4096)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := t.TempDir() + "/key.pem"
	passphrase := []byte("test123")

	err = EncryptAndSavePrivateKey(kp, passphrase, tmpFile)
	if err != nil {
		t.Fatalf("Failed to save encrypted key: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error("Key file not created")
	}

	// Load and decrypt
	loadedKey, err := LoadAndDecryptPrivateKey(tmpFile, passphrase)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}
	if loadedKey == nil {
		t.Error("Loaded key is nil")
	}
}

func TestLoadAndDecryptPrivateKeyWrongPassphrase(t *testing.T) {
	kp, err := GenerateKeyPair("rsa", 4096)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := t.TempDir() + "/key.pem"
	passphrase := []byte("test123")
	wrongPassphrase := []byte("wrong")

	err = EncryptAndSavePrivateKey(kp, passphrase, tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadAndDecryptPrivateKey(tmpFile, wrongPassphrase)
	if err == nil {
		t.Error("Expected error for wrong passphrase")
	}
}

func TestLoadPassphraseFromFile(t *testing.T) {
	tmpFile := t.TempDir() + "/pass.txt"
	content := []byte("mysecretpass\n")
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatal(err)
	}

	passphrase, err := LoadPassphraseFromFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load passphrase: %v", err)
	}

	if string(passphrase) != "mysecretpass" {
		t.Errorf("Expected 'mysecretpass', got '%s'", passphrase)
	}

	// Non-existent file
	_, err = LoadPassphraseFromFile("/nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase []byte
		shouldErr  bool
	}{
		{"Too short", []byte("Short1!"), true},
		{"No uppercase", []byte("nouppercase123!"), true},
		{"No lowercase", []byte("NOLOWERCASE123!"), true},
		{"No digit", []byte("NoDigit!"), true},
		{"Valid", []byte("ValidPass123!"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassphrase(tt.passphrase)
			if tt.shouldErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte("secret")
	SecureZero(data)
	for i := range data {
		if data[i] != 0 {
			t.Errorf("Byte %d not zeroed: %d", i, data[i])
		}
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := "secret"
	b := "secret"
	c := "different"

	if !ConstantTimeCompare(a, b) {
		t.Error("Expected true for equal strings")
	}
	if ConstantTimeCompare(a, c) {
		t.Error("Expected false for different strings")
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	serial, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("Failed to generate serial: %v", err)
	}
	if len(serial) != 20 {
		t.Errorf("Expected 20 bytes, got %d", len(serial))
	}
}

func TestEncryptAndSaveECCPrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair("ecc", 384)
	require.NoError(t, err)
	tmpFile := filepath.Join(t.TempDir(), "ecc_key.pem")
	passphrase := []byte("EccPass123")
	err = EncryptAndSavePrivateKey(kp, passphrase, tmpFile)
	require.NoError(t, err)
	require.FileExists(t, tmpFile)

	loadedKey, err := LoadAndDecryptPrivateKey(tmpFile, passphrase)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)
	// проверяем, что это ECC ключ
	_, ok := loadedKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
}

func TestConstantTimeBytesCompare(t *testing.T) {
	a := []byte("test")
	b := []byte("test")
	c := []byte("other")
	require.True(t, ConstantTimeBytesCompare(a, b))
	require.False(t, ConstantTimeBytesCompare(a, c))
}

func TestSecureCompare(t *testing.T) {
	a := []byte("abc")
	b := []byte("abc")
	c := []byte("abd")
	require.True(t, SecureCompare(a, b))
	require.False(t, SecureCompare(a, c))
}

func TestGenerateSecureRandom(t *testing.T) {
	rand, err := GenerateSecureRandom(16)
	require.NoError(t, err)
	require.Len(t, rand, 16)
}

func TestSecureUint64(t *testing.T) {
	_, err := SecureUint64()
	require.NoError(t, err)
}

func TestSecureString(t *testing.T) {
	s := "password"
	b := SecureString(s)
	require.Equal(t, len(s), len(b))
}

func TestSaveEncryptedKey(t *testing.T) {
	kp, _ := GenerateKeyPair("rsa", 2048)
	tmpFile := filepath.Join(t.TempDir(), "enc.key")
	pass := []byte("test123")
	err := SaveEncryptedKey(kp, pass, tmpFile, 0600)
	require.NoError(t, err)
	require.FileExists(t, tmpFile)
}

func TestEncryptAndSaveECCKey(t *testing.T) {
	kp, _ := GenerateKeyPair("ecc", 384)
	pass := []byte("TestPass123!")
	tmpFile := filepath.Join(t.TempDir(), "ecc_key.pem")
	err := EncryptAndSavePrivateKey(kp, pass, tmpFile)
	require.NoError(t, err)
	// загружаем обратно
	loadedKey, err := LoadAndDecryptPrivateKey(tmpFile, pass)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)
}

func TestGenerateKeyPair_ECC_BadSize(t *testing.T) {
	_, err := GenerateKeyPair("ecc", 256) // разрешены только 384
	require.Error(t, err)
}

func TestSaveEncryptedKey_ECC(t *testing.T) {
	kp, _ := GenerateKeyPair("ecc", 384)
	pass := []byte("test")
	tmpFile := filepath.Join(t.TempDir(), "ecc.key")
	err := SaveEncryptedKey(kp, pass, tmpFile, 0600)
	require.NoError(t, err)
	require.FileExists(t, tmpFile)
}

func TestLoadAndDecryptPrivateKey_WrongPassphrase(t *testing.T) {
	// Генерируем ключ и шифруем
	kp, _ := GenerateKeyPair("rsa", 2048)
	pass := []byte("correct")
	tmpFile := filepath.Join(t.TempDir(), "key.pem")
	err := EncryptAndSavePrivateKey(kp, pass, tmpFile)
	require.NoError(t, err)

	// Пытаемся загрузить с неверным паролем
	_, err = LoadAndDecryptPrivateKey(tmpFile, []byte("wrongpass"))
	require.Error(t, err)
}

func TestLoadAndDecryptPrivateKey_InvalidPEM(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(tmpFile, []byte("not a pem file"), 0600)
	_, err := LoadAndDecryptPrivateKey(tmpFile, nil)
	require.Error(t, err)
}

func TestLoadAndDecryptPrivateKey_BadPEM(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(tmpFile, []byte("not a pem"), 0600)
	_, err := LoadAndDecryptPrivateKey(tmpFile, nil)
	require.Error(t, err)
}

func TestEncryptAndSavePrivateKey_DirError(t *testing.T) {
	// Создаём файл, чтобы os.MkdirAll не смогла создать директорию с таким же именем
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "key.pem")
	// Сначала создадим файл, чтобы путь к нему стал невозможным для MkdirAll
	os.WriteFile(filePath, []byte("block"), 0600)

	kp, _ := GenerateKeyPair("rsa", 2048)
	pass := []byte("test")
	// Попытка сохранить ключ по пути, где компонент пути является файлом, вызовет ошибку
	err := EncryptAndSavePrivateKey(kp, pass, filePath+"/subdir/key.pem")
	require.Error(t, err)
}
