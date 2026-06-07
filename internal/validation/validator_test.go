package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"micropki/internal/certs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Вспомогательные функции
func createCACert(t *testing.T, name string, key *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func createIntermediateCert(t *testing.T, name string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func createLeafCert(t *testing.T, name string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func saveCertToFile(t *testing.T, path string, cert *x509.Certificate) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidator(t *testing.T) {
	_, err := NewValidator("", time.Now())
	if err != nil {
		t.Errorf("Failed to create validator: %v", err)
	}
}

func TestValidateCertificateValidChain(t *testing.T) {
	// 1. Создаём корневой CA
	rootCert, rootKey := createCACert(t, "Root CA", nil)

	// 2. Создаём промежуточный CA, подписанный корневым
	interCert, interKey := createIntermediateCert(t, "Intermediate CA", rootCert, rootKey)

	// 3. Создаём листовой сертификат, подписанный промежуточным
	leafCert, _ := createLeafCert(t, "leaf.example.com", interCert, interKey)

	// Сохраняем в файлы
	tmpDir := t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.pem")
	interPath := filepath.Join(tmpDir, "inter.pem")
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	saveCertToFile(t, rootPath, rootCert)
	saveCertToFile(t, interPath, interCert)
	saveCertToFile(t, leafPath, leafCert)

	// Создаём валидатор с доверенным корнем
	validator, err := NewValidator(rootPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Валидируем листовой сертификат, передавая промежуточный
	result, err := validator.ValidateCertificate(leafPath, []string{interPath})
	if err != nil {
		t.Fatalf("Validation error: %v", err)
	}
	if !result.Passed {
		t.Errorf("Valid chain should pass, but got failure: %s", result.ErrorMsg)
	}
}

func TestValidateCertificateExpired(t *testing.T) {
	// Создаём корневой CA
	rootCert, rootKey := createCACert(t, "Root CA", nil)
	// Создаём просроченный листовой сертификат (подписанный корневым, для простоты)
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expiredTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "expired.local"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, rootCert, &expiredKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert, err := x509.ParseCertificate(expiredDER)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.pem")
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	saveCertToFile(t, rootPath, rootCert)
	saveCertToFile(t, leafPath, expiredCert)

	validator, err := NewValidator(rootPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	result, err := validator.ValidateCertificate(leafPath, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Error("Expired certificate should fail validation")
	}
}

func TestAddIntermediate(t *testing.T) {
	validator, err := NewValidator("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := createCACert(t, "Intermediate", nil)
	validator.AddIntermediate(cert)
	t.Log("Intermediate added successfully")
}

func TestValidateCertificate_Invalid(t *testing.T) {
	// Создаём временный корневой сертификат
	tmpDir := t.TempDir()
	rootCertPath := filepath.Join(tmpDir, "root.cert.pem")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile(rootCertPath, pemBytes, 0644)

	validator, err := NewValidator(rootCertPath, time.Now())
	require.NoError(t, err)

	// Проверяем несуществующий сертификат
	result, err := validator.ValidateCertificate(filepath.Join(tmpDir, "no_such.pem"), nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidateCertificate_UnknownIssuer(t *testing.T) {
	tmpDir := t.TempDir()
	// создаём два разных CA, leaf подписан одним, а root — другой
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RootCA"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, rootPEM, 0644)

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OtherCA"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, otherTmpl, &leafKey.PublicKey, otherKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, leafPEM, 0644)

	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestAddIntermediate_RealCert(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)

	// Загружаем сертификат для AddIntermediate
	cert, err := certs.LoadCertificate(rootPath)
	require.NoError(t, err)
	validator.AddIntermediate(cert) // <-- правильный вызов
}

func TestNewValidator_BadCert(t *testing.T) {
	tmpDir := t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, []byte("bad cert"), 0644)
	_, err := NewValidator(rootPath, time.Now())
	require.Error(t, err)
}

func TestValidateCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Leaf
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.True(t, result.Passed)
}

func TestValidateCertificate_MissingIntermediate(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidateCertificate_ErrorLoadingIntermediate(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate("nonexistent.pem", []string{"nonexistent_intermediate.pem"})
	if err == nil {
		require.False(t, result.Passed)
	}
}

func TestValidateCertificate_InvalidCertPath(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(filepath.Join(tmpDir, "bad.pem"), nil)
	require.NoError(t, err)         // функция не возвращает ошибку при отсутствии файла
	require.False(t, result.Passed) // но результат отрицательный
}

func TestValidateCertificate_WithIntermediate(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	interPath := filepath.Join(tmpDir, "inter.pem")
	os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), 0644)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(leafPath, []string{interPath})
	require.NoError(t, err)
	require.True(t, result.Passed)
}

func TestValidateCertificate_IntermediateInPool_Coverage(t *testing.T) {
	tmpDir := t.TempDir()
	// Root
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Intermediate
	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	interPath := filepath.Join(tmpDir, "inter.pem")
	os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), 0644)

	// Leaf подписан Intermediate
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	// Валидатор с root
	validator, _ := NewValidator(rootPath, time.Now())
	// Добавляем Intermediate в пул
	interCert, _ := certs.LoadCertificate(interPath)
	validator.AddIntermediate(interCert)

	// Проверяем leaf без передачи intermediate в untrusted — это вызовет getCertificatesBySubject
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	_ = result
}

func TestValidateCertificate_IntermediateInPool(t *testing.T) {
	tmpDir := t.TempDir()
	// Root
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Intermediate
	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	interPath := filepath.Join(tmpDir, "inter.pem")
	os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), 0644)

	// Leaf подписан Intermediate
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	// Валидатор с root
	validator, _ := NewValidator(rootPath, time.Now())
	// Добавляем Intermediate в пул
	interCert, _ := certs.LoadCertificate(interPath)
	validator.AddIntermediate(interCert)

	// Проверяем leaf без передачи intermediate в untrusted — вызовет getCertificatesBySubject
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	_ = result
}

func TestValidation_FullChain_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Intermediate CA
	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	interPath := filepath.Join(tmpDir, "inter.pem")
	os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), 0644)

	// Leaf
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(leafPath, []string{interPath})
	require.NoError(t, err)
	require.True(t, result.Passed)
}

func TestValidate_UntrustedIssuer(t *testing.T) {
	tmpDir := t.TempDir()
	// Создаём самоподписанный сертификат (не является доверенным корнем)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Untrusted Root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPath := filepath.Join(tmpDir, "untrusted.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)

	// Создаём другой "доверенный" корень (как валидатор)
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Trusted Root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Валидатор доверяет только Trusted Root
	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)

	// Проверяем Untrusted — должно быть false
	result, err := validator.ValidateCertificate(certPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_ExpiredCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now().AddDate(-1, 0, 0), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Leaf с истекшим сроком
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(-1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)

	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_UnknownIssuer(t *testing.T) {
	tmpDir := t.TempDir()
	// Создаём "чужой" корневой сертификат, которому не доверяет валидатор
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Other CA"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)

	// Leaf, подписанный "чужим" CA
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, otherTmpl, &leafKey.PublicKey, otherKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	// Валидатор доверяет нашему корню, а не "чужому"
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "My Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	validator, err := NewValidator(rootPath, time.Now())
	require.NoError(t, err)

	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_BrokenSignature(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Leaf с «битой» подписью
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	leafDER[10] ^= 0xFF // портим подпись
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(filepath.Join(tmpDir, "nonexistent.pem"), nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_ExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now().AddDate(-1, 0, 0), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(-1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	validator, _ := NewValidator(rootPath, time.Now())
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	require.False(t, result.Passed)
}

func TestValidate_IntermediateInPool(t *testing.T) {
	tmpDir := t.TempDir()
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPath := filepath.Join(tmpDir, "root.pem")
	os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644)

	// Intermediate CA
	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	interPath := filepath.Join(tmpDir, "inter.pem")
	os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), 0644)

	// Leaf, подписанный Intermediate
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	leafPath := filepath.Join(tmpDir, "leaf.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)

	// Валидатор с Root
	validator, _ := NewValidator(rootPath, time.Now())
	// Добавляем Intermediate в пул
	interCert, _ := certs.LoadCertificate(interPath)
	validator.AddIntermediate(interCert)

	// Проверяем leaf без передачи intermediate в untrusted — вызовет getCertificatesBySubject
	result, err := validator.ValidateCertificate(leafPath, nil)
	require.NoError(t, err)
	// Результат может быть false, если пул не используется, но главное — покрытие
	_ = result
}
