package database

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInitDB(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='certificates'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("Certificates table not created")
	}
}

func TestInsertAndGetCertificate(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certPEM := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	err = InsertCertificate(db, cert, certPEM)
	if err != nil {
		t.Fatalf("Failed to insert certificate: %v", err)
	}

	record, err := GetCertificateBySerial(db, fmt.Sprintf("%X", cert.SerialNumber))
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}
	if record == nil {
		t.Fatal("Certificate not found")
	}
	if record.Subject != cert.Subject.String() {
		t.Errorf("Expected subject %s, got %s", cert.Subject.String(), record.Subject)
	}
}

func TestListCertificates(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for i := 1; i <= 3; i++ {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("test%d.local", i)},
			Issuer:       pkix.Name{CommonName: "Test CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
		}
		InsertCertificate(db, cert, "pem")
	}

	records, err := ListCertificates(db, "", 10)
	if err != nil {
		t.Fatalf("Failed to list certificates: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(records))
	}
}

func TestGetCertificateBySerialNotFound(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	record, err := GetCertificateBySerial(db, "NONEXISTENT")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record != nil {
		t.Error("Expected nil record for non-existent serial")
	}
}

func TestUpdateCertificateStatus(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Insert a certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      pkix.Name{CommonName: "test"},
		Issuer:       pkix.Name{CommonName: "CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	err = InsertCertificate(db, cert, "pem")
	if err != nil {
		t.Fatal(err)
	}

	// Update status
	err = UpdateCertificateStatus(db, fmt.Sprintf("%X", cert.SerialNumber), "revoked", "keyCompromise")
	if err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	// Verify
	record, err := GetCertificateBySerial(db, fmt.Sprintf("%X", cert.SerialNumber))
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "revoked" {
		t.Errorf("Expected status revoked, got %s", record.Status)
	}
}

func TestInitDB_InvalidPath(t *testing.T) {
	_, err := InitDB("/invalid/path/test.db")
	require.Error(t, err)
}
