package database

import (
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "math/big"
    "testing"
    "time"
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