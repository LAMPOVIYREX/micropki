package main

import (
    "database/sql"
    "fmt"
    "log"
    "time"
    
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    db, err := sql.Open("sqlite3", "./test-ca/pki-rsa/micropki.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // Добавляем тестовые сертификаты
    certs := []struct {
        serial  string
        subject string
    }{
        {"1111111111111111", "CN=server1.example.com"},
        {"2222222222222222", "CN=server2.example.com"},
        {"3333333333333333", "CN=client.example.com"},
    }
    
    for _, cert := range certs {
        _, err = db.Exec(`
            INSERT OR IGNORE INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
            cert.serial,
            cert.subject,
            "CN=Intermediate CA",
            time.Now().Format(time.RFC3339),
            time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "valid",
            time.Now().Format(time.RFC3339),
        )
        if err != nil {
            log.Printf("Error inserting %s: %v", cert.serial, err)
        } else {
            fmt.Printf("Inserted certificate: %s\n", cert.serial)
        }
    }
    
    // Показываем все сертификаты
    rows, err := db.Query("SELECT serial_hex, subject, status FROM certificates")
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    
    fmt.Println("\nCertificates in database:")
    for rows.Next() {
        var serial, subject, status string
        rows.Scan(&serial, &subject, &status)
        fmt.Printf("  Serial: %s, Subject: %s, Status: %s\n", serial, subject, status)
    }
}
