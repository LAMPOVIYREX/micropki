package database

import (
    "crypto/x509"
    "database/sql"
    "fmt"
    "time"
)

// CertificateRecord represents a certificate in the database
type CertificateRecord struct {
    ID               int
    SerialHex        string
    Subject          string
    Issuer           string
    NotBefore        time.Time
    NotAfter         time.Time
    CertPEM          string
    Status           string
    RevocationReason *string
    RevocationDate   *time.Time
    CreatedAt        time.Time
}

// InsertCertificate inserts a new certificate into the database
func InsertCertificate(db *sql.DB, cert *x509.Certificate, certPEM string) error {
    query := `
        INSERT INTO certificates (
            serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `
    
    _, err := db.Exec(query,
        fmt.Sprintf("%X", cert.SerialNumber),
        cert.Subject.String(),
        cert.Issuer.String(),
        cert.NotBefore.Format(time.RFC3339),
        cert.NotAfter.Format(time.RFC3339),
        certPEM,
        "valid",
        time.Now().Format(time.RFC3339),
    )
    
    if err != nil {
        return fmt.Errorf("failed to insert certificate: %w", err)
    }
    
    return nil
}

// GetCertificateBySerial retrieves a certificate by serial number
func GetCertificateBySerial(db *sql.DB, serialHex string) (*CertificateRecord, error) {
    query := `
        SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, 
               status, revocation_reason, revocation_date, created_at
        FROM certificates WHERE serial_hex = ?
    `
    
    row := db.QueryRow(query, serialHex)
    
    var record CertificateRecord
    var revocationReason sql.NullString
    var revocationDate sql.NullString
    
    err := row.Scan(
        &record.ID, &record.SerialHex, &record.Subject, &record.Issuer,
        &record.NotBefore, &record.NotAfter, &record.CertPEM,
        &record.Status, &revocationReason, &revocationDate, &record.CreatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get certificate: %w", err)
    }
    
    if revocationReason.Valid {
        record.RevocationReason = &revocationReason.String
    }
    if revocationDate.Valid {
        parsed, _ := time.Parse(time.RFC3339, revocationDate.String)
        record.RevocationDate = &parsed
    }
    
    return &record, nil
}

// ListCertificates lists certificates with optional filters
func ListCertificates(db *sql.DB, status string, limit int) ([]CertificateRecord, error) {
    query := "SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at FROM certificates"
    args := []interface{}{}
    
    if status != "" {
        query += " WHERE status = ?"
        args = append(args, status)
    }
    
    query += " ORDER BY created_at DESC"
    
    if limit > 0 {
        query += " LIMIT ?"
        args = append(args, limit)
    }
    
    rows, err := db.Query(query, args...)
    if err != nil {
        return nil, fmt.Errorf("failed to list certificates: %w", err)
    }
    defer rows.Close()
    
    var records []CertificateRecord
    for rows.Next() {
        var record CertificateRecord
        var notBeforeStr, notAfterStr, createdAtStr string
        
        err := rows.Scan(
            &record.ID, &record.SerialHex, &record.Subject, &record.Issuer,
            &notBeforeStr, &notAfterStr, &record.CertPEM,
            &record.Status, &createdAtStr,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan row: %w", err)
        }
        
        // Parse time strings
        record.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
        record.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
        record.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
        
        records = append(records, record)
    }
    
    return records, nil
}

// UpdateCertificateStatus updates the status of a certificate
func UpdateCertificateStatus(db *sql.DB, serialHex, status, reason string) error {
    query := `
        UPDATE certificates 
        SET status = ?, revocation_reason = ?, revocation_date = ?
        WHERE serial_hex = ?
    `
    
    revocationDate := time.Now().Format(time.RFC3339)
    _, err := db.Exec(query, status, reason, revocationDate, serialHex)
    if err != nil {
        return fmt.Errorf("failed to update certificate status: %w", err)
    }
    
    return nil
}

// AddCompromisedKey records a compromised public key
func AddCompromisedKey(db *sql.DB, pubKeyHash, serial, reason string) error {
    _, err := db.Exec(`INSERT OR IGNORE INTO compromised_keys 
        (public_key_hash, certificate_serial, compromise_date, compromise_reason)
        VALUES (?, ?, ?, ?)`,
        pubKeyHash, serial, time.Now().Format(time.RFC3339), reason)
    return err
}

// IsKeyCompromised checks if a public key hash is compromised
func IsKeyCompromised(db *sql.DB, pubKeyHash string) (bool, error) {
    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM compromised_keys WHERE public_key_hash = ?", pubKeyHash).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}
