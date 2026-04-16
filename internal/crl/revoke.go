package crl

import (
    "database/sql"
    "fmt"
    "math/big"
    "time"
)

// RevokeCertificate revokes a certificate in the database
func RevokeCertificate(db *sql.DB, serialHex, reason string) error {
    // Check if certificate exists
    var status string
    var currentReason sql.NullString
    err := db.QueryRow(
        "SELECT status, revocation_reason FROM certificates WHERE serial_hex = ?",
        serialHex,
    ).Scan(&status, &currentReason)
    
    if err == sql.ErrNoRows {
        return fmt.Errorf("certificate with serial %s not found", serialHex)
    }
    if err != nil {
        return fmt.Errorf("database error: %w", err)
    }
    
    // Check if already revoked
    if status == "revoked" {
        if currentReason.Valid {
            return fmt.Errorf("certificate already revoked with reason: %s", currentReason.String)
        }
        return fmt.Errorf("certificate already revoked")
    }
    
    // Validate reason
    if _, ok := ReasonCodeMap[reason]; !ok {
        return fmt.Errorf("invalid revocation reason: %s", reason)
    }
    
    // Update certificate status
    _, err = db.Exec(
        `UPDATE certificates 
         SET status = 'revoked', 
             revocation_reason = ?, 
             revocation_date = ?
         WHERE serial_hex = ?`,
        reason, time.Now().Format(time.RFC3339), serialHex,
    )
    if err != nil {
        return fmt.Errorf("failed to update certificate status: %w", err)
    }
    
    return nil
}

// GetRevokedCertificates retrieves all revoked certificates for a CA
func GetRevokedCertificates(db *sql.DB, issuerDN string) ([]RevokedCertificate, error) {
    rows, err := db.Query(
        `SELECT serial_hex, revocation_date, revocation_reason 
         FROM certificates 
         WHERE issuer = ? AND status = 'revoked'`,
        issuerDN,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to query revoked certificates: %w", err)
    }
    defer rows.Close()
    
    var revoked []RevokedCertificate
    for rows.Next() {
        var serialHex string
        var revocationDate sql.NullString
        var reason sql.NullString
        
        if err := rows.Scan(&serialHex, &revocationDate, &reason); err != nil {
            return nil, fmt.Errorf("failed to scan row: %w", err)
        }
        
        // Parse serial number
        var serial big.Int
        serial.SetString(serialHex, 16)
        
        // Parse revocation time (use current time if NULL)
        var revTime time.Time
        if revocationDate.Valid {
            revTime, err = time.Parse(time.RFC3339, revocationDate.String)
            if err != nil {
                revTime = time.Now()
            }
        } else {
            revTime = time.Now()
        }
        
        // Get reason code (default to unspecified if NULL)
        reasonCode := 0
        if reason.Valid {
            if code, ok := ReasonCodeMap[reason.String]; ok {
                reasonCode = code
            }
        }
        
        revoked = append(revoked, RevokedCertificate{
            SerialNumber:   &serial,
            RevocationTime: revTime,
            ReasonCode:     reasonCode,
        })
    }
    
    return revoked, nil
}