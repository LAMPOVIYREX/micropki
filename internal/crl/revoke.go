package crl

import (
    "crypto/x509"
    "database/sql"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "time"

    "micropki/internal/crypto"
    "micropki/internal/database"
)

// RevokeCertificate обновляет статус в БД и (опционально) генерирует новый CRL
func RevokeCertificate(db *sql.DB, serialHex, reason, caDir, caType, passphraseFile string) error {
    // 1. Проверка существования сертификата и текущего статуса
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
    if status == "revoked" {
        if currentReason.Valid {
            return fmt.Errorf("certificate already revoked with reason: %s", currentReason.String)
        }
        return fmt.Errorf("certificate already revoked")
    }

    // 2. Валидация причины отзыва
    if _, ok := ReasonCodeMap[reason]; !ok {
        return fmt.Errorf("invalid revocation reason: %s", reason)
    }

    // 3. Обновление статуса в БД
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

    // 4. *** АВТОМАТИЧЕСКАЯ ГЕНЕРАЦИЯ CRL ***
    //    Вызываем отдельную функцию, которая перегенерирует CRL для указанного CA
    if err := generateCRLAfterRevocation(caDir, caType, passphraseFile); err != nil {
        // Логируем ошибку, но не прерываем операцию отзыва
        // В реальной системе можно вернуть ошибку, но для простоты – только лог
        fmt.Fprintf(os.Stderr, "Warning: failed to auto-generate CRL: %v\n", err)
    }

    return nil
}

// generateCRLAfterRevocation загружает CA-сертификат и ключ, получает список отозванных из БД и создаёт CRL
func generateCRLAfterRevocation(caDir, caType, passphraseFile string) error {
    // Определяем пути к сертификату и ключу
    var caCertPath, caKeyPath, crlPath string
    if caType == "root" {
        caCertPath = filepath.Join(caDir, "certs", "ca.cert.pem")
        caKeyPath = filepath.Join(caDir, "private", "ca.key.pem")
        crlPath = filepath.Join(caDir, "crl", "root.crl.pem")
    } else if caType == "intermediate" {
        caCertPath = filepath.Join(caDir, "certs", "intermediate.cert.pem")
        caKeyPath = filepath.Join(caDir, "private", "intermediate.key.pem")
        crlPath = filepath.Join(caDir, "crl", "intermediate.crl.pem")
    } else {
        return fmt.Errorf("invalid CA type: %s", caType)
    }

    // Загружаем CA-сертификат
    caCert, err := loadCertificate(caCertPath)
    if err != nil {
        return err
    }

    // Загружаем пароль и расшифровываем ключ
    passphrase, err := crypto.LoadPassphraseFromFile(passphraseFile)
    if err != nil {
        return err
    }
    defer crypto.SecureZero(passphrase)

    caKey, err := crypto.LoadAndDecryptPrivateKey(caKeyPath, passphrase)
    if err != nil {
        return err
    }

    // Открываем БД (предполагается, что она в стандартном месте)
    db, err := database.InitDB(filepath.Join(caDir, "micropki.db"))
    if err != nil {
        return err
    }
    defer db.Close()

    // Получаем список отозванных сертификатов
    revokedCerts, err := GetRevokedCertificates(db, caCert.Subject.String())
    if err != nil {
        return err
    }

    // Генерируем новый CRL
    config := &CRLConfig{
        CAIssuer:     caCert,
        CAPrivateKey: caKey,
        Number:       time.Now().Unix(),
        ThisUpdate:   time.Now().UTC(),
        NextUpdate:   time.Now().UTC().AddDate(0, 0, 7), // default 7 days
        RevokedCerts: revokedCerts,
        OutPath:      crlPath,
    }
    crlBytes, err := GenerateCRL(config)
    if err != nil {
        return err
    }
    return SaveCRL(crlBytes, crlPath)
}

// loadCertificate – вспомогательная функция для загрузки PEM-сертификата
func loadCertificate(path string) (*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    return x509.ParseCertificate(block.Bytes)
}

// GetRevokedCertificates возвращает список отозванных сертификатов для указанного issuer
func GetRevokedCertificates(db *sql.DB, issuerDN string) ([]RevokedCertificate, error) {
    rows, err := db.Query(
        "SELECT serial_hex, revocation_date, revocation_reason FROM certificates WHERE issuer = ? AND status = 'revoked'",
        issuerDN,
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var revoked []RevokedCertificate
    for rows.Next() {
        var serialHex, revDate, reason string
        if err := rows.Scan(&serialHex, &revDate, &reason); err != nil {
            return nil, err
        }
        var serial big.Int
        serial.SetString(serialHex, 16)
        revTime, _ := time.Parse(time.RFC3339, revDate)
        revoked = append(revoked, RevokedCertificate{
            SerialNumber:   &serial,
            RevocationTime: revTime,
            ReasonCode:     ReasonCodeMap[reason],
        })
    }
    return revoked, nil
}