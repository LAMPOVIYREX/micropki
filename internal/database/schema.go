package database

import (
    "database/sql"
    "fmt"

    _ "github.com/mattn/go-sqlite3"
)

// Schema SQL for certificates table
const createTableSQL = `
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_not_after ON certificates(not_after);
`

const createCompromisedKeysTableSQL = `
CREATE TABLE IF NOT EXISTS compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);

CREATE INDEX IF NOT EXISTS idx_public_key_hash ON compromised_keys(public_key_hash);
`

// InitDB initializes the database and creates tables
func InitDB(dbPath string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }

    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    // Create certificates table
    if _, err := db.Exec(createTableSQL); err != nil {
        return nil, fmt.Errorf("failed to create certificates table: %w", err)
    }

    // Create compromised_keys table
    if _, err := db.Exec(createCompromisedKeysTableSQL); err != nil {
        return nil, fmt.Errorf("failed to create compromised_keys table: %w", err)
    }

    return db, nil
}