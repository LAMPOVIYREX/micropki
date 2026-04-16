package serial

import (
    "crypto/rand"
    "database/sql"
    "encoding/binary"
    "fmt"
    "time"
)

// SerialGenerator generates unique serial numbers for certificates
type SerialGenerator struct {
    db *sql.DB
}

// NewSerialGenerator creates a new serial generator
func NewSerialGenerator(db *sql.DB) *SerialGenerator {
    return &SerialGenerator{db: db}
}

// GenerateSerial generates a unique 64-bit serial number
// Format: 32 bits = Unix timestamp (seconds) + 32 bits = CSPRNG
func (g *SerialGenerator) GenerateSerial() (uint64, error) {
    // Get timestamp (32 bits)
    timestamp := uint32(time.Now().Unix())
    
    // Get random bytes (32 bits)
    var random uint32
    err := binary.Read(rand.Reader, binary.BigEndian, &random)
    if err != nil {
        return 0, fmt.Errorf("failed to generate random: %w", err)
    }
    
    // Combine: high 32 bits = timestamp, low 32 bits = random
    serial := (uint64(timestamp) << 32) | uint64(random)
    
    // Verify uniqueness in database
    var count int
    err = g.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE serial_hex = ?", 
        fmt.Sprintf("%016X", serial)).Scan(&count)
    if err != nil {
        return 0, fmt.Errorf("failed to check serial uniqueness: %w", err)
    }
    
    if count > 0 {
        // Collision detected - try again (very rare)
        return g.GenerateSerial()
    }
    
    return serial, nil
}

// SerialToHex converts serial number to hex string
func SerialToHex(serial uint64) string {
    return fmt.Sprintf("%016X", serial)
}