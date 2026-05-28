package serial

import (
    "testing"
    "micropki/internal/database"
)

func TestGenerateSerial(t *testing.T) {
    db, err := database.InitDB(":memory:")
    if err != nil {
        t.Fatal(err)
    }
    defer db.Close()
    gen := NewSerialGenerator(db)
    serial, err := gen.GenerateSerial()
    if err != nil {
        t.Fatalf("GenerateSerial failed: %v", err)
    }
    if serial == 0 {
        t.Error("Serial is zero")
    }
    hex := SerialToHex(serial)
    if len(hex) != 16 {
        t.Errorf("Expected 16 hex digits, got %d", len(hex))
    }
}