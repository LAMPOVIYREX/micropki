package serial

import (
	"testing"

	"micropki/internal/database"

	"github.com/stretchr/testify/require"
)

func TestGenerateSerial_Coverage(t *testing.T) {
	db, err := database.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	gen := NewSerialGenerator(db)
	serial, err := gen.GenerateSerial()
	require.NoError(t, err)
	require.NotEmpty(t, serial)

	hex := SerialToHex(serial)
	require.NotEmpty(t, hex)
}
