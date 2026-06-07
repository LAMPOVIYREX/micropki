package database

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// уже существующие тесты (если есть) оставьте, допишите новые:

func TestAddCompromisedKey(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// добавляем сертификат
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(555),
		Subject:      pkix.Name{CommonName: "test"},
		Issuer:       pkix.Name{CommonName: "CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	err = InsertCertificate(db, cert, "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
	require.NoError(t, err)

	err = AddCompromisedKey(db, "hash123", "22B", "keyCompromise")
	require.NoError(t, err)

	compromised, err := IsKeyCompromised(db, "hash123")
	require.NoError(t, err)
	require.True(t, compromised)

	// несуществующий хэш
	compromised, err = IsKeyCompromised(db, "nohash")
	require.NoError(t, err)
	require.False(t, compromised)
}
