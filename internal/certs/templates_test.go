package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificateTemplate(t *testing.T) {
	subj := &pkix.Name{CommonName: "server.example.com"}
	tmpl, err := CreateCertificateTemplate("server", subj, []string{"dns:example.com"}, 365)
	require.NoError(t, err)
	require.False(t, tmpl.IsCA)
	require.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, tmpl.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, tmpl.ExtKeyUsage)

	// client
	tmpl, err = CreateCertificateTemplate("client", subj, []string{"dns:client.local"}, 90)
	require.NoError(t, err)
	require.Equal(t, x509.KeyUsageDigitalSignature, tmpl.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, tmpl.ExtKeyUsage)

	// code-signing
	tmpl, err = CreateCertificateTemplate("code-signing", subj, []string{"dns:sig.example.com"}, 365)
	require.NoError(t, err)
	require.Equal(t, x509.KeyUsageDigitalSignature, tmpl.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, tmpl.ExtKeyUsage)

	// неизвестный тип
	_, err = CreateCertificateTemplate("invalid", subj, nil, 30)
	require.Error(t, err)
}
