package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateKeySize(t *testing.T) {
	tests := []struct {
		name      string
		certType  CertificateType
		keySize   int
		keyAlgo   string
		shouldErr bool
	}{
		// RSA
		{"Root CA RSA 4096", RootCA, 4096, "rsa", false},
		{"Root CA RSA 2048", RootCA, 2048, "rsa", true},
		{"Intermediate RSA 3072", IntermediateCA, 3072, "rsa", false},
		{"Intermediate RSA 2048", IntermediateCA, 2048, "rsa", true},
		{"Server RSA 2048", Server, 2048, "rsa", false},
		{"Server RSA 1024", Server, 1024, "rsa", true},
		// ECC
		{"Root CA ECC 384", RootCA, 384, "ecc", false},
		{"Root CA ECC 256", RootCA, 256, "ecc", true},
		{"Intermediate ECC 384", IntermediateCA, 384, "ecc", false},
		{"Server ECC 256", Server, 256, "ecc", false},
		{"Server ECC 224", Server, 224, "ecc", true},
		// Invalid algo
		{"Unknown algo", Server, 2048, "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeySize(tt.certType, tt.keySize, tt.keyAlgo)
			if tt.shouldErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestValidateValidity(t *testing.T) {
	tests := []struct {
		name      string
		certType  CertificateType
		days      int
		shouldErr bool
	}{
		{"Root CA 3650", RootCA, 3650, false},
		{"Root CA 4000", RootCA, 4000, true},
		{"Intermediate 1825", IntermediateCA, 1825, false},
		{"Intermediate 2000", IntermediateCA, 2000, true},
		{"Server 365", Server, 365, false},
		{"Server 400", Server, 400, true},
		{"Client 365", Client, 365, false},
		{"CodeSigning 365", CodeSigning, 365, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValidity(tt.certType, tt.days)
			if tt.shouldErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestValidateSAN(t *testing.T) {
	tests := []struct {
		name      string
		template  CertificateType
		sans      []string
		shouldErr bool
	}{
		// Server
		{"Server valid DNS", Server, []string{"dns:example.com"}, false},
		{"Server valid IP", Server, []string{"ip:192.168.1.1"}, false},
		{"Server wildcard", Server, []string{"dns:*.example.com"}, true},
		{"Server email not allowed", Server, []string{"email:user@example.com"}, true},
		// Client
		{"Client email", Client, []string{"email:user@example.com"}, false},
		{"Client DNS", Client, []string{"dns:client.local"}, false},
		{"Client IP not allowed", Client, []string{"ip:10.0.0.1"}, true},
		// CodeSigning
		{"CodeSigning DNS", CodeSigning, []string{"dns:signer.local"}, false},
		{"CodeSigning URI", CodeSigning, []string{"uri:https://example.com"}, false},
		{"CodeSigning email not allowed", CodeSigning, []string{"email:user@example.com"}, true},
		// Unknown template
		{"Unknown template", "unknown", []string{"dns:test"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSAN(tt.template, tt.sans)
			if tt.shouldErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestValidateSAN_WildcardClient(t *testing.T) {
	err := ValidateSAN(Client, []string{"dns:*.example.com"})
	require.NoError(t, err)
}

func TestValidateSAN_UnknownTemplate(t *testing.T) {
	err := ValidateSAN("unknown", []string{"dns:test"})
	require.Error(t, err)
}
