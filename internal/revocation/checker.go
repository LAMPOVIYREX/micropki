package revocation

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// RevocationStatus represents the status of a certificate
type RevocationStatus struct {
	Status           string
	RevocationTime   string
	RevocationReason string
	Method           string
}

// Checker handles revocation checking
type Checker struct {
	ocspFirst bool
}

// NewChecker creates a new revocation checker
func NewChecker() *Checker {
	return &Checker{
		ocspFirst: true,
	}
}

// CheckStatus checks revocation status using OCSP first, then CRL fallback
func (c *Checker) CheckStatus(certPath, issuerPath string, crlURL, ocspURL string) (*RevocationStatus, error) {
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	issuer, err := loadCertificate(issuerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	if ocspURL == "" && len(cert.OCSPServer) > 0 {
		ocspURL = cert.OCSPServer[0]
	}

	// Try OCSP first
	if ocspURL != "" && c.ocspFirst {
		status, err := checkOCSP(cert, issuer, ocspURL)
		if err == nil && status.Status != "unknown" {
			status.Method = "ocsp"
			return status, nil
		}
	}

	// Fallback to CRL
	if crlURL != "" {
		status, err := checkCRL(cert, issuer, crlURL)
		if err == nil {
			status.Method = "crl"
			return status, nil
		}
	}

	return &RevocationStatus{
		Status: "unknown",
		Method: "none",
	}, nil
}

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

// reasonCodeToString converts a reason code integer to a human-readable string
func reasonCodeToString(code int) string {
	switch code {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

// loadCRLData loads CRL data from a file path or HTTP URL
func loadCRLData(source string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("http get failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http status %s", resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(source)
}

// checkCRL checks certificate revocation status against a CRL (file or URL)
func checkCRL(cert, issuer *x509.Certificate, crlSource string) (*RevocationStatus, error) {
	data, err := loadCRLData(crlSource)
	if err != nil {
		return &RevocationStatus{Status: "unknown"}, fmt.Errorf("failed to load CRL: %w", err)
	}

	// Decode PEM wrapper if present, otherwise treat as raw DER
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type == "X509 CRL" || block.Type == "CRL" {
			der = block.Bytes
		}
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return &RevocationStatus{Status: "unknown"}, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify CRL signature using issuer certificate
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return &RevocationStatus{Status: "unknown"}, fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// Search for the certificate's serial number in revoked list
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}

		// Extract revocation reason from extension OID 2.5.29.21
		reasonStr := ""
		for _, ext := range entry.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 21}) {
				var reasonCode int
				if rest, err := asn1.Unmarshal(ext.Value, &reasonCode); err == nil && len(rest) == 0 {
					reasonStr = reasonCodeToString(reasonCode)
				}
				break
			}
		}

		return &RevocationStatus{
			Status:           "revoked",
			RevocationTime:   entry.RevocationTime.Format(time.RFC3339),
			RevocationReason: reasonStr,
			Method:           "crl",
		}, nil
	}

	// Certificate not found in CRL – considered good
	return &RevocationStatus{
		Status: "good",
		Method: "crl",
	}, nil
}
