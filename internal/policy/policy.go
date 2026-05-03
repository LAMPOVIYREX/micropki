package policy

import (
    "fmt"
    "strings"
)

// CertificateType represents the intended use
type CertificateType string

const (
    RootCA         CertificateType = "root"
    IntermediateCA CertificateType = "intermediate"
    Server         CertificateType = "server"
    Client         CertificateType = "client"
    CodeSigning    CertificateType = "code_signing"
)

// ValidateKeySize checks key size against policy
func ValidateKeySize(certType CertificateType, keySize int, keyAlgo string) error {
    switch keyAlgo {
    case "rsa":
        switch certType {
        case RootCA:
            if keySize < 4096 {
                return fmt.Errorf("Root CA RSA key size must be at least 4096 bits (got %d)", keySize)
            }
        case IntermediateCA:
            if keySize < 3072 {
                return fmt.Errorf("Intermediate CA RSA key size must be at least 3072 bits (got %d)", keySize)
            }
        default:
            if keySize < 2048 {
                return fmt.Errorf("End-entity RSA key size must be at least 2048 bits (got %d)", keySize)
            }
        }
    case "ecc":
        // For ECC we use curve name stored in keySize? We'll pass curve bits
        switch certType {
        case RootCA, IntermediateCA:
            if keySize != 384 {
                return fmt.Errorf("Root/Intermediate ECC must use P-384 (got %d)", keySize)
            }
        default:
            if keySize != 256 && keySize != 384 {
                return fmt.Errorf("End-entity ECC must use P-256 or P-384 (got %d)", keySize)
            }
        }
    default:
        return fmt.Errorf("unknown key algorithm: %s", keyAlgo)
    }
    return nil
}

// ValidateValidity checks validity days
func ValidateValidity(certType CertificateType, days int) error {
    max := 0
    switch certType {
    case RootCA:
        max = 3650 // 10 years
    case IntermediateCA:
        max = 1825 // 5 years
    default:
        max = 365 // 1 year
    }
    if days > max {
        return fmt.Errorf("%s validity cannot exceed %d days (got %d)", certType, max, days)
    }
    return nil
}

// ValidateSAN checks SAN list against template policy
func ValidateSAN(template CertificateType, sans []string) error {
    allowedTypes := map[CertificateType]map[string]bool{
        Server:      {"dns": true, "ip": true},
        Client:      {"email": true, "dns": true},
        CodeSigning: {"dns": true, "uri": true},
    }
    allowed, ok := allowedTypes[template]
    if !ok {
        return fmt.Errorf("unknown template: %s", template)
    }

    for _, san := range sans {
        // parse san: expecting prefix "dns:", "ip:", "email:", "uri:"
        parts := strings.SplitN(san, ":", 2)
        if len(parts) != 2 {
            return fmt.Errorf("invalid SAN format: %s", san)
        }
        typ := parts[0]
        value := parts[1]
        if !allowed[typ] {
            return fmt.Errorf("SAN type %s not allowed for %s certificate", typ, template)
        }
        // Wildcard check for server certs (reject wildcard by default)
        if template == Server && strings.Contains(value, "*") {
            return fmt.Errorf("wildcard SANs are rejected for server certificates (got %s)", san)
        }
    }
    return nil
}