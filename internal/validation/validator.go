package validation

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "time"
)

// ValidationResult contains the result of certificate validation
type ValidationResult struct {
    Passed      bool
    Chain       []*x509.Certificate
    Steps       []ValidationStep
    ErrorMsg    string
}

// ValidationStep represents a single validation check
type ValidationStep struct {
    Name    string
    Passed  bool
    Message string
}

// Validator handles certificate path validation
type Validator struct {
    trustedRoots   *x509.CertPool
    intermediates  *x509.CertPool
    validationTime time.Time
}

// NewValidator creates a new validator
func NewValidator(trustedRootsPath string, validationTime time.Time) (*Validator, error) {
    trustedRoots := x509.NewCertPool()
    
    if trustedRootsPath != "" {
        rootsPEM, err := os.ReadFile(trustedRootsPath)
        if err != nil {
            return nil, fmt.Errorf("failed to read trusted roots: %w", err)
        }
        if !trustedRoots.AppendCertsFromPEM(rootsPEM) {
            return nil, fmt.Errorf("no trusted certificates found in %s", trustedRootsPath)
        }
    }
    
    return &Validator{
        trustedRoots:   trustedRoots,
        intermediates:  x509.NewCertPool(),
        validationTime: validationTime,
    }, nil
}

// AddIntermediate adds an intermediate certificate
func (v *Validator) AddIntermediate(cert *x509.Certificate) {
    v.intermediates.AddCert(cert)
}

// ValidateCertificate validates a certificate chain
func (v *Validator) ValidateCertificate(leafPath string, untrustedPaths []string) (*ValidationResult, error) {
    result := &ValidationResult{
        Passed: true,
        Steps:  []ValidationStep{},
    }
    
    // Load leaf certificate
    leafCert, err := loadCertificate(leafPath)
    if err != nil {
        result.Passed = false
        result.ErrorMsg = fmt.Sprintf("Failed to load leaf certificate: %v", err)
        return result, nil
    }
    
    result.Steps = append(result.Steps, ValidationStep{
        Name:    "Leaf info",
        Passed:  true,
        Message: fmt.Sprintf("Leaf subject: %s, issuer: %s", leafCert.Subject.String(), leafCert.Issuer.String()),
    })
    
    // Create a new pool for this validation that includes all intermediates
    intermediates := x509.NewCertPool()
    
    // Add all pre-added intermediates
    for _, subj := range v.intermediates.Subjects() {
        // Find and add certificates by subject
        for _, cert := range v.getCertificatesBySubject(subj) {
            intermediates.AddCert(cert)
        }
    }
    
    // Also load intermediates from untrustedPaths
    for _, path := range untrustedPaths {
        cert, err := loadCertificate(path)
        if err != nil {
            result.Steps = append(result.Steps, ValidationStep{
                Name:    "Load intermediate",
                Passed:  false,
                Message: fmt.Sprintf("Failed to load intermediate from %s: %v", path, err),
            })
            continue
        }
        intermediates.AddCert(cert)
        result.Steps = append(result.Steps, ValidationStep{
            Name:    "Load intermediate",
            Passed:  true,
            Message: fmt.Sprintf("Loaded intermediate: %s", cert.Subject.String()),
        })
    }
    
    result.Steps = append(result.Steps, ValidationStep{
        Name:    "Trusted roots",
        Passed:  true,
        Message: fmt.Sprintf("Number of trusted roots: %d", len(v.trustedRoots.Subjects())),
    })
    
    // Build verification options
    opts := x509.VerifyOptions{
        Roots:         v.trustedRoots,
        Intermediates: intermediates,
        CurrentTime:   v.validationTime,
        KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
    }
    
    // Verify chain
    chains, err := leafCert.Verify(opts)
    if err != nil {
        result.Passed = false
        result.ErrorMsg = err.Error()
        result.Steps = append(result.Steps, ValidationStep{
            Name:    "Chain verification",
            Passed:  false,
            Message: err.Error(),
        })
        return result, nil
    }
    
    if len(chains) == 0 {
        result.Passed = false
        result.ErrorMsg = "No valid chain found"
        return result, nil
    }
    
    result.Chain = chains[0]
    result.Steps = append(result.Steps, ValidationStep{
        Name:    "Chain verification",
        Passed:  true,
        Message: fmt.Sprintf("Found chain with %d certificates", len(result.Chain)),
    })
    
    // Validate each certificate in chain
    for i, cert := range result.Chain {
        steps := validateCertificate(cert, v.validationTime, i == len(result.Chain)-1)
        result.Steps = append(result.Steps, steps...)
        
        for _, step := range steps {
            if !step.Passed {
                result.Passed = false
            }
        }
    }
    
    if result.Passed {
        result.Steps = append(result.Steps, ValidationStep{
            Name:    "Overall validation",
            Passed:  true,
            Message: "Certificate chain is valid",
        })
    }
    
    return result, nil
}

// Helper method to get certificates by subject (simplified)
func (v *Validator) getCertificatesBySubject(subj []byte) []*x509.Certificate {
    // This is a simplified version - in production you'd maintain a map
    return []*x509.Certificate{}
}

// validateCertificate performs basic checks on a single certificate
func validateCertificate(cert *x509.Certificate, validationTime time.Time, isLeaf bool) []ValidationStep {
    steps := []ValidationStep{}
    
    // Check validity period
    if validationTime.Before(cert.NotBefore) {
        steps = append(steps, ValidationStep{
            Name:    "Validity period",
            Passed:  false,
            Message: fmt.Sprintf("Certificate not yet valid (valid from %s)", cert.NotBefore.Format(time.RFC3339)),
        })
    } else if validationTime.After(cert.NotAfter) {
        steps = append(steps, ValidationStep{
            Name:    "Validity period",
            Passed:  false,
            Message: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
        })
    } else {
        steps = append(steps, ValidationStep{
            Name:    "Validity period",
            Passed:  true,
            Message: fmt.Sprintf("Valid from %s to %s", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339)),
        })
    }
    
    // Check Key Usage
    if !cert.IsCA && isLeaf {
        if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
            steps = append(steps, ValidationStep{
                Name:    "Key Usage",
                Passed:  false,
                Message: "Leaf certificate missing required key usages (DigitalSignature, KeyEncipherment)",
            })
        } else {
            steps = append(steps, ValidationStep{
                Name:    "Key Usage",
                Passed:  true,
                Message: "Key usage is appropriate for leaf certificate",
            })
        }
    }
    
    // Check Basic Constraints for CA
    if cert.IsCA {
        if !cert.BasicConstraintsValid {
            steps = append(steps, ValidationStep{
                Name:    "Basic Constraints",
                Passed:  false,
                Message: "CA certificate missing Basic Constraints",
            })
        } else {
            steps = append(steps, ValidationStep{
                Name:    "Basic Constraints",
                Passed:  true,
                Message: fmt.Sprintf("CA certificate with path length %d", cert.MaxPathLen),
            })
        }
    }
    
    return steps
}

// loadCertificate loads a certificate from PEM file
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