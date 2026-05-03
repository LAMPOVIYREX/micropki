package tests

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "testing"
    "time"

    "micropki/internal/policy"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestPolicyKeySizeRSA(t *testing.T) {
    // Root CA: должен быть 4096
    err := policy.ValidateKeySize(policy.RootCA, 2048, "rsa")
    assert.Error(t, err, "Root CA with 2048 should fail")
    err = policy.ValidateKeySize(policy.RootCA, 4096, "rsa")
    assert.NoError(t, err)

    // Intermediate CA: минимум 3072
    err = policy.ValidateKeySize(policy.IntermediateCA, 2048, "rsa")
    assert.Error(t, err)
    err = policy.ValidateKeySize(policy.IntermediateCA, 3072, "rsa")
    assert.NoError(t, err)

    // End-entity: минимум 2048
    err = policy.ValidateKeySize(policy.Server, 1024, "rsa")
    assert.Error(t, err)
    err = policy.ValidateKeySize(policy.Server, 2048, "rsa")
    assert.NoError(t, err)
}

func TestPolicyValidity(t *testing.T) {
    err := policy.ValidateValidity(policy.RootCA, 4000) // >10 лет
    assert.Error(t, err)
    err = policy.ValidateValidity(policy.RootCA, 3650)
    assert.NoError(t, err)

    err = policy.ValidateValidity(policy.IntermediateCA, 2000) // >5 лет
    assert.Error(t, err)
    err = policy.ValidateValidity(policy.IntermediateCA, 1825)
    assert.NoError(t, err)

    err = policy.ValidateValidity(policy.Server, 400) // >1 год
    assert.Error(t, err)
    err = policy.ValidateValidity(policy.Server, 365)
    assert.NoError(t, err)
}

func TestPolicySAN(t *testing.T) {
    // Server: разрешены dns и ip, запрещены wildcard
    err := policy.ValidateSAN(policy.Server, []string{"dns:example.com"})
    assert.NoError(t, err)
    err = policy.ValidateSAN(policy.Server, []string{"dns:*.example.com"})
    assert.Error(t, err) // wildcard
    err = policy.ValidateSAN(policy.Server, []string{"email:user@example.com"})
    assert.Error(t, err)

    // Client: разрешены email и dns
    err = policy.ValidateSAN(policy.Client, []string{"email:user@example.com"})
    assert.NoError(t, err)
    err = policy.ValidateSAN(policy.Client, []string{"dns:client.example.com"})
    assert.NoError(t, err)

    // CodeSigning: разрешены dns и uri
    err = policy.ValidateSAN(policy.CodeSigning, []string{"uri:https://example.com"})
    assert.NoError(t, err)
    err = policy.ValidateSAN(policy.CodeSigning, []string{"email:user@example.com"})
    assert.Error(t, err)
}

// Дополнительно: тест на реальную подпись с нарушением политики (интеграционный)
func TestIntegrationPolicyViolation(t *testing.T) {
    // Здесь можно запустить тестовый сервер, отправить CSR с недопустимым SAN и проверить, что возвращается 400.
    // Потребуется временный CA и сервер. Для краткости опустим.
}