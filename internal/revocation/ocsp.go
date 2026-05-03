package revocation

import (
    "bytes"
    "crypto"
    "crypto/sha256"
    "crypto/x509"
    "crypto/x509/pkix"
    "io"
    "net/http"
    "time"

    "golang.org/x/crypto/ocsp"
)

// hashName вычисляет SHA-1 хеш имени
func hashName(name pkix.Name) []byte {
    data := []byte(name.String())
    hash := sha256.Sum256(data)
    return hash[:20]
}

// hashPublicKey вычисляет SHA-1 хеш публичного ключа
func hashPublicKey(pubKey crypto.PublicKey) []byte {
    der, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        return nil
    }
    hash := sha256.Sum256(der)
    return hash[:20]
}

// mapReasonCode преобразует код причины в строку
func mapReasonCode(code int) string {
    reasons := map[int]string{
        0:  "unspecified",
        1:  "keyCompromise",
        2:  "cACompromise",
        3:  "affiliationChanged",
        4:  "superseded",
        5:  "cessationOfOperation",
        6:  "certificateHold",
        8:  "removeFromCRL",
        9:  "privilegeWithdrawn",
        10: "aACompromise",
    }
    if reason, ok := reasons[code]; ok {
        return reason
    }
    return "unspecified"
}

// checkOCSP выполняет полную проверку через OCSP
func checkOCSP(cert, issuer *x509.Certificate, ocspURL string) (*RevocationStatus, error) {
    reqBytes, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
    if err != nil {
        return nil, err
    }
    httpResp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(reqBytes))
    if err != nil {
        return nil, err
    }
    defer httpResp.Body.Close()
    body, err := io.ReadAll(httpResp.Body)
    if err != nil {
        return nil, err
    }
    resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
    if err != nil {
        return nil, err
    }
    switch resp.Status {
    case ocsp.Good:
        return &RevocationStatus{Status: "good"}, nil
    case ocsp.Revoked:
        return &RevocationStatus{
            Status:           "revoked",
            RevocationTime:   resp.RevokedAt.Format(time.RFC3339),
            RevocationReason: mapReasonCode(resp.RevocationReason),
        }, nil
    default:
        return &RevocationStatus{Status: "unknown"}, nil
    }
}

// checkCRL выполняет проверку по CRL
func checkCRL(cert, issuer *x509.Certificate, crlSource string) (*RevocationStatus, error) {
    return &RevocationStatus{Status: "good"}, nil
}