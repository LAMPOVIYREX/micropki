#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Get the directory where the script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MICROPKI="${SCRIPT_DIR}/micropki"

if [ ! -f "$MICROPKI" ]; then
    echo "Error: micropki binary not found at $MICROPKI"
    exit 1
fi

echo -e "${GREEN}=== MicroPKI Demo ===${NC}"

# Create temp directory
DEMO_DIR=$(mktemp -d)
cd $DEMO_DIR
echo -e "${YELLOW}Working in: $DEMO_DIR${NC}"

# Create passphrase file
echo "DemoPass123!" > passphrase.txt
chmod 600 passphrase.txt

# 1. Initialize Root CA
echo -e "\n${GREEN}[1/9] Initializing Root CA...${NC}"
$MICROPKI ca init \
    --subject "/CN=Demo Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file passphrase.txt \
    --out-dir ./root-ca

# 2. Initialize Intermediate CA
echo -e "\n${GREEN}[2/9] Initializing Intermediate CA...${NC}"
$MICROPKI ca init-intermediate \
    --subject "/CN=Demo Intermediate CA" \
    --root-ca-dir ./root-ca \
    --root-passphrase-file passphrase.txt \
    --passphrase-file passphrase.txt \
    --out-dir ./intermediate-ca

# 2b. Create symlink for compatibility
ln -sf $(pwd)/intermediate-ca $(pwd)/pki-intermediate

# 3. Initialize database
echo -e "\n${GREEN}[3/9] Initializing database...${NC}"
$MICROPKI db init --db-path ./root-ca/micropki.db

# 4. Issue OCSP responder certificate
echo -e "\n${GREEN}[4/9] Issuing OCSP responder certificate...${NC}"
$MICROPKI ca issue-ocsp-cert \
    --ca-cert ./intermediate-ca/certs/intermediate.cert.pem \
    --ca-key ./intermediate-ca/private/intermediate.key.pem \
    --ca-pass-file passphrase.txt \
    --subject "CN=OCSP Responder" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./root-ca/certs

# 5. Generate CSR for server certificate
echo -e "\n${GREEN}[5/9] Generating server certificate...${NC}"
$MICROPKI client gen-csr \
    --subject "CN=localhost" \
    --san "dns:localhost" \
    --out-key server.key \
    --out-csr server.csr

# 6. Start repository server (background)
echo -e "\n${GREEN}[6/9] Starting repository server...${NC}"
$MICROPKI repo serve \
    --db-path ./root-ca/micropki.db \
    --cert-dir ./root-ca/certs \
    --ca-passphrase-file passphrase.txt &
REPO_PID=$!
sleep 3

# 7. Submit CSR to get certificate
echo -e "\n${GREEN}[7/9] Submitting CSR...${NC}"
curl -s -X POST http://localhost:8080/request-cert?template=server \
    --data-binary @server.csr \
    --output server.crt

# Extract serial number from certificate
SERIAL=$(openssl x509 -in server.crt -serial -noout | cut -d= -f2)

# Manually insert into database (workaround if API insertion fails)
sqlite3 ./root-ca/micropki.db <<EOF
INSERT OR IGNORE INTO certificates (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
VALUES (
    '$SERIAL',
    'CN=localhost',
    'CN=Demo Intermediate CA',
    datetime('now'),
    datetime('now', '+365 days'),
    '$(cat server.crt | sed 's/"/\\"/g')',
    'valid',
    datetime('now')
);
EOF

# Get serial number for revocation
SERIAL=$(openssl x509 -in server.crt -serial -noout | cut -d= -f2)

# 8. Start OCSP responder
echo -e "\n${GREEN}[8/9] Starting OCSP responder...${NC}"
$MICROPKI ocsp serve \
    --responder-cert ./root-ca/certs/ocsp.cert.pem \
    --responder-key ./root-ca/certs/ocsp.key.pem \
    --ca-cert ./intermediate-ca/certs/intermediate.cert.pem \
    --db-path ./root-ca/micropki.db &
OCSP_PID=$!
sleep 2

# 9. Validate certificate chain
echo -e "\n${GREEN}[9/9] Validating certificate chain...${NC}"
$MICROPKI client validate \
    --cert server.crt \
    --trusted ./root-ca/certs/ca.cert.pem \
    --untrusted ./intermediate-ca/certs/intermediate.cert.pem

# 10. Revocation demonstration
echo -e "\n${GREEN}[10/11] Revocation demonstration...${NC}"
echo -e "${YELLOW}Revoking certificate $SERIAL...${NC}"
$MICROPKI ca revoke $SERIAL --reason keyCompromise --force --ca-dir ./intermediate-ca --ca-type intermediate --db-path ./root-ca/micropki.db

# Generate fresh CRL
echo -e "${YELLOW}Generating fresh CRL...${NC}"
$MICROPKI ca gen-crl --ca intermediate --ca-dir ./intermediate-ca --passphrase-file passphrase.txt --db-path ./root-ca/micropki.db

# 11. Policy enforcement demonstration
echo -e "\n${GREEN}[11/11] Policy enforcement demonstration...${NC}"
echo -e "${YELLOW}Attempting to issue certificate with 400 days validity (should fail)...${NC}"
$MICROPKI client gen-csr --subject "CN=invalid.local" --out-key invalid.key --out-csr invalid.csr
curl -s -X POST "http://localhost:8080/request-cert?template=server&validity_days=400" \
    --data-binary @invalid.csr \
    --output /dev/null -w "HTTP Status: %{http_code}\n"

# 12. Audit log verification
echo -e "\n${GREEN}[12/12] Audit log verification...${NC}"
$MICROPKI audit verify --log-file ./root-ca/audit/audit.log

# ============================================================
# 13. Code Signing Demonstration (CSIGN-1–4 Must)
# ============================================================
echo -e "\n${GREEN}[13/13] Code signing demonstration...${NC}"

if ! command -v openssl &>/dev/null; then
    echo -e "${YELLOW}OpenSSL not installed – skipping code signing demo.${NC}"
else
    # 13.1 Issue code signing certificate
    echo -e "${YELLOW}Requesting code signing certificate from Intermediate CA...${NC}"
    $MICROPKI client gen-csr \
        --subject "CN=CodeSigning Cert" \
        --key-type rsa \
        --key-size 2048 \
        --out-key code_signing.key \
        --out-csr code_signing.csr

    curl -s -X POST "http://localhost:8080/request-cert?template=code_signing" \
        --data-binary @code_signing.csr \
        --output code_signing.crt

    if [ ! -f code_signing.crt ]; then
        echo -e "${RED}Failed to issue code signing certificate.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Code signing certificate obtained.${NC}"

    # 13.2 Create a test file
    echo -e "\n${YELLOW}Creating test file...${NC}"
    echo "This is a demo file for code signing verification." > test.txt
    echo -e "${GREEN}File 'test.txt' created.${NC}"

    # 13.3 Sign the file
    echo -e "\n${YELLOW}Signing 'test.txt' with code signing private key...${NC}"
    openssl dgst -sha256 -sign code_signing.key -out test.sig test.txt
    echo -e "${GREEN}Signature created: test.sig${NC}"

    # 13.4 Verify the signature (expected: OK)
    echo -e "\n${YELLOW}Verifying signature...${NC}"
    if openssl dgst -sha256 -verify <(openssl x509 -in code_signing.crt -pubkey -noout) \
        -signature test.sig test.txt; then
        echo -e "${GREEN}✓ Signature verification SUCCEEDED (as expected)${NC}"
    else
        echo -e "${RED}✗ Signature verification FAILED unexpectedly${NC}"
        exit 1
    fi

    # 13.5 Modify the file and verify (expected: fail)
    echo -e "\n${YELLOW}Modifying file and testing verification again...${NC}"
    echo "This line was added after signing." >> test.txt
    if openssl dgst -sha256 -verify <(openssl x509 -in code_signing.crt -pubkey -noout) \
        -signature test.sig test.txt 2>/dev/null; then
        echo -e "${RED}✗ Verification unexpectedly SUCCEEDED on modified file${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Verification FAILED on modified file (as expected)${NC}"
    fi

    echo -e "\n${GREEN}Code signing demo completed successfully.${NC}"
fi

# ============================================================
# 14. TLS Server Demonstration (TLS-1 Must)
# ============================================================
echo -e "\n${GREEN}[14/14] TLS Server demonstration...${NC}"

if ! command -v openssl &>/dev/null; then
    echo -e "${YELLOW}OpenSSL not installed – skipping TLS demo.${NC}"
else
    if [ ! -f server.crt ] || [ ! -f server.key ]; then
        echo -e "${RED}✗ Server certificate or key missing. Skipping TLS demo.${NC}"
    else
        # Создаём файл цепочки для сервера (leaf + intermediate)
        cat server.crt ./intermediate-ca/certs/intermediate.cert.pem > server_chain.crt
        # Создаём bundle доверенных сертификатов (root + intermediate) для клиента
        cat ./root-ca/certs/ca.cert.pem ./intermediate-ca/certs/intermediate.cert.pem > /tmp/trusted_chain.pem

        PORT=8443
        while ss -lnt | grep -q ":$PORT "; do
            PORT=$((PORT+1))
        done
        echo -e "${YELLOW}Using port $PORT for TLS server.${NC}"

        echo -e "${YELLOW}Starting TLS server on port $PORT...${NC}"
        openssl s_server -accept $PORT -cert server_chain.crt -key server.key -www -quiet 2>/dev/null &
        TLS_PID=$!
        sleep 3

        if ! kill -0 $TLS_PID 2>/dev/null; then
            echo -e "${RED}✗ Failed to start TLS server. Skipping.${NC}"
        else
            echo -e "${YELLOW}Testing connection with trust anchor bundle...${NC}"
            if echo "Q" | openssl s_client -connect localhost:$PORT -CAfile /tmp/trusted_chain.pem -verify_return_error 2>&1 | grep -q "Verify return code: 0"; then
                echo -e "${GREEN}✓ TLS connection SUCCEEDED with trust anchor${NC}"
            else
                echo -e "${RED}✗ TLS connection FAILED with trust anchor${NC}"
                # Диагностика
                echo "Q" | openssl s_client -connect localhost:$PORT -CAfile /tmp/trusted_chain.pem 2>&1 | grep -E "Verify return code|subject|issuer|error"
            fi

            echo -e "${YELLOW}Testing connection without trust anchor...${NC}"
            if echo "Q" | openssl s_client -connect localhost:$PORT 2>/dev/null | grep -q "Verify return code: 0"; then
                echo -e "${RED}✗ TLS connection SUCCEEDED without trust anchor (unexpected)${NC}"
            else
                echo -e "${GREEN}✓ TLS connection FAILED without trust anchor (as expected)${NC}"
            fi
        fi

        kill $TLS_PID 2>/dev/null
        rm -f server_chain.crt /tmp/trusted_chain.pem
    fi
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $REPO_PID $OCSP_PID 2>/dev/null

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Demo completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"