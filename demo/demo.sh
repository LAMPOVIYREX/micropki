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

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $REPO_PID $OCSP_PID 2>/dev/null

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Demo completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"