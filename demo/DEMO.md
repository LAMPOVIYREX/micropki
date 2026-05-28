# Demo Walkthrough

The demo script (`demo.sh`) performs the following steps:

1. **Initialize Root CA** – creates self-signed root certificate
2. **Initialize Intermediate CA** – creates intermediate signed by root
3. **Initialize database** – creates SQLite schema
4. **Issue server certificate** – generates CSR and gets signed certificate
5. **Issue client certificate** – generates CSR and gets signed certificate
6. **Start repository server** – HTTP server for certificate retrieval
7. **Validate certificate chain** – full chain validation (root→intermediate→leaf)
8. **Check revocation status** – OCSP/CRL check (should return "good")

Expected output: all steps should report [OK] or [PASS].