.PHONY: help build clean test test-verbose run run-rsa run-ecc run-intermediate run-force clean-ca deps tidy fmt all

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
NC=\033[0m

# Default parameters
BINARY_NAME=micropki
TEST_CA_DIR=./test-ca
PASSPHRASE_FILE=$(TEST_CA_DIR)/passphrase.txt
LOG_DIR=./logs

help: ## Show this help
	@echo "$(BLUE)MicroPKI Makefile$(NC)"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

build: ## Build the project
	@echo "$(BLUE)Building project...$(NC)"
	go build -o $(BINARY_NAME) cmd/micropki/main.go
	@echo "$(GREEN)✓ Binary created: ./$(BINARY_NAME)$(NC)"

clean: ## Clean all generated files
	@echo "$(YELLOW)Cleaning...$(NC)"
	rm -f $(BINARY_NAME)
	rm -rf $(TEST_CA_DIR)
	rm -rf $(LOG_DIR)
	go clean -cache
	@echo "$(GREEN)✓ Clean completed$(NC)"

clean-ca: ## Clean only test CA directories
	@echo "$(YELLOW)Cleaning test CAs...$(NC)"
	rm -rf $(TEST_CA_DIR)/pki*
	rm -rf $(LOG_DIR)
	@echo "$(GREEN)✓ Test CAs cleaned$(NC)"

deps: ## Download dependencies
	@echo "$(BLUE)Downloading dependencies...$(NC)"
	go mod download
	go mod verify
	@echo "$(GREEN)✓ Dependencies downloaded$(NC)"

tidy: ## Clean and update dependencies
	@echo "$(BLUE)Updating dependencies...$(NC)"
	go mod tidy
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(NC)"
	go fmt ./...
	@echo "$(GREEN)✓ Code formatted$(NC)"

test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	go test ./...
	@echo "$(GREEN)✓ Tests completed$(NC)"

test-verbose: ## Run tests with verbose output
	@echo "$(BLUE)Running tests (verbose)...$(NC)"
	go test -v ./...
	@echo "$(GREEN)✓ Tests completed$(NC)"

prepare-test-dir:
	@echo "$(BLUE)Preparing test directory...$(NC)"
	mkdir -p $(TEST_CA_DIR)
	mkdir -p $(LOG_DIR)
	@if [ ! -f $(PASSPHRASE_FILE) ]; then \
		echo "MySecure-Passphrase-$$(date +%s)" > $(PASSPHRASE_FILE); \
		chmod 600 $(PASSPHRASE_FILE); \
		echo "$(GREEN)✓ Created passphrase file: $(PASSPHRASE_FILE)$(NC)"; \
	fi

run-rsa: build prepare-test-dir ## Create RSA Root CA
	@echo "$(BLUE)Creating RSA Root CA...$(NC)"
	./$(BINARY_NAME) ca init \
		--subject "/CN=RSA Root CA/OU=Development/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file $(PASSPHRASE_FILE) \
		--out-dir $(TEST_CA_DIR)/pki-rsa \
		--validity-days 365 \
		--log-file $(LOG_DIR)/rsa-init.log
	@echo "$(GREEN)✓ RSA Root CA created in $(TEST_CA_DIR)/pki-rsa$(NC)"

run-ecc: build prepare-test-dir ## Create ECC Root CA
	@echo "$(BLUE)Creating ECC Root CA...$(NC)"
	./$(BINARY_NAME) ca init \
		--subject "/CN=ECC Root CA" \
		--key-type ecc \
		--key-size 384 \
		--passphrase-file $(PASSPHRASE_FILE) \
		--out-dir $(TEST_CA_DIR)/pki-ecc \
		--validity-days 365 \
		--log-file $(LOG_DIR)/ecc-init.log
	@echo "$(GREEN)✓ ECC Root CA created in $(TEST_CA_DIR)/pki-ecc$(NC)"

run-intermediate: build prepare-test-dir ## Create Intermediate CA
	@echo "$(BLUE)Creating Intermediate CA...$(NC)"
	@if [ ! -d "$(TEST_CA_DIR)/pki-rsa" ]; then \
		echo "$(RED)Root CA not found. Run 'make run-rsa' first$(NC)"; \
		exit 1; \
	fi
	./$(BINARY_NAME) ca init-intermediate \
		--subject "/CN=Intermediate CA/OU=Security/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--out-dir $(TEST_CA_DIR)/pki-intermediate \
		--validity-days 365 \
		--root-ca-dir $(TEST_CA_DIR)/pki-rsa \
		--root-passphrase-file $(PASSPHRASE_FILE) \
		--passphrase-file $(PASSPHRASE_FILE) \
		--max-path-len 1
	@echo "$(GREEN)✓ Intermediate CA created$(NC)"

run-all: run-rsa run-intermediate ## Create Root and Intermediate CAs
	@echo "$(GREEN)✓ Root and Intermediate CAs created$(NC)"

show-info-rsa: ## Show information about RSA CA
	@echo "$(BLUE)=== RSA CA Information ===$(NC)"
	@if [ -f $(TEST_CA_DIR)/pki-rsa/certs/ca.cert.pem ]; then \
		openssl x509 -in $(TEST_CA_DIR)/pki-rsa/certs/ca.cert.pem -text -noout | head -10; \
		echo "\n$(YELLOW)Verification:$(NC)"; \
		openssl verify -CAfile $(TEST_CA_DIR)/pki-rsa/certs/ca.cert.pem $(TEST_CA_DIR)/pki-rsa/certs/ca.cert.pem; \
	else \
		echo "$(RED)RSA CA not found. Run 'make run-rsa' first$(NC)"; \
	fi

show-info-intermediate: ## Show information about Intermediate CA
	@echo "$(BLUE)=== Intermediate CA Information ===$(NC)"
	@if [ -f $(TEST_CA_DIR)/pki-intermediate/certs/intermediate.cert.pem ]; then \
		openssl x509 -in $(TEST_CA_DIR)/pki-intermediate/certs/intermediate.cert.pem -text -noout | head -10; \
		echo "\n$(YELLOW)Verification:$(NC)"; \
		openssl verify -CAfile $(TEST_CA_DIR)/pki-rsa/certs/ca.cert.pem $(TEST_CA_DIR)/pki-intermediate/certs/intermediate.cert.pem; \
		echo "\n$(YELLOW)Extensions:$(NC)"; \
		openssl x509 -in $(TEST_CA_DIR)/pki-intermediate/certs/intermediate.cert.pem -text -noout | grep -A 5 "X509v3 extensions"; \
	else \
		echo "$(RED)Intermediate CA not found. Run 'make run-intermediate' first$(NC)"; \
	fi

list: ## List all created CAs
	@echo "$(BLUE)=== Created CAs ===$(NC)"
	@ls -la $(TEST_CA_DIR)/ 2>/dev/null | grep pki || echo "No CAs created"

view-log: ## View the latest log
	@echo "$(BLUE)=== Latest Log ===$(NC)"
	@if [ -f $(LOG_DIR)/rsa-init.log ]; then \
		cat $(LOG_DIR)/rsa-init.log; \
	elif [ -f $(LOG_DIR)/ecc-init.log ]; then \
		cat $(LOG_DIR)/ecc-init.log; \
	else \
		echo "$(RED)Log files not found$(NC)"; \
	fi

.DEFAULT_GOAL := help

db-init: build ## Initialize certificate database
	@echo "$(BLUE)Initializing database...$(NC)"
	./$(BINARY_NAME) db init --db-path ./test-ca/pki-rsa/micropki.db

repo-serve: build ## Start repository server
	@echo "$(BLUE)Starting repository server...$(NC)"
	./$(BINARY_NAME) repo serve \
		--host 127.0.0.1 \
		--port 8080 \
		--db-path ./test-ca/pki-rsa/micropki.db \
		--cert-dir ./test-ca/pki-rsa/certs

list-certs: build ## List all certificates
	@echo "$(BLUE)Listing certificates...$(NC)"
	./$(BINARY_NAME) ca list-certs --db-path ./test-ca/pki-rsa/micropki.db

revoke: build ## Revoke a certificate
	@echo "$(BLUE)Revoking certificate...$(NC)"
	@read -p "Enter serial number: " serial; \
	read -p "Enter reason (keyCompromise, superseded, etc.): " reason; \
	./$(BINARY_NAME) ca revoke $$serial --reason $$reason --db-path ./test-ca/pki-rsa/micropki.db

gen-crl-root: build ## Generate Root CRL
	@echo "$(BLUE)Generating Root CRL...$(NC)"
	./$(BINARY_NAME) ca gen-crl --ca root --ca-dir ./test-ca/pki-rsa --passphrase-file ./test-ca/passphrase.txt --db-path ./test-ca/pki-rsa/micropki.db

gen-crl-intermediate: build ## Generate Intermediate CRL
	@echo "$(BLUE)Generating Intermediate CRL...$(NC)"
	./$(BINARY_NAME) ca gen-crl --ca intermediate --ca-dir ./test-ca/pki-intermediate --passphrase-file ./test-ca/passphrase.txt --db-path ./test-ca/pki-rsa/micropki.db

verify-crl: build ## Verify CRL with OpenSSL
	@echo "$(BLUE)Verifying CRL...$(NC)"
	@openssl crl -in ./test-ca/pki-rsa/crl/root.crl.pem -inform PEM -text -noout || echo "CRL not found"