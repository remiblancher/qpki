.PHONY: build test test-race lint clean all help install build-all smoke-test

# Build variables
BINARY_NAME=pki
BUILD_DIR=bin

# Go variables
GOFLAGS=-trimpath
LDFLAGS=-s -w

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/pki

install: ## Install to GOPATH/bin
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/pki

test: ## Run tests
	go test -v ./...

test-race: ## Run tests with race detector
	go test -v -race ./...

coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	go fmt ./...
	goimports -w .

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)/
	rm -f coverage.out coverage.html

deps: ## Download dependencies
	go mod download
	go mod tidy

build-all: ## Build for all platforms
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/pki
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/pki
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/pki
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/pki
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/pki

smoke-test: build ## Run smoke test
	@mkdir -p /tmp/pki-test
	./$(BUILD_DIR)/$(BINARY_NAME) init-ca --name "Test CA" --dir /tmp/pki-test/ca
	./$(BUILD_DIR)/$(BINARY_NAME) issue --ca-dir /tmp/pki-test/ca --profile ec/tls-server \
		--cn test.local --dns test.local \
		--out /tmp/pki-test/server.crt --key-out /tmp/pki-test/server.key
	./$(BUILD_DIR)/$(BINARY_NAME) list --ca-dir /tmp/pki-test/ca
	openssl verify -CAfile /tmp/pki-test/ca/ca.crt /tmp/pki-test/server.crt
	@rm -rf /tmp/pki-test
	@echo "Smoke test passed!"

all: lint test-race build ## Run all checks and build

# =============================================================================
# Cross-Testing (OpenSSL + BouncyCastle)
# =============================================================================

.PHONY: crosstest crosstest-fixtures crosstest-openssl crosstest-bc

crosstest-fixtures: build ## Generate cross-test fixtures
	@echo "=== Generating cross-test fixtures ==="
	./test/generate_fixtures.sh

crosstest-openssl: crosstest-fixtures ## Run OpenSSL cross-tests
	@echo "=== Running OpenSSL cross-tests ==="
	cd test/openssl && ./run_all.sh

crosstest-bc: crosstest-fixtures ## Run BouncyCastle cross-tests (requires Java 17+)
	@echo "=== Running BouncyCastle cross-tests ==="
	cd test/bouncycastle && mvn -q test

crosstest: crosstest-openssl crosstest-bc ## Run all cross-tests
	@echo ""
	@echo "=== All cross-tests PASSED ==="

# Development helpers
dev-setup: ## Setup development environment
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
