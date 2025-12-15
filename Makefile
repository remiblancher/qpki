.PHONY: build test test-race lint clean all help

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

test: ## Run tests
	go test -v ./...

test-race: ## Run tests with race detector
	go test -v -race ./...

test-cover: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-openssl: ## Run OpenSSL validation tests
	./test/openssl/run_all.sh

test-bc: ## Run Bouncy Castle validation tests
	cd test/bouncycastle && mvn -q package
	./test/bouncycastle/run.sh

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

all: lint test-race build ## Run all checks and build

# Development helpers
dev-setup: ## Setup development environment
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
