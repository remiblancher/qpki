.PHONY: build test test-race test-acceptance test-crossval test-all lint clean all help install build-all smoke-test fuzz fuzz-quick fuzz-all test-acceptance-hsm-pqc test-acceptance-softhsm test-acceptance-utimaco docker-utimaco-sim docker-qpki-runner run-utimaco-sim test-hsm-utimaco

# Build variables
BINARY_NAME=qpki
BUILD_DIR=bin

# Go variables
GOFLAGS=-trimpath
LDFLAGS=-s -w

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qpki

install: ## Install to GOPATH/bin
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/qpki

test: ## Run unit and functional tests
	go test -v ./...

test-race: ## Run tests with race detector
	go test -v -race ./...

test-acceptance: build ## Run acceptance tests (CLI black box)
	go test -v -tags=acceptance ./test/acceptance/...

test-acceptance-pki: build ## Run PKI acceptance tests
	go test -v -tags=acceptance -run 'TestA_(Key|CA|CSR|Cert|CRL|Credential|Profile|Inspect|E2E|CLI)' ./test/acceptance/...

test-acceptance-ocsp: build ## Run OCSP acceptance tests
	go test -v -tags=acceptance -run 'TestA_OCSP' ./test/acceptance/...

test-acceptance-tsa: build ## Run TSA acceptance tests
	go test -v -tags=acceptance -run 'TestA_TSA' ./test/acceptance/...

test-acceptance-cms: build ## Run CMS acceptance tests
	go test -v -tags=acceptance -run 'TestA_CMS' ./test/acceptance/...

test-acceptance-hsm: build ## Run HSM-specific tests (any HSM via HSM_CONFIG)
	go test -v -tags=acceptance -run 'TestA_HSM' ./test/acceptance/...

test-acceptance-hsm-pqc: build ## Run PQC HSM tests (requires HSM_PQC_ENABLED=1)
	go test -v -tags=acceptance -run 'TestA_HSM_PQC' ./test/acceptance/...

test-acceptance-softhsm: build ## Run ALL acceptance tests with SoftHSM (TEST_HSM_MODE=1)
	@echo "=== Running all acceptance tests with SoftHSM (EC/RSA) ==="
	@echo "Note: PQC tests will be skipped (SoftHSM doesn't support ML-DSA/ML-KEM)"
	TEST_HSM_MODE=1 go test -v -tags=acceptance ./test/acceptance/...

test-acceptance-agility: build ## Run crypto-agility acceptance tests (includes rotation)
	go test -v -tags=acceptance -run 'TestA_Agility' ./test/acceptance/...

test-crossval: ## Run cross-validation tests (OpenSSL, BouncyCastle)
	go test -v -tags=crossval ./test/crossval/...

test-all: test test-acceptance test-crossval ## Run all tests

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
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qpki
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/qpki
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/qpki
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/qpki
	-@which lipo > /dev/null 2>&1 && lipo -create -output $(BUILD_DIR)/$(BINARY_NAME)-darwin-universal $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/qpki

smoke-test: build ## Run smoke test
	@rm -rf /tmp/pki-test
	@mkdir -p /tmp/pki-test
	./$(BUILD_DIR)/$(BINARY_NAME) ca init --profile ec/root-ca --var cn="Test CA" --ca-dir /tmp/pki-test/ca
	./$(BUILD_DIR)/$(BINARY_NAME) ca export --ca-dir /tmp/pki-test/ca --out /tmp/pki-test/ca.crt
	./$(BUILD_DIR)/$(BINARY_NAME) credential enroll --ca-dir /tmp/pki-test/ca --cred-dir /tmp/pki-test/creds \
		--profile ec/tls-server --var cn=test.local --var dns_names=test.local
	./$(BUILD_DIR)/$(BINARY_NAME) cert list --ca-dir /tmp/pki-test/ca
	openssl verify -CAfile /tmp/pki-test/ca.crt /tmp/pki-test/creds/*/certificates.pem
	@rm -rf /tmp/pki-test
	@echo "Smoke test passed!"

all: lint test-race build ## Run all checks and build

# =============================================================================
# Fuzz Testing
# =============================================================================

FUZZ_TIME ?= 60s
FUZZ_PARALLEL ?= 4

fuzz: ## Run fuzz tests (FUZZ_TIME=60s by default)
	@echo "=== Running Fuzz Tests ($(FUZZ_TIME) per target) ==="
	@echo "--- x509util package ---"
	go test -fuzz=FuzzParsePQCCSR -fuzztime=$(FUZZ_TIME) ./internal/x509util/
	go test -fuzz=FuzzDecodeHybridExtension -fuzztime=$(FUZZ_TIME) ./internal/x509util/
	go test -fuzz=FuzzParseCatalystExtensions -fuzztime=$(FUZZ_TIME) ./internal/x509util/
	go test -fuzz=FuzzDecodeRelatedCertificate -fuzztime=$(FUZZ_TIME) ./internal/x509util/
	@echo "--- ca package ---"
	go test -fuzz=FuzzParseCompositeSignatureValue -fuzztime=$(FUZZ_TIME) ./internal/ca/
	go test -fuzz=FuzzParseCompositePublicKey -fuzztime=$(FUZZ_TIME) ./internal/ca/
	go test -fuzz=FuzzParseMLDSA65PublicKey -fuzztime=$(FUZZ_TIME) ./internal/ca/
	@echo "--- crypto package ---"
	go test -fuzz=FuzzParseAlgorithm -fuzztime=$(FUZZ_TIME) ./internal/crypto/
	go test -fuzz=FuzzParsePublicKeyMLDSA65 -fuzztime=$(FUZZ_TIME) ./internal/crypto/
	@echo "--- profile package ---"
	go test -fuzz=FuzzLoadProfileFromBytes -fuzztime=$(FUZZ_TIME) ./internal/profile/
	go test -fuzz=FuzzParseDuration -fuzztime=$(FUZZ_TIME) ./internal/profile/
	@echo "--- credential package ---"
	go test -fuzz=FuzzCredentialUnmarshalJSON -fuzztime=$(FUZZ_TIME) ./internal/credential/
	go test -fuzz=FuzzGenerateCredentialID -fuzztime=$(FUZZ_TIME) ./internal/credential/
	@echo "--- cms package ---"
	go test -fuzz=FuzzParseSignedData -fuzztime=$(FUZZ_TIME) ./internal/cms/
	go test -fuzz=FuzzParseEnvelopedData -fuzztime=$(FUZZ_TIME) ./internal/cms/
	@echo "--- ocsp package ---"
	go test -fuzz=FuzzU_ParseRequest -fuzztime=$(FUZZ_TIME) ./internal/ocsp/
	@echo "--- tsa package ---"
	go test -fuzz=FuzzU_Request_Parse -fuzztime=$(FUZZ_TIME) ./internal/tsa/
	@echo "=== Fuzz Testing Complete ==="

fuzz-quick: ## Run quick fuzz tests (10s per target)
	$(MAKE) fuzz FUZZ_TIME=10s

fuzz-all: ## Run all fuzz targets for extended time (5min each)
	@echo "=== Running Extended Fuzz Tests (5min per target) ==="
	@for pkg in x509util ca crypto profile credential cms ocsp tsa; do \
		echo "--- Fuzzing $$pkg ---"; \
		go test -fuzz=. -fuzztime=5m ./internal/$$pkg/ || true; \
	done
	@echo "=== Extended Fuzz Testing Complete ==="

# =============================================================================
# Cross-Testing (OpenSSL + BouncyCastle)
# =============================================================================

.PHONY: crosstest crosstest-fixtures crosstest-openssl crosstest-bc

crosstest-fixtures: build ## Generate cross-test fixtures
	@echo "=== Generating cross-test fixtures ==="
	./test/generate_qpki_fixtures.sh

crosstest-openssl: crosstest-fixtures ## Run OpenSSL cross-tests
	@echo "=== Running OpenSSL cross-tests ==="
	cd test/crossval/openssl && ./run_all.sh

crosstest-bc: crosstest-fixtures ## Run BouncyCastle cross-tests (requires Java 17+)
	@echo "=== Running BouncyCastle cross-tests ==="
	cd test/crossval/bouncycastle && mvn -q test

crosstest: crosstest-openssl crosstest-bc ## Run all cross-tests
	@echo ""
	@echo "=== All cross-tests PASSED ==="

# Development helpers
dev-setup: ## Setup development environment
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

# =============================================================================
# Quality & Compliance Reports
# =============================================================================

.PHONY: quality-docs quality-report validate-profiles validate-specs ci-report

quality-docs: ## Generate all quality documentation from specs
	@echo "=== Generating Quality Documentation ==="
	./scripts/generate-quality-docs.sh

quality-report: ## Generate quality dashboard report (legacy)
	@echo "=== Generating Quality Dashboard ==="
	./scripts/generate-quality-report.sh

ci-report: coverage ## Generate CI-style consolidated report
	@echo "=== Generating CI Quality Report ==="
	COVERAGE_FILE=coverage.out OUTPUT_FILE=docs/quality/testing/COVERAGE.md ./scripts/ci/generate-ci-report.sh

validate-profiles: ## Validate all profiles against JSON Schema
	@echo "=== Validating Profile Schemas ==="
	@if command -v ajv > /dev/null 2>&1; then \
		ajv validate -s specs/schemas/profile-schema.json -d "profiles/**/*.yaml" --all-errors; \
	else \
		echo "ajv not installed. Install with: npm install -g ajv-cli"; \
		exit 1; \
	fi

validate-specs: ## Validate all spec YAML files
	@echo "=== Validating Spec Files ==="
	@for f in specs/**/*.yaml; do \
		echo "Checking $$f..."; \
		yq eval 'true' "$$f" > /dev/null || exit 1; \
	done
	@echo "All spec files are valid YAML"

# =============================================================================
# Utimaco HSM Testing (macOS → Docker)
# =============================================================================

docker-utimaco-sim: ## Build Utimaco simulator Docker image
	@if [ ! -d "vendor/utimaco-sim/sim5_linux" ]; then \
		echo "Error: vendor/utimaco-sim/sim5_linux not found"; \
		echo "Copy sim5_linux from QuantumProtect evaluation package"; \
		exit 1; \
	fi
	cp -r vendor/utimaco-sim/sim5_linux docker/utimaco-sim/
	docker build -t utimaco-sim docker/utimaco-sim/
	rm -rf docker/utimaco-sim/sim5_linux

docker-qpki-runner: ## Build qpki runner Docker image (compiles from source)
	@if [ ! -f "vendor/utimaco-sdk/lib/libcs_pkcs11_R3.so" ]; then \
		echo "Error: vendor/utimaco-sdk/lib/libcs_pkcs11_R3.so not found"; \
		echo "Copy PKCS11_R3 from SecurityServer SDK"; \
		exit 1; \
	fi
	docker build -t qpki-runner -f docker/qpki-runner/Dockerfile .

run-utimaco-sim: docker-qpki-runner ## Start Utimaco simulator container and initialize HSM
	@docker network create qpki-net 2>/dev/null || true
	@docker ps -q -f name=utimaco-sim | xargs -r docker stop
	@docker ps -aq -f name=utimaco-sim | xargs -r docker rm
	docker run -d --network qpki-net --name utimaco-sim utimaco-sim
	@echo "Waiting for simulator to start..."
	@sleep 3
	@docker logs utimaco-sim 2>&1 | tail -5
	@echo "Initializing HSM..."
	@docker run --rm --network qpki-net \
		-e CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg \
		--entrypoint /opt/utimaco/bin/init-hsm.sh qpki-runner

test-hsm-utimaco: run-utimaco-sim ## Run qpki HSM tests with Utimaco simulator
	@echo "=== Testing qpki version ==="
	docker run --rm --network qpki-net \
		-e HSM_PIN=12345688 \
		qpki-runner version
	@echo "=== Testing ML-DSA key generation ==="
	docker run --rm --network qpki-net \
		-e HSM_PIN=12345688 \
		qpki-runner key gen --algorithm ml-dsa-65 --hsm-config /etc/qpki/hsm.yaml --key-label test-mldsa-$$(date +%s)

test-acceptance-utimaco: run-utimaco-sim ## Run ALL acceptance tests with Utimaco (EC/RSA/ML-DSA/ML-KEM)
	@echo "=== Running all acceptance tests with Utimaco HSM ==="
	@echo "Note: SLH-DSA tests will be skipped (Utimaco doesn't support SLH-DSA)"
	docker run --rm --network qpki-net \
		-e TEST_HSM_MODE=1 \
		-e HSM_CONFIG=/etc/qpki/hsm.yaml \
		-e HSM_PIN=12345688 \
		-e HSM_PQC_ENABLED=1 \
		-e QPKI_BINARY=/opt/qpki/bin/qpki \
		--entrypoint /opt/qpki/bin/hsm_test \
		qpki-runner -test.v
