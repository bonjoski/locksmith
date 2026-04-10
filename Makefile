# Project variables
BINARY_NAME=locksmith
BUILD_DIR=bin
PROD_SIGN_ID?="Developer ID Application: Benjamin Skolmoski"
SIGN_ID?=$(PROD_SIGN_ID)
IDENTIFIER="io.github.bonjoski.locksmith"
GPG_KEY_ID=7BB5B44244E586B0
VERSION=$(shell grep "Version =" pkg/locksmith/version.go | cut -d '"' -f 2)

# Path configuration
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# Tool versions
GOLANGCI_LINT_VERSION=v1.64.2
GOVULNCHECK_VERSION=v1.1.4
GOSEC_VERSION=v2.22.11

.PHONY: all build sign clean test lint govulncheck gosec gitleaks check fmt tidy vet help updates

# Default target
all: build sign

## Build targets
build: ## Compile the binary
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/locksmith

sign: build ## Sign the binary with developer identity and hardened runtime
	@echo "Signing $(BINARY_NAME) with $(SIGN_ID)..."
	@codesign --force --options runtime --identifier $(IDENTIFIER) --sign "$(SIGN_ID)" $(BINARY_NAME)
	@codesign -dvvv $(BINARY_NAME)

release: ## Build release binaries for multiple architectures
	@echo "Building release binaries for $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building for darwin/arm64..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/locksmith
	@echo "Building for darwin/amd64..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/locksmith
	@echo "Building for windows/amd64..."
	@cd cmd/locksmith && \
		go run github.com/tc-hib/go-winres@latest init > /dev/null && \
		cp ../../assets/icon.png winres/icon.png && \
		sips -z 256 256 winres/icon.png > /dev/null && \
		go run github.com/tc-hib/go-winres@latest make > /dev/null
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/locksmith
	@echo "Building for windows/arm64..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe ./cmd/locksmith
	@rm -rf cmd/locksmith/winres cmd/locksmith/rsrc_*.syso
	@echo "Building for linux/amd64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/locksmith
	@echo "Building for linux/arm64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/locksmith
	@echo "Signing macOS binaries..."
	@codesign --force --options runtime --identifier $(IDENTIFIER) --sign "$(SIGN_ID)" $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64
	@codesign --force --options runtime --identifier $(IDENTIFIER) --sign "$(SIGN_ID)" $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	@echo "Packaging macOS App Bundles..."
	@./package_macos.sh assets/icon.png $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(BUILD_DIR)/Locksmith-darwin-arm64.app $(VERSION)
	@./package_macos.sh assets/icon.png $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BUILD_DIR)/Locksmith-darwin-amd64.app $(VERSION)
	@echo "Signing .app bundles..."
	@codesign --force --deep --options runtime --identifier $(IDENTIFIER) --sign "$(SIGN_ID)" $(BUILD_DIR)/Locksmith-darwin-arm64.app
	@codesign --force --deep --options runtime --identifier $(IDENTIFIER) --sign "$(SIGN_ID)" $(BUILD_DIR)/Locksmith-darwin-amd64.app
	@echo "Packaging release apps into zips..."
	@cd $(BUILD_DIR) && zip -q -r Locksmith-darwin-arm64.zip Locksmith-darwin-arm64.app
	@cd $(BUILD_DIR) && zip -q -r Locksmith-darwin-amd64.zip Locksmith-darwin-amd64.app
	@echo "Creating checksums..."
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-darwin-arm64 > checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-darwin-amd64 >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 Locksmith-darwin-arm64.zip >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 Locksmith-darwin-amd64.zip >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-windows-amd64.exe >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-windows-arm64.exe >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-linux-amd64 >> checksums.txt
	@cd $(BUILD_DIR) && shasum -a 256 $(BINARY_NAME)-linux-arm64 >> checksums.txt
	@make gpg-sign
	@echo "Release binaries and .app zips built in $(BUILD_DIR)/"

notarize: ## Notarize macOS ZIP artifacts
	@echo "Notarizing arm64..."
	@ARM64_ID=$$(xcrun notarytool submit $(BUILD_DIR)/Locksmith-darwin-arm64.zip \
		--keychain-profile "notarytool-profile" --output-format json | jq -r '.id'); \
	echo "arm64 submission ID: $$ARM64_ID"; \
	xcrun notarytool wait $$ARM64_ID --keychain-profile "notarytool-profile" --timeout 30m || \
	{ echo "--- Apple notarization log (arm64) ---"; \
	  xcrun notarytool log $$ARM64_ID --keychain-profile "notarytool-profile"; \
	  exit 1; }
	@echo "Notarizing amd64..."
	@AMD64_ID=$$(xcrun notarytool submit $(BUILD_DIR)/Locksmith-darwin-amd64.zip \
		--keychain-profile "notarytool-profile" --output-format json | jq -r '.id'); \
	echo "amd64 submission ID: $$AMD64_ID"; \
	xcrun notarytool wait $$AMD64_ID --keychain-profile "notarytool-profile" --timeout 30m || \
	{ echo "--- Apple notarization log (amd64) ---"; \
	  xcrun notarytool log $$AMD64_ID --keychain-profile "notarytool-profile"; \
	  exit 1; }

staple: ## Staple notarization tickets to .app bundles
	@echo "Stapling notarization tickets..."
	@xcrun stapler staple $(BUILD_DIR)/Locksmith-darwin-arm64.app
	@xcrun stapler staple $(BUILD_DIR)/Locksmith-darwin-amd64.app
	@echo "✓ Stapling complete. Re-packaging into ZIPs..."
	@rm -f $(BUILD_DIR)/Locksmith-darwin-arm64.zip
	@rm -f $(BUILD_DIR)/Locksmith-darwin-amd64.zip
	@cd $(BUILD_DIR) && zip -q -r Locksmith-darwin-arm64.zip Locksmith-darwin-arm64.app
	@cd $(BUILD_DIR) && zip -q -r Locksmith-darwin-amd64.zip Locksmith-darwin-amd64.app

gpg-sign: ## Sign all release artifacts with GPG
	@echo "Signing release artifacts with GPG (Key: $(GPG_KEY_ID))..."
	@for file in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
		gpg --detach-sign --armor --local-user $(GPG_KEY_ID) $$file; \
	done
	@gpg --detach-sign --armor --local-user $(GPG_KEY_ID) $(BUILD_DIR)/checksums.txt
	@echo "✓ GPG signatures created (.asc files)"

## Summon provider
build-summon: ## Build Summon provider binary
	@echo "Building summon-locksmith provider..."
	@go build -tags locksmith_admin -ldflags "-X main.version=$(VERSION)" -o summon-locksmith ./cmd/summon-locksmith

 install-summon: build-summon ## Install Summon provider
	@echo "Installing Summon provider..."
	@mkdir -p /usr/local/lib/summon
	@cp summon-locksmith /usr/local/lib/summon/locksmith
	@chmod +x /usr/local/lib/summon/locksmith
	@echo "✓ Summon provider installed at /usr/local/lib/summon/locksmith"

uninstall-summon: ## Uninstall Summon provider
	@echo "Uninstalling Summon provider..."
	@rm -f /usr/local/lib/summon/locksmith
	@echo "✓ Summon provider uninstalled"

## Verification targets
check: fmt tidy verify-deps vet lint govulncheck gosec trufflehog semgrep complexity entropy ## Run all quality and security checks

test: ## Run unit tests
	@echo "Running tests..."
	@go test -tags locksmith_admin ./...

test-manual: build ## Run manual biometric regression tests (macOS only)
	@echo "Running manual biometric tests..."
	@go test -v -tags manual_test ./cmd/locksmith/cmd

fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...

tidy: ## Tidy Go modules
	@echo "Tidying modules..."
	@go mod tidy

verify-deps: ## Verify dependencies and check for vulnerabilities
	@echo "Verifying module checksums..."
	@go mod verify
	@echo "Checking for vulnerable dependencies..."
	@go list -m all | xargs -n1 go list -json 2>/dev/null | jq -r 'select(.Vulnerable != null) | .Path' || echo "No vulnerable dependencies found"

vet: ## Run go vet
	@echo "Vetting code..."
	@go vet -tags locksmith_admin ./...

# Tool checks and installation
define install_if_missing
	@if [ ! -f $(GOBIN)/$(1) ]; then \
		echo "Installing $(1)..."; \
		$(2); \
	fi
endef

lint: ## Run golangci-lint (installs if missing)
	$(call install_if_missing,golangci-lint,go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))
	@echo "Running golangci-lint..."
	@$(GOBIN)/golangci-lint run --build-tags locksmith_admin

govulncheck: ## Run govulncheck (installs if missing)
	$(call install_if_missing,govulncheck,go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION))
	@echo "Running govulncheck..."
	@$(GOBIN)/govulncheck -tags locksmith_admin ./...

gosec: ## Run gosec (installs if missing)
	$(call install_if_missing,gosec,go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION))
	@echo "Running gosec..."
	@$(GOBIN)/gosec -tags locksmith_admin -severity high -exclude=G115 ./...

trufflehog: ## Run TruffleHog secret scanning (Modern)
	@if ! command -v trufflehog > /dev/null; then \
		echo "Installing TruffleHog..."; \
		brew install trufflehog; \
	fi
	@echo "Running TruffleHog..."
	@trufflehog git file://. --since-commit main --only-verified --fail 2> /dev/null && echo "No secrets found."

semgrep: ## Run semgrep (installs if missing)
	@if ! command -v semgrep > /dev/null; then \
		echo "Installing semgrep..."; \
		brew install semgrep; \
	fi
	@echo "Running semgrep..."
	@semgrep scan --config auto --error --quiet && echo "No issues found."

complexity: ## Run cyclomatic complexity check
	@echo "Checking code complexity..."
	@$(GOBIN)/gocyclo -over 15 .

entropy: ## Run entropy check for secrets
	@echo "Checking for high-entropy strings..."
	@go run scripts/entropy-checker/main.go 5.0 $$(grep -rhE "[a-zA-Z0-9+/]{20,}" . --exclude-dir=.git --exclude=go.sum || true)

install-tools: ## Manually install all required tools
	@echo "Checking/Installing tools..."
	$(call install_if_missing,golangci-lint,curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN))
	$(call install_if_missing,govulncheck,go install golang.org/x/vuln/cmd/govulncheck@latest)
	$(call install_if_missing,gosec,go install github.com/securego/gosec/v2/cmd/gosec@latest)
	@if ! command -v trufflehog > /dev/null; then brew install trufflehog; fi
	@if ! command -v semgrep > /dev/null; then brew install semgrep; fi

## Utility targets
clean: ## Remove build artifacts
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)
	@rm -f summon-locksmith
	@rm -rf $(BUILD_DIR)

updates: ## Check for Go module updates
	@go list -u -m all

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
