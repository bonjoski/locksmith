# Project variables
BINARY_NAME=locksmith
BUILD_DIR=bin
SIGN_ID="Apple Development"
IDENTIFIER="com.locksmith"
VERSION=$(shell grep "Version =" pkg/locksmith/version.go | cut -d '"' -f 2)

# Path configuration
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

.PHONY: all build sign clean test lint security gosec gitleaks check fmt tidy vet help

# Default target
all: build sign

## Build targets
build: ## Compile the binary
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/locksmith

sign: build ## Sign the binary with developer identity
	@echo "Signing $(BINARY_NAME)..."
	@codesign --force --identifier $(IDENTIFIER) --sign $(SIGN_ID) $(BINARY_NAME)
	@codesign -dvvv $(BINARY_NAME)

## Verification targets
check: fmt tidy vet lint security gosec gitleaks semgrep ## Run all quality and security checks

test: ## Run unit tests
	@echo "Running tests..."
	@go test ./...

fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...

tidy: ## Tidy Go modules
	@echo "Tidying modules..."
	@go mod tidy

vet: ## Run go vet
	@echo "Vetting code..."
	@go vet ./...

# Tool checks and installation
define install_if_missing
	@if [ ! -f $(GOBIN)/$(1) ]; then \
		echo "Installing $(1)..."; \
		$(2); \
	fi
endef

lint: ## Run golangci-lint (installs if missing)
	$(call install_if_missing,golangci-lint,curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN))
	@echo "Running golangci-lint..."
	@$(GOBIN)/golangci-lint run

security: ## Run govulncheck (installs if missing)
	$(call install_if_missing,govulncheck,go install golang.org/x/vuln/cmd/govulncheck@latest)
	@echo "Running govulncheck..."
	@$(GOBIN)/govulncheck ./...

gosec: ## Run gosec (installs if missing)
	$(call install_if_missing,gosec,go install github.com/securego/gosec/v2/cmd/gosec@latest)
	@echo "Running gosec..."
	@$(GOBIN)/gosec -exclude=G115 ./...

gitleaks: ## Run gitleaks (installs if missing)
	@if ! command -v gitleaks > /dev/null; then \
		echo "Installing gitleaks..."; \
		brew install gitleaks; \
	fi
	@echo "Running gitleaks..."
	@if [ -d .git ]; then \
		gitleaks detect --verbose; \
	else \
		gitleaks detect --no-git --source . --verbose; \
	fi

semgrep: ## Run semgrep (installs if missing)
	@if ! command -v semgrep > /dev/null; then \
		echo "Installing semgrep..."; \
		brew install semgrep; \
	fi
	@echo "Running semgrep..."
	@semgrep scan --config auto --error --quiet

install-tools: ## Manually install all required tools
	@echo "Checking/Installing tools..."
	$(call install_if_missing,golangci-lint,curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN))
	$(call install_if_missing,govulncheck,go install golang.org/x/vuln/cmd/govulncheck@latest)
	$(call install_if_missing,gosec,go install github.com/securego/gosec/v2/cmd/gosec@latest)
	@if ! command -v gitleaks > /dev/null; then brew install gitleaks; fi
	@if ! command -v semgrep > /dev/null; then brew install semgrep; fi

## Utility targets
clean: ## Remove build artifacts
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)
	@rm -rf $(BUILD_DIR)

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
