# Claude Code Guidelines for `locksmith`


## Build & Test Commands
- **Build CLI:** `go build -o bin/locksmith ./cmd/locksmith`
- **Build Summon Provider:** `go build -o bin/summon-locksmith ./cmd/summon-locksmith`
- **Unit Tests:** `go test -v ./...`
- **Cryptographic & SPIFFE Tests:** `go test -v ./pkg/slice ./pkg/spiffe ./pkg/ca ./pkg/stepup`
- **Linter:** `golangci-lint run`
- **Diagnostics:** `./bin/locksmith doctor`

## Code Style & Architectural Invariants
- Enclave-first security: secrets must remain sealed in Keychain/Secure Enclave/TPM2.
- In-memory slicing (`pkg/slice`) with explicit `memclr` zeroization for all decrypted secrets.
- SPIFFE X.509 SVIDs must enforce Name Constraints and local trust domain (`spiffe://bonjoski/...`).
- Zero plaintext secret logging to disk or stdout.
- Subagent burst rate limiting to avoid Touch ID modal spam during concurrent execution.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
