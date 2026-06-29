//go:build test_native

package locksmith

// NewWithCache overrides the default implementation when the test_native build tag is set.
// It injects a mock backend that uses in‑memory storage, enabling deterministic tests
// without touching the real OS keychain.
func NewWithCacheMock(cache Cache) *Locksmith {
	return &Locksmith{
		Service: DefaultService,
		Cache:   cache,
		Backend: newMockBackend(),
		Options: Options{RequireBiometrics: false}, // default read‑only behavior
	}
}
