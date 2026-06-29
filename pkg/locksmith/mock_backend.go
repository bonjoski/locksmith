//go:build test_native && locksmith_admin

package locksmith

import (
	"errors"
	"sync"
)

// MockBackend implements the Backend interface for testing.
// It stores secrets in an in-memory map and does not perform any biometric checks.
type MockBackend struct {
	mu    sync.RWMutex
	store map[string][]byte
}

func newMockBackend() *MockBackend {
	return &MockBackend{store: make(map[string][]byte)}
}

func (m *MockBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	key := service + "/" + account
	m.mu.Lock()
	defer m.mu.Unlock()
	copyData := make([]byte, len(data))
	copy(copyData, data)
	m.store[key] = copyData
	return nil
}

func (m *MockBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	key := service + "/" + account
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.store[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	copyData := make([]byte, len(data))
	copy(copyData, data)
	return copyData, nil
}

func (m *MockBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	key := service + "/" + account
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, key)
	return nil
}

func (m *MockBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	prefix := service + "/"
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.store {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}
