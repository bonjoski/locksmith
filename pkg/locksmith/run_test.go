package locksmith

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResolveEnvironment tests parsing and resolving secrets from host environment and file env variables
func TestResolveEnvironment(t *testing.T) {
	// Set up mock cache and backend
	mc := &MockCache{secrets: make(map[string]Secret)}

	// Seed secrets
	sec1 := Secret{
		Value:     []byte("super-secret-123"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	sec2 := Secret{
		Value:     []byte("api-token-xyz"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Marshaled secrets to simulate Backend database storage
	sec1Data, _ := json.Marshal(sec1)
	sec2Data, _ := json.Marshal(sec2)

	mb := &testBackend{
		secrets: map[string][]byte{
			"db/password": sec1Data,
			"api/token":   sec2Data,
		},
	}

	ls := NewWithCache(mc)
	ls.Backend = mb

	// Host env
	hostEnv := []string{
		"NORMAL_VAR=hello",
		"DB_PASSWORD=locksmith://db/password",
		"ANOTHER_VAR=world",
	}

	// Env file vars
	envFileVars := map[string]string{
		"LOCKSMITH_SECRET_API_TOKEN": "api/token",
		"NORMAL_VAR":                 "overridden-hello", // overrides hostEnv
	}

	resolved, err := ls.ResolveEnvironment(hostEnv, envFileVars)
	if err != nil {
		t.Fatalf("ResolveEnvironment failed: %v", err)
	}

	// Convert result slice to map for easy assertion
	resMap := make(map[string]string)
	for _, item := range resolved {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			resMap[parts[0]] = parts[1]
		}
	}

	// Assertions
	if val := resMap["NORMAL_VAR"]; val != "overridden-hello" {
		t.Errorf("Expected NORMAL_VAR=overridden-hello, got %s", val)
	}
	if val := resMap["ANOTHER_VAR"]; val != "world" {
		t.Errorf("Expected ANOTHER_VAR=world, got %s", val)
	}
	if val := resMap["DB_PASSWORD"]; val != "super-secret-123" {
		t.Errorf("Expected DB_PASSWORD=super-secret-123, got %s", val)
	}
	if val := resMap["API_TOKEN"]; val != "api-token-xyz" {
		t.Errorf("Expected API_TOKEN=api-token-xyz, got %s", val)
	}
	if _, exists := resMap["LOCKSMITH_SECRET_API_TOKEN"]; exists {
		t.Error("LOCKSMITH_SECRET_API_TOKEN should be stripped from output environment")
	}
}

// TestParseEnvFile tests parsing a standard .env file
func TestParseEnvFile(t *testing.T) {
	content := `
# This is a comment
KEY1=val1
  KEY2 = val2  
KEY3="quoted-value"
KEY4='single-quoted'

# Another comment
KEY5=
`
	tmpDir, err := os.MkdirTemp("", "locksmith-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	vars, err := parseEnvFile(envPath)
	if err != nil {
		t.Fatalf("parseEnvFile failed: %v", err)
	}

	if vars["KEY1"] != "val1" {
		t.Errorf("Expected val1, got %q", vars["KEY1"])
	}
	if vars["KEY2"] != "val2" {
		t.Errorf("Expected val2, got %q", vars["KEY2"])
	}
	if vars["KEY3"] != "quoted-value" {
		t.Errorf("Expected quoted-value, got %q", vars["KEY3"])
	}
	if vars["KEY4"] != "single-quoted" {
		t.Errorf("Expected single-quoted, got %q", vars["KEY4"])
	}
	if val, ok := vars["KEY5"]; !ok || val != "" {
		t.Errorf("Expected empty string for KEY5, got %q (ok=%v)", val, ok)
	}
}

type testBackend struct {
	secrets map[string][]byte
}

func (t *testBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (t *testBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return t.secrets[account], nil
}

func (t *testBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (t *testBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return nil, nil
}
