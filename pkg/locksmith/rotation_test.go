//go:build locksmith_admin

package locksmith

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

type testRotationBackend struct {
	secrets map[string][]byte
}

func (t *testRotationBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	t.secrets[account] = data
	return nil
}

func (t *testRotationBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	d, ok := t.secrets[account]
	if !ok {
		return nil, fmt.Errorf("secret %s not found", account)
	}
	return d, nil
}

func (t *testRotationBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(t.secrets, account)
	return nil
}

func (t *testRotationBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	var keys []string
	for k := range t.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestRotateSecretScript(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}
	mb := &testRotationBackend{secrets: make(map[string][]byte)}
	ls := NewWithCache(mc)
	ls.Backend = mb

	initialTime := time.Now().Add(-10 * time.Minute)
	oldSecret := Secret{
		Value:     []byte("old-pass"),
		CreatedAt: initialTime,
		ExpiresAt: initialTime.Add(time.Hour),
	}
	secretData, _ := json.Marshal(oldSecret)
	mb.secrets["db/password"] = secretData
	_ = mc.Set("db/password", oldSecret, time.Hour)

	var targetCommand string
	if runtime.GOOS == "windows" {
		targetCommand = `echo rotated-secret-123`
	} else {
		targetCommand = `echo "rotated-secret-123"`
	}

	ls.Config = &Config{
		Notifications: NotificationConfig{ExpiringThreshold: "5m"},
		Rotation: []RotationRule{
			{
				Secret:     "db/*",
				HookType:   "script",
				HookTarget: targetCommand,
				Timeout:    "5s",
			},
		},
	}

	err := ls.RotateSecret("db/password")
	if err != nil {
		t.Fatalf("RotateSecret failed: %v", err)
	}

	rotated, err := ls.Get("db/password")
	if err != nil {
		t.Fatalf("Failed to retrieve rotated secret: %v", err)
	}

	if string(rotated) != "rotated-secret-123" {
		t.Errorf("Expected rotated value 'rotated-secret-123', got '%s'", rotated)
	}

	meta, err := ls.GetWithMetadata("db/password")
	if err != nil {
		t.Fatalf("Failed to get rotated metadata: %v", err)
	}

	timeRemaining := time.Until(meta.ExpiresAt)
	if timeRemaining < 45*time.Minute || timeRemaining > 65*time.Minute {
		t.Errorf("Expected renewed expiration to be ~1 hour, got TTL duration: %v", timeRemaining)
	}
}

func TestRotateSecretWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		var req struct {
			Key    string `json:"key"`
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Key != "api/key" || req.Action != "rotate" {
			t.Errorf("Unexpected request JSON: %+v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":"webhook-rotated-xyz","expires_in":"2h"}`))
	}))
	defer server.Close()

	mc := &MockCache{secrets: make(map[string]Secret)}
	mb := &testRotationBackend{secrets: make(map[string][]byte)}
	ls := NewWithCache(mc)
	ls.Backend = mb

	oldSecret := Secret{
		Value:     []byte("old-api-key"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	secretData, _ := json.Marshal(oldSecret)
	mb.secrets["api/key"] = secretData
	_ = mc.Set("api/key", oldSecret, time.Hour)

	ls.Config = &Config{
		Notifications: NotificationConfig{ExpiringThreshold: "5m"},
		Rotation: []RotationRule{
			{
				Secret:     "api/*",
				HookType:   "webhook",
				HookTarget: server.URL,
				Timeout:    "5s",
			},
		},
	}

	err := ls.RotateSecret("api/key")
	if err != nil {
		t.Fatalf("RotateSecret failed: %v", err)
	}

	rotated, err := ls.Get("api/key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(rotated) != "webhook-rotated-xyz" {
		t.Errorf("Expected value 'webhook-rotated-xyz', got '%s'", rotated)
	}

	meta, err := ls.GetWithMetadata("api/key")
	if err != nil {
		t.Fatalf("GetWithMetadata failed: %v", err)
	}

	timeRemaining := time.Until(meta.ExpiresAt)
	if timeRemaining < 1*time.Hour || timeRemaining > 3*time.Hour {
		t.Errorf("Expected renewed expiration to be ~2 hours, got TTL duration: %v", timeRemaining)
	}
}

func TestLazyAutoRotationOnGet(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}
	mb := &testRotationBackend{secrets: make(map[string][]byte)}
	ls := NewWithCache(mc)
	ls.Backend = mb

	expiredTime := time.Now().Add(-2 * time.Hour)
	oldSecret := Secret{
		Value:     []byte("expired-val"),
		CreatedAt: expiredTime,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	secretData, _ := json.Marshal(oldSecret)
	mb.secrets["service/token"] = secretData
	_ = mc.Set("service/token", oldSecret, time.Hour)

	var targetCommand string
	if runtime.GOOS == "windows" {
		targetCommand = `echo lazy-rotated-secret`
	} else {
		targetCommand = `echo "lazy-rotated-secret"`
	}

	ls.Config = &Config{
		Notifications: NotificationConfig{ExpiringThreshold: "5m"},
		Rotation: []RotationRule{
			{
				Secret:     "service/*",
				HookType:   "script",
				HookTarget: targetCommand,
				Timeout:    "5s",
			},
		},
	}

	val, err := ls.Get("service/token")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(val) != "lazy-rotated-secret" {
		t.Errorf("Expected auto-rotated value 'lazy-rotated-secret', got '%s'", val)
	}

	cached, err := ls.Cache.Get("service/token")
	if err != nil || cached == nil {
		t.Fatalf("Failed to retrieve from cache: %v", err)
	}
	if string(cached.Value) != "lazy-rotated-secret" {
		t.Errorf("Expected cache to contain 'lazy-rotated-secret', got '%s'", cached.Value)
	}
}

func TestRotateSecretTimeout(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}
	mb := &testRotationBackend{secrets: make(map[string][]byte)}
	ls := NewWithCache(mc)
	ls.Backend = mb

	oldSecret := Secret{
		Value:     []byte("old-pass"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	secretData, _ := json.Marshal(oldSecret)
	mb.secrets["db/password"] = secretData
	_ = mc.Set("db/password", oldSecret, time.Hour)

	var targetCommand string
	if runtime.GOOS == "windows" {
		targetCommand = `ping 127.0.0.1 -n 6 > nul`
	} else {
		targetCommand = `sleep 5`
	}

	ls.Config = &Config{
		Notifications: NotificationConfig{ExpiringThreshold: "5m"},
		Rotation: []RotationRule{
			{
				Secret:     "db/*",
				HookType:   "script",
				HookTarget: targetCommand,
				Timeout:    "100ms",
			},
		},
	}

	err := ls.RotateSecret("db/password")
	if err == nil {
		t.Fatal("Expected RotateSecret to fail with timeout error, but it succeeded")
	}

	val, _ := ls.Get("db/password")
	if string(val) != "old-pass" {
		t.Errorf("Expected secret to remain 'old-pass' after failed rotation, got '%s'", val)
	}
}

func TestRotateExpiringSecrets(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}
	mb := &testRotationBackend{secrets: make(map[string][]byte)}
	ls := NewWithCache(mc)
	ls.Backend = mb

	// 1. Seed secrets
	now := time.Now()
	expiringSecretRule := Secret{Value: []byte("old-val-1"), CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-10 * time.Minute)}
	expiringSecretNoRule := Secret{Value: []byte("old-val-2"), CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-5 * time.Minute)}
	validSecretRule := Secret{Value: []byte("old-val-3"), CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)} // far future

	// Add to mock backend and cache
	mb.secrets["expiring/secret-1"] = marshalSecret(expiringSecretRule)
	mb.secrets["expiring/secret-no-rule"] = marshalSecret(expiringSecretNoRule)
	mb.secrets["valid/secret-1"] = marshalSecret(validSecretRule)

	_ = mc.Set("expiring/secret-1", expiringSecretRule, time.Hour)
	_ = mc.Set("expiring/secret-no-rule", expiringSecretNoRule, time.Hour)
	_ = mc.Set("valid/secret-1", validSecretRule, time.Hour)

	// Configure rotation rules
	var targetCommand string
	if runtime.GOOS == "windows" {
		targetCommand = `echo batch-rotated`
	} else {
		targetCommand = `echo "batch-rotated"`
	}

	ls.Config = &Config{
		Notifications: NotificationConfig{ExpiringThreshold: "5m"},
		Rotation: []RotationRule{
			{
				Secret:     "expiring/secret-1",
				HookType:   "script",
				HookTarget: targetCommand,
				Timeout:    "5s",
			},
			{
				Secret:     "valid/secret-1",
				HookType:   "script",
				HookTarget: targetCommand,
				Timeout:    "5s",
			},
		},
	}

	// 2. Run batch rotation
	rotated, skipped, failed, err := ls.RotateExpiringSecrets()
	if err != nil {
		t.Fatalf("RotateExpiringSecrets failed: %v", err)
	}

	if len(failed) > 0 {
		t.Fatalf("Rotation failed with errors: %v", failed)
	}

	// Verify expiring/secret-1 was rotated
	if !contains(rotated, "expiring/secret-1") {
		t.Error("Expected expiring/secret-1 to be rotated")
	}

	val1, _ := ls.Get("expiring/secret-1")
	if string(val1) != "batch-rotated" {
		t.Errorf("Expected expiring/secret-1 value 'batch-rotated', got '%s'", val1)
	}

	// Verify expiring/secret-no-rule was skipped
	if !contains(skipped, "expiring/secret-no-rule") {
		t.Error("Expected expiring/secret-no-rule to be skipped")
	}

	val2, _ := ls.Get("expiring/secret-no-rule")
	if string(val2) != "old-val-2" {
		t.Errorf("Expected expiring/secret-no-rule to remain 'old-val-2', got '%s'", val2)
	}

	// Verify valid/secret-1 was skipped
	if !contains(skipped, "valid/secret-1") {
		t.Error("Expected valid/secret-1 to be skipped")
	}

	val3, _ := ls.Get("valid/secret-1")
	if string(val3) != "old-val-3" {
		t.Errorf("Expected valid/secret-1 to remain 'old-val-3', got '%s'", val3)
	}
}

func contains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}

func marshalSecret(s Secret) []byte {
	d, _ := json.Marshal(s)
	return d
}
