package locksmith

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// TestNotifierStderr tests stderr notifications
func TestNotifierStderr(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "stderr",
			ShowOnGet:         true,
		},
	}

	notifier := NewNotifier(cfg)

	// Test expiring secret
	secret := &Secret{
		Value:     []byte("test"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * 24 * time.Hour), // 2 days (< 7 days threshold)
	}

	notifier.NotifyExpiration("test-key", secret)

	// Restore stderr and read output
	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Warning") {
		t.Errorf("Expected warning message, got: %s", output)
	}
	if !strings.Contains(output, "test-key") {
		t.Errorf("Expected key name in warning, got: %s", output)
	}
}

// TestNotifierSilent tests silent mode
func TestNotifierSilent(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "silent",
			ShowOnGet:         true,
		},
	}

	notifier := NewNotifier(cfg)

	secret := &Secret{
		Value:     []byte("test"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * 24 * time.Hour),
	}

	notifier.NotifyExpiration("test-key", secret)

	// Restore stderr and read output
	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if output != "" {
		t.Errorf("Expected no output in silent mode, got: %s", output)
	}
}

// TestNotifierValidSecret tests that valid secrets don't trigger notifications
func TestNotifierValidSecret(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "stderr",
			ShowOnGet:         true,
		},
	}

	notifier := NewNotifier(cfg)

	// Valid secret (30 days)
	secret := &Secret{
		Value:     []byte("test"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	notifier.NotifyExpiration("test-key", secret)

	// Restore stderr and read output
	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if output != "" {
		t.Errorf("Expected no output for valid secret, got: %s", output)
	}
}

// TestFormatDuration tests duration formatting
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{5 * 24 * time.Hour, "5 days"},
		{1 * 24 * time.Hour, "1 days"},
		{12 * time.Hour, "12 hours"},
		{1 * time.Hour, "1 hours"},
		{30 * time.Minute, "30 minutes"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
		}
	}
}

// TestFormatMessageExpired tests expired message formatting
func TestFormatMessageExpired(t *testing.T) {
	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "stderr",
		},
	}

	notifier := NewNotifier(cfg)

	secret := &Secret{
		ExpiresAt: time.Now().Add(-2 * 24 * time.Hour), // Expired 2 days ago
	}

	message := notifier.formatMessage("test-key", secret, StatusExpired)

	if !strings.Contains(message, "expired") {
		t.Errorf("Expected 'expired' in message, got: %s", message)
	}
	if !strings.Contains(message, "ago") {
		t.Errorf("Expected 'ago' in message, got: %s", message)
	}
}

// TestFormatMessageExpiring tests expiring message formatting
func TestFormatMessageExpiring(t *testing.T) {
	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "stderr",
		},
	}

	notifier := NewNotifier(cfg)

	secret := &Secret{
		ExpiresAt: time.Now().Add(2 * 24 * time.Hour), // Expires in 2 days
	}

	message := notifier.formatMessage("test-key", secret, StatusExpiring)

	if !strings.Contains(message, "expires in") {
		t.Errorf("Expected 'expires in' in message, got: %s", message)
	}
	if !strings.Contains(message, "test-key") {
		t.Errorf("Expected key name in message, got: %s", message)
	}
}
