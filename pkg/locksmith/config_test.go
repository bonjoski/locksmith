package locksmith

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadConfigDefaults tests loading config with defaults
func TestLoadConfigDefaults(t *testing.T) {
	// Temporarily move config file if it exists
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".locksmith", "config.yml")

	// Backup existing config
	var hadConfig bool
	if _, err := os.Stat(configPath); err == nil {
		hadConfig = true
		backupPath := configPath + ".backup"
		_ = os.Rename(configPath, backupPath)
		defer func() { _ = os.Rename(backupPath, configPath) }()
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check defaults
	if cfg.Notifications.ExpiringThreshold != "7d" {
		t.Errorf("Expected default threshold '7d', got '%s'", cfg.Notifications.ExpiringThreshold)
	}
	if cfg.Notifications.Method != "stderr" {
		t.Errorf("Expected default method 'stderr', got '%s'", cfg.Notifications.Method)
	}
	if !cfg.Notifications.ShowOnGet {
		t.Error("Expected ShowOnGet to be true by default")
	}
	if !cfg.Notifications.ShowOnList {
		t.Error("Expected ShowOnList to be true by default")
	}

	_ = hadConfig // Avoid unused variable warning
}

// TestGetExpiringThreshold tests duration parsing
func TestGetExpiringThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold string
		expected  time.Duration
		wantErr   bool
	}{
		{"7 days", "7d", 7 * 24 * time.Hour, false},
		{"2 weeks", "2w", 14 * 24 * time.Hour, false},
		{"1 month", "1mo", 30 * 24 * time.Hour, false},
		{"1 year", "1y", 365 * 24 * time.Hour, false},
		{"24 hours", "24h", 24 * time.Hour, false},
		{"invalid", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Notifications: NotificationConfig{
					ExpiringThreshold: tt.threshold,
				},
			}

			duration, err := cfg.GetExpiringThreshold()

			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got error=%v", tt.wantErr, err)
			}

			if !tt.wantErr && duration != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, duration)
			}
		})
	}
}

// TestParseDuration tests the internal parseDuration function
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"1d", 24 * time.Hour, false},
		{"7D", 7 * 24 * time.Hour, false},
		{"2w", 14 * 24 * time.Hour, false},
		{"3W", 21 * 24 * time.Hour, false},
		{"1mo", 30 * 24 * time.Hour, false},
		{"6MO", 180 * 24 * time.Hour, false},
		{"1y", 365 * 24 * time.Hour, false},
		{"2Y", 730 * 24 * time.Hour, false},
		{"x", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			duration, err := parseDuration(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}

			if !tt.wantErr && duration != tt.expected {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, duration, tt.expected)
			}
		})
	}
}
