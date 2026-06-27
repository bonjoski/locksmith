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
			duration, err := ParseDuration(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}

			if !tt.wantErr && duration != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, duration, tt.expected)
			}
		})
	}
}

func TestLoadAccessControlConfig(t *testing.T) {
	yamlContent := `
notifications:
  expiring_threshold: 7d
  method: stderr
auth:
  require_biometrics: true
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "/usr/local/bin/aws"
        identifier: "com.amazon.aws"
        team_id: "TEAMID123"
  - secret: "db/password"
    allowed_apps:
      - path: "/Applications/Postgres.app"
`
	tempDir, err := os.MkdirTemp("", "locksmith-test-home")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	locksmithDir := filepath.Join(tempDir, ".locksmith")
	if err := os.MkdirAll(locksmithDir, 0700); err != nil {
		t.Fatalf("Failed to create .locksmith dir: %v", err)
	}

	configPath := filepath.Join(locksmithDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.AccessControl) != 2 {
		t.Fatalf("Expected 2 access control rules, got %d", len(cfg.AccessControl))
	}

	rule1 := cfg.AccessControl[0]
	if rule1.Secret != "aws/*" {
		t.Errorf("Expected secret pattern 'aws/*', got '%s'", rule1.Secret)
	}
	if len(rule1.AllowedApps) != 1 {
		t.Fatalf("Expected 1 allowed app for rule 1, got %d", len(rule1.AllowedApps))
	}
	app1 := rule1.AllowedApps[0]
	if app1.Path != "/usr/local/bin/aws" {
		t.Errorf("Expected path '/usr/local/bin/aws', got '%s'", app1.Path)
	}
	if app1.Identifier != "com.amazon.aws" {
		t.Errorf("Expected identifier 'com.amazon.aws', got '%s'", app1.Identifier)
	}
	if app1.TeamID != "TEAMID123" {
		t.Errorf("Expected team ID 'TEAMID123', got '%s'", app1.TeamID)
	}

	rule2 := cfg.AccessControl[1]
	if rule2.Secret != "db/password" {
		t.Errorf("Expected secret pattern 'db/password', got '%s'", rule2.Secret)
	}
	if len(rule2.AllowedApps) != 1 {
		t.Fatalf("Expected 1 allowed app for rule 2, got %d", len(rule2.AllowedApps))
	}
	app2 := rule2.AllowedApps[0]
	if app2.Path != "/Applications/Postgres.app" {
		t.Errorf("Expected path '/Applications/Postgres.app', got '%s'", app2.Path)
	}
}
