package locksmith

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// NotificationConfig holds notification-related settings
type NotificationConfig struct {
	ExpiringThreshold string `yaml:"expiring_threshold"` // e.g., "7d"
	Method            string `yaml:"method"`             // stderr, macos, silent
	ShowOnGet         bool   `yaml:"show_on_get"`
	ShowOnList        bool   `yaml:"show_on_list"`
}

// Config represents the locksmith configuration
type Config struct {
	Notifications NotificationConfig `yaml:"notifications"`
}

// LoadConfig loads configuration from ~/.locksmith/config.yml
// Returns default config if file doesn't exist
func LoadConfig() (*Config, error) {
	// Default config
	cfg := &Config{
		Notifications: NotificationConfig{
			ExpiringThreshold: "7d",
			Method:            "stderr",
			ShowOnGet:         true,
			ShowOnList:        true,
		},
	}

	// Try to load from ~/.locksmith/config.yml
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil // Return defaults
	}

	configPath := filepath.Join(home, ".locksmith", "config.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, nil // Return defaults if file doesn't exist
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Check for LOCKSMITH_SILENT environment variable (used by Summon provider)
	if os.Getenv("LOCKSMITH_SILENT") == "true" {
		cfg.Notifications.Method = "silent"
	}

	return cfg, nil
}

// GetExpiringThreshold parses and returns the expiring threshold duration
func (c *Config) GetExpiringThreshold() (time.Duration, error) {
	s := c.Notifications.ExpiringThreshold

	// Try standard Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Parse custom formats (d, w, mo, y)
	return parseDuration(c.Notifications.ExpiringThreshold)
}

// parseDuration parses duration strings like "7d", "2w", "1mo", "1y"
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}

	// Days
	if s[len(s)-1] == 'd' || s[len(s)-1] == 'D' {
		var days int
		_, err := fmt.Sscanf(s[:len(s)-1], "%d", &days)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Weeks
	if s[len(s)-1] == 'w' || s[len(s)-1] == 'W' {
		var weeks int
		_, err := fmt.Sscanf(s[:len(s)-1], "%d", &weeks)
		if err != nil {
			return 0, err
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}

	// Months
	if len(s) >= 3 && (s[len(s)-2:] == "mo" || s[len(s)-2:] == "MO") {
		var months int
		_, err := fmt.Sscanf(s[:len(s)-2], "%d", &months)
		if err != nil {
			return 0, err
		}
		return time.Duration(months) * 30 * 24 * time.Hour, nil
	}

	// Years
	if s[len(s)-1] == 'y' || s[len(s)-1] == 'Y' {
		var years int
		_, err := fmt.Sscanf(s[:len(s)-1], "%d", &years)
		if err != nil {
			return 0, err
		}
		return time.Duration(years) * 365 * 24 * time.Hour, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}
