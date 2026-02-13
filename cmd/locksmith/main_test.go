package main

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Days
		{"single day", "1d", 24 * time.Hour, false},
		{"30 days", "30d", 30 * 24 * time.Hour, false},
		{"90 days", "90d", 90 * 24 * time.Hour, false},
		{"uppercase D", "7D", 7 * 24 * time.Hour, false},

		// Weeks
		{"single week", "1w", 7 * 24 * time.Hour, false},
		{"two weeks", "2w", 14 * 24 * time.Hour, false},
		{"uppercase W", "4W", 28 * 24 * time.Hour, false},

		// Months
		{"single month", "1mo", 30 * 24 * time.Hour, false},
		{"six months", "6mo", 180 * 24 * time.Hour, false},
		{"uppercase MO", "3MO", 90 * 24 * time.Hour, false},

		// Years
		{"single year", "1y", 365 * 24 * time.Hour, false},
		{"two years", "2y", 730 * 24 * time.Hour, false},
		{"uppercase Y", "1Y", 365 * 24 * time.Hour, false},

		// Standard Go durations
		{"hours", "24h", 24 * time.Hour, false},
		{"minutes", "30m", 30 * time.Minute, false},
		{"seconds", "60s", 60 * time.Second, false},
		{"mixed", "1h30m", 90 * time.Minute, false},

		// Error cases
		{"invalid format", "invalid", 0, true},
		{"empty string", "", 0, true},
		{"just letter", "d", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
