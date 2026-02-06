package main

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		err      bool
	}{
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"5s", 5 * time.Second, false},
		{"1d", 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"1mo", 30 * 24 * time.Hour, false},
		{"1y", 365 * 24 * time.Hour, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseDuration(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.err)
			continue
		}
		if got != tt.expected {
			t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
