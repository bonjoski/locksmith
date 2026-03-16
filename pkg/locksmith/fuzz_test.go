package locksmith

import (
	"encoding/json"
	"testing"
)

func FuzzParseDuration(f *testing.F) {
	// Add seed corpus from existing tests
	f.Add("7d")
	f.Add("2w")
	f.Add("1mo")
	f.Add("1y")
	f.Add("24h")
	f.Add("invalid")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		// We just want to make sure it doesn't crash
		_, _ = ParseDuration(s)

		// Also test the wrapper
		cfg := &Config{
			Notifications: NotificationConfig{
				ExpiringThreshold: s,
			},
		}
		_, _ = cfg.GetExpiringThreshold()
	})
}

func FuzzJSONUnmarshal(f *testing.F) {
	// Add valid and slightly invalid JSON seeds
	f.Add([]byte(`{"value":"c2VjcmV0", "created_at":"2024-01-01T00:00:00Z", "expires_at":"2025-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"value":""}`))
	f.Add([]byte(`invalid-json`))
	f.Add([]byte(`{value`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var secret Secret
		// We just want to ensure that parsing garbage data
		// from a potentially corrupted local keystore never panics the CLI.
		_ = json.Unmarshal(data, &secret)
	})
}
