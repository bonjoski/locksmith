package locksmith

import (
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
		_, _ = parseDuration(s)

		// Also test the wrapper
		cfg := &Config{
			Notifications: NotificationConfig{
				ExpiringThreshold: s,
			},
		}
		_, _ = cfg.GetExpiringThreshold()
	})
}
