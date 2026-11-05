package ca_test

import (
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

func FuzzParseSPIFFEID(f *testing.F) {
	seeds := []string{
		"spiffe://bonjoski.local/ns/dev/sa/worker",
		"spiffe://bonjoski.local/sa/worker",
		"spiffe://localhost/a/b/c",
		"http://bonjoski.local",
		"spiffe://",
		"spiffe:///path",
		"spiffe://bonjoski.local",
		"spiffe://example.com/sa/test",
		"spiffe://bonjoski.local/ns/../../escape",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		spiffeID, err := ca.ParseSPIFFEID(raw)
		if err == nil {
			if spiffeID == nil {
				t.Fatalf("ParseSPIFFEID returned nil spiffeID with nil error for %q", raw)
			}
			if spiffeID.TrustDomain() == "" {
				t.Fatalf("ParseSPIFFEID returned empty trust domain for %q", raw)
			}
			if spiffeID.Path() == "" {
				t.Fatalf("ParseSPIFFEID returned empty path for %q", raw)
			}
		}
	})
}
