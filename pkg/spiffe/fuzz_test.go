package spiffe

import (
	"strings"
	"testing"
)

type fuzzVsockAddr struct {
	net string
	str string
}

func (a fuzzVsockAddr) Network() string { return a.net }
func (a fuzzVsockAddr) String() string  { return a.str }

func FuzzParseVsockAddr(f *testing.F) {
	seeds := []string{
		"3:9099",
		"vsock:3:9099",
		"vsock://3:9099",
		"<3:9099>",
		"vm(3):9099",
		"0:9099",
		"1:9099",
		"2:9099",
		"-1:9099",
		"invalid",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		addr := fuzzVsockAddr{net: "vsock", str: raw}
		cid, err := parseVsockAddr(addr)
		if err == nil {
			if cid < 3 {
				t.Fatalf("parseVsockAddr accepted reserved/invalid CID %d for %q", cid, raw)
			}
		}
	})
}

func FuzzMatchPattern(f *testing.F) {
	seeds := []struct {
		pattern string
		id      string
	}{
		{"spiffe://bonjoski.local/sa/worker", "spiffe://bonjoski.local/sa/worker"},
		{"spiffe://bonjoski.local/sa/*", "spiffe://bonjoski.local/sa/worker"},
		{"spiffe://bonjoski.local/sa/**", "spiffe://bonjoski.local/sa/team/worker"},
		{"*", "spiffe://bonjoski.local/sa/worker"},
		{"", "spiffe://bonjoski.local/sa/worker"},
	}
	for _, seed := range seeds {
		f.Add(seed.pattern, seed.id)
	}

	f.Fuzz(func(t *testing.T, pattern, rawID string) {
		matched := matchPattern(pattern, rawID)

		// Invariant 1: Identity match - identical pattern and target always matches
		if pattern == rawID && !matched {
			t.Fatalf("INVARIANT VIOLATION: identical pattern and ID did not match: %q vs %q", pattern, rawID)
		}

		// Invariant 2: Non-wildcard patterns match ONLY exact strings
		if !strings.ContainsAny(pattern, "*?[\\]") {
			if matched && pattern != rawID {
				t.Fatalf("INVARIANT VIOLATION: non-wildcard pattern %q matched different ID %q", pattern, rawID)
			}
		}

		// Invariant 3: Empty pattern never matches non-empty target
		if pattern == "" && rawID != "" && matched {
			t.Fatalf("INVARIANT VIOLATION: empty pattern matched non-empty ID %q", rawID)
		}

		// Invariant 4: Scheme boundary - spiffe:// patterns never match non-spiffe schemes
		if strings.HasPrefix(pattern, "spiffe://") && !strings.Contains(pattern, "*") {
			if matched && !strings.HasPrefix(rawID, "spiffe://") {
				t.Fatalf("INVARIANT VIOLATION: spiffe:// pattern %q matched non-spiffe ID %q", pattern, rawID)
			}
		}
	})
}
