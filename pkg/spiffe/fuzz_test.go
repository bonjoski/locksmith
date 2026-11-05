package spiffe

import (
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
		_ = matchPattern(pattern, rawID)
	})
}
