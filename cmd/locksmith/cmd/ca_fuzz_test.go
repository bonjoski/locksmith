package cmd

import (
	"strings"
	"testing"
)

func FuzzParsePermittedIPs(f *testing.F) {
	seeds := []string{
		"127.0.0.1/32",
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"192.168.1.0/24",
		"0.0.0.0/0",
		"::/0",
		"8.8.8.8/32",
		"invalid_cidr",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		nets, err := parsePermittedIPs([]string{raw})
		if err != nil {
			if nets != nil {
				t.Fatalf("expected nil nets on error, got %v", nets)
			}
			return
		}
		for _, n := range nets {
			if n == nil || n.IP == nil || n.Mask == nil {
				t.Fatalf("parsePermittedIPs returned incomplete IPNet for %q: %+v", raw, n)
			}
			if !n.Contains(n.IP) {
				t.Fatalf("parsePermittedIPs returned net %v that does not contain its own IP %v", n, n.IP)
			}
		}
	})
}

func assertValidSovereignDomain(t *testing.T, domain, clean, cleanNoDot string) {
	if clean == "" || clean == "*" || clean == "." {
		t.Fatalf("INVARIANT VIOLATION: isSovereignDomain accepted invalid domain %q", domain)
	}
	if strings.Contains(clean, "/") {
		t.Fatalf("INVARIANT VIOLATION: isSovereignDomain accepted domain with path delimiter %q", domain)
	}
	hasSuffix := false
	for _, sfx := range sovereignSpecialUseSuffixes {
		if cleanNoDot == sfx || strings.HasSuffix(cleanNoDot, "."+sfx) {
			hasSuffix = true
			break
		}
	}
	if !hasSuffix {
		t.Fatalf("INVARIANT VIOLATION: isSovereignDomain accepted non-sovereign domain %q", domain)
	}
}

func FuzzIsSovereignDomain(f *testing.F) {
	seeds := []string{
		"localhost",
		"bonjoski.local",
		"cluster.internal",
		"home.arpa",
		"test.example",
		"example.com",
		"attacker.org",
		"service.eu",
		"cloud.tech",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, domain string) {
		err := isSovereignDomain(domain)
		clean := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
		cleanNoDot := strings.TrimPrefix(clean, ".")
		if err == nil {
			assertValidSovereignDomain(t, domain, clean, cleanNoDot)
		}
	})
}
