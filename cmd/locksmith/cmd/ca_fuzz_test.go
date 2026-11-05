package cmd

import (
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
		_ = isSovereignDomain(domain)
	})
}
