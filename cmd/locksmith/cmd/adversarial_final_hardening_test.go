package cmd

import (
	"crypto/subtle"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
)

// ADV-FINAL-01: Suffix Smuggling & Domain Evasion Attack
// An attacker attempts to bypass sovereign domain allowlisting using trailing dots,
// subdomains on public TLDs, case manipulation, or nested domain suffix tricks.
func TestAdversarial_DomainAllowlistEvasion(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	maliciousDomains := []struct {
		domain      string
		attackClass string
	}{
		// Public TLDs outside legacy 30 denylist
		{"example.eu", "Public ccTLD (.eu) outside legacy denylist"},
		{"bank.ch", "Public ccTLD (.ch) outside legacy denylist"},
		{"service.nl", "Public ccTLD (.nl) outside legacy denylist"},
		{"cloud.tech", "Public gTLD (.tech) outside legacy denylist"},
		{"infra.space", "Public gTLD (.space) outside legacy denylist"},
		// Trailing dot evasions
		{"google.com.", "Trailing FQDN dot bypass"},
		{"example.eu.", "Trailing FQDN dot on ccTLD"},
		{"internal.attacker.com", "Nested sovereign keyword before public domain"},
		{"localhost.attacker.com", "Nested localhost keyword before public domain"},
		{"bonjoski.local.attacker.org", "Nested .local keyword in public domain"},
		{"home.arpa.attacker.net", "Nested home.arpa keyword before public domain"},
		{"test.attacker.com", "Nested test keyword before public domain"},
		// Dotless public TLDs
		{"eu", "Bare public ccTLD"},
		{"de", "Bare public ccTLD"},
		{"org", "Bare public gTLD"},
		{"com", "Bare public gTLD"},
		// Pseudo/unreserved domains
		{"cluster.lan", "Non-standard unreserved pseudo-TLD (.lan)"},
		{"corp.corp", "Non-standard pseudo-TLD (.corp)"},
	}

	for _, tc := range maliciousDomains {
		t.Run(tc.domain, func(t *testing.T) {
			tampered := *rootCA.Certificate
			tampered.PermittedDNSDomains = []string{tc.domain}
			if err := validateRootSecurityProfile(&tampered); err == nil {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: Attack %q (%s) bypassed sovereign domain allowlist!", tc.domain, tc.attackClass)
			}
		})
	}
}

// ADV-FINAL-02: IPv4-Mapped IPv6 & Supernet CIDR Smuggling
// An attacker attempts to bypass IP range validation using supernets or unaligned masks.
func TestAdversarial_IPRangeContainmentSmuggling(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	evasionCIDRs := []struct {
		cidr        string
		attackClass string
	}{
		{"0.0.0.0/0", "All-IPv4 supernet /0"},
		{"127.0.0.0/0", "Loopback prefix with /0 supernet mask"},
		{"127.0.0.0/7", "Loopback prefix with /7 supernet mask (encompasses public IPs)"},
		{"::/0", "All-IPv6 supernet /0"},
		{"::1/0", "IPv6 loopback with /0 supernet mask"},
		{"8.8.8.8/32", "Public Google DNS IPv4"},
		{"1.1.1.1/32", "Public Cloudflare DNS IPv4"},
		{"224.0.0.0/4", "Multicast address space"},
		{"240.0.0.0/4", "Reserved future-use space"},
	}

	for _, tc := range evasionCIDRs {
		t.Run(tc.cidr, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tc.cidr)
			if err != nil {
				t.Fatalf("invalid test CIDR: %v", err)
			}
			tampered := *rootCA.Certificate
			tampered.PermittedIPRanges = []*net.IPNet{ipNet}
			if err := validateRootSecurityProfile(&tampered); err == nil {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: CIDR attack %q (%s) bypassed IP containment checks!", tc.cidr, tc.attackClass)
			}
		})
	}
}

// ADV-FINAL-03: Process Spoofing via Bare Binary Policy Smuggling
// An attacker process creates an executable matching a bare binary name in policy.json.
// The policy engine MUST reject the policy at load time and refuse authorization.
func TestAdversarial_PolicyBareBinarySpoofing(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.Rules = []spiffe.PolicyRule{
		{
			SPIFFEPattern:   "spiffe://bonjoski.local/ns/prod/sa/payment",
			AllowedBinaries: []string{"payment-worker"}, // Bare binary
		},
	}

	// 1. Policy validation MUST fail closed
	if _, err := pol.Validate(); err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Bare binary rule 'payment-worker' passed Policy.Validate()!")
	}

	// 2. Even if an attacker executes a binary named "payment-worker", authorization must fail
	attackerIdentity := &spiffe.CallerIdentity{
		PID:     9999,
		UID:     uint32(os.Getuid()),
		Comm:    "payment-worker",
		ExePath: "/tmp/evil/payment-worker",
	}

	spiffeID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/prod/sa/payment")
	// Since bare binary validation fails, matchesBinary returns false
	if err := pol.Authorize(attackerIdentity, spiffeID); err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Attacker spoofed binary identity via process name matching!")
	}
}

// ADV-FINAL-04: Bridge Master Key Weakness & Cross-CID Transposition
// An attacker attempts to supply a weak bridge key (<32 bytes) or derive tokens for reserved CIDs.
func TestAdversarial_BridgeTokenKeyStrengthAndCIDBoundaries(t *testing.T) {
	// 1. Weak key (< 32 bytes) must be rejected by deriver constructor
	weakKeys := [][]byte{
		nil,
		{},
		[]byte("short-16-bytes!"),
		[]byte("almost-32-bytes-key-31-chars!"),
	}
	for _, wk := range weakKeys {
		if _, err := spiffe.NewBridgeTokenDeriver(wk); err == nil {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: NewBridgeTokenDeriver accepted weak key of %d bytes!", len(wk))
		}
	}

	// 2. Reserved CIDs (0: hypervisor, 1: loopback, 2: host) must fail in CLI
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i + 1)
	}

	caDir := t.TempDir()
	keyFile := filepath.Join(caDir, "bridge.key")
	if err := os.WriteFile(keyFile, validKey, 0600); err != nil {
		t.Fatal(err)
	}

	reservedCIDs := []string{"0", "1", "2"}
	for _, cid := range reservedCIDs {
		outBuf, errBuf := setupTest()
		rootCmd.SetArgs([]string{"ca", "derive-bridge-token", "--cid", cid, "--key-file", keyFile})
		if err := rootCmd.Execute(); err == nil {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: derive-bridge-token allowed derivation for reserved CID %s, out=%s, err=%s", cid, outBuf.String(), errBuf.String())
		}
	}

	// 3. Constant-time comparison assertion
	deriver, err := spiffe.NewBridgeTokenDeriver(validKey)
	if err != nil {
		t.Fatal(err)
	}
	tokenCID3 := deriver.DeriveToken(3)
	tokenCID4 := deriver.DeriveToken(4)

	// ConstantTimeCompare must yield 0 for cross-CID tokens
	if subtle.ConstantTimeCompare([]byte(tokenCID3), []byte(tokenCID4)) != 0 {
		t.Fatalf("CRITICAL: Token for CID 3 matched CID 4 in constant time comparison!")
	}
}

// ADV-FINAL-05: Zero Plaintext Key Disk Residue After Complete CA Lifecycle
// An attacker with local filesystem access inspects the CA directory after initialization.
// No private keys or bridge keys must be present without explicit opt-in flags.
func TestAdversarial_ZeroPlaintextKeyDiskResidue(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")

	// 1. Pre-seed mock keychain
	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--ca-dir", caDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca init failed: %v, err=%s", err, errBuf.String())
	}

	// 2. Assert no .key files exist
	files, err := os.ReadDir(caDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".key") {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: Plaintext key file %q leaked to disk during ca init!", f.Name())
		}
		data, err := os.ReadFile(filepath.Join(caDir, f.Name()))
		if err == nil && strings.Contains(string(data), "PRIVATE KEY") {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: File %q contains cleartext PRIVATE KEY bytes!", f.Name())
		}
	}

	// 3. Status command does not leak private key material
	outBuf, errBuf = setupTest()
	rootCmd.SetArgs([]string{"ca", "status", "--ca-dir", caDir})
	_ = rootCmd.Execute()
	statusOutput := outBuf.String() + errBuf.String()
	if strings.Contains(statusOutput, "PRIVATE KEY") {
		t.Fatalf("CRITICAL: ca status printed private key material to terminal!")
	}
}
