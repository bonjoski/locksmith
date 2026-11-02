package spiffe_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
	"golang.org/x/time/rate"
)

// MockAttestor simulates malicious peer attestation scenarios.
type MockAttestor struct {
	Identity *spiffe.CallerIdentity
	Err      error
}

func (m *MockAttestor) AttestPeer(conn net.Conn) (*spiffe.CallerIdentity, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Identity, nil
}

// ADV-SPIFFE-04: PID Recycling & TOCTOU Race Condition Mitigation
// If a process terminates and its PID is recycled during the socket connection handshake,
// the attestor detects the timestamp discrepancy and strictly rejects with ErrProcessIdentityRace.
func TestAdversarial_PIDRecyclingDefense(t *testing.T) {
	rootCA, _ := ca.GenerateRootCA("Test CA", "Bonjoski", 30)
	sockPath := shortTempSock(t, "race")

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		CA:          rootCA,
		Attestor: &MockAttestor{
			Err: spiffe.ErrProcessIdentityRace,
		},
	})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	go func() { _ = ws.Start() }()
	time.Sleep(50 * time.Millisecond)
	defer func() { _ = ws.Stop(context.Background()) }()

	client := newUnixHTTPClient(sockPath)
	resp, err := client.Get("http://localhost/v1/svid")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: PID recycling race was not blocked! status = %d", resp.StatusCode)
	}
	t.Logf("PASS: PID recycling attack intercepted and blocked with 403 Forbidden.")
}

// ADV-SPIFFE-06: Cross-Trust-Domain Impersonation Defense
// Attacker requests an SVID for a foreign trust domain; server strictly rejects.
func TestAdversarial_TrustDomainConfusion(t *testing.T) {
	rootCA, _ := ca.GenerateRootCA("Test CA", "Bonjoski", 30)
	sockPath := shortTempSock(t, "domain")

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		CA:          rootCA,
	})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	go func() { _ = ws.Start() }()
	time.Sleep(50 * time.Millisecond)
	defer func() { _ = ws.Stop(context.Background()) }()

	client := newUnixHTTPClient(sockPath)
	resp, err := client.Get("http://localhost/v1/svid?spiffe_id=spiffe://evil.attacker.local/ns/dev/sa/worker")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CRITICAL: Cross-trust-domain spoofing was not blocked! status = %d", resp.StatusCode)
	}
	t.Logf("PASS: Cross-trust-domain request rejected with 403 Forbidden.")
}

// DoS Mitigation: Rate Limiter Token-Bucket Defense
// Rapid requests from a single client UID must be throttled to prevent CA CPU exhaustion.
func TestAdversarial_RateLimitThrottling(t *testing.T) {
	rootCA, _ := ca.GenerateRootCA("Test CA", "Bonjoski", 30)
	sockPath := shortTempSock(t, "ratelimit")

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		CA:          rootCA,
		RateLimit:   rate.Limit(2), // 2 requests per second
		BurstLimit:  2,             // Burst of 2
	})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	go func() { _ = ws.Start() }()
	time.Sleep(50 * time.Millisecond)
	defer func() { _ = ws.Stop(context.Background()) }()

	client := newUnixHTTPClient(sockPath)

	throttled := false
	for i := 0; i < 10; i++ {
		resp, err := client.Get("http://localhost/v1/bundle")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}

	if !throttled {
		t.Fatalf("CRITICAL: Rate limiter failed to throttle high-frequency requests!")
	}
	t.Logf("PASS: Rate limiter successfully throttled burst requests with 429.")
}

func init() {
	_ = errors.New("") // ensure errors import
}
