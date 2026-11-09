package spiffe_test

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"os"
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

// ADV-SPIFFE-08: Unattested Loopback TCP Identity Spoofing Defense
// Asserts that loopback TCP bridge requests without an authenticated bridge token
// or with arbitrary requested SPIFFE IDs are rejected with 403 Forbidden (GHSA-wfmr-rw42-3rv7 Finding 2).
func TestAdversarial_VsockBridgeUnattestedTCPSpoofing(t *testing.T) {
	rootCA, _ := ca.GenerateRootCA("Test CA", "Bonjoski", 30)
	sockPath := shortTempSock(t, "spoof-test")

	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.AllowedCIDs = []uint32{3}

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		VsockPort:   29099,
		BridgeToken: "secure-bridge-secret-token",
		TrustDomain: "bonjoski.local",
		Policy:      pol,
		CA:          rootCA,
	})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	go func() { _ = ws.Start() }()
	time.Sleep(50 * time.Millisecond)
	defer func() { _ = ws.Stop(context.Background()) }()

	// 1. Attack: Unauthenticated TCP connection attempting to forge an admin SVID
	spoofReq, _ := http.NewRequest("GET", "http://127.0.0.1:29099/v1/svid?spiffe_id=spiffe://bonjoski.local/ns/prod/sa/admin", nil)
	resp, err := http.DefaultClient.Do(spoofReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Unauthenticated TCP bridge connection returned %d instead of 403 Forbidden!", resp.StatusCode)
	}
	t.Logf("PASS: Unauthenticated loopback TCP connection correctly rejected with 403.")

	// 2. Attack: Valid bridge token but attempting to request an unpermitted arbitrary SPIFFE ID
	authSpoofReq, _ := http.NewRequest("GET", "http://127.0.0.1:29099/v1/svid?spiffe_id=spiffe://bonjoski.local/ns/prod/sa/admin", nil)
	authSpoofReq.Header.Set("X-Locksmith-Bridge-Token", "secure-bridge-secret-token")
	authSpoofReq.Header.Set("X-Locksmith-CID", "3")
	authResp, err := http.DefaultClient.Do(authSpoofReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: CID 3 was allowed to mint arbitrary admin SVID, status: %d", authResp.StatusCode)
	}
	t.Logf("PASS: MicroVM CID 3 attempting to request unauthorized admin SPIFFE ID correctly rejected with 403.")

	// 3. Legitimate: Valid bridge token requesting derived pinned CID SVID
	legitReq, _ := http.NewRequest("GET", "http://127.0.0.1:29099/v1/svid", nil)
	legitReq.Header.Set("X-Locksmith-Bridge-Token", "secure-bridge-secret-token")
	legitReq.Header.Set("X-Locksmith-CID", "3")
	legitResp, err := http.DefaultClient.Do(legitReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer legitResp.Body.Close()
	if legitResp.StatusCode != http.StatusOK {
		t.Fatalf("Legitimate authenticated SVID fetch failed with status: %d", legitResp.StatusCode)
	}
	t.Logf("PASS: Authenticated microVM request for pinned SVID succeeded with 200 OK.")
}

// ADV-SPIFFE-09: Fine-Grained PolicyRule Enforcement
// Asserts that PolicyRule restrictions on spiffe_pattern and allowed_binaries are strictly enforced
// rather than being silently ignored (GHSA-wfmr-rw42-3rv7 Finding 3).
func TestAdversarial_PolicyRuleEnforcement(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.Rules = []spiffe.PolicyRule{
		{
			SPIFFEPattern:   "spiffe://bonjoski.local/ns/dev/*",
			AllowedUIDs:     []uint32{uint32(os.Getuid())},
			AllowedBinaries: []string{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, // specific binary hash
		},
	}

	// 1. Caller with matching UID and binary hash
	legitCaller := &spiffe.CallerIdentity{
		UID:     uint32(os.Getuid()),
		Comm:    "valid-agent",
		ExeHash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	legitID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/worker")
	if err := pol.Authorize(legitCaller, legitID); err != nil {
		t.Fatalf("Expected authorized rule for legit caller, got: %v", err)
	}
	t.Logf("PASS: Legit caller with matching binary hash authorized.")

	// 2. Caller with mismatched binary hash
	rogueCaller := &spiffe.CallerIdentity{
		UID:     uint32(os.Getuid()),
		Comm:    "rogue-agent",
		ExeHash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	if err := pol.Authorize(rogueCaller, legitID); err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Rogue binary hash bypassed policy rule enforcement!")
	}
	t.Logf("PASS: Rogue binary hash correctly blocked by policy rule.")

	// 3. Caller with matching hash but requesting out-of-pattern production SPIFFE ID
	prodID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/prod/sa/admin")
	if err := pol.Authorize(legitCaller, prodID); err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Caller bypassed pattern restriction and accessed prod admin ID!")
	}
	t.Logf("PASS: Out-of-pattern production SPIFFE ID correctly blocked.")
}

// TestAdversarial_HMACBridgeCIDTransposition verifies that a microVM with a valid token for CID 4
// cannot spoof X-Locksmith-CID: 3 across the TCP bridge (GHSA-wfmr-rw42-3rv7 Residual Finding 1).
func TestAdversarial_HMACBridgeCIDTransposition(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901") // 32-byte key
	deriver, err := spiffe.NewBridgeTokenDeriver(masterKey)
	if err != nil {
		t.Fatalf("Failed to create deriver: %v", err)
	}

	// ADV-SPIFFE-10: Assert key length under 32 bytes is strictly rejected
	if _, err := spiffe.NewBridgeTokenDeriver([]byte("short-key")); err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: BridgeTokenDeriver accepted key < 32 bytes!")
	}

	tokenCID3 := deriver.DeriveToken(3)
	tokenCID4 := deriver.DeriveToken(4)

	if subtle.ConstantTimeCompare([]byte(tokenCID3), []byte(tokenCID4)) == 1 {
		t.Fatalf("Expected distinct tokens for CID 3 and CID 4")
	}

	sockPath := shortTempSock(t, "hmac-cid")
	rootCA, err := ca.GenerateRootCA("Sovereign Test Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.AllowedCIDs = []uint32{3, 4}

	server, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		VsockPort:   29199,
		BridgeKey:   masterKey,
		TrustDomain: "bonjoski.local",
		Policy:      pol,
		CA:          rootCA,
	})
	if err != nil {
		t.Fatalf("Failed to create workload server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()
	defer func() {
		_ = server.Stop(context.Background())
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("server.Start() failed immediately: %v", err)
	default:
	}

	client := &http.Client{Timeout: 2 * time.Second}

	// 1. CID 4 presents token for CID 4 but claims X-Locksmith-CID: 3 (Transposition attack)
	reqSpoof, err := http.NewRequest("GET", "http://127.0.0.1:29199/v1/svid?spiffe_id=spiffe://bonjoski.local/vm/cid/3", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reqSpoof.Header.Set("X-Locksmith-Bridge-Token", tokenCID4) // Token for CID 4
	reqSpoof.Header.Set("X-Locksmith-CID", "3")                 // Claiming CID 3
	respSpoof, err := client.Do(reqSpoof)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = respSpoof.Body.Close()
	if respSpoof.StatusCode != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: CID 4 token allowed claiming CID 3! Expected 403, got %d", respSpoof.StatusCode)
	}
	t.Logf("PASS: Cross-CID bridge transposition attack blocked with 403.")

	// 2. CID 3 presents authentic token for CID 3 -> 200 OK
	reqLegit, err := http.NewRequest("GET", "http://127.0.0.1:29199/v1/svid?spiffe_id=spiffe://bonjoski.local/vm/cid/3", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reqLegit.Header.Set("X-Locksmith-Bridge-Token", tokenCID3)
	reqLegit.Header.Set("X-Locksmith-CID", "3")
	respLegit, err := client.Do(reqLegit)
	if err != nil {
		t.Fatalf("Legitimate request failed: %v", err)
	}
	_ = respLegit.Body.Close()
	if respLegit.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for authentic CID 3 token, got: %d", respLegit.StatusCode)
	}
	t.Logf("PASS: Authentic CID 3 token authorized successfully.")
}

func init() {
	_ = errors.New("") // ensure errors import
}

// TestAdversarial_LCK05_EmptyRulesDenyArbitrarySPIFFEID verifies that when
// Policy.Rules is empty, a caller can ONLY obtain its own DefaultSPIFFEIDForIdentity
// and cannot mint arbitrary ?spiffe_id= identities.
func TestAdversarial_LCK05_EmptyRulesDenyArbitrarySPIFFEID(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.Rules = nil // len(Rules) == 0

	caller := &spiffe.CallerIdentity{
		PID:  1234,
		UID:  uint32(os.Getuid()),
		Comm: "worker-bin",
	}

	if _, err := pol.ResolveSPIFFEID(caller, "spiffe://bonjoski.local/ns/prod/sa/cluster-admin"); err == nil {
		t.Fatal("CRITICAL (LCK-05): empty Policy.Rules permitted arbitrary ?spiffe_id= escalation!")
	}

	defaultID := pol.DefaultSPIFFEIDForIdentity(caller)
	resolved, err := pol.ResolveSPIFFEID(caller, defaultID)
	if err != nil {
		t.Fatalf("expected caller's own default SPIFFE ID %q to be authorized, got: %v", defaultID, err)
	}
	if resolved.String() != defaultID {
		t.Fatalf("expected %q, got %q", defaultID, resolved.String())
	}
}

func floodCID3AndVerifyThrottled(t *testing.T, tcpClient *http.Client, tokenCID3 string) {
	t.Helper()
	cid3Throttled := false
	for i := 0; i < 10; i++ {
		req, reqErr := http.NewRequest("GET", "http://127.0.0.1:29299/v1/bundle", nil)
		if reqErr != nil {
			t.Fatalf("NewRequest CID3: %v", reqErr)
		}
		req.Header.Set("X-Locksmith-CID", "3")
		req.Header.Set("X-Locksmith-Bridge-Token", tokenCID3)
		resp, doErr := tcpClient.Do(req)
		if doErr != nil {
			t.Fatalf("CID3 request failed: %v", doErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			cid3Throttled = true
			break
		}
	}
	if !cid3Throttled {
		t.Fatal("expected CID=3 flood to trigger 429 rate limiting")
	}
}

func verifyCID4AndUDSNotThrottled(t *testing.T, tcpClient *http.Client, tokenCID4, sockPath string) {
	t.Helper()
	reqCID4, err := http.NewRequest("GET", "http://127.0.0.1:29299/v1/bundle", nil)
	if err != nil {
		t.Fatalf("NewRequest CID4: %v", err)
	}
	reqCID4.Header.Set("X-Locksmith-CID", "4")
	reqCID4.Header.Set("X-Locksmith-Bridge-Token", tokenCID4)
	respCID4, err := tcpClient.Do(reqCID4)
	if err != nil {
		t.Fatalf("CID4 request failed: %v", err)
	}
	_ = respCID4.Body.Close()
	if respCID4.StatusCode != http.StatusOK {
		t.Fatalf("CRITICAL (LCK-05): noisy-neighbor CID=3 throttled independent microVM CID=4 (status=%d)!", respCID4.StatusCode)
	}

	udsClient := newUnixHTTPClient(sockPath)
	respUDS, err := udsClient.Get("http://localhost/v1/bundle")
	if err != nil {
		t.Fatalf("UDS request failed: %v", err)
	}
	_ = respUDS.Body.Close()
	if respUDS.StatusCode != http.StatusOK {
		t.Fatalf("CRITICAL (LCK-05): microVM bridge flood throttled host UDS caller (status=%d)!", respUDS.StatusCode)
	}
}

// TestAdversarial_LCK05_CompositeRateLimitIsolatesMicroVMCIDs verifies that
// rate limiters are keyed by composite (Transport, UID, CID) so a noisy-neighbor
// microVM (CID=3, UID=0) exhausting its burst cannot DoS microVM CID=4 (UID=0)
// or host UDS workloads.
func TestAdversarial_LCK05_CompositeRateLimitIsolatesMicroVMCIDs(t *testing.T) {
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	deriver, err := spiffe.NewBridgeTokenDeriver(masterKey)
	if err != nil {
		t.Fatalf("NewBridgeTokenDeriver: %v", err)
	}
	tokenCID3 := deriver.DeriveToken(3)
	tokenCID4 := deriver.DeriveToken(4)

	rootCA, err := ca.GenerateRootCA("RateLimit Isolation CA", "Bonjoski", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}

	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.AllowedCIDs = []uint32{3, 4}

	sockPath := shortTempSock(t, "cid-rl")
	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		VsockPort:   29299,
		BridgeKey:   masterKey,
		TrustDomain: "bonjoski.local",
		Policy:      pol,
		CA:          rootCA,
		RateLimit:   rate.Limit(1),
		BurstLimit:  2,
	})
	if err != nil {
		t.Fatalf("NewWorkloadServer: %v", err)
	}

	go func() {
		if srvErr := ws.Start(); srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			t.Logf("server exit: %v", srvErr)
		}
	}()
	defer func() {
		if stopErr := ws.Stop(context.Background()); stopErr != nil {
			t.Logf("server stop: %v", stopErr)
		}
	}()
	time.Sleep(80 * time.Millisecond)

	tcpClient := &http.Client{Timeout: 2 * time.Second}
	floodCID3AndVerifyThrottled(t, tcpClient, tokenCID3)
	verifyCID4AndUDSNotThrottled(t, tcpClient, tokenCID4, sockPath)
}
