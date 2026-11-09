package locksmith

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
	"github.com/bonjoski/locksmith/v2/pkg/stepup"
)

// TestAdversarial_LCK02_DiskCacheBoundaryAndAtomicWrite verifies:
// 1. validatePath enforces strict directory-separator boundaries (blocking sibling-prefix bypasses),
//    NUL bytes, leading slashes, and traversal segments.
func assertLCK02BadKeys(t *testing.T, dc *DiskCache) {
	t.Helper()
	badKeys := []string{
		"",
		".",
		"..",
		"/etc/passwd",
		"../cache-evil/pwned",
		"git/../../cache-evil/pwned",
		"git/github.com/../../outside",
		"valid\x00null",
	}
	for _, k := range badKeys {
		if _, err := dc.validatePath(k); err == nil {
			t.Fatalf("CRITICAL (LCK-02): validatePath accepted malicious key %q", k)
		}
	}
}

func assertLCK02SymlinkIntact(t *testing.T, dc *DiskCache, cacheDir, siblingDir string) {
	t.Helper()
	victimPath := filepath.Join(siblingDir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("INTACT_VICTIM_DATA"), 0600); err != nil {
		t.Fatalf("write victim file: %v", err)
	}
	symlinkInCache := filepath.Join(cacheDir, "symlinked-secret")
	if err := os.Symlink(victimPath, symlinkInCache); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := dc.Set("symlinked-secret", Secret{
		Value:     []byte("attacker-overwrite"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Hour)
	if err == nil {
		t.Fatal("CRITICAL (LCK-02): DiskCache.Set overwrote pre-planted symlink target")
	}

	victimAfter, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("read victim file: %v", err)
	}
	if string(victimAfter) != "INTACT_VICTIM_DATA" {
		t.Fatalf("CRITICAL (LCK-02): victim file modified via symlink: %q", string(victimAfter))
	}
}

func assertLCK02ConcurrentAtomic(t *testing.T, dc *DiskCache, cacheDir string) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("atomic-secret-payload-worker-%d-%s", worker, strings.Repeat("X", 512)))
			for iter := 0; iter < 15; iter++ {
				if setErr := dc.Set("git/github.com/concurrent", Secret{
					Value:     payload,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}, time.Hour); setErr != nil {
					t.Errorf("concurrent Set failed: %v", setErr)
					return
				}
				got, getErr := dc.Get("git/github.com/concurrent")
				if getErr != nil {
					t.Errorf("concurrent Get returned torn/corrupt read: %v", getErr)
					return
				}
				if got == nil || len(got.Value) == 0 {
					t.Errorf("concurrent Get returned empty secret")
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(cacheDir, "git", "github.com", "concurrent"))
		if err != nil {
			t.Fatalf("stat cached file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 cache file permissions, got %o", info.Mode().Perm())
		}
	}
}

// 2. DiskCache.Set writes atomically with 0600 permissions and refuses pre-planted symlinks.
// 3. Concurrent DiskCache Set/Get operations produce zero torn JSON reads.
func TestAdversarial_LCK02_DiskCacheBoundaryAndAtomicWrite(t *testing.T) {
	baseDir := t.TempDir()
	cacheDir := filepath.Join(baseDir, "cache")
	siblingDir := filepath.Join(baseDir, "cache-evil")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("mkdir cacheDir: %v", err)
	}
	if err := os.MkdirAll(siblingDir, 0700); err != nil {
		t.Fatalf("mkdir siblingDir: %v", err)
	}

	dc := &DiskCache{
		Dir:       cacheDir,
		MasterKey: []byte("0123456789abcdef0123456789abcdef"),
	}

	assertLCK02BadKeys(t, dc)
	assertLCK02SymlinkIntact(t, dc, cacheDir, siblingDir)
	assertLCK02ConcurrentAtomic(t, dc, cacheDir)
}

func assertLCK03UnauthAndStepUp(t *testing.T, sendJSON func(map[string]any) []byte, priv ed25519.PrivateKey) string {
	t.Helper()
	// 1. Unauthenticated create_session MUST be DENIED.
	unauthResp := sendJSON(map[string]any{
		"action":          protocol.ActionCreateSession,
		"pgid":            os.Getpid(),
		"ttl":             int64(5 * time.Minute),
		"allowed_secrets": []string{"PROD_DB_PASSWORD"},
	})
	if !strings.Contains(string(unauthResp), "DENIED") {
		t.Fatalf("CRITICAL (LCK-03): unauthenticated create_session succeeded: %s", string(unauthResp))
	}

	// 2. Signed step-up token authorizes create_session once.
	tok, err := stepup.Authorize(context.Background(), stepup.StepUpRequest{
		Challenge: "Create daemon session",
		Severity:  stepup.SeverityHigh,
		TTL:       2 * time.Minute,
		Audience:  "locksmithd",
	}, stepup.WithAuthenticator(func(string) error { return nil }), stepup.WithPrivateKey(priv))
	if err != nil {
		t.Fatalf("stepup.Authorize: %v", err)
	}

	authResp := sendJSON(map[string]any{
		"action":          protocol.ActionCreateSession,
		"pgid":            os.Getpid(),
		"ttl":             int64(5 * time.Minute),
		"allowed_secrets": []string{"PROD_DB_PASSWORD"},
		"step_up_token":   tok.RawToken,
	})
	var ticket protocol.SessionTicket
	if err := json.Unmarshal(authResp, &ticket); err != nil || ticket.TicketID == "" {
		t.Fatalf("expected valid SessionTicket with step_up_token, got: %s (err=%v)", string(authResp), err)
	}

	// 3. Replaying the exact same step_up_token MUST be DENIED.
	replayResp := sendJSON(map[string]any{
		"action":          protocol.ActionCreateSession,
		"pgid":            os.Getpid(),
		"ttl":             int64(5 * time.Minute),
		"allowed_secrets": []string{"PROD_DB_PASSWORD"},
		"step_up_token":   tok.RawToken,
	})
	if !strings.Contains(string(replayResp), "DENIED") {
		t.Fatalf("CRITICAL (LCK-03): replayed step_up_token was accepted: %s", string(replayResp))
	}
	return ticket.TicketID
}

func assertLCK03LeaseAndListRedaction(t *testing.T, sendJSON func(map[string]any) []byte, ticketID string) {
	t.Helper()
	// 4. Request lease bound to this session ticket, then verify list_leases NEVER leaks TicketID.
	myPID := os.Getpid()
	myStart, err := protocol.GetProcessStartTime(myPID)
	if err != nil {
		t.Fatalf("GetProcessStartTime: %v", err)
	}

	leaseRaw := sendJSON(map[string]any{
		"version":            protocol.ProtocolVersion,
		"action":             protocol.ActionRequestLease,
		"client_pid":         myPID,
		"process_start_time": myStart,
		"secret_name":        "PROD_DB_PASSWORD",
		"lease_ttl":          int64(2 * time.Minute),
		"session_ticket":     ticketID,
	})
	var leaseResp protocol.LeaseResponse
	if err := json.Unmarshal(leaseRaw, &leaseResp); err != nil || leaseResp.Status != protocol.StatusGranted {
		t.Fatalf("expected GRANTED lease with valid ticket, got %s (err=%v)", string(leaseRaw), err)
	}

	listRaw := sendJSON(map[string]any{
		"action": protocol.ActionListLeases,
	})
	if bytes.Contains(listRaw, []byte(ticketID)) {
		t.Fatalf("CRITICAL (LCK-03): list_leases leaked bearer SessionTicketID %q in output: %s", ticketID, string(listRaw))
	}
}

// TestAdversarial_LCK03_SessionTicketRedactionAndStepUpGate verifies:
// 1. Unauthenticated UDS callers cannot invoke create_session.
// 2. Signed step_up_token authorizes create_session once and blocks token replay.
// 3. list_leases redacts SessionTicketID so bearer session tickets never leak.
func TestAdversarial_LCK03_SessionTicketRedactionAndStepUpGate(t *testing.T) {
	t.Setenv("LOCKSMITH_AUDIT_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))

	store := &mockSecretStore{
		secrets: map[string][]byte{
			"PROD_DB_PASSWORD": []byte("db-secret-value-99"),
		},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}

	sockPath := fmt.Sprintf("/tmp/ls-lck03-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
	defer func() {
		if rmErr := os.Remove(sockPath); rmErr != nil && !os.IsNotExist(rmErr) {
			t.Logf("cleanup socket: %v", rmErr)
		}
	}()

	server := NewDaemonServer(lm, sockPath)
	server.StepUpPublicKey = pub

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if srvErr := server.ListenAndServe(ctx); srvErr != nil {
			t.Logf("daemon exit: %v", srvErr)
		}
	}()
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Logf("server close: %v", closeErr)
		}
	}()

	for i := 0; i < 30; i++ {
		c, dialErr := net.Dial("unix", sockPath)
		if dialErr == nil {
			if cErr := c.Close(); cErr != nil {
				t.Logf("probe close: %v", cErr)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	sendJSON := func(payload map[string]any) []byte {
		t.Helper()
		conn, dialErr := net.Dial("unix", sockPath)
		if dialErr != nil {
			t.Fatalf("dial socket: %v", dialErr)
		}
		defer func() {
			if cErr := conn.Close(); cErr != nil {
				t.Logf("conn close: %v", cErr)
			}
		}()
		raw, mErr := json.Marshal(payload)
		if mErr != nil {
			t.Fatalf("marshal request: %v", mErr)
		}
		if _, wErr := conn.Write(raw); wErr != nil {
			t.Fatalf("write request: %v", wErr)
		}
		respBytes, rErr := io.ReadAll(conn)
		if rErr != nil {
			t.Fatalf("read response: %v", rErr)
		}
		return respBytes
	}

	ticketID := assertLCK03UnauthAndStepUp(t, sendJSON, priv)
	assertLCK03LeaseAndListRedaction(t, sendJSON, ticketID)
}

// TestAdversarial_LCK03_UnattestedSpiffeIDCannotBypassPIDOrStartTime verifies:
// 1. Caller-supplied JSON SpiffeID over plain UDS cannot spoof ClientPID or ProcessStartTime.
// 2. When SpiffeRootCA is configured, unattested SpiffeID is rejected while a valid CA-signed SVID succeeds.
func TestAdversarial_LCK03_UnattestedSpiffeIDCannotBypassPIDOrStartTime(t *testing.T) {
	t.Setenv("LOCKSMITH_AUDIT_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))

	store := &mockSecretStore{
		secrets: map[string][]byte{
			"VAULT_TOKEN": []byte("s3cr3t-vault-tok"),
		},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	peer := &protocol.PeerCredentials{
		PID:       4242,
		UID:       uint32(os.Getuid()),
		StartTime: 1700000000000000000,
		ExePath:   "/usr/local/bin/agent",
		ExeHash:   "sha256:1111",
	}

	// 1. Spoofed ClientPID alongside JSON SpiffeID over UDS -> DENIED.
	spoofPIDResp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        1, // spoofed PID
		ProcessStartTime: peer.StartTime,
		SpiffeID:         "spiffe://bonjoski.local/workload/attacker",
		SecretName:       "VAULT_TOKEN",
		LeaseTTL:         2 * time.Minute,
	}, peer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofPIDResp.Status != protocol.StatusDenied {
		t.Fatalf("CRITICAL (LCK-03): JSON SpiffeID bypassed kernel PID check! status=%s", spoofPIDResp.Status)
	}

	// 2. Spoofed ProcessStartTime alongside JSON SpiffeID over UDS -> DENIED.
	spoofStartResp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        peer.PID,
		ProcessStartTime: peer.StartTime - 99999,
		SpiffeID:         "spiffe://bonjoski.local/workload/attacker",
		SecretName:       "VAULT_TOKEN",
		LeaseTTL:         2 * time.Minute,
	}, peer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofStartResp.Status != protocol.StatusDenied {
		t.Fatalf("CRITICAL (LCK-03): JSON SpiffeID bypassed ProcessStartTime check! status=%s", spoofStartResp.Status)
	}

	// 3. With SpiffeRootCA configured, unattested SpiffeID is rejected while CA-signed SVID succeeds.
	rootCA, err := ca.GenerateRootCAWithConfig(ca.RootCAConfig{
		CommonName:          "Locksmith Test Root",
		Organization:        "Bonjoski",
		ValidityDays:        30,
		PermittedURIDomains: []string{"bonjoski.local"},
	})
	if err != nil {
		t.Fatalf("GenerateRootCAWithConfig: %v", err)
	}

	strictLM := NewLeaseManager(store, LeaseManagerOptions{
		SpiffeRootCA: rootCA.Certificate,
	})
	defer strictLM.Close()

	unattestedResp, err := strictLM.RequestLease(&protocol.LeaseRequest{
		Version:    protocol.ProtocolVersion,
		Action:     protocol.ActionRequestLease,
		SpiffeID:   "spiffe://bonjoski.local/ns/prod/sa/admin",
		SecretName: "VAULT_TOKEN",
		LeaseTTL:   2 * time.Minute,
	}, peer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unattestedResp.Status != protocol.StatusDenied {
		t.Fatalf("CRITICAL (LCK-03): unattested SpiffeID accepted when SpiffeRootCA is configured!")
	}

	svidID, err := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/prod/sa/worker")
	if err != nil {
		t.Fatalf("ParseSPIFFEID: %v", err)
	}
	svidCertPEM, svidKeyPEM, err := rootCA.IssueSVID(&ca.SVIDProfile{
		SPIFFEID: svidID,
		TTL:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}
	defer slice.ExplicitBzero(svidKeyPEM)

	// SVID URI mismatch (presenting worker SVID while claiming admin SpiffeID) -> DENIED.
	mismatchResp, err := strictLM.RequestLease(&protocol.LeaseRequest{
		Version:    protocol.ProtocolVersion,
		Action:     protocol.ActionRequestLease,
		SpiffeID:   "spiffe://bonjoski.local/ns/prod/sa/admin",
		SpiffeSVID: string(svidCertPEM),
		SecretName: "VAULT_TOKEN",
		LeaseTTL:   2 * time.Minute,
	}, peer)
	if err != nil || mismatchResp.Status != protocol.StatusDenied {
		t.Fatalf("CRITICAL (LCK-03): mismatched SVID SAN allowed claiming admin SpiffeID!")
	}

	// Authentic matching SVID -> GRANTED.
	attestedResp, err := strictLM.RequestLease(&protocol.LeaseRequest{
		Version:    protocol.ProtocolVersion,
		Action:     protocol.ActionRequestLease,
		SpiffeID:   "spiffe://bonjoski.local/ns/prod/sa/worker",
		SpiffeSVID: string(svidCertPEM),
		SecretName: "VAULT_TOKEN",
		LeaseTTL:   2 * time.Minute,
	}, peer)
	if err != nil || attestedResp.Status != protocol.StatusGranted {
		t.Fatalf("expected GRANTED for authentic SVID, got status=%s err=%s (%v)", attestedResp.Status, attestedResp.Error, err)
	}
}

// TestAdversarial_LCK03_PeerBinaryAttestationChecksPeerNotSelf verifies that
// binary access controls evaluate the peer's kernel-attested executable path/hash
// rather than hashing os.Executable() (locksmith itself).
func TestAdversarial_LCK03_PeerBinaryAttestationChecksPeerNotSelf(t *testing.T) {
	t.Setenv("LOCKSMITH_AUDIT_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))

	mb := NewMockBackend()
	secBytes, err := json.Marshal(Secret{
		Value:     []byte("restricted-vault-secret"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	if err := mb.Set("locksmith-test", "RESTRICTED_KEY", secBytes, false); err != nil {
		t.Fatalf("seed mock backend: %v", err)
	}

	ls := &Locksmith{
		Service: "locksmith-test",
		Backend: mb,
		Options: Options{
			AllowBinaries: []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}

	// Untrusted peer hash must be denied even if locksmith's own binary is running.
	_, err = ls.GetForPeer("RESTRICTED_KEY", &protocol.PeerCredentials{
		PID:       9001,
		StartTime: 1700000000000000000,
		ExePath:   "/tmp/rogue-caller",
		ExeHash:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err == nil {
		t.Fatal("CRITICAL (LCK-03): GetForPeer allowed untrusted peer binary hash!")
	}

	// Trusted peer hash matching AllowBinaries succeeds.
	got, err := ls.GetForPeer("RESTRICTED_KEY", &protocol.PeerCredentials{
		PID:       9002,
		StartTime: 1700000000000000000,
		ExePath:   "/usr/local/bin/trusted-caller",
		ExeHash:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("expected trusted peer binary hash to be authorized, got: %v", err)
	}
	if string(got) != "restricted-vault-secret" {
		t.Fatalf("unexpected secret value: %q", string(got))
	}
}

type countingSlowBackend struct {
	gets    atomic.Int32
	payload []byte
	delay   time.Duration
}

func (b *countingSlowBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (b *countingSlowBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	b.gets.Add(1)
	time.Sleep(b.delay)
	out := make([]byte, len(b.payload))
	copy(out, b.payload)
	return out, nil
}

func (b *countingSlowBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (b *countingSlowBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return []string{"cold-secret"}, nil
}

// TestAdversarial_LCK06_ColdCacheSingleflightCoalescing verifies that N=8 parallel
// subagents hitting a cold cache trigger only 1 backend unlock (preventing 8 Touch ID
// prompts) and receive isolated secret buffers.
func TestAdversarial_LCK06_ColdCacheSingleflightCoalescing(t *testing.T) {
	t.Setenv("LOCKSMITH_AUDIT_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))

	secJSON, err := json.Marshal(Secret{
		Value:     []byte("coalesced-touchid-secret-value"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}

	backend := &countingSlowBackend{
		payload: secJSON,
		delay:   50 * time.Millisecond,
	}
	ls := &Locksmith{
		Service: "singleflight-test",
		Backend: backend,
		Cache:   &DiskCache{Dir: t.TempDir()},
	}

	const numAgents = 8
	results := make([][]byte, numAgents)
	errs := make([]error, numAgents)

	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < numAgents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier
			results[idx], errs[idx] = ls.Get("cold-secret")
		}(i)
	}
	close(startBarrier)
	wg.Wait()

	for i := 0; i < numAgents; i++ {
		if errs[i] != nil {
			t.Fatalf("agent %d failed: %v", i, errs[i])
		}
		if string(results[i]) != "coalesced-touchid-secret-value" {
			t.Fatalf("agent %d received wrong value: %q", i, string(results[i]))
		}
	}

	if gotCalls := backend.gets.Load(); gotCalls != 1 {
		t.Fatalf("CRITICAL (LCK-06): expected singleflight to coalesce 8 cold-cache gets into 1 backend call, got %d", gotCalls)
	}

	// Zeroize agent 0's buffer and ensure agents 1..7 are unaffected (no shared backing array).
	slice.ExplicitBzero(results[0])
	for i := 1; i < numAgents; i++ {
		if string(results[i]) != "coalesced-touchid-secret-value" {
			t.Fatalf("CRITICAL (LCK-06): zeroizing caller 0 buffer corrupted caller %d buffer!", i)
		}
	}
}
