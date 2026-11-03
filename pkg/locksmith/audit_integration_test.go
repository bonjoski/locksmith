package locksmith

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/audit"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

type auditTestBackend struct {
	mu    sync.RWMutex
	store map[string][]byte
}

func newAuditTestBackend() *auditTestBackend {
	return &auditTestBackend{store: make(map[string][]byte)}
}

func (b *auditTestBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.store[account] = data
	return nil
}

func (b *auditTestBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	d, ok := b.store[account]
	if !ok {
		return nil, os.ErrNotExist
	}
	return d, nil
}

func (b *auditTestBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.store, account)
	return nil
}

func (b *auditTestBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var keys []string
	for k := range b.store {
		keys = append(keys, k)
	}
	return keys, nil
}

func readAuditFileLines(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var events []audit.Event
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

func TestAuditIntegration_LocksmithGet(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mock := newAuditTestBackend()
	cache, err := NewDiskCache(make([]byte, 32))
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	ls := &Locksmith{
		Service: "test-service",
		Backend: mock,
		Cache:   cache,
		Options: Options{
			AuditIdentity: "test-identity",
		},
	}

	// 1. Secret not found -> writes DENIED audit record
	_, err = ls.Get("missing-key")
	if err == nil {
		t.Fatalf("expected error on missing key, got nil")
	}

	// 2. Add secret and get
	secretPayload, _ := json.Marshal(Secret{
		Value:      []byte("secret-value-123"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		SecretType: SecretTypeAPIKey,
	})
	_ = mock.Set("test-service", "api/key", secretPayload, false)

	val, err := ls.Get("api/key")
	if err != nil || string(val) != "secret-value-123" {
		t.Fatalf("unexpected Get result: val=%s, err=%v", string(val), err)
	}

	// 3. Read audit log
	events := readAuditFileLines(t, auditFile)
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events (DENIED, GRANTED), got %d", len(events))
	}

	deniedEv, grantEv := events[0], events[1]
	if deniedEv.SecretName != "missing-key" || deniedEv.Outcome != audit.OutcomeDenied {
		t.Errorf("unexpected denied event: %+v", deniedEv)
	}
	if grantEv.SecretName != "api/key" || grantEv.Outcome != audit.OutcomeGranted {
		t.Errorf("unexpected grant event: %+v", grantEv)
	}
	if grantEv.Identity != "test-identity" || grantEv.ClientPID != os.Getpid() {
		t.Errorf("unexpected grant attribution: identity=%s, pid=%d", grantEv.Identity, grantEv.ClientPID)
	}
}

func TestAuditIntegration_LeaseManager(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "lease_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mockStore := newAuditTestBackend()
	secretPayload, _ := json.Marshal(Secret{
		Value:     []byte("lease-secret-data"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	_ = mockStore.Set("sh.locksmith.v2", "db/token", secretPayload, false)

	diskCache, _ := NewDiskCache(make([]byte, 32))
	ls := &Locksmith{
		Service: "sh.locksmith.v2",
		Backend: mockStore,
		Cache:   diskCache,
		Options: Options{
			DisableAudit: true, // internal store shouldn't double-log
		},
	}

	lm := NewLeaseManager(ls, LeaseManagerOptions{
		DefaultTTL:    5 * time.Minute,
		MaxTTL:        10 * time.Minute,
		WatchInterval: 50 * time.Millisecond,
	})
	defer lm.Close()

	peer := &protocol.PeerCredentials{
		PID:       99999,
		ExePath:   "/usr/local/bin/my-app",
		ExeHash:   "sha256:fedcba9876543210",
		StartTime: 12345678,
	}

	// 1. Request lease with SPIFFE identity
	req := &protocol.LeaseRequest{
		Version:    protocol.ProtocolVersion,
		Action:     protocol.ActionRequestLease,
		SecretName: "db/token",
		SpiffeID:   "spiffe://aegisbox.internal/agent/sandbox",
		LeaseTTL:   5 * time.Minute,
	}

	resp, err := lm.RequestLease(req, peer)
	if err != nil || resp.Status != protocol.StatusGranted {
		t.Fatalf("RequestLease error: %v, resp: %+v", err, resp)
	}

	// 2. Revoke lease
	revResp, err := lm.RevokeLease(&protocol.RevokeRequest{
		Version: protocol.ProtocolVersion,
		Action:  protocol.ActionRevokeLease,
		LeaseID: resp.LeaseID,
	}, peer)
	if err != nil || !revResp.Success {
		t.Fatalf("RevokeLease error: %v, success=%v", err, revResp.Success)
	}

	// 3. Inspect audit events written
	events := readAuditFileLines(t, auditFile)
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events (GRANTED, REVOKED), got %d", len(events))
	}

	grantEv, revEv := events[0], events[1]
	if grantEv.SecretName != "db/token" || grantEv.Outcome != audit.OutcomeGranted {
		t.Errorf("unexpected grant event: %+v", grantEv)
	}
	if grantEv.Identity != "spiffe://aegisbox.internal/agent/sandbox" {
		t.Errorf("expected spiffe identity, got %s", grantEv.Identity)
	}
	if grantEv.ClientPID != 99999 || grantEv.BinaryPath != "/usr/local/bin/my-app" {
		t.Errorf("unexpected peer attribution: pid=%d, path=%s", grantEv.ClientPID, grantEv.BinaryPath)
	}
	if revEv.SecretName != "db/token" || revEv.Outcome != audit.OutcomeRevoked {
		t.Errorf("unexpected revoke event: %+v", revEv)
	}
}

func TestAuditIntegration_SocketLivenessRevocation(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "liveness_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mockStore := newAuditTestBackend()
	secretPayload, _ := json.Marshal(Secret{
		Value:     []byte("test-data"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	_ = mockStore.Set("sh.locksmith.v2", "my/secret", secretPayload, false)

	diskCache, _ := NewDiskCache(make([]byte, 32))
	ls := &Locksmith{
		Service: "sh.locksmith.v2",
		Backend: mockStore,
		Cache:   diskCache,
		Options: Options{DisableAudit: true},
	}

	lm := NewLeaseManager(ls, LeaseManagerOptions{
		DefaultTTL:    50 * time.Millisecond,
		MaxTTL:        1 * time.Minute,
		WatchInterval: 10 * time.Millisecond,
	})
	defer lm.Close()

	// Connect a dummy listener/connection to test socket peer flow
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer l.Close()

	peer := &protocol.PeerCredentials{
		PID:       os.Getpid(),
		ExePath:   "/test/bin",
		ExeHash:   "sha256:1234",
		StartTime: time.Now().Unix(),
	}

	req := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		SecretName:       "my/secret",
		ClientPID:        os.Getpid(),
		ProcessStartTime: peer.StartTime,
		LeaseTTL:         40 * time.Millisecond,
	}

	resp, err := lm.RequestLease(req, peer)
	if err != nil || resp.Status != protocol.StatusGranted {
		t.Fatalf("failed to grant lease: %v", err)
	}

	// Wait for TTL expiration
	time.Sleep(150 * time.Millisecond)

	// Verify expiration was audited as REVOKED
	f, err := os.Open(auditFile)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var events []audit.Event
	for scanner.Scan() {
		var ev audit.Event
		_ = json.Unmarshal(scanner.Bytes(), &ev)
		events = append(events, ev)
	}

	if len(events) < 2 {
		t.Fatalf("expected at least 2 events (GRANTED, REVOKED), got %d", len(events))
	}
	lastEv := events[len(events)-1]
	if lastEv.Outcome != audit.OutcomeRevoked {
		t.Errorf("expected final event REVOKED, got %s", lastEv.Outcome)
	}
}
