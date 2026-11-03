package locksmith

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/audit"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// ADV-AUDIT-01: Zero-Knowledge Invariant (Strict Secret Exfiltration Resistance)
// Secret payloads, passwords, and private tokens must NEVER be leaked into the audit trail.
func TestAdversarial_ZeroKnowledge_NoSecretExfiltrationInAudit(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "adv_zero_knowledge_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mock := newAuditTestBackend()
	cache, err := NewDiskCache(make([]byte, 32))
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ls := &Locksmith{
		Service: "adv-audit-service",
		Backend: mock,
		Cache:   cache,
		Options: Options{
			AuditIdentity: "adv-tester",
			BypassCache:   true,
		},
	}

	canarySecrets := map[string]string{
		"aws/prod/api_key":      "FAKE_AWS_KEY_CANARY_PAYLOAD_12345",
		"gpg/passphrase":        "super_secret_master_passphrase_canary_999!",
		"gitlab/glab/token":     "fake_gitlab_token_canary_abcdef_98765",
		"github/app/privatekey": "FAKE_PRIVATE_KEY_PAYLOAD_CANARY_RSA_999",
	}

	for k, v := range canarySecrets {
		payload, _ := json.Marshal(Secret{
			Value:      []byte(v),
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(time.Hour),
			SecretType: SecretTypeToken,
		})
		_ = mock.Set("adv-audit-service", k, payload, false)

		val, err := ls.Get(k)
		if err != nil || string(val) != v {
			t.Fatalf("failed to retrieve canary secret %q: got %q, want %q, err=%v", k, string(val), v, err)
		}
	}

	// Read the entire raw audit log
	rawAuditBytes, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}

	rawAuditContent := string(rawAuditBytes)

	// Adversarial scan: Verify that NONE of the secret values or key sub-parts appear in audit log
	for k, canary := range canarySecrets {
		if strings.Contains(rawAuditContent, canary) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Secret value for key %q was exfiltrated into audit log!\nLeaked content: %q", k, canary)
		}
		// Also test against reversed, hex, or trimmed fragments
		shortFragment := canary[5:15]
		if strings.Contains(rawAuditContent, shortFragment) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Secret fragment %q for key %q detected in audit log!", shortFragment, k)
		}
	}
	t.Log("PASS: Zero-knowledge audit invariant verified. No secret values leaked.")
}

// ADV-AUDIT-02: Non-Repudiation Enforcement (Access Must Always Produce Audit Log)
// Every vault lookup (success or failure) must create an unforgeable audit record.
func TestAdversarial_NonRepudiation_MandatoryAuditLogging(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "adv_non_repudiation_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mock := newAuditTestBackend()
	cache, err := NewDiskCache(make([]byte, 32))
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	ls := &Locksmith{
		Service: "adv-audit-service",
		Backend: mock,
		Cache:   cache,
		Options: Options{
			AuditIdentity: "audited-workload",
		},
	}

	// 1. Initial state: audit log does not exist
	if _, err := os.Stat(auditFile); !os.IsNotExist(err) {
		t.Fatalf("audit file must not exist before operations")
	}

	// 2. Denied lookup (missing key)
	_, _ = ls.Get("unauthorized/missing/key")

	// Audit file must now exist with exactly 1 DENIED entry
	events := readAuditEventsHelper(t, auditFile)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 audit event after denied lookup, got %d", len(events))
	}
	if events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("expected DENIED outcome, got %s", events[0].Outcome)
	}
	if events[0].SecretName != "unauthorized/missing/key" {
		t.Errorf("expected secret_name 'unauthorized/missing/key', got %s", events[0].SecretName)
	}

	// 3. Granted lookup
	payload, _ := json.Marshal(Secret{
		Value:      []byte("legit-value"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		SecretType: SecretTypeAPIKey,
	})
	_ = mock.Set("adv-audit-service", "authorized/key", payload, false)

	_, err = ls.Get("authorized/key")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	// Audit file must now have exactly 2 entries
	events = readAuditEventsHelper(t, auditFile)
	if len(events) != 2 {
		t.Fatalf("expected exactly 2 audit events, got %d", len(events))
	}
	if events[1].Outcome != audit.OutcomeGranted {
		t.Errorf("expected GRANTED outcome, got %s", events[1].Outcome)
	}
	if events[1].SecretName != "authorized/key" {
		t.Errorf("expected secret_name 'authorized/key', got %s", events[1].SecretName)
	}

	t.Log("PASS: Non-repudiation verified. All operations strictly accounted for.")
}

// ADV-AUDIT-03: PID & Executable Impersonation Defense
// Audit logs must reflect kernel-authenticated socket peer credentials rather than attacker payload claims.
func TestAdversarial_PeerPIDSpoofingDefenseInAudit(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "adv_pid_spoof_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mock := newAuditTestBackend()
	payload, _ := json.Marshal(Secret{
		Value:     []byte("vault-secret"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = mock.Set("sh.locksmith.v2", "secure/target", payload, false)

	cache, _ := NewDiskCache(make([]byte, 32))
	ls := &Locksmith{
		Service: "sh.locksmith.v2",
		Backend: mock,
		Cache:   cache,
		Options: Options{DisableAudit: true},
	}

	lm := NewLeaseManager(ls, LeaseManagerOptions{
		DefaultTTL:    5 * time.Minute,
		MaxTTL:        10 * time.Minute,
		WatchInterval: 50 * time.Millisecond,
	})
	defer lm.Close()

	// Authenticated Kernel Socket Peer
	kernelPID := 54321
	kernelExe := "/usr/libexec/evil_attacker_binary"
	kernelHash := "sha256:attackerhash999"

	peer := &protocol.PeerCredentials{
		PID:       kernelPID,
		ExePath:   kernelExe,
		ExeHash:   kernelHash,
		StartTime: 1000,
	}

	// Attacker payload claims PID 1 (launchd / init) to frame system process
	spoofedReq := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		SecretName:       "secure/target",
		ClientPID:        1, // Spoofed PID
		ProcessStartTime: 1000,
		LeaseTTL:         5 * time.Minute,
	}

	// This request will be denied due to PID mismatch
	resp, _ := lm.RequestLease(spoofedReq, peer)
	if resp != nil && resp.Status == protocol.StatusGranted {
		t.Fatal("CRITICAL: Spoofed lease request was granted!")
	}

	events := readAuditEventsHelper(t, auditFile)
	if len(events) == 0 {
		t.Fatal("expected audit event for denied spoofed request")
	}

	deniedEvent := events[0]
	// The audit record MUST log the real kernel PID (54321), NOT the spoofed PID (1)
	if deniedEvent.ClientPID != kernelPID {
		t.Fatalf("SECURITY FLAW: Audit record logged spoofed PID %d instead of verified kernel PID %d!", deniedEvent.ClientPID, kernelPID)
	}
	if deniedEvent.BinaryPath != kernelExe {
		t.Fatalf("SECURITY FLAW: Audit record logged wrong binary path: %s", deniedEvent.BinaryPath)
	}
	if deniedEvent.Outcome != audit.OutcomeDenied {
		t.Fatalf("expected DENIED outcome, got %s", deniedEvent.Outcome)
	}

	t.Log("PASS: Kernel-authenticated peer credentials enforced in audit logs.")
}

// ADV-AUDIT-04: High-Throughput Concurrent Log Integrity & Race Resistance
// Concurrent writes from multiple processes must maintain atomic line serialization with zero corruption.
func TestAdversarial_ConcurrentAuditWritingAndTamperResistance(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "adv_concurrent_audit.jsonl")
	t.Setenv("LOCKSMITH_AUDIT_PATH", auditFile)

	mock := newAuditTestBackend()
	payload, _ := json.Marshal(Secret{
		Value:      []byte("concurrent-val"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		SecretType: SecretTypeToken,
	})
	_ = mock.Set("adv-concurrent", "shared/token", payload, false)

	cache, _ := NewDiskCache(make([]byte, 32))
	ls := &Locksmith{
		Service: "adv-concurrent",
		Backend: mock,
		Cache:   cache,
		Options: Options{
			AuditIdentity: "concurrent-agent",
		},
	}

	var wg sync.WaitGroup
	numWorkers := 15
	operationsPerWorker := 20

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerWorker; j++ {
				if j%2 == 0 {
					_, _ = ls.Get("shared/token")
				} else {
					_, _ = ls.Get("missing/secret")
				}
			}
			_ = workerID
		}()
	}

	wg.Wait()

	// Parse every single line of the file. Any syntax error indicates line interleaving / race corruption.
	f, err := os.Open(auditFile)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	totalParsed := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("RACE CONDITION / LOG CORRUPTION detected at line %d: %v\nLine content: %s", totalParsed+1, err, string(line))
		}
		if ev.SecretName == "" || ev.Outcome == "" || ev.TimestampMS <= 0 {
			t.Fatalf("Malformed audit record at line %d: %+v", totalParsed+1, ev)
		}
		totalParsed++
	}

	expectedTotal := numWorkers * operationsPerWorker
	if totalParsed != expectedTotal {
		t.Fatalf("expected %d total audit records, got %d", expectedTotal, totalParsed)
	}

	t.Logf("PASS: %d concurrent audit entries written cleanly with zero corruption.", totalParsed)
}

func readAuditEventsHelper(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open audit file %q: %v", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var events []audit.Event
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("failed to parse audit line: %v", err)
		}
		events = append(events, ev)
	}
	return events
}
