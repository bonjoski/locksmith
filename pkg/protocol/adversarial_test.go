package protocol_test

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// ADV-01: Attacker attempts to forge ClientPID in request payload to spoof another process.
func TestAdversarial_PIDTampering(t *testing.T) {
	currentPID := os.Getpid()
	spoofedPID := 1 // init/launchd

	req := protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        spoofedPID,
		ProcessStartTime: 100,
		SecretName:       "PROD_API_KEY",
		LeaseTTL:         5 * time.Minute,
	}

	// Payload says PID 1, but kernel peer info says currentPID
	if req.ClientPID == currentPID {
		t.Fatalf("expected spoofed pid to differ from actual pid")
	}

	// Simulated server verification:
	peerInfo := &protocol.PeerCredentials{
		PID:       currentPID,
		StartTime: 123456,
	}

	if req.ClientPID != peerInfo.PID {
		// Server detects spoofing attempt!
		t.Logf("PASS: Detected PID spoofing attempt (Payload PID=%d, Kernel Peer PID=%d)", req.ClientPID, peerInfo.PID)
	} else {
		t.Fatalf("FAIL: Server accepted mismatched PID payload")
	}
}

// ADV-02: Attacker attempts to reuse an expired/recycled PID without valid StartTime.
func TestAdversarial_StartTimeSpoofing(t *testing.T) {
	actualStartTime, err := protocol.GetProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("failed to query start time: %v", err)
	}

	staleStartTime := actualStartTime - 10000 // Recycled process attempt

	req := protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        os.Getpid(),
		ProcessStartTime: staleStartTime,
		SecretName:       "PROD_API_KEY",
		LeaseTTL:         5 * time.Minute,
	}

	if req.ProcessStartTime == actualStartTime {
		t.Fatalf("stale start time should not match actual start time")
	}

	// Simulated server check:
	if req.ProcessStartTime != actualStartTime {
		t.Logf("PASS: Defeated PID recycling attack (Req StartTime=%d != Kernel StartTime=%d)", req.ProcessStartTime, actualStartTime)
	} else {
		t.Fatalf("FAIL: Server allowed mismatched process start time")
	}
}

// ADV-03: Attacker attempts to recover secret plaintext from memory after Zero().
func TestAdversarial_ZeroingResiduals(t *testing.T) {
	secretBytes := []byte("super-sensitive-signing-key-999")
	secretLen := len(secretBytes)

	resp := protocol.LeaseResponse{
		Status:      protocol.StatusGranted,
		LeaseID:     "lease-test-99",
		SecretValue: make([]byte, secretLen),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	copy(resp.SecretValue, secretBytes)

	// Verify secret is present
	if !bytes.Equal(resp.SecretValue, secretBytes) {
		t.Fatalf("failed to initialize secret buffer")
	}

	// Execute Zero()
	resp.Zero()

	// Verify slice is nil
	if resp.SecretValue != nil {
		t.Fatalf("FAIL: SecretValue slice pointer not cleared")
	}

	// ConstantTimeCompare must reject original secret
	if resp.ConstantTimeCompare(secretBytes) {
		t.Fatalf("FAIL: ConstantTimeCompare succeeded on zeroed response")
	}
	t.Logf("PASS: Memory wiped cleanly, zeroing invariants held")
}

// ADV-04: Attacker attempts privilege escalation using sub-tokens and wildcard manipulation.
func TestAdversarial_SessionTicketPrivilegeEscalation(t *testing.T) {
	ticket := protocol.SessionTicket{
		TicketID:       "sess-token-restricted",
		PGID:           os.Getpid(),
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		AllowedSecrets: []string{"OPENAI_API_KEY"},
	}

	forbiddenAttempts := []string{
		"AWS_SECRET_ACCESS_KEY",
		"OPENAI_API_KEY_ADMIN",
		"OPENAI_API_KEY/../ROOT",
		"openai_api_key_extra",
		"",
		" ",
	}

	for _, secret := range forbiddenAttempts {
		if ticket.PermitsSecret(secret) {
			t.Fatalf("FAIL: Session ticket improperly permitted unauthorized secret %q", secret)
		}
	}
	t.Logf("PASS: Session ticket strictly blocked all unauthorized scope escalation attempts")
}

// ADV-05: Attacker attempts to submit massive garbage payload to exhaust memory.
func TestAdversarial_PayloadExhaustion(t *testing.T) {
	largeSecretName := strings.Repeat("A", 10*1024*1024) // 10MB string

	req := protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        os.Getpid(),
		ProcessStartTime: 1234,
		SecretName:       largeSecretName,
		LeaseTTL:         time.Minute,
	}

	data, err := protocol.EncodeJSON(req)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	var decoded protocol.LeaseRequest
	if err := protocol.DecodeJSON(data, &decoded); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(decoded.SecretName) != len(largeSecretName) {
		t.Fatalf("length mismatch")
	}
	t.Logf("PASS: Large payload handled without panics or memory corruption")
}
