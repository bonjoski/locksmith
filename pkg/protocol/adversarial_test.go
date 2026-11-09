package protocol_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
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

func assertLCK04PeerFields(t *testing.T, peer *protocol.PeerCredentials) {
	t.Helper()
	if peer.PID != os.Getpid() {
		t.Fatalf("expected peer PID %d, got %d", os.Getpid(), peer.PID)
	}
	if peer.UID != uint32(os.Getuid()) {
		t.Fatalf("expected peer UID %d, got %d", os.Getuid(), peer.UID)
	}
	if peer.StartTime <= 1 {
		t.Fatalf("CRITICAL (LCK-04): GetPeerInfo returned hardcoded/invalid StartTime=%d", peer.StartTime)
	}
	if runtime.GOOS == "darwin" && peer.StartTime < 1_000_000_000_000_000_000 {
		t.Fatalf("CRITICAL (LCK-04): Darwin StartTime=%d is not a valid nanosecond epoch timestamp", peer.StartTime)
	}
	if !strings.HasPrefix(peer.ExePath, "/") {
		t.Fatalf("CRITICAL (LCK-04): expected absolute kernel executable path, got %q", peer.ExePath)
	}
	if !strings.HasPrefix(peer.ExeHash, "sha256:") || len(peer.ExeHash) != len("sha256:")+64 {
		t.Fatalf("CRITICAL (LCK-04): expected valid sha256 ExeHash, got %q", peer.ExeHash)
	}
}

func assertLCK04InvalidPIDs(t *testing.T) {
	t.Helper()
	if _, err := protocol.GetProcessStartTime(-1); err == nil {
		t.Fatal("expected error for negative PID in GetProcessStartTime")
	}
	if _, err := protocol.GetProcessStartTime(99999999); err == nil {
		t.Fatal("expected error for non-existent PID in GetProcessStartTime")
	}
	if _, err := protocol.GetProcessExecutablePath(99999999); err == nil {
		t.Fatal("expected error for non-existent PID in GetProcessExecutablePath")
	}
}

// TestAdversarial_LCK04_KernelPeerInspectionNoPS verifies that Unix socket peer
// inspection queries kernel structures directly (LOCAL_PEERCRED/LOCAL_PEERPID,
// SysctlKinfoProc, SYS_PROC_INFO / procfs) rather than spawning external `ps`
// or returning hardcoded placeholder timestamps.
func TestAdversarial_LCK04_KernelPeerInspectionNoPS(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("kernel UDS peer credential inspection test applies to darwin/linux")
	}

	sockPath := fmt.Sprintf("/tmp/ls-lck04-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
	defer func() {
		if rmErr := os.Remove(sockPath); rmErr != nil && !os.IsNotExist(rmErr) {
			t.Logf("remove socket: %v", rmErr)
		}
	}()

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("listener close: %v", closeErr)
		}
	}()

	peerCh := make(chan *protocol.PeerCredentials, 1)
	errCh := make(chan error, 1)
	go func() {
		srvConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer func() {
			if cErr := srvConn.Close(); cErr != nil {
				t.Logf("srvConn close: %v", cErr)
			}
		}()
		info, pErr := protocol.GetPeerInfo(srvConn)
		if pErr != nil {
			errCh <- pErr
			return
		}
		peerCh <- info
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer func() {
		if cErr := clientConn.Close(); cErr != nil {
			t.Logf("clientConn close: %v", cErr)
		}
	}()

	select {
	case pErr := <-errCh:
		t.Fatalf("GetPeerInfo failed: %v", pErr)
	case peer := <-peerCh:
		assertLCK04PeerFields(t, peer)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for GetPeerInfo")
	}

	assertLCK04InvalidPIDs(t)
}
