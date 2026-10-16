package locksmith

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// ADV-P2-01: Unauthorized Secret Revocation Hijack
// An attacker process with a different PID attempts to revoke another process's lease.
func TestAdversarial_UnauthorizedRevocation(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{"SEC": []byte("val")},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	legitPID := 12345
	legitStartTime := int64(1000)
	peerLegit := &protocol.PeerCredentials{PID: legitPID, StartTime: legitStartTime}

	resp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        legitPID,
		ProcessStartTime: legitStartTime,
		SecretName:       "SEC",
		LeaseTTL:         5 * time.Minute,
	}, peerLegit)
	if err != nil || resp.Status != protocol.StatusGranted {
		t.Fatalf("setup failed: %v", err)
	}

	// Attacker with different PID tries to revoke legit lease
	attackerPID := 99999
	peerAttacker := &protocol.PeerCredentials{PID: attackerPID, StartTime: 2000}

	revokeResp, err := lm.RevokeLease(&protocol.RevokeRequest{
		Version:   protocol.ProtocolVersion,
		Action:    protocol.ActionRevokeLease,
		LeaseID:   resp.LeaseID,
		ClientPID: legitPID, // Spoofing client PID in payload
	}, peerAttacker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revokeResp.Success {
		t.Fatal("CRITICAL: Attacker was able to revoke another process's lease!")
	}
	t.Logf("PASS: Unauthorized revocation blocked: %s", revokeResp.Error)
}

// ADV-P2-02: Socket Permissions and Eavesdropping Protection
// Daemon socket file must be strictly 0600 in a 0700 directory.
func TestAdversarial_SocketPermissionsHardening(t *testing.T) {
	store := &mockSecretStore{secrets: map[string][]byte{"K": []byte("V")}}
	sockPath := fmt.Sprintf("/tmp/ls-perm-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(sockPath)

	lm := NewLeaseManager(store)
	defer lm.Close()

	server := NewDaemonServer(lm, sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.ListenAndServe(ctx)
	}()

	// Wait for socket creation
	var fi os.FileInfo
	for i := 0; i < 20; i++ {
		var err error
		fi, err = os.Stat(sockPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fi == nil {
		t.Fatal("socket file was not created")
	}

	// Verify permissions: must NOT have group or other read/write permissions
	perm := fi.Mode().Perm()
	if perm&0077 != 0 {
		t.Fatalf("CRITICAL: Socket permissions too permissive: %v (expected 0600)", perm)
	}
	t.Logf("PASS: Socket permissions strictly enforced at %v", perm)
}

// ADV-P2-03: Orphaned Lease Scavenging under Client Crash (VAL-05)
// When a child process is hard-killed (e.g. SIGKILL), the lease must be reclaimed automatically.
func TestAdversarial_OrphanedLeaseZombieReclamation(t *testing.T) {
	store := &mockSecretStore{secrets: map[string][]byte{"SECRET": []byte("data")}}
	lm := NewLeaseManager(store, LeaseManagerOptions{
		DefaultTTL:    10 * time.Minute,
		WatchInterval: 25 * time.Millisecond,
	})
	defer lm.Close()

	// Simulate dead PID
	ghostPID := 99999991
	ghostStartTime := int64(5555)
	peer := &protocol.PeerCredentials{PID: ghostPID, StartTime: ghostStartTime}

	resp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        ghostPID,
		ProcessStartTime: ghostStartTime,
		SecretName:       "SECRET",
		LeaseTTL:         5 * time.Minute,
	}, peer)
	if err != nil || resp.Status != protocol.StatusGranted {
		t.Fatalf("failed to request lease: %v", err)
	}

	// Verify active count is 1 initially
	if lm.ActiveCount() != 1 {
		t.Fatalf("expected 1 active lease, got %d", lm.ActiveCount())
	}

	// Within 150ms, watcher must discover ghostPID does not exist and scavenge it
	time.Sleep(150 * time.Millisecond)

	if lm.ActiveCount() != 0 {
		t.Fatalf("CRITICAL: Orphaned lease was not scavenged! Active count: %d", lm.ActiveCount())
	}
	t.Log("PASS: Orphaned lease successfully identified and cleaned up by liveness watcher")
}

// ADV-P2-04: Session Ticket Wildcard & Prefix Hijack
// Session tickets must strictly enforce allowed secrets and deny prefix tampering.
func TestAdversarial_SessionTicketPrefixBypass(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{
			"GH_TOKEN":       []byte("ghp_valid"),
			"GH_TOKEN_ADMIN": []byte("ghp_admin_secret"),
		},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	myPID := os.Getpid()
	myStartTime, _ := protocol.GetProcessStartTime(myPID)
	peer := &protocol.PeerCredentials{PID: myPID, StartTime: myStartTime}

	// Session ticket only permits "GH_TOKEN"
	ticket, err := lm.CreateSession(1, 10*time.Minute, []string{"GH_TOKEN"})
	if err != nil {
		t.Fatalf("session creation failed: %v", err)
	}

	// Attacker attempts prefix-extension attack: asking for GH_TOKEN_ADMIN
	resp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        myPID,
		ProcessStartTime: myStartTime,
		SecretName:       "GH_TOKEN_ADMIN",
		LeaseTTL:         time.Minute,
		SessionTicket:    ticket.TicketID,
	}, peer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != protocol.StatusDenied {
		t.Fatalf("CRITICAL: Session ticket allowed prefix extension to GH_TOKEN_ADMIN! Status: %s", resp.Status)
	}
	t.Logf("PASS: Prefix manipulation attack blocked: %s", resp.Error)
}

// ADV-P2-05: Constant-Time Zeroing of Leased Memory Residuals
func TestAdversarial_LeaseResponseMemorySanitization(t *testing.T) {
	resp := &protocol.LeaseResponse{
		Status:      protocol.StatusGranted,
		LeaseID:     "ls-lease-test",
		SecretValue: []byte("super-sensitive-signing-key"),
	}

	candidate := []byte("super-sensitive-signing-key")
	if !resp.ConstantTimeCompare(candidate) {
		t.Fatal("pre-condition failed: ConstantTimeCompare should match")
	}

	// Call Zero()
	resp.Zero()

	// Verify buffer is wiped and nil'd
	if resp.SecretValue != nil {
		t.Fatal("CRITICAL: SecretValue is not nil after Zero()")
	}
	if resp.ConstantTimeCompare(candidate) {
		t.Fatal("CRITICAL: Zeroed response still matched candidate secret!")
	}
	t.Log("PASS: In-memory secret buffer securely wiped and residual comparison fails")
}

// ADV-P2-06: Socket Request Payload Exhaustion (Buffer Bomb)
func TestAdversarial_DaemonSocketPayloadBomb(t *testing.T) {
	store := &mockSecretStore{secrets: map[string][]byte{"K": []byte("V")}}
	sockPath := fmt.Sprintf("/tmp/ls-bomb-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(sockPath)

	lm := NewLeaseManager(store)
	defer lm.Close()

	server := NewDaemonServer(lm, sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.ListenAndServe(ctx)
	}()

	var conn net.Conn
	for i := 0; i < 20; i++ {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("failed to connect to socket")
	}
	defer conn.Close()

	// Send 500KB garbage payload (exceeding 64KB daemon read buffer)
	bomb := make([]byte, 512*1024)
	for i := range bomb {
		bomb[i] = 'A'
	}
	_, _ = conn.Write(bomb)

	// Daemon must not panic or crash; next valid ping must succeed
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("daemon crashed after payload bomb: %v", err)
	}
	defer conn2.Close()

	_ = json.NewEncoder(conn2).Encode(map[string]any{"action": protocol.ActionPing})
	var pingResp struct{ Status string }
	if err := json.NewDecoder(conn2).Decode(&pingResp); err != nil || pingResp.Status != "PONG" {
		t.Fatalf("daemon failed to recover after buffer bomb: %v", err)
	}
	t.Log("PASS: Daemon resiliently survived 512KB payload exhaustion attempt")
}
