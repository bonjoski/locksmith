package locksmith

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

type mockSecretStore struct {
	secrets map[string][]byte
}

func (m *mockSecretStore) Get(key string) ([]byte, error) {
	val, ok := m.secrets[key]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	return cp, nil
}

func TestLeaseManager_BasicLeaseAndRevoke(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{
			"OPENAI_API_KEY": []byte("sk-test-1234567890"),
		},
	}

	lm := NewLeaseManager(store, LeaseManagerOptions{
		DefaultTTL:    10 * time.Minute,
		WatchInterval: 50 * time.Millisecond,
	})
	defer lm.Close()

	myPID := os.Getpid()
	myStartTime, err := protocol.GetProcessStartTime(myPID)
	if err != nil {
		t.Fatalf("failed to get my process start time: %v", err)
	}

	peer := &protocol.PeerCredentials{
		PID:       myPID,
		StartTime: myStartTime,
		ExePath:   "/path/to/caller",
		ExeHash:   "sha256:abc",
	}

	req := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        myPID,
		ProcessStartTime: myStartTime,
		ClientBinaryHash: "sha256:abc",
		SecretName:       "OPENAI_API_KEY",
		LeaseTTL:         2 * time.Minute,
		MaxUses:          1,
	}

	resp, err := lm.RequestLease(req, peer)
	if err != nil {
		t.Fatalf("RequestLease error: %v", err)
	}
	if resp.Status != protocol.StatusGranted {
		t.Fatalf("expected GRANTED, got %s (error: %s)", resp.Status, resp.Error)
	}
	if string(resp.SecretValue) != "sk-test-1234567890" {
		t.Fatalf("secret value mismatch: got %q", string(resp.SecretValue))
	}
	if resp.LeaseID == "" {
		t.Fatal("expected non-empty lease ID")
	}

	if lm.ActiveCount() != 1 {
		t.Fatalf("expected 1 active lease, got %d", lm.ActiveCount())
	}

	// Revoke lease
	revokeReq := &protocol.RevokeRequest{
		Version:   protocol.ProtocolVersion,
		Action:    protocol.ActionRevokeLease,
		LeaseID:   resp.LeaseID,
		ClientPID: myPID,
	}

	revokeResp, err := lm.RevokeLease(revokeReq, peer)
	if err != nil {
		t.Fatalf("RevokeLease error: %v", err)
	}
	if !revokeResp.Success {
		t.Fatalf("revoke failed: %s", revokeResp.Error)
	}

	if lm.ActiveCount() != 0 {
		t.Fatalf("expected 0 active leases after revocation, got %d", lm.ActiveCount())
	}
}

func TestLeaseManager_PIDMismatchProtection(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{"TEST_KEY": []byte("val")},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	peer := &protocol.PeerCredentials{
		PID:       9999,
		StartTime: 100,
	}

	// Attacker tries to spoof client PID as 1
	req := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        1,
		ProcessStartTime: 100,
		SecretName:       "TEST_KEY",
		LeaseTTL:         time.Minute,
	}

	resp, err := lm.RequestLease(req, peer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != protocol.StatusDenied {
		t.Fatalf("expected DENIED, got %s", resp.Status)
	}
}

func TestLeaseManager_SessionTicketPrivileges(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{
			"ALLOWED_KEY": []byte("allowed_val"),
			"DENIED_KEY":  []byte("denied_val"),
		},
	}
	lm := NewLeaseManager(store)
	defer lm.Close()

	myPID := os.Getpid()
	myStartTime, _ := protocol.GetProcessStartTime(myPID)
	peer := &protocol.PeerCredentials{PID: myPID, StartTime: myStartTime}

	ticket, err := lm.CreateSession(1234, 15*time.Minute, []string{"ALLOWED_KEY"})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// 1. Allowed key request
	req1 := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        myPID,
		ProcessStartTime: myStartTime,
		SecretName:       "ALLOWED_KEY",
		LeaseTTL:         time.Minute,
		SessionTicket:    ticket.TicketID,
	}
	resp1, err := lm.RequestLease(req1, peer)
	if err != nil || resp1.Status != protocol.StatusGranted {
		t.Fatalf("expected granted for allowed key, got %v (err: %s)", resp1, resp1.Error)
	}

	// 2. Denied key request with same session ticket
	req2 := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        myPID,
		ProcessStartTime: myStartTime,
		SecretName:       "DENIED_KEY",
		LeaseTTL:         time.Minute,
		SessionTicket:    ticket.TicketID,
	}
	resp2, err := lm.RequestLease(req2, peer)
	if err != nil || resp2.Status != protocol.StatusDenied {
		t.Fatalf("expected denied for unauthorized key, got %v", resp2)
	}
}

func TestLeaseManager_OrphanedPIDLivenessScavenging(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{"KEY": []byte("value")},
	}

	// Fast watch interval (20ms) for testing
	lm := NewLeaseManager(store, LeaseManagerOptions{
		DefaultTTL:    10 * time.Minute,
		WatchInterval: 20 * time.Millisecond,
	})
	defer lm.Close()

	// Use an impossible/dead PID (e.g. 99999999)
	deadPID := 99999999
	deadStartTime := int64(123456)

	peer := &protocol.PeerCredentials{
		PID:       deadPID,
		StartTime: deadStartTime,
	}

	req := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        deadPID,
		ProcessStartTime: deadStartTime,
		SecretName:       "KEY",
		LeaseTTL:         time.Minute,
	}

	resp, err := lm.RequestLease(req, peer)
	if err != nil {
		t.Fatalf("RequestLease failed: %v", err)
	}
	if resp.Status != protocol.StatusGranted {
		t.Fatalf("expected granted initially, got %s (%s)", resp.Status, resp.Error)
	}

	// Watcher should detect that deadPID does not exist and scavenge it within ~100ms
	time.Sleep(150 * time.Millisecond)

	if lm.ActiveCount() != 0 {
		t.Fatalf("expected orphaned lease to be scavenged, but active count is %d", lm.ActiveCount())
	}
}

func TestDaemonServer_SocketEndToEnd(t *testing.T) {
	store := &mockSecretStore{
		secrets: map[string][]byte{
			"DEMO_SECRET": []byte("super-secret-passphrase"),
		},
	}

	sockPath := fmt.Sprintf("/tmp/ls-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(sockPath)

	lm := NewLeaseManager(store)
	defer lm.Close()

	server := NewDaemonServer(lm, sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe(ctx)
	}()

	// Wait for socket to become ready
	var conn net.Conn
	var dialErr error
	for i := 0; i < 20; i++ {
		conn, dialErr = net.Dial("unix", sockPath)
		if dialErr == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("failed to connect to daemon socket: %v", dialErr)
	}

	// 1. Send Ping
	pingPayload, _ := json.Marshal(map[string]any{
		"action": protocol.ActionPing,
	})
	_, _ = conn.Write(pingPayload)

	var pingResp struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&pingResp); err != nil {
		t.Fatalf("failed to decode ping response: %v", err)
	}
	if pingResp.Status != "PONG" {
		t.Fatalf("expected PONG, got %s", pingResp.Status)
	}
	conn.Close()

	// 2. Request Lease over Socket
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial socket: %v", err)
	}
	defer conn2.Close()

	myPID := os.Getpid()
	myStartTime, _ := protocol.GetProcessStartTime(myPID)

	leaseReq := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        myPID,
		ProcessStartTime: myStartTime,
		SecretName:       "DEMO_SECRET",
		LeaseTTL:         2 * time.Minute,
	}

	reqBytes, _ := json.Marshal(leaseReq)
	_, _ = conn2.Write(reqBytes)

	var leaseResp protocol.LeaseResponse
	if err := json.NewDecoder(conn2).Decode(&leaseResp); err != nil {
		t.Fatalf("failed to decode lease response: %v", err)
	}
	if leaseResp.Status != protocol.StatusGranted {
		t.Fatalf("expected GRANTED, got %s (err: %s)", leaseResp.Status, leaseResp.Error)
	}
	if string(leaseResp.SecretValue) != "super-secret-passphrase" {
		t.Fatalf("secret value mismatch: got %s", string(leaseResp.SecretValue))
	}

	cancel()
	_ = server.Close()
}
