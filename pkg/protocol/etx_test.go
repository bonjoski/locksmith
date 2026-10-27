package protocol_test

import (
	"os"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

func TestLeaseRequestValidation(t *testing.T) {
	req := protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        os.Getpid(),
		ProcessStartTime: 12345678,
		ClientBinaryHash: "sha256:abcd",
		SecretName:       "OPENAI_API_KEY",
		LeaseTTL:         5 * time.Minute,
		MaxUses:          1,
	}

	if err := req.Validate(); err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}

	// Test invalid version
	invalidReq := req
	invalidReq.Version = "0.1"
	if err := invalidReq.Validate(); err == nil {
		t.Errorf("expected error for invalid version, got nil")
	}

	// Test negative PID
	invalidReq = req
	invalidReq.ClientPID = -1
	if err := invalidReq.Validate(); err == nil {
		t.Errorf("expected error for negative PID, got nil")
	}

	// Test missing start time
	invalidReq = req
	invalidReq.ProcessStartTime = 0
	if err := invalidReq.Validate(); err == nil {
		t.Errorf("expected error for missing start time, got nil")
	}

	// Test valid SPIFFE workload identity request (ClientPID and ProcessStartTime not required)
	spiffeReq := protocol.LeaseRequest{
		Version:    protocol.ProtocolVersion,
		Action:     protocol.ActionRequestLease,
		SpiffeID:   "spiffe://aegisbox.local/workload/microvm",
		SecretName: "GITHUB_TOKEN",
		LeaseTTL:   120 * time.Second,
	}
	if err := spiffeReq.Validate(); err != nil {
		t.Fatalf("expected valid spiffe request, got: %v", err)
	}

	// Test invalid SPIFFE ID formats
	badSpiffeReq := spiffeReq
	badSpiffeReq.SpiffeID = "https://aegisbox.local/microvm"
	if err := badSpiffeReq.Validate(); err == nil {
		t.Errorf("expected error for non-spiffe scheme, got nil")
	}

	badSpiffeReq.SpiffeID = "spiffe:///workload"
	if err := badSpiffeReq.Validate(); err == nil {
		t.Errorf("expected error for missing trust domain, got nil")
	}

	badSpiffeReq.SpiffeID = "spiffe://aegisbox.local"
	if err := badSpiffeReq.Validate(); err == nil {
		t.Errorf("expected error for missing workload path, got nil")
	}
}

func TestLeaseResponseZeroing(t *testing.T) {
	resp := protocol.LeaseResponse{
		Status:      protocol.StatusGranted,
		LeaseID:     "lease-123",
		SecretValue: []byte("super-secret-token"),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if !resp.ConstantTimeCompare([]byte("super-secret-token")) {
		t.Errorf("expected constant time comparison to match")
	}

	resp.Zero()

	if resp.SecretValue != nil {
		t.Errorf("expected SecretValue to be nil after Zero()")
	}
	if resp.ConstantTimeCompare([]byte("super-secret-token")) {
		t.Errorf("expected constant time comparison to fail after Zero()")
	}
}

func TestSessionTicketPermissions(t *testing.T) {
	ticket := protocol.SessionTicket{
		TicketID:       "ticket-abc",
		PGID:           os.Getpid(),
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		AllowedSecrets: []string{"OPENAI_API_KEY", "GITHUB_TOKEN"},
	}

	if !ticket.PermitsSecret("OPENAI_API_KEY") {
		t.Errorf("expected ticket to permit OPENAI_API_KEY")
	}
	if !ticket.PermitsSecret("openai_api_key") {
		t.Errorf("expected case-insensitive match")
	}
	if ticket.PermitsSecret("AWS_SECRET_ACCESS_KEY") {
		t.Errorf("expected ticket to deny AWS_SECRET_ACCESS_KEY")
	}

	// Test wildcard ticket
	wildcardTicket := ticket
	wildcardTicket.AllowedSecrets = []string{"*"}
	if !wildcardTicket.PermitsSecret("ANYTHING") {
		t.Errorf("expected wildcard ticket to permit any secret")
	}

	// Test expired ticket
	expiredTicket := ticket
	expiredTicket.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if expiredTicket.PermitsSecret("OPENAI_API_KEY") {
		t.Errorf("expected expired ticket to deny all secrets")
	}
}

func TestPeerProcessInspection(t *testing.T) {
	pid := os.Getpid()

	startTime, err := protocol.GetProcessStartTime(pid)
	if err != nil {
		t.Fatalf("failed to get start time for current pid %d: %v", pid, err)
	}
	if startTime <= 0 {
		t.Errorf("expected positive start time, got %d", startTime)
	}

	exePath, err := protocol.GetProcessExecutablePath(pid)
	if err != nil {
		t.Fatalf("failed to get executable path for current pid %d: %v", pid, err)
	}
	if exePath == "" {
		t.Errorf("expected non-empty executable path")
	}
}

func TestActionListLeasesConstant(t *testing.T) {
	if protocol.ActionListLeases != "list_leases" {
		t.Errorf("expected ActionListLeases to be 'list_leases', got %q", protocol.ActionListLeases)
	}
}
