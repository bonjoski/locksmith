package spiffe_test

import (
	"os"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
)

func TestPolicy_Authorize(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	currentUID := uint32(os.Getuid())

	validIdentity := &spiffe.CallerIdentity{
		PID:  1234,
		UID:  currentUID,
		Comm: "agent-worker",
	}

	invalidIdentity := &spiffe.CallerIdentity{
		PID:  5678,
		UID:  currentUID + 9999,
		Comm: "rogue-agent",
	}

	validID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/worker")
	foreignDomainID, _ := ca.ParseSPIFFEID("spiffe://corp.external/ns/dev/sa/worker")

	// 1. Authorized identity + matching trust domain
	if err := pol.Authorize(validIdentity, validID); err != nil {
		t.Errorf("expected authorized, got: %v", err)
	}

	// 2. Unauthorized UID rejected
	if err := pol.Authorize(invalidIdentity, validID); err == nil {
		t.Errorf("expected unauthorized UID to be rejected, got nil")
	}

	// 3. Foreign trust domain rejected
	if err := pol.Authorize(validIdentity, foreignDomainID); err == nil {
		t.Errorf("expected foreign trust domain to be rejected, got nil")
	}

	// 4. Nil identity rejected
	if err := pol.Authorize(nil, validID); err == nil {
		t.Errorf("expected nil identity to be rejected, got nil")
	}

	// 5. Vsock CID authorization (fails closed by default when AllowedCIDs is empty)
	vmIdentity := &spiffe.CallerIdentity{
		VsockCID: 3,
		Comm:     "aegisbox-vm",
	}
	if err := pol.Authorize(vmIdentity, validID); err == nil {
		t.Errorf("expected vsock identity to be rejected when AllowedCIDs is empty")
	}

	// 6. AllowedCIDs permits explicit CID
	pol.AllowedCIDs = []uint32{3}
	if err := pol.Authorize(vmIdentity, validID); err != nil {
		t.Errorf("expected CID 3 to be authorized when AllowedCIDs=[3], got: %v", err)
	}

	// 7. Restrictive AllowedCIDs mismatch
	pol.AllowedCIDs = []uint32{4, 5}
	if err := pol.Authorize(vmIdentity, validID); err == nil {
		t.Errorf("expected CID 3 to be rejected when AllowedCIDs=[4,5]")
	}
	vmIdentity.VsockCID = 4
	if err := pol.Authorize(vmIdentity, validID); err != nil {
		t.Errorf("expected CID 4 to be authorized, got: %v", err)
	}
}

func TestPolicy_ResolveSPIFFEID(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	identity := &spiffe.CallerIdentity{
		PID:  1234,
		UID:  uint32(os.Getuid()),
		Comm: "my agent",
	}

	// Explicit request
	resolved, err := pol.ResolveSPIFFEID(identity, "spiffe://bonjoski.local/ns/dev/sa/custom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.String() != "spiffe://bonjoski.local/ns/dev/sa/custom" {
		t.Errorf("got %q, want custom ID", resolved.String())
	}

	// Default fallback derivation from comm
	defaultResolved, err := pol.ResolveSPIFFEID(identity, "")
	if err != nil {
		t.Fatalf("unexpected error resolving default ID: %v", err)
	}
	if defaultResolved.String() != "spiffe://bonjoski.local/workload/my-agent" {
		t.Errorf("got %q, want spiffe://bonjoski.local/workload/my-agent", defaultResolved.String())
	}

	// Default fallback derivation for vsock microVM
	pol.AllowedCIDs = []uint32{3}
	vmIdentity := &spiffe.CallerIdentity{VsockCID: 3}
	vmResolved, err := pol.ResolveSPIFFEID(vmIdentity, "")
	if err != nil {
		t.Fatalf("unexpected error resolving vm ID: %v", err)
	}
	if vmResolved.String() != "spiffe://bonjoski.local/vm/cid/3" {
		t.Errorf("got %q, want spiffe://bonjoski.local/vm/cid/3", vmResolved.String())
	}
}
