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

	defaultID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/workload/agent-worker")
	arbitraryID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/worker")
	foreignDomainID, _ := ca.ParseSPIFFEID("spiffe://corp.external/ns/dev/sa/worker")

	// 1. Authorized identity + caller's own default SPIFFE ID (no rules required)
	if err := pol.Authorize(validIdentity, defaultID); err != nil {
		t.Errorf("expected caller default SPIFFE ID to be authorized, got: %v", err)
	}

	// 1b. Arbitrary non-default SPIFFE ID rejected when Rules is empty (LCK-05)
	if err := pol.Authorize(validIdentity, arbitraryID); err == nil {
		t.Errorf("expected arbitrary non-default SPIFFE ID to be rejected when Rules is empty")
	}

	// 2. Unauthorized UID rejected
	if err := pol.Authorize(invalidIdentity, defaultID); err == nil {
		t.Errorf("expected unauthorized UID to be rejected, got nil")
	}

	// 3. Foreign trust domain rejected
	if err := pol.Authorize(validIdentity, foreignDomainID); err == nil {
		t.Errorf("expected foreign trust domain to be rejected, got nil")
	}

	// 4. Nil identity rejected
	if err := pol.Authorize(nil, defaultID); err == nil {
		t.Errorf("expected nil identity to be rejected, got nil")
	}

	// 5. Vsock CID authorization (fails closed by default when AllowedCIDs is empty)
	vmIdentity := &spiffe.CallerIdentity{
		VsockCID: 3,
		Comm:     "aegisbox-vm",
	}
	vmDefaultCID3, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/vm/cid/3")
	if err := pol.Authorize(vmIdentity, vmDefaultCID3); err == nil {
		t.Errorf("expected vsock identity to be rejected when AllowedCIDs is empty")
	}

	// 6. AllowedCIDs permits explicit CID for its pinned default VM ID, rejects arbitrary ID
	pol.AllowedCIDs = []uint32{3}
	if err := pol.Authorize(vmIdentity, vmDefaultCID3); err != nil {
		t.Errorf("expected CID 3 to be authorized for pinned VM ID when AllowedCIDs=[3], got: %v", err)
	}
	if err := pol.Authorize(vmIdentity, arbitraryID); err == nil {
		t.Errorf("expected CID 3 arbitrary ID to be rejected without explicit rule")
	}

	// 7. Restrictive AllowedCIDs mismatch
	pol.AllowedCIDs = []uint32{4, 5}
	if err := pol.Authorize(vmIdentity, vmDefaultCID3); err == nil {
		t.Errorf("expected CID 3 to be rejected when AllowedCIDs=[4,5]")
	}
	vmIdentity.VsockCID = 4
	vmDefaultCID4, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/vm/cid/4")
	if err := pol.Authorize(vmIdentity, vmDefaultCID4); err != nil {
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

	// Arbitrary explicit request without rules must fail closed (LCK-05)
	if _, err := pol.ResolveSPIFFEID(identity, "spiffe://bonjoski.local/ns/dev/sa/custom"); err == nil {
		t.Fatalf("expected custom SPIFFE ID without policy rules to be rejected")
	}

	// Default fallback derivation from comm succeeds without rules
	defaultResolved, err := pol.ResolveSPIFFEID(identity, "")
	if err != nil {
		t.Fatalf("unexpected error resolving default ID: %v", err)
	}
	if defaultResolved.String() != "spiffe://bonjoski.local/workload/my-agent" {
		t.Errorf("got %q, want spiffe://bonjoski.local/workload/my-agent", defaultResolved.String())
	}

	// Default fallback derivation for vsock microVM succeeds without rules
	pol.AllowedCIDs = []uint32{3}
	vmIdentity := &spiffe.CallerIdentity{VsockCID: 3}
	vmResolved, err := pol.ResolveSPIFFEID(vmIdentity, "")
	if err != nil {
		t.Fatalf("unexpected error resolving vm ID: %v", err)
	}
	if vmResolved.String() != "spiffe://bonjoski.local/vm/cid/3" {
		t.Errorf("got %q, want spiffe://bonjoski.local/vm/cid/3", vmResolved.String())
	}

	// Explicit custom request succeeds once an explicit PolicyRule authorizes it
	pol.Rules = []spiffe.PolicyRule{
		{
			SPIFFEPattern: "spiffe://bonjoski.local/ns/dev/sa/*",
			AllowedUIDs:   []uint32{uint32(os.Getuid())},
		},
	}
	resolved, err := pol.ResolveSPIFFEID(identity, "spiffe://bonjoski.local/ns/dev/sa/custom")
	if err != nil {
		t.Fatalf("unexpected error with explicit rule: %v", err)
	}
	if resolved.String() != "spiffe://bonjoski.local/ns/dev/sa/custom" {
		t.Errorf("got %q, want custom ID", resolved.String())
	}
}

func TestPolicy_BareBinaryValidation(t *testing.T) {
	pol := spiffe.NewDefaultPolicy("bonjoski.local")
	pol.Rules = []spiffe.PolicyRule{
		{
			SPIFFEPattern:   "spiffe://bonjoski.local/sa/worker",
			AllowedBinaries: []string{"nginx"}, // bare binary without sha256:, path:, or comm:
		},
	}

	// 1. Bare binary identifier fails validation
	if _, err := pol.Validate(); err == nil {
		t.Fatalf("expected bare binary 'nginx' to fail validation, got nil")
	}

	// 2. Prefixed identifier passes validation
	pol.Rules[0].AllowedBinaries = []string{"comm:nginx"}
	warnings, err := pol.Validate()
	if err != nil {
		t.Fatalf("expected comm:nginx to pass validation, got err: %v", err)
	}
	if len(warnings) == 0 {
		t.Errorf("expected warning for non-cryptographic comm provenance")
	}

	// 3. Cryptographic sha256 digest passes without warning
	pol.Rules[0].AllowedBinaries = []string{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	warnings, err = pol.Validate()
	if err != nil {
		t.Fatalf("expected sha256 digest to pass validation, got err: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings for sha256 digest, got: %v", warnings)
	}
}
