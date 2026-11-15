package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	stdruntime "runtime"
	"strings"
	"testing"
	"time"
)

type mockPrimaryGenerator struct {
	fail bool
	cred *SlicedCredential
}

func (m *mockPrimaryGenerator) GenerateCredentials(ctx context.Context, req WorkloadRequest) (*SlicedCredential, error) {
	if m.fail {
		return nil, errors.New("upstream STS service unreachable")
	}
	if m.cred != nil {
		return m.cred, nil
	}
	return &SlicedCredential{
		AccessKeyID:     []byte("ASIAUPSTREAMKEY12345"),
		SecretAccessKey: []byte("upstreamSecretAccessKey0123456789abcdef"),
		SessionToken:    []byte("upstreamSessionTokenPayload"),
		Expiration:      time.Now().Add(req.Duration),
		RoleARN:         req.RoleARN,
		SessionName:     req.SessionName,
		Attested:        false,
	}, nil
}

func TestSlicer_DefaultTTL(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{
		DefaultTTL:      0, // should default to 60s
		CleanupInterval: 50 * time.Millisecond,
	})
	defer slicer.Close()

	if slicer.config.DefaultTTL != DefaultTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultTTL, slicer.config.DefaultTTL)
	}

	cred, err := slicer.GetCredentials(context.Background(), WorkloadRequest{
		RoleARN: "arn:aws:iam::123456789012:role/WorkloadAgentRole",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remaining := time.Until(cred.Expiration)
	if remaining < 55*time.Second || remaining > 61*time.Second {
		t.Fatalf("expected expiration close to 60s, got %v", remaining)
	}

	sts, err := cred.STSCredentials()
	if err != nil {
		t.Fatalf("failed to get STS credentials: %v", err)
	}
	if !strings.HasPrefix(sts.AccessKeyID, "ASIA") {
		t.Fatalf("expected STS key starting with ASIA, got %s", sts.AccessKeyID)
	}
	if len(sts.SecretAccessKey) != 40 {
		t.Fatalf("expected 40-char secret access key, got len %d", len(sts.SecretAccessKey))
	}
	if !cred.Attested {
		t.Fatal("expected fallback emulator credentials to be marked attested")
	}
}

func TestSlicer_InMemoryCaching(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{
		DefaultTTL: 60 * time.Second,
	})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/WorkloadAgentRole",
		SessionName: "agent-session-alpha",
	}

	cred1, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("first GetCredentials failed: %v", err)
	}

	cred2, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("second GetCredentials failed: %v", err)
	}

	if string(cred1.AccessKeyID) != string(cred2.AccessKeyID) {
		t.Fatalf("expected cached credentials, but got distinct access keys: %s vs %s",
			string(cred1.AccessKeyID), string(cred2.AccessKeyID))
	}
	if slicer.ActiveSessionCount() != 1 {
		t.Fatalf("expected 1 active session in RAM cache, got %d", slicer.ActiveSessionCount())
	}
}

func TestSlicer_ExpirationAndAutoZeroize(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{
		DefaultTTL:      100 * time.Millisecond,
		CleanupInterval: 20 * time.Millisecond,
	})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/ShortLivedRole",
		SessionName: "short-lived-session",
		Duration:    100 * time.Millisecond,
	}

	cred, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	if cred.IsExpired() {
		t.Fatal("expected credentials to be fresh immediately after generation")
	}

	// Wait for expiration and background sweeper
	time.Sleep(250 * time.Millisecond)

	if !cred.IsExpired() {
		t.Fatal("expected credentials to be expired after wait duration")
	}
	if !cred.IsZeroized() {
		t.Fatal("expected credentials to be zeroized by background sweep")
	}

	_, err = cred.STSCredentials()
	if !errors.Is(err, ErrCredentialsZeroized) && !errors.Is(err, ErrCredentialsExpired) {
		t.Fatalf("expected ErrCredentialsZeroized or ErrCredentialsExpired, got %v", err)
	}

	// Next request should generate fresh credentials
	freshCred, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("GetCredentials for refreshed session failed: %v", err)
	}
	if freshCred.IsZeroized() {
		t.Fatal("refreshed credential should not be zeroized")
	}
	if string(freshCred.AccessKeyID) == string(cred.AccessKeyID) {
		t.Fatal("expected new distinct access key after expiration")
	}
}

func TestSlicer_GeneratorFallbackToEmulator(t *testing.T) {
	primary := &mockPrimaryGenerator{fail: true}
	emulator := NewLocalAttestedEmulator("test-cluster", "test-node")

	slicer := NewWorkloadSlicer(SlicerConfig{
		PrimaryGenerator: primary,
		AttestedEmulator: emulator,
	})
	defer slicer.Close()

	cred, err := slicer.GetCredentials(context.Background(), WorkloadRequest{
		RoleARN: "arn:aws:iam::123456789012:role/FallbackRole",
	})
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}

	if !cred.Attested {
		t.Fatal("expected credential to be issued by attested emulator")
	}

	sts, err := cred.STSCredentials()
	if err != nil {
		t.Fatalf("failed to get STS credentials: %v", err)
	}

	claims, err := emulator.VerifyToken(sts.SessionToken)
	if err != nil {
		t.Fatalf("failed to verify attested emulator session token: %v", err)
	}
	if claims.RoleARN != "arn:aws:iam::123456789012:role/FallbackRole" {
		t.Fatalf("unexpected role ARN in token claims: %s", claims.RoleARN)
	}
	if claims.ClusterID != "test-cluster" {
		t.Fatalf("unexpected cluster ID: %s", claims.ClusterID)
	}
}

func TestSlicer_PrimaryGeneratorSuccess(t *testing.T) {
	primary := &mockPrimaryGenerator{fail: false}
	slicer := NewWorkloadSlicer(SlicerConfig{
		PrimaryGenerator: primary,
	})
	defer slicer.Close()

	cred, err := slicer.GetCredentials(context.Background(), WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/UpstreamRole",
		SessionName: "upstream-sess",
		Duration:    60 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cred.Attested {
		t.Fatal("expected primary generator credentials (not attested emulator)")
	}
	if string(cred.AccessKeyID) != "ASIAUPSTREAMKEY12345" {
		t.Fatalf("unexpected access key: %s", string(cred.AccessKeyID))
	}
}

func TestSlicer_AnonymousDescriptorSlice(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/SliceTestRole",
		SessionName: "slice-session-1",
	}

	sl, cred, err := slicer.SliceCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("SliceCredentials failed: %v", err)
	}
	defer sl.Close()

	if sl.FD() == 0 {
		t.Fatal("expected non-zero anonymous descriptor FD")
	}

	payload, err := sl.ReadAll()
	if err != nil {
		t.Fatalf("failed to read slice descriptor: %v", err)
	}

	var sts STSCredentials
	if err := json.Unmarshal(payload, &sts); err != nil {
		t.Fatalf("failed to unmarshal JSON from slice: %v", err)
	}

	if sts.AccessKeyID != string(cred.AccessKeyID) {
		t.Fatalf("slice content mismatch: expected %s, got %s", string(cred.AccessKeyID), sts.AccessKeyID)
	}
	if sts.SecretAccessKey != string(cred.SecretAccessKey) {
		t.Fatalf("slice secret key mismatch")
	}
	if sts.SessionToken != string(cred.SessionToken) {
		t.Fatalf("slice session token mismatch")
	}
}

func TestSlicer_ExplicitRevocation(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/RevokeRole",
		SessionName: "session-to-revoke",
	}

	cred, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	if cred.IsZeroized() {
		t.Fatal("credential should not be zeroized initially")
	}

	err = slicer.Revoke(req.RoleARN, req.SessionName)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	if !cred.IsZeroized() {
		t.Fatal("expected credential to be actively zeroized upon revocation")
	}

	_, err = cred.STSCredentials()
	if !errors.Is(err, ErrCredentialsZeroized) {
		t.Fatalf("expected ErrCredentialsZeroized, got %v", err)
	}

	if slicer.ActiveSessionCount() != 0 {
		t.Fatalf("expected 0 active sessions after revocation, got %d", slicer.ActiveSessionCount())
	}
}

func TestSlicer_RevokeAll(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	creds := make([]*SlicedCredential, 5)
	for i := 0; i < 5; i++ {
		c, err := slicer.GetCredentials(context.Background(), WorkloadRequest{
			RoleARN:     fmt.Sprintf("arn:aws:iam::123456789012:role/Role-%d", i),
			SessionName: fmt.Sprintf("session-%d", i),
		})
		if err != nil {
			t.Fatalf("GetCredentials failed: %v", err)
		}
		creds[i] = c
	}

	if slicer.ActiveSessionCount() != 5 {
		t.Fatalf("expected 5 active sessions, got %d", slicer.ActiveSessionCount())
	}

	slicer.RevokeAll()

	if slicer.ActiveSessionCount() != 0 {
		t.Fatalf("expected 0 active sessions after RevokeAll, got %d", slicer.ActiveSessionCount())
	}

	for i, c := range creds {
		if !c.IsZeroized() {
			t.Fatalf("expected credential %d to be zeroized", i)
		}
	}
}

func TestSlicer_SanitizeEnvironment(t *testing.T) {
	dirtyEnv := []string{
		"PATH=/usr/bin:/bin",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=test-dummy-secret-key-12345",
		"AWS_SESSION_TOKEN=AQoDYXdzEJr1...",
		"AWS_SECURITY_TOKEN=legacy_token",
		"AWS_REGION=us-west-2",
		"USER=agent",
		"LOCKSMITH_SECRET_DB_PASS=xyz123",
	}

	cleanEnv := SanitizeEnvironment(dirtyEnv)

	for _, entry := range cleanEnv {
		if strings.HasPrefix(entry, "AWS_ACCESS_KEY_ID") ||
			strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY") ||
			strings.HasPrefix(entry, "AWS_SESSION_TOKEN") ||
			strings.HasPrefix(entry, "AWS_SECURITY_TOKEN") ||
			strings.HasPrefix(entry, "LOCKSMITH_SECRET_") {
			t.Fatalf("leaked secret environment variable detected: %s", entry)
		}
	}

	foundPath := false
	foundRegion := false
	for _, entry := range cleanEnv {
		if strings.HasPrefix(entry, "PATH=") {
			foundPath = true
		}
		if strings.HasPrefix(entry, "AWS_REGION=") {
			foundRegion = true
		}
	}
	if !foundPath || !foundRegion {
		t.Fatal("legitimate environment variables were inadvertently stripped")
	}
}

func TestSlicer_SliceForCommandChildProcess(t *testing.T) {
	if stdruntime.GOOS == "windows" {
		t.Skip("ExtraFiles FD inheritance is not supported on Windows")
	}

	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/ChildProcessRole",
		SessionName: "child-subagent-session",
	}

	// Python script that reads credentials from FD 3 and verifies NO secrets in os.environ
	pythonScript := `
import os, sys, json

# 1. Verify LOCKSMITH_FD is 3
fd = int(os.environ.get('LOCKSMITH_FD', '-1'))
if fd != 3:
    sys.stderr.write(f"Invalid LOCKSMITH_FD: {fd}\n")
    sys.exit(2)

# 2. Verify /proc/environ or os.environ contains ZERO AWS secrets
env_str = str(os.environ)
if 'AWS_SECRET_ACCESS_KEY' in env_str or 'AWS_SESSION_TOKEN' in env_str:
    sys.stderr.write("LEAK DETECTED: AWS secret in os.environ!\n")
    sys.exit(3)

# 3. Read and validate credentials from inherited FD 3
with os.fdopen(fd, 'r') as f:
    data = json.load(f)

if not data.get('AccessKeyId', '').startswith('ASIA'):
    sys.stderr.write("Invalid AccessKeyId in slice\n")
    sys.exit(4)

if not data.get('SecretAccessKey') or not data.get('SessionToken'):
    sys.stderr.write("Missing secret fields in slice payload\n")
    sys.exit(5)

sys.exit(0)
`

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping child execution test")
	}

	cmd := exec.Command("python3", "-c", pythonScript)
	sl, cred, err := slicer.SliceForCommand(context.Background(), req, cmd)
	if err != nil {
		t.Fatalf("SliceForCommand failed: %v", err)
	}
	defer sl.Close()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Child process execution failed: %v, output: %s", err, string(out))
	}

	// Verify credential in slicer is still intact until revoked or expired
	if cred.IsZeroized() {
		t.Fatal("credential should remain active until explicit revocation or expiration")
	}
}
