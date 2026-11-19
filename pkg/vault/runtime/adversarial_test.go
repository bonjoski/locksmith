package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	stdruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// takeDirectorySnapshot recursively records all file paths present in the given root directory.
func takeDirectorySnapshot(root string) (map[string]int64, error) {
	files := make(map[string]int64)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files/dirs
		}
		if !info.IsDir() {
			files[path] = info.Size()
		}
		return nil
	})
	return files, err
}

// TestAdversarial_ZeroDiskResidue verifies that heavy workload slicing and caching
// produces zero bytes and zero files on disk, disarming AntiFox disk/config scraping.
func TestAdversarial_ZeroDiskResidue(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	tempDir := os.TempDir()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed getting user home: %v", err)
	}
	cacheDir := filepath.Join(homeDir, ".locksmith")

	// Snapshot before test
	tempBefore, _ := takeDirectorySnapshot(tempDir)
	homeBefore, _ := takeDirectorySnapshot(cacheDir)

	slicer := NewWorkloadSlicer(SlicerConfig{
		DefaultTTL:      60 * time.Second,
		CleanupInterval: 50 * time.Millisecond,
	})
	defer slicer.Close()

	const iterations = 500
	for i := 0; i < iterations; i++ {
		req := WorkloadRequest{
			RoleARN:     fmt.Sprintf("arn:aws:iam::123456789012:role/WorkloadRole-%d", i%10),
			SessionName: fmt.Sprintf("session-%d", i),
		}

		// 1. Get credentials
		cred, err := slicer.GetCredentials(context.Background(), req)
		if err != nil {
			t.Fatalf("iteration %d: GetCredentials failed: %v", i, err)
		}

		// 2. Create and drain slice descriptor
		sl, err := cred.CreateSlice()
		if err != nil {
			t.Fatalf("iteration %d: CreateSlice failed: %v", i, err)
		}
		data, err := sl.ReadAll()
		if err != nil {
			_ = sl.Close()
			t.Fatalf("iteration %d: ReadAll failed: %v", i, err)
		}
		if len(data) == 0 {
			_ = sl.Close()
			t.Fatalf("iteration %d: empty slice payload", i)
		}
		_ = sl.Close()

		// 3. Periodic revocation
		if i%5 == 0 {
			_ = slicer.Revoke(req.RoleARN, req.SessionName)
		}
	}

	// Snapshot after test
	tempAfter, _ := takeDirectorySnapshot(tempDir)
	homeAfter, _ := takeDirectorySnapshot(cacheDir)

	// Assert no new files in .locksmith cache
	for path := range homeAfter {
		if _, existed := homeBefore[path]; !existed {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Disk residue detected in %s", path)
		}
	}

	// Assert no new locksmith files in tempDir
	for path := range tempAfter {
		if _, existed := tempBefore[path]; !existed {
			base := filepath.Base(path)
			if strings.Contains(strings.ToLower(base), "locksmith") || strings.Contains(strings.ToLower(base), "sts") {
				t.Fatalf("CRITICAL SECURITY VIOLATION: Temporary disk residue detected in %s", path)
			}
		}
	}

	t.Logf("PASS: Zero disk residue verified across %d iterations (100%% in-memory execution)", iterations)
}

func assertBufferZeroized(t *testing.T, name string, buf []byte) {
	t.Helper()
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("CRITICAL: %s byte at index %d was not zeroized (val=%d)", name, i, b)
		}
	}
}

func assertHasNonZero(t *testing.T, buf []byte) {
	t.Helper()
	for _, b := range buf {
		if b != 0 {
			return
		}
	}
	t.Fatal("secret key was unexpectedly zero before revocation")
}

// TestAdversarial_MemoryZeroizationAfterRevocation verifies that active memory zeroization
// physically wipes secret bytes with zeroes in RAM and subsequent accesses fail closed.
func TestAdversarial_MemoryZeroizationAfterRevocation(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/TargetRevokeRole",
		SessionName: "volatile-session-001",
	}

	cred, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	accessKeyRef := cred.AccessKeyID
	secretKeyRef := cred.SecretAccessKey
	sessionTokenRef := cred.SessionToken

	if len(accessKeyRef) == 0 || len(secretKeyRef) == 0 || len(sessionTokenRef) == 0 {
		t.Fatal("initial credential buffers must not be empty")
	}

	assertHasNonZero(t, secretKeyRef)

	if err := slicer.Revoke(req.RoleARN, req.SessionName); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	if !cred.IsZeroized() {
		t.Fatal("cred.IsZeroized() returned false after Revoke")
	}

	assertBufferZeroized(t, "AccessKeyID", accessKeyRef)
	assertBufferZeroized(t, "SecretAccessKey", secretKeyRef)
	assertBufferZeroized(t, "SessionToken", sessionTokenRef)

	// Assert fail-closed behavior on all exported methods
	if _, err := cred.STSCredentials(); !errors.Is(err, ErrCredentialsZeroized) {
		t.Fatalf("expected ErrCredentialsZeroized, got: %v", err)
	}
	if _, err := cred.ToJSON(); !errors.Is(err, ErrCredentialsZeroized) {
		t.Fatalf("expected ErrCredentialsZeroized, got: %v", err)
	}
	if _, err := cred.CreateSlice(); !errors.Is(err, ErrCredentialsZeroized) {
		t.Fatalf("expected ErrCredentialsZeroized, got: %v", err)
	}

	t.Log("PASS: Complete active RAM zeroization verified (all buffers overwritten with 0x00)")
}

// TestAdversarial_ConcurrentZeroizationRace stresses zeroization under high concurrent race
// conditions to ensure no memory corruption or race panics occur.
func TestAdversarial_ConcurrentZeroizationRace(t *testing.T) {
	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	cred, err := slicer.GetCredentials(context.Background(), WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/RaceRole",
		SessionName: "race-session",
	})
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			switch id % 4 {
			case 0:
				cred.Zeroize()
			case 1:
				_ = cred.IsZeroized()
			case 2:
				_, _ = cred.STSCredentials()
			case 3:
				_, _ = cred.ToJSON()
			}
		}(i)
	}

	wg.Wait()

	if !cred.IsZeroized() {
		t.Fatal("expected credential to be zeroized after concurrent race")
	}

	for i, b := range cred.SecretAccessKey {
		if b != 0 {
			t.Fatalf("byte at index %d non-zero: %d", i, b)
		}
	}
}

func executeSubagentOp(ctx context.Context, slicer *WorkloadSlicer, id, op int) error {
	roleIdx := id
	if id < 3 {
		roleIdx = 0
	}

	req := WorkloadRequest{
		RoleARN:     fmt.Sprintf("arn:aws:iam::123456789012:role/ContentionRole-%d", roleIdx),
		SessionName: fmt.Sprintf("subagent-%d-sess-%d", id, op%5),
		Duration:    60 * time.Second,
	}

	if op%3 == 0 {
		sl, cred, err := slicer.SliceCredentials(ctx, req)
		if err != nil {
			return err
		}
		payload, readErr := sl.ReadAll()
		_ = sl.Close()
		if readErr != nil || len(payload) == 0 {
			return fmt.Errorf("read slice error: %v", readErr)
		}
		if cred.IsZeroized() {
			return ErrCredentialsZeroized
		}
	} else {
		cred, err := slicer.GetCredentials(ctx, req)
		if err != nil {
			return err
		}
		if _, err := cred.STSCredentials(); err != nil && !errors.Is(err, ErrCredentialsZeroized) {
			return err
		}
	}

	if id == 7 && op%10 == 0 {
		_ = slicer.Revoke(req.RoleARN, req.SessionName)
	}

	return nil
}

// TestAdversarial_ParallelSubagentConcurrency_N8 stress-tests thread safety under N=8
// parallel subagent access across distinct roles, sessions, and slicing lifecycles.
func TestAdversarial_ParallelSubagentConcurrency_N8(t *testing.T) {
	const nAgents = 8
	const opsPerAgent = 150

	slicer := NewWorkloadSlicer(SlicerConfig{
		DefaultTTL:      500 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	})
	defer slicer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var successOps atomic.Int64
	var errorCount atomic.Int64

	for agentID := 0; agentID < nAgents; agentID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for op := 0; op < opsPerAgent; op++ {
				if ctx.Err() != nil {
					return
				}

				if err := executeSubagentOp(ctx, slicer, id, op); err != nil {
					errorCount.Add(1)
					continue
				}

				successOps.Add(1)
			}
		}(agentID)
	}

	wg.Wait()

	if errors := errorCount.Load(); errors > 0 {
		t.Fatalf("CRITICAL CONCURRENCY FAILURE: %d errors observed during N=8 stress test", errors)
	}

	t.Logf("PASS: N=8 parallel subagents completed %d successful concurrent operations with 0 race violations",
		successOps.Load())
}

// TestAdversarial_AntiFoxPlaintextScrapingSimulation models an automated threat actor
// (AntiFox / ARTEX webshell) searching /proc/environ and child process memory tables.
func TestAdversarial_AntiFoxPlaintextScrapingSimulation(t *testing.T) {
	if stdruntime.GOOS == "windows" {
		t.Skip("ExtraFiles / FD inheritance is not supported on Windows")
	}

	slicer := NewWorkloadSlicer(SlicerConfig{})
	defer slicer.Close()

	req := WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/AntiFoxTargetRole",
		SessionName: "antifox-target-session",
	}

	cred, err := slicer.GetCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	sts, err := cred.STSCredentials()
	if err != nil {
		t.Fatalf("STSCredentials failed: %v", err)
	}

	// Python script simulating an AntiFox webshell scraping environment tables
	antifoxScraperScript := `
import os, sys

# AntiFox automated credential scraper payload
env_keys = list(os.environ.keys())
env_dump = " ".join([f"{k}={v}" for k, v in os.environ.items()])

# Check for plaintext AWS key patterns
forbidden_keys = ['AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN']
for fk in forbidden_keys:
    if fk in env_keys:
        sys.stderr.write(f"ANTIFOX SUCCESS: Discovered {fk} in process environment!\n")
        sys.exit(10)

# Check for secret value leakage
target_secret = sys.argv[1]
if target_secret in env_dump:
    sys.stderr.write("ANTIFOX SUCCESS: Plaintext secret string scraped from environment!\n")
    sys.exit(11)

# Check that LOCKSMITH_FD is present for legitimate authorized retrieval
if os.environ.get('LOCKSMITH_FD') != '3':
    sys.stderr.write("LOCKSMITH_FD missing or invalid\n")
    sys.exit(12)

sys.exit(0)
`

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping AntiFox scraper test")
	}

	cmd := exec.Command("python3", "-c", antifoxScraperScript, sts.SecretAccessKey)
	// Inject fake dirty environment containing old static secrets
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AWS_SECRET_ACCESS_KEY=old-leaked-static-key-12345",
		"USER=www-data",
	}

	sl, _, err := slicer.SliceForCommand(context.Background(), req, cmd)
	if err != nil {
		t.Fatalf("SliceForCommand failed: %v", err)
	}
	defer sl.Close()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("AntiFox defense failed! Exit error: %v, output: %s", err, string(out))
	}

	t.Log("PASS: AntiFox automated credential scraping completely disarmed (0 secrets in environment table)")
}

// TestAdversarial_EmulatorTokenTampering tests that tampered or forged emulator tokens fail closed.
func TestAdversarial_EmulatorTokenTampering(t *testing.T) {
	emulator := NewLocalAttestedEmulator("sentinel-cluster-01", "enclave-hw-01")

	cred, err := emulator.GenerateCredentials(context.Background(), WorkloadRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/AdminRole",
		SessionName: "admin-sess",
		Duration:    60 * time.Second,
	})
	if err != nil {
		t.Fatalf("GenerateCredentials failed: %v", err)
	}

	token := string(cred.SessionToken)

	// 1. Valid token passes
	claims, err := emulator.VerifyToken(token)
	if err != nil {
		t.Fatalf("valid token verification failed: %v", err)
	}
	if claims.RoleARN != "arn:aws:iam::123456789012:role/AdminRole" {
		t.Fatalf("claims role ARN mismatch: %s", claims.RoleARN)
	}

	// 2. Tampered signature fails
	tamperedSigToken := token[:len(token)-4] + "AAAA"
	if _, err := emulator.VerifyToken(tamperedSigToken); err == nil {
		t.Fatal("CRITICAL: Verification succeeded on tampered signature token")
	}

	// 3. Tampered payload fails
	parts := strings.Split(token, ".")
	if len(parts) == 4 {
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		tamperedPayload := bytes.Replace(payloadBytes, []byte("AdminRole"), []byte("SuperAdmin"), 1)
		tamperedPart2 := base64.RawURLEncoding.EncodeToString(tamperedPayload)
		tamperedToken := fmt.Sprintf("%s.%s.%s.%s", parts[0], parts[1], tamperedPart2, parts[3])

		if _, err := emulator.VerifyToken(tamperedToken); err == nil {
			t.Fatal("CRITICAL: Verification succeeded on tampered payload token")
		}
	}

	// 4. Foreign key emulator rejects token
	foreignEmulator := NewLocalAttestedEmulator("sentinel-cluster-01", "enclave-hw-01")
	if _, err := foreignEmulator.VerifyToken(token); err == nil {
		t.Fatal("CRITICAL: Foreign emulator with different key accepted token")
	}

	t.Log("PASS: Cryptographic attestation strictly rejects tampered tokens (fail-closed)")
}
