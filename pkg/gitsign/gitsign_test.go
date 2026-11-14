package gitsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyCommitPayload(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	payload := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Bonjo <bonjo@local> 1731545000 -0700\ncommitter Bonjo <bonjo@local> 1731545000 -0700\n\nfeat: hardware commit")

	armored, att, err := SignCommitPayload(payload, priv, "bonjo@local")
	if err != nil {
		t.Fatalf("SignCommitPayload failed: %v", err)
	}

	if len(armored) == 0 {
		t.Fatal("empty armored signature")
	}
	if att.KeyID == "" {
		t.Fatal("empty key id")
	}

	// Verify valid signature
	verifiedAtt, err := VerifyCommitPayload(payload, armored, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyCommitPayload failed: %v", err)
	}
	if verifiedAtt.KeyID != att.KeyID {
		t.Errorf("key id mismatch: %s vs %s", verifiedAtt.KeyID, att.KeyID)
	}

	// Tamper test: modifying the payload must cause verification failure
	tamperedPayload := append(payload, []byte("\nmalicious commit injection")...)
	_, err = VerifyCommitPayload(tamperedPayload, armored, &priv.PublicKey)
	if err == nil {
		t.Error("expected verification failure for tampered payload, got nil")
	}

	// Tamper test: wrong public key
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = VerifyCommitPayload(payload, armored, &otherKey.PublicKey)
	if err == nil {
		t.Error("expected verification failure for wrong public key, got nil")
	}
}

func TestHandleGitInvocation(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	commitData := []byte("commit test payload for git invocation")
	stdin := bytes.NewReader(commitData)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// 1. Test Signing mode (-bsau <keyid>)
	args := []string{"-bsau", "LS-1234", "--status-fd=2"}
	exitCode, err := HandleGitInvocation(args, stdin, &stdout, &stderr, priv, &priv.PublicKey)
	if err != nil || exitCode != 0 {
		t.Fatalf("HandleGitInvocation signing failed (exit %d): %v", exitCode, err)
	}

	sigOutput := stdout.String()
	if !bytes.Contains(stdout.Bytes(), []byte(SignatureHeader)) {
		t.Errorf("stdout does not contain signature header: %s", sigOutput)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("[GNUPG:] SIG_CREATED")) {
		t.Errorf("stderr does not contain status line: %s", stderr.String())
	}

	// 2. Test Verification mode (--status-fd=2 --verify <sigfile> <commitfile>)
	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "commit.sig")
	commitPath := filepath.Join(tmpDir, "commit.txt")

	_ = os.WriteFile(sigPath, []byte(sigOutput), 0600)
	_ = os.WriteFile(commitPath, commitData, 0600)

	var verifyStderr bytes.Buffer
	var verifyStdout bytes.Buffer
	verifyArgs := []string{"--status-fd=2", "--verify", sigPath, commitPath}
	exitCode, err = HandleGitInvocation(verifyArgs, nil, &verifyStdout, &verifyStderr, priv, &priv.PublicKey)
	if err != nil || exitCode != 0 {
		t.Fatalf("HandleGitInvocation verify failed (exit %d): %v", exitCode, err)
	}

	if !bytes.Contains(verifyStderr.Bytes(), []byte("[GNUPG:] GOODSIG")) {
		t.Errorf("verify stderr missing GOODSIG: %s", verifyStderr.String())
	}
}

func TestAppendTransparencyLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "transparency.jsonl")

	att := &CommitAttestation{
		PayloadSHA256: "abcd1234ef",
		AuthorEmail:   "test@local",
		Timestamp:     1731545000,
		KeyID:         "LS-TEST",
		Signature:     "dGVzdHNpZw==",
		Version:       "locksmith-v2",
	}

	if err := AppendTransparencyLog(att, logPath); err != nil {
		t.Fatalf("AppendTransparencyLog failed: %v", err)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log failed: %v", err)
	}
	if !bytes.Contains(content, []byte("LS-TEST")) {
		t.Errorf("log missing attestation content: %s", string(content))
	}
}
