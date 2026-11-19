// Package gitsign implements hardware-enclosed Git commit provenance,
// acting as a drop-in Git gpg.program helper with local transparency logging.
package gitsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SignatureHeader = "-----BEGIN LOCKSMITH SIGNED COMMIT-----"
	SignatureFooter = "-----END LOCKSMITH SIGNED COMMIT-----"
)

// CommitAttestation captures hardware-anchored provenance for a git commit.
type CommitAttestation struct {
	PayloadSHA256 string `json:"payload_sha256"`
	AuthorEmail   string `json:"author_email,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
	Version       string `json:"version"`
}

// ComputeGitKeyID computes an abbreviated thumbprint from a public key.
func ComputeGitKeyID(pub *ecdsa.PublicKey) string {
	h := sha256.New()
	h.Write(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y))
	return fmt.Sprintf("LS-%X", h.Sum(nil)[:8])
}

// SignCommitPayload signs the commit buffer and generates an armored signature and attestation.
func SignCommitPayload(payload []byte, priv *ecdsa.PrivateKey, authorEmail string) (string, *CommitAttestation, error) {
	if priv == nil {
		return "", nil, errors.New("gitsign: private key is nil")
	}

	digest := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", nil, fmt.Errorf("gitsign: ECDSA sign failed: %w", err)
	}

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	keyID := ComputeGitKeyID(&priv.PublicKey)

	attestation := &CommitAttestation{
		PayloadSHA256: fmt.Sprintf("%x", digest[:]),
		AuthorEmail:   authorEmail,
		Timestamp:     time.Now().UTC().Unix(),
		KeyID:         keyID,
		Signature:     base64.StdEncoding.EncodeToString(sigBytes),
		Version:       "locksmith-v2",
	}

	attBytes, err := json.Marshal(attestation)
	if err != nil {
		return "", nil, fmt.Errorf("gitsign: marshal attestation failed: %w", err)
	}

	armored := fmt.Sprintf("%s\nVersion: Locksmith v2.0 (Secure Enclave)\n\n%s\n%s\n",
		SignatureHeader,
		base64.StdEncoding.EncodeToString(attBytes),
		SignatureFooter,
	)

	return armored, attestation, nil
}

// VerifyCommitPayload extracts and cryptographically validates the commit attestation against the payload.
func VerifyCommitPayload(payload []byte, armoredSig string, pub *ecdsa.PublicKey) (*CommitAttestation, error) {
	if pub == nil {
		return nil, errors.New("gitsign: public key is nil")
	}

	// Extract base64 payload between delimiters
	start := strings.Index(armoredSig, SignatureHeader)
	end := strings.Index(armoredSig, SignatureFooter)
	if start == -1 || end == -1 || start >= end {
		return nil, errors.New("gitsign: invalid armored signature delimiters")
	}

	body := strings.TrimSpace(armoredSig[start+len(SignatureHeader) : end])
	// Skip headers if present
	lines := strings.Split(body, "\n")
	var base64Content string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Version:") || l == "" {
			continue
		}
		base64Content = l
		break
	}

	attBytes, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return nil, fmt.Errorf("gitsign: decode attestation base64 failed: %w", err)
	}

	var att CommitAttestation
	if err := json.Unmarshal(attBytes, &att); err != nil {
		return nil, fmt.Errorf("gitsign: unmarshal attestation failed: %w", err)
	}

	// Check payload hash
	expectedDigest := sha256.Sum256(payload)
	expectedHashHex := fmt.Sprintf("%x", expectedDigest[:])
	if att.PayloadSHA256 != expectedHashHex {
		return nil, fmt.Errorf("gitsign: payload hash mismatch (expected %s, got %s)", expectedHashHex, att.PayloadSHA256)
	}

	// Check cryptographic signature
	sigBytes, err := base64.StdEncoding.DecodeString(att.Signature)
	if err != nil || len(sigBytes) != 64 {
		return nil, errors.New("gitsign: invalid signature bytes in attestation")
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pub, expectedDigest[:], r, s) {
		return nil, errors.New("gitsign: signature verification failed")
	}

	return &att, nil
}

// AppendTransparencyLog records the commit attestation to the local transparency ledger.
func AppendTransparencyLog(att *CommitAttestation, logPath string) error {
	if logPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		logDir := filepath.Join(home, ".locksmith")
		if err := os.MkdirAll(logDir, 0700); err != nil {
			return err
		}
		logPath = filepath.Join(logDir, "commit-transparency.jsonl")
	}

	f, err := os.OpenFile(filepath.Clean(logPath), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("gitsign: open log failed: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("gitsign: marshal log record failed: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("gitsign: write log record failed: %w", err)
	}

	return nil
}

func parseGitArgs(args []string) (isVerify bool, statusFD int, sigFile, dataFile string) {
	statusFD = -1
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--verify" {
			isVerify = true
			if i+1 < len(args) {
				sigFile = args[i+1]
			}
			if i+2 < len(args) {
				dataFile = args[i+2]
			}
		} else if strings.HasPrefix(arg, "--status-fd=") {
			var parsedFD int
			if _, err := fmt.Sscanf(arg, "--status-fd=%d", &parsedFD); err == nil {
				statusFD = parsedFD
			}
		}
	}
	return isVerify, statusFD, sigFile, dataFile
}

func handleGitVerify(sigFile, dataFile string, stderr io.Writer, pub *ecdsa.PublicKey) (int, error) {
	if sigFile == "" || dataFile == "" {
		return 1, errors.New("gitsign: missing signature or data file for --verify")
	}
	sigBytes, err := os.ReadFile(filepath.Clean(sigFile))
	if err != nil {
		return 1, fmt.Errorf("gitsign: read sig file failed: %w", err)
	}
	dataBytes, err := os.ReadFile(filepath.Clean(dataFile))
	if err != nil {
		return 1, fmt.Errorf("gitsign: read data file failed: %w", err)
	}

	att, err := VerifyCommitPayload(dataBytes, string(sigBytes), pub)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[GNUPG:] BADSIG %s\n", err)
		return 1, err
	}

	_, _ = fmt.Fprintf(stderr, "[GNUPG:] GOODSIG %s Locksmith Enclave Attestation\n", att.KeyID)
	_, _ = fmt.Fprintf(stderr, "[GNUPG:] VALIDSIG %s %d\n", att.KeyID, att.Timestamp)
	return 0, nil
}

func handleGitSign(stdin io.Reader, stdout, stderr io.Writer, statusFD int, priv *ecdsa.PrivateKey) (int, error) {
	commitData, err := io.ReadAll(stdin)
	if err != nil {
		return 1, fmt.Errorf("gitsign: read stdin failed: %w", err)
	}

	armored, att, err := SignCommitPayload(commitData, priv, "locksmith-enclave@local")
	if err != nil {
		return 1, fmt.Errorf("gitsign: sign commit failed: %w", err)
	}

	if statusFD >= 0 {
		statusMsg := fmt.Sprintf("[GNUPG:] SIG_CREATED D 10 %s %d\n", att.KeyID, att.Timestamp)
		_, _ = fmt.Fprint(stderr, statusMsg)
	}

	if err := AppendTransparencyLog(att, ""); err != nil {
		return 1, fmt.Errorf("gitsign: record commit transparency failed: %w", err)
	}

	if _, err = fmt.Fprint(stdout, armored); err != nil {
		return 1, fmt.Errorf("gitsign: write signature to stdout failed: %w", err)
	}

	return 0, nil
}

// HandleGitInvocation processes git CLI arguments when locksmith is configured as gpg.program.
func HandleGitInvocation(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (int, error) {
	isVerify, statusFD, sigFile, dataFile := parseGitArgs(args)
	if isVerify {
		return handleGitVerify(sigFile, dataFile, stderr, pub)
	}
	return handleGitSign(stdin, stdout, stderr, statusFD, priv)
}
