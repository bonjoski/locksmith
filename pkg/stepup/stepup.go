package stepup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/native"
)

// Severity represents the criticality level of the step-up authorization challenge.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// NormalizeSeverity sanitizes and normalizes the severity string.
func NormalizeSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case string(SeverityCritical):
		return SeverityCritical
	case string(SeverityHigh):
		return SeverityHigh
	case string(SeverityMedium):
		return SeverityMedium
	case string(SeverityLow):
		return SeverityLow
	default:
		return SeverityCritical
	}
}

// StepUpRequest defines the input to a biometric step-up challenge.
type StepUpRequest struct {
	Challenge  string        `json:"challenge"`
	Severity   Severity      `json:"severity"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Audience   string        `json:"audience,omitempty"`
	WorkloadID string        `json:"workload_id,omitempty"`
}

// AttestationClaims contains the cryptographic attestation payload.
type AttestationClaims struct {
	TokenID    string   `json:"jti"`
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   string   `json:"aud,omitempty"`
	Challenge  string   `json:"challenge"`
	Severity   Severity `json:"severity"`
	AuthMethod string   `json:"auth_method"`
	Platform   string   `json:"platform"`
	IssuedAt   int64    `json:"iat"`
	ExpiresAt  int64    `json:"exp"`
}

// AttestationToken represents the complete signed verification attestation token.
type AttestationToken struct {
	Claims    AttestationClaims `json:"claims"`
	Signature string            `json:"signature"`
	RawToken  string            `json:"raw_token"`
	PublicKey string            `json:"public_key"`
}

// BiometricAuthenticator abstracts the native platform biometric check.
type BiometricAuthenticator func(prompt string) error

var (
	keyMu         sync.Mutex
	cachedPrivKey ed25519.PrivateKey
)

type options struct {
	authenticator BiometricAuthenticator
	privateKey    ed25519.PrivateKey
}

// Option configures step-up authorization behavior.
type Option func(*options)

// WithAuthenticator overrides the biometric authentication implementation (e.g. for testing).
func WithAuthenticator(auth BiometricAuthenticator) Option {
	return func(o *options) {
		o.authenticator = auth
	}
}

// WithPrivateKey provides an explicit Ed25519 private key for signing attestation tokens.
func WithPrivateKey(priv ed25519.PrivateKey) Option {
	return func(o *options) {
		o.privateKey = priv
	}
}

// DefaultKeyPath returns the persistent path to the attestation keypair.
func DefaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "attestation_ed25519.key")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-attestation-%d.key", os.Getuid()))
}

// GetOrGenerateAttestationKey retrieves or generates the local Ed25519 signing key.
func GetOrGenerateAttestationKey() (ed25519.PrivateKey, error) {
	keyMu.Lock()
	defer keyMu.Unlock()

	if cachedPrivKey != nil {
		return cachedPrivKey, nil
	}

	keyPath := DefaultKeyPath()
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == ed25519.PrivateKeySize {
		cachedPrivKey = ed25519.PrivateKey(data)
		return cachedPrivKey, nil
	}

	// Generate new key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("step-up: failed to generate attestation key: %w", err)
	}

	_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
	if err := os.WriteFile(keyPath, priv, 0600); err != nil {
		// Log non-fatal error; key will still work in-memory
	}

	cachedPrivKey = priv
	return cachedPrivKey, nil
}

// GetAttestationPublicKey returns the corresponding Ed25519 public key.
func GetAttestationPublicKey() (ed25519.PublicKey, error) {
	priv, err := GetOrGenerateAttestationKey()
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

// PlatformAuthMethod returns the standard platform biometric identifier.
func PlatformAuthMethod() string {
	switch runtime.GOOS {
	case "darwin":
		return "TouchID_LocalAuthentication"
	case "windows":
		return "WindowsHello_UserConsentVerifier"
	default:
		return "Biometric_PAM_Polkit"
	}
}

// Authorize triggers the native platform biometric challenge and returns a signed attestation token.
func Authorize(ctx context.Context, req StepUpRequest, opts ...Option) (*AttestationToken, error) {
	if strings.TrimSpace(req.Challenge) == "" {
		return nil, errors.New("step-up: challenge description cannot be empty")
	}

	cfg := &options{
		authenticator: native.AuthenticateBiometric,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	severity := NormalizeSeverity(string(req.Severity))

	// Format platform prompt
	prompt := fmt.Sprintf("[Locksmith %s] %s", severity, req.Challenge)

	// Trigger native biometric challenge (Touch ID on macOS, Windows Hello on Windows)
	if err := cfg.authenticator(prompt); err != nil {
		return nil, fmt.Errorf("step-up authorization rejected: %w", err)
	}

	// Retrieve or generate signing key
	privKey := cfg.privateKey
	if privKey == nil {
		var err error
		privKey, err = GetOrGenerateAttestationKey()
		if err != nil {
			return nil, fmt.Errorf("step-up: failed to obtain signing key: %w", err)
		}
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	// TTL calculation (defaults to 5 minutes)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > 1*time.Hour {
		ttl = 1 * time.Hour
	}

	now := time.Now()
	exp := now.Add(ttl)

	// Generate unique TokenID
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return nil, fmt.Errorf("step-up: failed to generate token ID: %w", err)
	}
	tokenID := "attest-" + hex.EncodeToString(tokenIDBytes)

	// Resolve subject
	subject := os.Getenv("USER")
	if subject == "" {
		subject = "workload"
	}

	claims := AttestationClaims{
		TokenID:    tokenID,
		Issuer:     "sh.locksmith.v2",
		Subject:    subject,
		Audience:   req.Audience,
		Challenge:  req.Challenge,
		Severity:   severity,
		AuthMethod: PlatformAuthMethod(),
		Platform:   runtime.GOOS,
		IssuedAt:   now.Unix(),
		ExpiresAt:  exp.Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("step-up: failed to serialize claims: %w", err)
	}

	sig := ed25519.Sign(privKey, claimsJSON)

	payloadB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubKey)

	rawToken := fmt.Sprintf("%s.%s", payloadB64, sigB64)

	return &AttestationToken{
		Claims:    claims,
		Signature: sigB64,
		RawToken:  rawToken,
		PublicKey: pubB64,
	}, nil
}

// Verify validates the cryptographic signature and expiration of an attestation token.
func Verify(rawToken string, pubKey ed25519.PublicKey) (*AttestationToken, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 2 {
		return nil, errors.New("step-up: invalid token format, expected payload.signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("step-up: invalid claims encoding: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("step-up: invalid signature encoding: %w", err)
	}

	if !ed25519.Verify(pubKey, claimsJSON, sig) {
		return nil, errors.New("step-up: cryptographic attestation signature verification failed")
	}

	var claims AttestationClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("step-up: malformed claims: %w", err)
	}

	// Verify expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("step-up: attestation token expired at %s", time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}

	return &AttestationToken{
		Claims:    claims,
		Signature: parts[1],
		RawToken:  rawToken,
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKey),
	}, nil
}
