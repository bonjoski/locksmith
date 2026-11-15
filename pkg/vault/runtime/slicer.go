// Package runtime implements Zero-Config-Secret Workload Credential Slicing
// in Locksmith to disarm automated plaintext AWS credential scraping (AntiFox defense per RFC-2026-11-13-30).
//
// Workload credentials (such as ephemeral AWS STS sessions) are vended exclusively
// in volatile RAM with a strict 60-second default TTL, cached in-memory with zero disk
// or swap residue, and injected into child processes via anonymous file descriptors (FD 3)
// instead of environment variables or static configuration files.
package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/slice"
)

const (
	// DefaultTTL is the default lifetime for ephemeral workload credentials (60s per RFC-2026-11-13-30).
	DefaultTTL = 60 * time.Second

	// MaxTTL is the maximum permitted lifetime for any sliced credential.
	MaxTTL = 15 * time.Minute

	// DefaultCleanupInterval is how frequently the background cleaner scans and zeroizes expired credentials.
	DefaultCleanupInterval = 2 * time.Second

	// EnvironmentFDKey is the environment variable signaling the inherited anonymous file descriptor.
	EnvironmentFDKey = "LOCKSMITH_FD"

	// CredentialSliceFD is the file descriptor number inherited by child processes (FD 3).
	CredentialSliceFD = 3
)

var (
	// ErrCredentialsExpired indicates requested credentials have passed their TTL.
	ErrCredentialsExpired = errors.New("workload credentials expired")

	// ErrCredentialsZeroized indicates that in-memory credentials have been actively overwritten with zeroes.
	ErrCredentialsZeroized = errors.New("workload credentials have been zeroized")

	// ErrSessionRevoked indicates the session was explicitly revoked.
	ErrSessionRevoked = errors.New("workload session has been revoked")

	// ErrInvalidRequest indicates missing or malformed request parameters.
	ErrInvalidRequest = errors.New("invalid workload credential request")

	// ErrSlicerClosed indicates the workload slicer runtime has been shut down.
	ErrSlicerClosed = errors.New("workload slicer runtime is closed")

	// ErrAttestationFailed indicates that the emulator token attestation signature verification failed.
	ErrAttestationFailed = errors.New("attestation signature verification failed")
)

// STSCredentials represents the wire/JSON format expected by AWS SDK credential_process
// and AWS-compatible workload runtimes.
type STSCredentials struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

// WorkloadRequest specifies the parameters for obtaining sliced ephemeral credentials.
type WorkloadRequest struct {
	RoleARN         string        `json:"role_arn"`
	SessionName     string        `json:"session_name"`
	ExternalID      string        `json:"external_id,omitempty"`
	Duration        time.Duration `json:"duration,omitempty"`
	AttestationData []byte        `json:"attestation_data,omitempty"`
}

// SlicedCredential represents an active in-memory credential holding volatile byte slices
// that can be actively zeroized in RAM upon revocation or expiration.
type SlicedCredential struct {
	mu              sync.RWMutex
	AccessKeyID     []byte    `json:"-"`
	SecretAccessKey []byte    `json:"-"`
	SessionToken    []byte    `json:"-"`
	Expiration      time.Time `json:"expiration"`
	RoleARN         string    `json:"role_arn"`
	SessionName     string    `json:"session_name"`
	Attested        bool      `json:"attested"`
	zeroized        bool
}

// Zeroize securely overwrites all volatile memory buffers containing credential data with zeroes,
// defeating memory-scraping attacks and compiler dead-store elimination.
func (c *SlicedCredential) Zeroize() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.zeroized {
		return
	}
	slice.ExplicitBzero(c.AccessKeyID)
	slice.ExplicitBzero(c.SecretAccessKey)
	slice.ExplicitBzero(c.SessionToken)
	c.zeroized = true
}

// IsZeroized returns whether this credential's memory has been wiped.
func (c *SlicedCredential) IsZeroized() bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.zeroized
}

// IsExpired returns whether this credential has passed its expiration time.
func (c *SlicedCredential) IsExpired() bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Now().After(c.Expiration)
}

// STSCredentials exports a copy of the credentials in standard AWS STS format.
// Returns an error if the credential has been zeroized or expired.
func (c *SlicedCredential) STSCredentials() (*STSCredentials, error) {
	if c == nil {
		return nil, ErrCredentialsZeroized
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.zeroized {
		return nil, ErrCredentialsZeroized
	}
	if time.Now().After(c.Expiration) {
		return nil, ErrCredentialsExpired
	}

	return &STSCredentials{
		Version:         1,
		AccessKeyID:     string(c.AccessKeyID),
		SecretAccessKey: string(c.SecretAccessKey),
		SessionToken:    string(c.SessionToken),
		Expiration:      c.Expiration,
	}, nil
}

// ToJSON serializes the credentials into AWS credential_process JSON format.
// The caller is responsible for wiping the returned byte slice when finished.
func (c *SlicedCredential) ToJSON() ([]byte, error) {
	sts, err := c.STSCredentials()
	if err != nil {
		return nil, err
	}
	return json.Marshal(sts)
}

// CreateSlice packages the credentials into an anonymous OS descriptor (pipe or memfd)
// suitable for passing directly to child processes without writing to disk or environment.
func (c *SlicedCredential) CreateSlice() (slice.Slice, error) {
	data, err := c.ToJSON()
	if err != nil {
		return nil, err
	}
	defer slice.ExplicitBzero(data)
	return slice.Create(data)
}

// CredentialGenerator is the interface for upstream dynamic credential issuance.
type CredentialGenerator interface {
	GenerateCredentials(ctx context.Context, req WorkloadRequest) (*SlicedCredential, error)
}

// LocalAttestedEmulator generates cryptographically attested ephemeral STS credentials
// locally when an upstream provider is unconfigured or unreachable.
type LocalAttestedEmulator struct {
	mu              sync.RWMutex
	SigningKey      []byte
	ClusterID       string
	NodeFingerprint string
}

// NewLocalAttestedEmulator creates a local attested STS generator.
func NewLocalAttestedEmulator(clusterID, nodeFingerprint string) *LocalAttestedEmulator {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("failed to initialize cryptographically secure signing key: %v", err))
	}
	if clusterID == "" {
		clusterID = "locksmith-sovereign-node"
	}
	if nodeFingerprint == "" {
		nodeFingerprint = "local-enclave-attested"
	}
	return &LocalAttestedEmulator{
		SigningKey:      key,
		ClusterID:       clusterID,
		NodeFingerprint: nodeFingerprint,
	}
}

// TokenAttestation holds parsed attestation claims from an emulator session token.
type TokenAttestation struct {
	RoleARN         string    `json:"role_arn"`
	SessionName     string    `json:"session_name"`
	ClusterID       string    `json:"cluster_id"`
	NodeFingerprint string    `json:"node_fingerprint"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Nonce           string    `json:"nonce"`
}

// GenerateCredentials generates attested ephemeral AWS STS credentials with 60s default TTL.
func (e *LocalAttestedEmulator) GenerateCredentials(ctx context.Context, req WorkloadRequest) (*SlicedCredential, error) {
	if req.RoleARN == "" {
		return nil, fmt.Errorf("%w: role_arn cannot be empty", ErrInvalidRequest)
	}
	if req.SessionName == "" {
		req.SessionName = "workload-session-" + hex.EncodeToString(randomBytes(4))
	}

	ttl := req.Duration
	if ttl <= 0 {
		ttl = DefaultTTL
	} else if ttl > MaxTTL {
		ttl = MaxTTL
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	// AccessKeyId: ASIA + 16 random uppercase base32 characters
	accessKeyID := []byte("ASIA" + generateRandomAlphanumeric(16))

	// SecretAccessKey: 40 base64 characters
	secretAccessKey := []byte(base64.StdEncoding.EncodeToString(randomBytes(30)))

	// SessionToken: HMAC-attested session payload
	tokenPayload := TokenAttestation{
		RoleARN:         req.RoleARN,
		SessionName:     req.SessionName,
		ClusterID:       e.ClusterID,
		NodeFingerprint: e.NodeFingerprint,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
		Nonce:           hex.EncodeToString(randomBytes(16)),
	}

	payloadJSON, err := json.Marshal(tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation payload: %w", err)
	}

	e.mu.RLock()
	mac := hmac.New(sha256.New, e.SigningKey)
	e.mu.RUnlock()
	mac.Write(payloadJSON)
	signature := mac.Sum(nil)

	tokenStr := fmt.Sprintf("locksmith-attested.v1.%s.%s",
		base64.RawURLEncoding.EncodeToString(payloadJSON),
		base64.RawURLEncoding.EncodeToString(signature),
	)
	sessionToken := []byte(tokenStr)

	return &SlicedCredential{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      expiresAt,
		RoleARN:         req.RoleARN,
		SessionName:     req.SessionName,
		Attested:        true,
	}, nil
}

// VerifyToken validates that an emulator-issued session token is authentic, untampered, and unexpired.
func (e *LocalAttestedEmulator) VerifyToken(token string) (*TokenAttestation, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "locksmith-attested" || parts[1] != "v1" {
		return nil, fmt.Errorf("%w: invalid token header format", ErrAttestationFailed)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrAttestationFailed)
	}

	expectedSig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrAttestationFailed)
	}

	e.mu.RLock()
	mac := hmac.New(sha256.New, e.SigningKey)
	e.mu.RUnlock()
	mac.Write(payloadJSON)
	actualSig := mac.Sum(nil)

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrAttestationFailed)
	}

	var claims TokenAttestation
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: unmarshal claims failed", ErrAttestationFailed)
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrCredentialsExpired
	}

	return &claims, nil
}

// SlicerConfig holds configuration parameters for the WorkloadSlicer.
type SlicerConfig struct {
	// DefaultTTL sets default lifetime for sliced credentials (defaults to 60s).
	DefaultTTL time.Duration

	// PrimaryGenerator is the upstream dynamic STS provider (optional).
	PrimaryGenerator CredentialGenerator

	// AttestedEmulator is the local attested generator fallback.
	AttestedEmulator *LocalAttestedEmulator

	// CleanupInterval is how often expired credentials in RAM are zeroized (defaults to 2s).
	CleanupInterval time.Duration
}

// WorkloadSlicer manages ephemeral in-memory AWS STS credential slicing, in-memory caching,
// zeroization upon revocation/expiration, and child process anonymous descriptor injection.
type WorkloadSlicer struct {
	mu       sync.RWMutex
	config   SlicerConfig
	cache    map[string]*SlicedCredential
	stopCh   chan struct{}
	closed   bool
	wg       sync.WaitGroup
}

// NewWorkloadSlicer initializes a zero-disk-residue workload credential slicer.
func NewWorkloadSlicer(cfg SlicerConfig) *WorkloadSlicer {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = DefaultTTL
	} else if cfg.DefaultTTL > MaxTTL {
		cfg.DefaultTTL = MaxTTL
	}

	if cfg.AttestedEmulator == nil {
		cfg.AttestedEmulator = NewLocalAttestedEmulator("", "")
	}

	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = DefaultCleanupInterval
	}

	s := &WorkloadSlicer{
		config: cfg,
		cache:  make(map[string]*SlicedCredential),
		stopCh: make(chan struct{}),
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	return s
}

func cacheKey(roleARN, sessionName string) string {
	return fmt.Sprintf("%s::%s", strings.TrimSpace(roleARN), strings.TrimSpace(sessionName))
}

// cleanupLoop periodically sweeps in-memory credentials, wiping any expired sessions with zeroes.
func (s *WorkloadSlicer) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sweepExpired()
		}
	}
}

// sweepExpired iterates over active cache entries and zeroizes expired credentials in RAM.
func (s *WorkloadSlicer) sweepExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, cred := range s.cache {
		if cred.IsZeroized() || now.After(cred.Expiration) {
			cred.Zeroize()
			delete(s.cache, key)
		}
	}
}

func (s *WorkloadSlicer) normalizeRequest(req *WorkloadRequest) error {
	if req.RoleARN == "" {
		return fmt.Errorf("%w: role_arn is required", ErrInvalidRequest)
	}
	if req.SessionName == "" {
		req.SessionName = "workload-" + hex.EncodeToString(randomBytes(4))
	}
	if req.Duration <= 0 {
		req.Duration = s.config.DefaultTTL
	}
	return nil
}

func (s *WorkloadSlicer) getCached(key string) (*SlicedCredential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, false
	}
	cached, exists := s.cache[key]
	if exists && !cached.IsZeroized() && !cached.IsExpired() {
		return cached, true
	}
	return nil, false
}

func (s *WorkloadSlicer) generate(ctx context.Context, req WorkloadRequest) (*SlicedCredential, error) {
	if s.config.PrimaryGenerator != nil {
		if cred, err := s.config.PrimaryGenerator.GenerateCredentials(ctx, req); err == nil {
			return cred, nil
		}
	}
	cred, err := s.config.AttestedEmulator.GenerateCredentials(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("credential generation failed: %w", err)
	}
	return cred, nil
}

// GetCredentials retrieves an active credential from volatile RAM or generates a new one.
// Plaintext credentials are NEVER written to disk, swap, or host environment.
func (s *WorkloadSlicer) GetCredentials(ctx context.Context, req WorkloadRequest) (*SlicedCredential, error) {
	if err := s.normalizeRequest(&req); err != nil {
		return nil, err
	}

	key := cacheKey(req.RoleARN, req.SessionName)

	if cached, ok := s.getCached(key); ok {
		return cached, nil
	}

	// Cache miss or expired: Generate new credentials under write lock
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSlicerClosed
	}

	if cached, exists := s.cache[key]; exists {
		if !cached.IsZeroized() && !cached.IsExpired() {
			return cached, nil
		}
		cached.Zeroize()
		delete(s.cache, key)
	}

	cred, err := s.generate(ctx, req)
	if err != nil {
		return nil, err
	}

	s.cache[key] = cred
	return cred, nil
}

// SliceCredentials generates or retrieves credentials and packages them into an anonymous
// operating system descriptor (FD 3). The memory buffer holding the intermediate serialized
// payload is wiped with zeroes immediately.
func (s *WorkloadSlicer) SliceCredentials(ctx context.Context, req WorkloadRequest) (slice.Slice, *SlicedCredential, error) {
	cred, err := s.GetCredentials(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	sl, err := cred.CreateSlice()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create anonymous descriptor slice: %w", err)
	}

	return sl, cred, nil
}

// SliceForCommand attaches an anonymous descriptor slice holding AWS STS credentials to
// cmd.ExtraFiles[0] (inheriting as FD 3) and sanitizes cmd.Env, strictly preventing plaintext
// AWS credentials from leaking into process environment blocks or /proc/<pid>/environ.
func (s *WorkloadSlicer) SliceForCommand(ctx context.Context, req WorkloadRequest, cmd *exec.Cmd) (slice.Slice, *SlicedCredential, error) {
	if cmd == nil {
		return nil, nil, errors.New("command cannot be nil")
	}

	sl, cred, err := s.SliceCredentials(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	// Inherit anonymous descriptor as FD 3
	cmd.ExtraFiles = append(cmd.ExtraFiles, sl.File())

	// Sanitize environment: strip any existing AWS credential variables and set LOCKSMITH_FD
	baseEnv := cmd.Env
	if len(baseEnv) == 0 {
		baseEnv = os.Environ()
	}

	sanitized := SanitizeEnvironment(baseEnv)
	sanitized = append(sanitized, fmt.Sprintf("%s=%d", EnvironmentFDKey, CredentialSliceFD))
	cmd.Env = sanitized

	return sl, cred, nil
}

// Revoke actively wipes the credentials matching the role and session name from RAM with zeroes
// and removes them from the in-memory cache.
func (s *WorkloadSlicer) Revoke(roleARN, sessionName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := cacheKey(roleARN, sessionName)
	cred, exists := s.cache[key]
	if !exists {
		return nil
	}

	cred.Zeroize()
	delete(s.cache, key)
	return nil
}

// RevokeAll zeroizes all cached workload credentials in RAM and empties the cache.
func (s *WorkloadSlicer) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, cred := range s.cache {
		cred.Zeroize()
		delete(s.cache, key)
	}
}

// ActiveSessionCount returns the number of unexpired, non-zeroized sessions in RAM.
func (s *WorkloadSlicer) ActiveSessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, cred := range s.cache {
		if !cred.IsZeroized() && !now.After(cred.Expiration) {
			count++
		}
	}
	return count
}

// Close shuts down the workload slicer, terminates the background cleaner goroutine,
// and zeroizes all cached credential memory.
func (s *WorkloadSlicer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stopCh)

	for key, cred := range s.cache {
		cred.Zeroize()
		delete(s.cache, key)
	}
	s.mu.Unlock()

	s.wg.Wait()
	return nil
}

// SanitizeEnvironment filters out known AWS credential variables and secrets from an environment
// slice, neutralizing automated scraping attacks (e.g. AntiFox / ARTEX webshells inspecting /proc/environ).
func SanitizeEnvironment(env []string) []string {
	deniedPrefixes := []string{
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"AWS_SESSION_TOKEN=",
		"AWS_SECURITY_TOKEN=",
		"AWS_CREDENTIALS=",
		"LOCKSMITH_SECRET_",
	}

	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		blocked := false
		for _, prefix := range deniedPrefixes {
			if strings.HasPrefix(strings.ToUpper(entry), prefix) {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// Helper utilities

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return b
}

func generateRandomAlphanumeric(n int) string {
	b := randomBytes(n)
	result := make([]byte, n)
	for i := range result {
		val := int(b[i]) % 36
		if val < 26 {
			result[i] = byte('A' + val)
		} else {
			result[i] = byte('0' + (val - 26))
		}
	}
	return string(result)
}
