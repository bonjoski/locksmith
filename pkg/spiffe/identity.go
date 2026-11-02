// Package spiffe provides sovereign SPIFFE workload attestation, local policy
// evaluation, and the zero-dependency SPIFFE Workload API Unix domain socket server.
package spiffe

import (
	"errors"
	"net"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

var (
	// ErrAttestationFailed is returned when kernel peer credentials cannot be resolved.
	ErrAttestationFailed = errors.New("workload peer attestation failed")
	// ErrProcessIdentityRace is returned if a PID recycling or TOCTOU race is detected.
	ErrProcessIdentityRace = errors.New("security violation: process identity changed after connection establishment")
	// ErrUnauthorizedWorkload is returned when a caller identity violates the policy.
	ErrUnauthorizedWorkload = errors.New("workload unauthorized by local policy")
	// ErrRateLimitExceeded is returned when a caller exceeds the attestation rate limit.
	ErrRateLimitExceeded = errors.New("rate limit exceeded for workload attestation")
)

// CallerIdentity encapsulates peer attestation metadata verified by the OS kernel.
type CallerIdentity struct {
	PID       int
	UID       uint32
	GID       uint32
	Comm      string
	StartTime time.Time
	VsockCID  uint32
}

// WorkloadAttestor inspects incoming socket connections to verify the peer identity.
type WorkloadAttestor interface {
	AttestPeer(conn net.Conn) (*CallerIdentity, error)
}

// SVIDResponse contains the issued SVID and cryptographic trust bundle for a workload.
type SVIDResponse struct {
	SPIFFEID    string    `json:"spiffe_id"`
	CertPEM     string    `json:"cert_pem"`
	KeyPEM      string    `json:"key_pem"`
	ChainPEM    string    `json:"chain_pem"`
	ExpiresAt   time.Time `json:"expires_at"`
	Fingerprint string    `json:"fingerprint"`
}

// BundleResponse contains the trust anchor bundle for the local trust domain.
type BundleResponse struct {
	TrustDomain string `json:"trust_domain"`
	CAPEM       string `json:"ca_pem"`
	PQCCAPEM    string `json:"pqc_ca_pem,omitempty"`
}

// WorkloadRequest specifies the parameters requested by an attested workload.
type WorkloadRequest struct {
	SPIFFEID string        `json:"spiffe_id,omitempty"`
	TTL      time.Duration `json:"ttl,omitempty"`
}

// WorkloadPolicyEvaluator evaluates whether a caller identity is permitted to receive an SVID.
type WorkloadPolicyEvaluator interface {
	Authorize(identity *CallerIdentity, requestedID *ca.SPIFFEID) error
}
