package protocol

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// DeliveryModeFD3Slice indicates secrets are redeemed out-of-band by sandboxed executors
	// into an FD=3 memory slice rather than returned in LLM tool output.
	DeliveryModeFD3Slice = "fd3_memory_slice"

	// MinOpaqueLeaseTTL is the minimum permitted TTL for an opaque lease.
	MinOpaqueLeaseTTL = 1 * time.Second

	// MaxOpaqueLeaseTTL is the maximum permitted TTL for an opaque lease.
	MaxOpaqueLeaseTTL = 300 * time.Second
)

// MintOpaqueLeaseRequest asks Locksmith to check out a vault secret into daemon RAM
// and return only an opaque CSPRNG handle (zero raw secret bytes).
type MintOpaqueLeaseRequest struct {
	Version          string        `json:"version"`
	Action           Action        `json:"action"`
	SessionID        string        `json:"session_id"`
	SecretName       string        `json:"secret_name"`
	TargetEnvVar     string        `json:"target_env_var,omitempty"`
	LeaseTTL         time.Duration `json:"lease_ttl"`
	ClientPID        int           `json:"client_pid,omitempty"`
	ProcessStartTime int64         `json:"process_start_time,omitempty"`
	ClientBinaryHash string        `json:"client_binary_hash,omitempty"`
	SpiffeID         string        `json:"spiffe_id,omitempty"`
}

// Validate checks bounds and required fields for an opaque lease mint request.
func (r *MintOpaqueLeaseRequest) Validate() error {
	if r == nil {
		return errors.New("etx: nil mint_opaque_lease request")
	}
	if r.Version != ProtocolVersion {
		return fmt.Errorf("etx: unsupported protocol version %q, expected %q", r.Version, ProtocolVersion)
	}
	if r.Action != ActionMintOpaqueLease {
		return fmt.Errorf("etx: unexpected action %q, expected %q", r.Action, ActionMintOpaqueLease)
	}
	if err := ValidateSessionID(r.SessionID); err != nil {
		return err
	}
	if strings.TrimSpace(r.SecretName) == "" {
		return errors.New("etx: secret_name cannot be empty")
	}
	if r.LeaseTTL < MinOpaqueLeaseTTL || r.LeaseTTL > MaxOpaqueLeaseTTL {
		return fmt.Errorf("etx: lease_ttl %s out of allowed range [%s, %s]", r.LeaseTTL, MinOpaqueLeaseTTL, MaxOpaqueLeaseTTL)
	}
	if r.ClientPID < 0 || r.ProcessStartTime < 0 {
		return errors.New("etx: client_pid and process_start_time cannot be negative")
	}
	if r.SpiffeID != "" {
		if err := ValidateSpiffeID(r.SpiffeID); err != nil {
			return fmt.Errorf("etx: invalid spiffe_id: %w", err)
		}
	}
	envVar := strings.TrimSpace(r.TargetEnvVar)
	if envVar == "" {
		envVar = strings.TrimSpace(r.SecretName)
	}
	if strings.ContainsAny(envVar, "=\x00\r\n") {
		return errors.New("etx: target_env_var contains forbidden characters")
	}
	return nil
}

// EffectiveEnvVar returns the resolved target environment variable name.
func (r *MintOpaqueLeaseRequest) EffectiveEnvVar() string {
	if envVar := strings.TrimSpace(r.TargetEnvVar); envVar != "" {
		return envVar
	}
	return strings.TrimSpace(r.SecretName)
}

// MintOpaqueLeaseResponse contains ONLY the opaque lease handle metadata — never raw secret bytes.
type MintOpaqueLeaseResponse struct {
	Status    LeaseStatus `json:"status"`
	LeaseID   string      `json:"lease_id,omitempty"`
	EnvVar    string      `json:"env_var,omitempty"`
	ExpiresAt time.Time   `json:"expires_at,omitempty"`
	Delivery  string      `json:"delivery,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// RedeemOpaqueLeaseRequest is sent by an attested local executor (e.g. airlock, aegisbox)
// over UDS to exchange a single-use opaque handle for the sliced secret bytes.
type RedeemOpaqueLeaseRequest struct {
	Version          string `json:"version"`
	Action           Action `json:"action"`
	LeaseID          string `json:"lease_id"`
	SessionID        string `json:"session_id"`
	ClientPID        int    `json:"client_pid,omitempty"`
	ProcessStartTime int64  `json:"process_start_time,omitempty"`
	ClientBinaryHash string `json:"client_binary_hash,omitempty"`
}

// Validate checks bounds and required fields for an opaque lease redemption request.
func (r *RedeemOpaqueLeaseRequest) Validate() error {
	if r == nil {
		return errors.New("etx: nil redeem_opaque_lease request")
	}
	if r.Version != ProtocolVersion {
		return fmt.Errorf("etx: unsupported protocol version %q, expected %q", r.Version, ProtocolVersion)
	}
	if r.Action != ActionRedeemOpaqueLease {
		return fmt.Errorf("etx: unexpected action %q, expected %q", r.Action, ActionRedeemOpaqueLease)
	}
	if err := ValidateOpaqueLeaseID(r.LeaseID); err != nil {
		return err
	}
	if err := ValidateSessionID(r.SessionID); err != nil {
		return err
	}
	if r.ClientPID < 0 || r.ProcessStartTime < 0 {
		return errors.New("etx: client_pid and process_start_time cannot be negative")
	}
	return nil
}

// RedeemOpaqueLeaseResponse returns the single-use redeemed secret payload to an attested local sandbox.
type RedeemOpaqueLeaseResponse struct {
	Status    LeaseStatus `json:"status"`
	LeaseID   string      `json:"lease_id,omitempty"`
	EnvVar    string      `json:"env_var,omitempty"`
	SecretB64 string      `json:"secret_b64,omitempty"`
	ExpiresAt time.Time   `json:"expires_at,omitempty"`
	Error     string      `json:"error,omitempty"`
}
