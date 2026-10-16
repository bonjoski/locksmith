// Package protocol defines the shared wire format and security contracts
// for the Ephemeral Token Exchange (ETX) and Agentic Security Fabric.
package protocol

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Current ETX Protocol Version
const ProtocolVersion = "1.0"

// LeaseStatus represents the outcome of an ephemeral lease request.
type LeaseStatus string

const (
	StatusGranted           LeaseStatus = "GRANTED"
	StatusDenied            LeaseStatus = "DENIED"
	StatusChallengeRequired LeaseStatus = "CHALLENGE_REQUIRED"
	StatusRevoked           LeaseStatus = "REVOKED"
	StatusExpired           LeaseStatus = "EXPIRED"
)

// Action represents an ETX IPC action over the local socket.
type Action string

const (
	ActionRequestLease  Action = "request_lease"
	ActionRevokeLease   Action = "revoke_lease"
	ActionCreateSession Action = "create_session"
	ActionRevokeSession Action = "revoke_session"
	ActionPing          Action = "ping"
)

// LeaseRequest represents an inquiry from Airlock/Agent runner to Locksmith.
type LeaseRequest struct {
	Version          string        `json:"version"`
	Action           Action        `json:"action"`
	ClientPID        int           `json:"client_pid"`
	ProcessStartTime int64         `json:"process_start_time"`
	ClientBinaryHash string        `json:"client_binary_hash"`
	SecretName       string        `json:"secret_name"`
	LeaseTTL         time.Duration `json:"lease_ttl"`
	MaxUses          int           `json:"max_uses"`
	SessionTicket    string        `json:"session_ticket,omitempty"`
	TargetCommand    string        `json:"target_command,omitempty"`
}

// Validate checks the completeness and sanity of a lease request.
func (r *LeaseRequest) Validate() error {
	if r.Version != ProtocolVersion {
		return fmt.Errorf("etx: unsupported protocol version %q, expected %q", r.Version, ProtocolVersion)
	}
	if r.ClientPID <= 0 {
		return errors.New("etx: client_pid must be positive")
	}
	if r.ProcessStartTime <= 0 {
		return errors.New("etx: process_start_time must be positive (used for PID recycling protection)")
	}
	if strings.TrimSpace(r.SecretName) == "" && r.Action == ActionRequestLease {
		return errors.New("etx: secret_name cannot be empty")
	}
	if r.LeaseTTL <= 0 && r.Action == ActionRequestLease {
		return errors.New("etx: lease_ttl must be positive")
	}
	return nil
}

// LeaseResponse represents Locksmith's response to an ephemeral lease request.
type LeaseResponse struct {
	Status        LeaseStatus `json:"status"`
	LeaseID       string      `json:"lease_id,omitempty"`
	SecretValue   []byte      `json:"secret_value,omitempty"`
	ExpiresAt     time.Time   `json:"expires_at,omitempty"`
	SessionTicket string      `json:"session_ticket,omitempty"`
	Error         string      `json:"error,omitempty"`
}

// Zero securely wipes the secret value from memory.
func (res *LeaseResponse) Zero() {
	if res.SecretValue != nil {
		for i := range res.SecretValue {
			res.SecretValue[i] = 0
		}
		res.SecretValue = nil
	}
}

// ConstantTimeCompare compares a candidate secret with the response securely.
func (res *LeaseResponse) ConstantTimeCompare(candidate []byte) bool {
	if res.SecretValue == nil || candidate == nil {
		return false
	}
	return subtle.ConstantTimeCompare(res.SecretValue, candidate) == 1
}

// RevokeRequest informs Locksmith that a process finished and the lease is void.
type RevokeRequest struct {
	Version   string `json:"version"`
	Action    Action `json:"action"`
	LeaseID   string `json:"lease_id"`
	ClientPID int    `json:"client_pid"`
}

// RevokeResponse indicates whether revocation completed cleanly.
type RevokeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// SessionTicket allows multiple agent sub-commands to avoid biometric prompt fatigue.
type SessionTicket struct {
	TicketID       string    `json:"ticket_id"`
	PGID           int       `json:"pgid"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	AllowedSecrets []string  `json:"allowed_secrets"`
}

// IsExpired checks whether the ticket has exceeded its TTL.
func (st *SessionTicket) IsExpired() bool {
	return time.Now().After(st.ExpiresAt)
}

// PermitsSecret checks whether the ticket grants access to the specified secret key.
func (st *SessionTicket) PermitsSecret(secretName string) bool {
	if st.IsExpired() {
		return false
	}
	for _, s := range st.AllowedSecrets {
		if s == "*" || strings.EqualFold(s, secretName) {
			return true
		}
	}
	return false
}

// EncodeJSON serializes a struct to byte buffer.
func EncodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeJSON deserializes byte buffer into target struct.
func DecodeJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
