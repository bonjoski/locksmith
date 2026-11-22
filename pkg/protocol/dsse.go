package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// MaxDSSEPAEBytes bounds the decoded PAE payload size accepted over the local daemon socket.
const MaxDSSEPAEBytes = 64 * 1024

// SessionKeyID returns the canonical SPIFFE key identifier for a session's amortized Ed25519 leaf key.
func SessionKeyID(sessionID string) string {
	return "spiffe://bonjoski.local/session/" + sessionID
}

// SignDSSERequest requests an Ed25519 signature over DSSE Pre-Authentication Encoding (PAE) bytes
// using the daemon's amortized per-session leaf key.
type SignDSSERequest struct {
	Version   string `json:"version"`
	Action    Action `json:"action"`
	SessionID string `json:"session_id"`
	PAEB64    string `json:"pae_b64"`
}

// Validate checks the integrity and bounds of a DSSE signing request.
func (r *SignDSSERequest) Validate() ([]byte, error) {
	if r == nil {
		return nil, errors.New("etx: nil sign_dsse request")
	}
	if r.Version != ProtocolVersion {
		return nil, fmt.Errorf("etx: unsupported protocol version %q, expected %q", r.Version, ProtocolVersion)
	}
	if r.Action != ActionSignDSSE {
		return nil, fmt.Errorf("etx: unexpected action %q, expected %q", r.Action, ActionSignDSSE)
	}
	if err := ValidateSessionID(r.SessionID); err != nil {
		return nil, err
	}
	if r.PAEB64 == "" {
		return nil, errors.New("etx: pae_b64 cannot be empty")
	}
	pae, err := base64.StdEncoding.DecodeString(r.PAEB64)
	if err != nil {
		return nil, fmt.Errorf("etx: invalid base64 pae_b64: %w", err)
	}
	if len(pae) == 0 {
		return nil, errors.New("etx: decoded pae_b64 cannot be empty")
	}
	if len(pae) > MaxDSSEPAEBytes {
		return nil, fmt.Errorf("etx: pae_b64 exceeds max size (%d bytes)", MaxDSSEPAEBytes)
	}
	return pae, nil
}

// SignDSSEResponse contains the Ed25519 signature and public key for a session's amortized leaf key.
type SignDSSEResponse struct {
	Status    LeaseStatus `json:"status"`
	KeyID     string      `json:"keyid,omitempty"`
	SigB64    string      `json:"sig_b64,omitempty"`
	PubKeyB64 string      `json:"pubkey_b64,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// GetSessionPubKeyRequest requests the public key corresponding to a session's amortized Ed25519 leaf key.
type GetSessionPubKeyRequest struct {
	Version   string `json:"version"`
	Action    Action `json:"action"`
	SessionID string `json:"session_id"`
}

// Validate checks the integrity of a session public key lookup request.
func (r *GetSessionPubKeyRequest) Validate() error {
	if r == nil {
		return errors.New("etx: nil get_session_pubkey request")
	}
	if r.Version != ProtocolVersion {
		return fmt.Errorf("etx: unsupported protocol version %q, expected %q", r.Version, ProtocolVersion)
	}
	if r.Action != ActionGetSessionPubKey {
		return fmt.Errorf("etx: unexpected action %q, expected %q", r.Action, ActionGetSessionPubKey)
	}
	return ValidateSessionID(r.SessionID)
}

// GetSessionPubKeyResponse returns the SPIFFE key ID and base64-encoded Ed25519 public key for a session.
type GetSessionPubKeyResponse struct {
	Status    LeaseStatus `json:"status"`
	KeyID     string      `json:"keyid,omitempty"`
	PubKeyB64 string      `json:"pubkey_b64,omitempty"`
	Error     string      `json:"error,omitempty"`
}
