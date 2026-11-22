package locksmith

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
)

const maxTrackedSessionKeys = 1024

type sessionLeafKey struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	createdAt time.Time
}

// SignDSSE signs DSSE PAE bytes using an amortized per-session Ed25519 leaf key held
// strictly in daemon memory (zero extra Touch ID prompts across concurrent requests).
func (lm *LeaseManager) SignDSSE(req *protocol.SignDSSERequest, peer *protocol.PeerCredentials) (*protocol.SignDSSEResponse, error) {
	pae, err := req.Validate()
	if err != nil {
		return &protocol.SignDSSEResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	if err := lm.validateDSSEPeer(peer); err != nil {
		return &protocol.SignDSSEResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}

	// Fast path: RLock lookup & sign without contending across N=8 concurrent signers.
	lm.mu.RLock()
	if lm.closed {
		lm.mu.RUnlock()
		return &protocol.SignDSSEResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}
	if key, ok := lm.sessionKeys[req.SessionID]; ok && key != nil && len(key.priv) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(key.priv, pae)
		pubB64 := base64.StdEncoding.EncodeToString(key.pub)
		lm.mu.RUnlock()
		return &protocol.SignDSSEResponse{
			Status:    protocol.StatusGranted,
			KeyID:     protocol.SessionKeyID(req.SessionID),
			SigB64:    base64.StdEncoding.EncodeToString(sig),
			PubKeyB64: pubB64,
		}, nil
	}
	lm.mu.RUnlock()

	// Slow path: double-checked key creation under write lock so N=8 concurrent calls
	// for a brand-new session_id mint exactly one leaf key.
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return &protocol.SignDSSEResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}
	key, err := lm.getOrCreateSessionKeyLocked(req.SessionID)
	if err != nil {
		return &protocol.SignDSSEResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	sig := ed25519.Sign(key.priv, pae)
	return &protocol.SignDSSEResponse{
		Status:    protocol.StatusGranted,
		KeyID:     protocol.SessionKeyID(req.SessionID),
		SigB64:    base64.StdEncoding.EncodeToString(sig),
		PubKeyB64: base64.StdEncoding.EncodeToString(key.pub),
	}, nil
}

// GetSessionPubKey returns the SPIFFE key ID and base64-encoded Ed25519 public key
// for a session's amortized leaf key, creating the leaf key lazily if needed.
func (lm *LeaseManager) GetSessionPubKey(req *protocol.GetSessionPubKeyRequest, peer *protocol.PeerCredentials) (*protocol.GetSessionPubKeyResponse, error) {
	if err := req.Validate(); err != nil {
		return &protocol.GetSessionPubKeyResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	if err := lm.validateDSSEPeer(peer); err != nil {
		return &protocol.GetSessionPubKeyResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}

	lm.mu.RLock()
	if lm.closed {
		lm.mu.RUnlock()
		return &protocol.GetSessionPubKeyResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}
	if key, ok := lm.sessionKeys[req.SessionID]; ok && key != nil {
		pubB64 := base64.StdEncoding.EncodeToString(key.pub)
		lm.mu.RUnlock()
		return &protocol.GetSessionPubKeyResponse{
			Status:    protocol.StatusGranted,
			KeyID:     protocol.SessionKeyID(req.SessionID),
			PubKeyB64: pubB64,
		}, nil
	}
	lm.mu.RUnlock()

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return &protocol.GetSessionPubKeyResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}
	key, err := lm.getOrCreateSessionKeyLocked(req.SessionID)
	if err != nil {
		return &protocol.GetSessionPubKeyResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	return &protocol.GetSessionPubKeyResponse{
		Status:    protocol.StatusGranted,
		KeyID:     protocol.SessionKeyID(req.SessionID),
		PubKeyB64: base64.StdEncoding.EncodeToString(key.pub),
	}, nil
}

func (lm *LeaseManager) validateDSSEPeer(peer *protocol.PeerCredentials) error {
	if peer == nil {
		return errors.New("peer credentials required")
	}
	if peer.PID <= 0 {
		return errors.New("kernel peer PID required")
	}
	return CheckBinaryAccessForExecutable(peer.ExePath, peer.ExeHash, lm.opts.AllowBinaries, lm.opts.DenyBinaries)
}

func (lm *LeaseManager) getOrCreateSessionKeyLocked(sessionID string) (*sessionLeafKey, error) {
	if lm.sessionKeys == nil {
		lm.sessionKeys = make(map[string]*sessionLeafKey)
	}
	if existing, ok := lm.sessionKeys[sessionID]; ok && existing != nil {
		return existing, nil
	}
	if len(lm.sessionKeys) >= maxTrackedSessionKeys {
		lm.evictOldestSessionKeyLocked()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session Ed25519 leaf key: %w", err)
	}
	leaf := &sessionLeafKey{
		pub:       pub,
		priv:      priv,
		createdAt: time.Now(),
	}
	lm.sessionKeys[sessionID] = leaf
	return leaf, nil
}

func (lm *LeaseManager) evictOldestSessionKeyLocked() {
	var oldestID string
	var oldestTime time.Time
	for id, k := range lm.sessionKeys {
		if oldestID == "" || k.createdAt.Before(oldestTime) {
			oldestID = id
			oldestTime = k.createdAt
		}
	}
	if oldestID != "" {
		if old := lm.sessionKeys[oldestID]; old != nil && len(old.priv) > 0 {
			slice.ExplicitBzero(old.priv)
			old.priv = nil
		}
		delete(lm.sessionKeys, oldestID)
	}
}
