package locksmith

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/audit"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
)

type opaqueLease struct {
	leaseID      string
	sessionID    string
	secretName   string
	targetEnvVar string
	peerUID      uint32
	hasPeerUID   bool
	secretBytes  []byte
	createdAt    time.Time
	expiresAt    time.Time
	singleUse    bool
	spiffeID     string
	expiryTimer  *time.Timer
}

func (ol *opaqueLease) zeroAndStop() {
	if ol == nil {
		return
	}
	if ol.expiryTimer != nil {
		ol.expiryTimer.Stop()
		ol.expiryTimer = nil
	}
	if ol.secretBytes != nil {
		slice.ExplicitBzero(ol.secretBytes)
		ol.secretBytes = nil
	}
}

func generateOpaqueLeaseID() (string, error) {
	b := make([]byte, 16) // 128-bit CSPRNG entropy
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "lease_" + hex.EncodeToString(b), nil
}

// MintOpaqueLease stores a secret in daemon RAM under a 128-bit CSPRNG opaque handle bound
// to (session_id, peer_uid, target_env_var, expires_at, single_use=true) and returns ONLY
// opaque metadata — ZERO raw secret bytes.
func (lm *LeaseManager) MintOpaqueLease(req *protocol.MintOpaqueLeaseRequest, peer *protocol.PeerCredentials) (*protocol.MintOpaqueLeaseResponse, error) {
	if err := req.Validate(); err != nil {
		lm.logOpaqueAudit(req.SecretName, req.SpiffeID, peer, audit.OutcomeDenied, err.Error())
		return &protocol.MintOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	if err := validateOpaquePeer(req.ClientPID, req.ProcessStartTime, req.ClientBinaryHash, peer, lm.opts.AllowBinaries, lm.opts.DenyBinaries); err != nil {
		lm.logOpaqueAudit(req.SecretName, req.SpiffeID, peer, audit.OutcomeDenied, err.Error())
		return &protocol.MintOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return &protocol.MintOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}

	now := time.Now()
	lm.scavengeExpiredOpaqueLeasesLocked(now)

	secretBytes, err := lm.fetchSecret(req.SecretName, peer)
	if err != nil {
		lm.logOpaqueAudit(req.SecretName, req.SpiffeID, peer, audit.OutcomeDenied, err.Error())
		return &protocol.MintOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}

	// Store an owned zeroizable copy.
	owned := make([]byte, len(secretBytes))
	copy(owned, secretBytes)
	slice.ExplicitBzero(secretBytes)

	leaseID, err := generateOpaqueLeaseID()
	if err != nil {
		slice.ExplicitBzero(owned)
		return &protocol.MintOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "failed to generate opaque lease ID",
		}, nil
	}

	envVar := req.EffectiveEnvVar()
	expiresAt := now.Add(req.LeaseTTL)

	ol := &opaqueLease{
		leaseID:      leaseID,
		sessionID:    req.SessionID,
		secretName:   req.SecretName,
		targetEnvVar: envVar,
		peerUID:      peer.UID,
		hasPeerUID:   true,
		secretBytes:  owned,
		createdAt:    now,
		expiresAt:    expiresAt,
		singleUse:    true,
		spiffeID:     req.SpiffeID,
	}

	// Proactively zeroize and delete on TTL expiration even if never redeemed.
	ol.expiryTimer = time.AfterFunc(req.LeaseTTL, func() {
		lm.expireOpaqueLease(leaseID)
	})

	if lm.opaqueLeases == nil {
		lm.opaqueLeases = make(map[string]*opaqueLease)
	}
	lm.opaqueLeases[leaseID] = ol

	// Record non-secret metadata in activeLeases for GetLease/ListLeases observability.
	lm.activeLeases[leaseID] = &ActiveLease{
		LeaseID:          leaseID,
		SecretName:       req.SecretName,
		ClientPID:        peer.PID,
		ProcessStartTime: peer.StartTime,
		ClientBinaryPath: peer.ExePath,
		ClientBinaryHash: peer.ExeHash,
		SpiffeID:         req.SpiffeID,
		CreatedAt:        now,
		ExpiresAt:        expiresAt,
		MaxUses:          1,
		UsesCount:        0,
		Revoked:          false,
	}

	lm.logOpaqueAudit(req.SecretName, req.SpiffeID, peer, audit.OutcomeGranted, fmt.Sprintf("opaque lease minted (TTL: %s, delivery: %s)", req.LeaseTTL, protocol.DeliveryModeFD3Slice))

	return &protocol.MintOpaqueLeaseResponse{
		Status:    protocol.StatusGranted,
		LeaseID:   leaseID,
		EnvVar:    envVar,
		ExpiresAt: expiresAt.UTC(),
		Delivery:  protocol.DeliveryModeFD3Slice,
	}, nil
}

// RedeemOpaqueLease validates session_id exact match, peer UID match, expiration, and single-use
// semantics, immediately deleting and zeroing the stored secret bytes on redemption or expiry.
func (lm *LeaseManager) RedeemOpaqueLease(req *protocol.RedeemOpaqueLeaseRequest, peer *protocol.PeerCredentials) (*protocol.RedeemOpaqueLeaseResponse, error) {
	if err := req.Validate(); err != nil {
		lm.logOpaqueAudit("", "", peer, audit.OutcomeDenied, err.Error())
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}
	if err := validateOpaquePeer(req.ClientPID, req.ProcessStartTime, req.ClientBinaryHash, peer, lm.opts.AllowBinaries, lm.opts.DenyBinaries); err != nil {
		lm.logOpaqueAudit("", "", peer, audit.OutcomeDenied, err.Error())
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  err.Error(),
		}, nil
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "lease manager is shutting down",
		}, nil
	}

	now := time.Now()
	lm.scavengeExpiredOpaqueLeasesLocked(now)

	ol, exists := lm.opaqueLeases[req.LeaseID]
	if !exists || ol == nil {
		lm.logOpaqueAudit("", "", peer, audit.OutcomeDenied, "opaque lease not found, expired, or already redeemed")
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "opaque lease not found, expired, or already redeemed",
		}, nil
	}

	if now.After(ol.expiresAt) {
		ol.zeroAndStop()
		delete(lm.opaqueLeases, req.LeaseID)
		delete(lm.activeLeases, req.LeaseID)
		lm.logOpaqueAudit(ol.secretName, ol.spiffeID, peer, audit.OutcomeDenied, "opaque lease expired")
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "opaque lease expired",
		}, nil
	}

	// Enforce exact session_id match in constant time (blocks cross-session hijack).
	if subtle.ConstantTimeCompare([]byte(ol.sessionID), []byte(req.SessionID)) != 1 {
		lm.logOpaqueAudit(ol.secretName, ol.spiffeID, peer, audit.OutcomeDenied, "opaque lease session_id mismatch")
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "opaque lease denied: session mismatch",
		}, nil
	}

	// Enforce peer UID match when authenticated over UDS.
	if ol.hasPeerUID && peer.UID != ol.peerUID {
		lm.logOpaqueAudit(ol.secretName, ol.spiffeID, peer, audit.OutcomeDenied, fmt.Sprintf("opaque lease peer UID mismatch: caller %d != owner %d", peer.UID, ol.peerUID))
		return &protocol.RedeemOpaqueLeaseResponse{
			Status: protocol.StatusDenied,
			Error:  "opaque lease denied: peer UID mismatch",
		}, nil
	}

	// Single-use redemption: encode, immediately zeroize stored secret bytes, and delete lease.
	secretB64 := base64.StdEncoding.EncodeToString(ol.secretBytes)
	envVar := ol.targetEnvVar
	expiresAt := ol.expiresAt.UTC()
	secretName := ol.secretName
	spiffeID := ol.spiffeID

	ol.zeroAndStop()
	delete(lm.opaqueLeases, req.LeaseID)
	delete(lm.activeLeases, req.LeaseID)

	lm.logOpaqueAudit(secretName, spiffeID, peer, audit.OutcomeGranted, "opaque lease redeemed (single-use wiped)")

	return &protocol.RedeemOpaqueLeaseResponse{
		Status:    protocol.StatusGranted,
		LeaseID:   req.LeaseID,
		EnvVar:    envVar,
		SecretB64: secretB64,
		ExpiresAt: expiresAt,
	}, nil
}

func (lm *LeaseManager) expireOpaqueLease(leaseID string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if ol, ok := lm.opaqueLeases[leaseID]; ok {
		ol.zeroAndStop()
		delete(lm.opaqueLeases, leaseID)
		delete(lm.activeLeases, leaseID)
	}
}

func (lm *LeaseManager) scavengeExpiredOpaqueLeasesLocked(now time.Time) {
	for id, ol := range lm.opaqueLeases {
		if ol == nil || now.After(ol.expiresAt) {
			ol.zeroAndStop()
			delete(lm.opaqueLeases, id)
			delete(lm.activeLeases, id)
		}
	}
}

func validateOpaquePeer(clientPID int, startTime int64, binaryHash string, peer *protocol.PeerCredentials, allowBinaries, denyBinaries []string) error {
	if peer == nil {
		return errors.New("peer credentials required")
	}
	if peer.PID <= 0 {
		return errors.New("kernel peer PID required")
	}
	if clientPID > 0 && peer.PID != clientPID {
		return fmt.Errorf("peer PID spoofing detected: kernel PID %d != payload PID %d", peer.PID, clientPID)
	}
	if startTime > 0 && peer.StartTime > 0 && peer.StartTime != startTime {
		return fmt.Errorf("process start time mismatch: kernel %d != payload %d", peer.StartTime, startTime)
	}
	if binaryHash != "" && peer.ExeHash != "" && !strings.EqualFold(binaryHash, peer.ExeHash) {
		return fmt.Errorf("client binary hash mismatch: kernel %s != payload %s", peer.ExeHash, binaryHash)
	}
	return CheckBinaryAccessForExecutable(peer.ExePath, peer.ExeHash, allowBinaries, denyBinaries)
}

func (lm *LeaseManager) logOpaqueAudit(secretName, spiffeID string, peer *protocol.PeerCredentials, outcome audit.Outcome, reason string) {
	identity := spiffeID
	peerPID := 0
	peerPath := ""
	peerHash := ""
	if peer != nil {
		peerPID = peer.PID
		peerPath = peer.ExePath
		peerHash = peer.ExeHash
		if identity == "" {
			identity = fmt.Sprintf("pid:%d", peer.PID)
		}
	}
	if identity == "" {
		identity = "etx:opaque_lease"
	}
	_ = audit.Log(audit.Event{
		SecretName: secretName,
		ClientPID:  peerPID,
		BinaryPath: peerPath,
		BinaryHash: peerHash,
		Identity:   identity,
		Outcome:    outcome,
		Reason:     reason,
	})
}
