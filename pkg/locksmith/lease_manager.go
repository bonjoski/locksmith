package locksmith

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/audit"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// ActiveLease represents an in-flight ephemeral credential lease.
type ActiveLease struct {
	LeaseID          string    `json:"lease_id"`
	SecretName       string    `json:"secret_name"`
	ClientPID        int       `json:"client_pid"`
	ProcessStartTime int64     `json:"process_start_time"`
	ClientBinaryPath string    `json:"client_binary_path,omitempty"`
	ClientBinaryHash string    `json:"client_binary_hash"`
	SpiffeID         string    `json:"spiffe_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	MaxUses          int       `json:"max_uses"`
	UsesCount        int       `json:"uses_count"`
	SessionTicketID  string    `json:"-"`
	Revoked          bool      `json:"revoked"`
	cancelWatcher    func()
}

// LeaseManagerOptions configures the lease lifecycle parameters.
type LeaseManagerOptions struct {
	DefaultTTL               time.Duration
	MaxTTL                   time.Duration
	WatchInterval            time.Duration
	RequireBioAuth           bool
	DisableAmbientEnv        bool
	AllowBinaries            []string
	DenyBinaries             []string
	SpiffeRootCA             *x509.Certificate
	RequireSpiffeAttestation bool
}

// SecretGetter abstracts the secret retrieval source (e.g. *Locksmith).
type SecretGetter interface {
	Get(key string) ([]byte, error)
}

type peerSecretGetter interface {
	GetForPeer(key string, peer *protocol.PeerCredentials) ([]byte, error)
}

// LeaseManager orchestrates ephemeral secret leases, PID liveness monitoring,
// and session ticket lifecycle for agentic runtimes.
type LeaseManager struct {
	mu            sync.RWMutex
	store         SecretGetter
	opts          LeaseManagerOptions
	activeLeases  map[string]*ActiveLease
	sessionTokens map[string]*protocol.SessionTicket
	stopChan      chan struct{}
	closed        bool
}

// NewLeaseManager initializes a new thread-safe lease manager.
func NewLeaseManager(store SecretGetter, opts ...LeaseManagerOptions) *LeaseManager {
	opt := LeaseManagerOptions{
		DefaultTTL:    5 * time.Minute,
		MaxTTL:        1 * time.Hour,
		WatchInterval: 500 * time.Millisecond,
	}
	if len(opts) > 0 {
		if opts[0].DefaultTTL > 0 {
			opt.DefaultTTL = opts[0].DefaultTTL
		}
		if opts[0].MaxTTL > 0 {
			opt.MaxTTL = opts[0].MaxTTL
		}
		if opts[0].WatchInterval > 0 {
			opt.WatchInterval = opts[0].WatchInterval
		}
		opt.RequireBioAuth = opts[0].RequireBioAuth
		opt.DisableAmbientEnv = opts[0].DisableAmbientEnv
		opt.AllowBinaries = append([]string(nil), opts[0].AllowBinaries...)
		opt.DenyBinaries = append([]string(nil), opts[0].DenyBinaries...)
		opt.SpiffeRootCA = opts[0].SpiffeRootCA
		opt.RequireSpiffeAttestation = opts[0].RequireSpiffeAttestation
	}

	lm := &LeaseManager{
		store:         store,
		opts:          opt,
		activeLeases:  make(map[string]*ActiveLease),
		sessionTokens: make(map[string]*protocol.SessionTicket),
		stopChan:      make(chan struct{}),
	}

	return lm
}

func generateLeaseID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ls-lease-" + hex.EncodeToString(b), nil
}

func (lm *LeaseManager) verifySpiffeSVID(req *protocol.LeaseRequest) (bool, error) {
	if req.SpiffeID == "" {
		return false, nil
	}
	if req.SpiffeSVID == "" {
		if lm.opts.RequireSpiffeAttestation || lm.opts.SpiffeRootCA != nil {
			return false, errors.New("unattested spiffe_id rejected: cryptographic X.509-SVID required")
		}
		return false, nil
	}
	if lm.opts.SpiffeRootCA == nil {
		return false, errors.New("spiffe_svid rejected: no SPIFFE Root CA configured")
	}

	block, _ := pem.Decode([]byte(req.SpiffeSVID))
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("invalid spiffe_svid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed parsing spiffe_svid certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(lm.opts.SpiffeRootCA)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		return false, fmt.Errorf("spiffe_svid verification failed: %w", err)
	}

	matchedSAN := false
	for _, u := range cert.URIs {
		if u != nil && u.String() == req.SpiffeID {
			matchedSAN = true
			break
		}
	}
	if !matchedSAN {
		return false, fmt.Errorf("spiffe_svid URI SAN does not match requested spiffe_id %q", req.SpiffeID)
	}
	return true, nil
}

func normalizeSpiffeRequest(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) {
	if req.SpiffeID == "" {
		return
	}
	if req.LeaseTTL <= 0 || req.LeaseTTL > 300*time.Second {
		req.LeaseTTL = 300 * time.Second
	} else if req.LeaseTTL < 60*time.Second {
		req.LeaseTTL = 60 * time.Second
	}
	if peer != nil && req.ClientPID == 0 && req.ProcessStartTime == 0 {
		req.ClientPID = peer.PID
		req.ProcessStartTime = peer.StartTime
	}
}

// RequestLease evaluates a lease request against peer credentials and policy.
func (lm *LeaseManager) RequestLease(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) (*protocol.LeaseResponse, error) {
	if err := req.Validate(); err != nil {
		lm.logLeaseDenied(req, peer, err.Error())
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	spiffeAttested, svidErr := lm.verifySpiffeSVID(req)
	if svidErr != nil {
		lm.logLeaseDenied(req, peer, svidErr.Error())
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: svidErr.Error()}, nil
	}

	normalizeSpiffeRequest(req, peer)

	if err := validatePeerCreds(req, peer, spiffeAttested); err != nil {
		lm.logLeaseDenied(req, peer, err.Error())
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	if peer != nil {
		if err := CheckBinaryAccessForExecutable(peer.ExePath, peer.ExeHash, lm.opts.AllowBinaries, lm.opts.DenyBinaries); err != nil {
			lm.logLeaseDenied(req, peer, err.Error())
			return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
		}
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		lm.logLeaseDenied(req, peer, "lease manager is shutting down")
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: "lease manager is shutting down"}, nil
	}

	if req.SessionTicket != "" {
		if err := lm.verifySessionTicket(req.SessionTicket, req.SecretName); err != nil {
			lm.logLeaseDenied(req, peer, err.Error())
			return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
		}
	}

	secretBytes, err := lm.fetchSecret(req.SecretName, peer)
	if err != nil {
		lm.logLeaseDenied(req, peer, err.Error())
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	ttl := lm.calculateTTL(req.LeaseTTL)
	leaseID, err := generateLeaseID()
	if err != nil {
		lm.logLeaseDenied(req, peer, "failed to generate lease ID")
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: "failed to generate lease ID"}, nil
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	peerPID := 0
	peerStartTime := int64(0)
	peerExePath := ""
	peerExeHash := ""
	if peer != nil {
		peerPID = peer.PID
		peerStartTime = peer.StartTime
		peerExePath = peer.ExePath
		peerExeHash = peer.ExeHash
	}

	active := &ActiveLease{
		LeaseID:          leaseID,
		SecretName:       req.SecretName,
		ClientPID:        peerPID,
		ProcessStartTime: peerStartTime,
		ClientBinaryPath: peerExePath,
		ClientBinaryHash: peerExeHash,
		SpiffeID:         req.SpiffeID,
		CreatedAt:        now,
		ExpiresAt:        expiresAt,
		MaxUses:          req.MaxUses,
		UsesCount:        1,
		SessionTicketID:  req.SessionTicket,
		Revoked:          false,
	}

	// VAL-05: Active PID Liveness Watcher & Expiration Ticker
	watcherStop := make(chan struct{})
	active.cancelWatcher = func() {
		select {
		case <-watcherStop:
		default:
			close(watcherStop)
		}
	}

	if peerPID > 0 {
		go lm.watchLeaseLiveness(leaseID, peerPID, peerStartTime, expiresAt, watcherStop)
	}

	lm.activeLeases[leaseID] = active
	lm.logLeaseGranted(req, peer, ttl)

	return &protocol.LeaseResponse{
		Status:        protocol.StatusGranted,
		LeaseID:       leaseID,
		SecretValue:   secretBytes,
		ExpiresAt:     expiresAt,
		SessionTicket: req.SessionTicket,
		SpiffeID:      req.SpiffeID,
		TTLSeconds:    int64(ttl.Seconds()),
	}, nil
}

func validateAttestedPeerCreds(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) error {
	if req.ClientPID > 0 && peer.PID > 0 && peer.PID != req.ClientPID {
		return fmt.Errorf("peer PID spoofing detected: kernel PID %d != payload PID %d", peer.PID, req.ClientPID)
	}
	if req.ClientPID > 0 && peer.StartTime > 0 && req.ProcessStartTime > 0 && peer.StartTime != req.ProcessStartTime {
		return fmt.Errorf("process start time mismatch: kernel %d != payload %d (possible PID recycling)", peer.StartTime, req.ProcessStartTime)
	}
	return nil
}

func validateUnattestedPeerCreds(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) error {
	if peer.PID <= 0 {
		return errors.New("kernel peer PID required for unattested lease request")
	}
	if peer.PID != req.ClientPID {
		return fmt.Errorf("peer PID spoofing detected: kernel PID %d != payload PID %d", peer.PID, req.ClientPID)
	}
	if peer.StartTime > 0 && peer.StartTime != req.ProcessStartTime {
		return fmt.Errorf("process start time mismatch: kernel %d != payload %d (possible PID recycling)", peer.StartTime, req.ProcessStartTime)
	}
	return nil
}

func validatePeerCreds(req *protocol.LeaseRequest, peer *protocol.PeerCredentials, spiffeAttested bool) error {
	if peer == nil {
		return errors.New("peer credentials required")
	}

	if req.ClientBinaryHash != "" && peer.ExeHash != "" && !strings.EqualFold(req.ClientBinaryHash, peer.ExeHash) {
		return fmt.Errorf("client binary hash mismatch: kernel %s != payload %s", peer.ExeHash, req.ClientBinaryHash)
	}

	// Only cryptographically attested X.509-SVID requests may omit host PID/start-time binding
	// (e.g. a verified microVM workload identity). Caller-supplied JSON SpiffeID fields over
	// plain UDS MUST NEVER bypass kernel PID or start-time binding (LCK-03).
	if spiffeAttested {
		return validateAttestedPeerCreds(req, peer)
	}
	return validateUnattestedPeerCreds(req, peer)
}

func (lm *LeaseManager) verifySessionTicket(ticketID, secretName string) error {
	st, exists := lm.sessionTokens[ticketID]
	if !exists || st.IsExpired() {
		return errors.New("session ticket invalid or expired")
	}
	if !st.PermitsSecret(secretName) {
		return fmt.Errorf("session ticket does not permit access to secret %q", secretName)
	}
	return nil
}

func (lm *LeaseManager) fetchSecret(secretName string, peer *protocol.PeerCredentials) ([]byte, error) {
	if lm.store != nil {
		var (
			secretBytes []byte
			err         error
		)
		if ps, ok := lm.store.(peerSecretGetter); ok {
			secretBytes, err = ps.GetForPeer(secretName, peer)
		} else {
			secretBytes, err = lm.store.Get(secretName)
		}
		if err != nil {
			if lm.opts.DisableAmbientEnv || strings.Contains(err.Error(), "access control") || strings.Contains(err.Error(), "allowed list") {
				return nil, err
			}
		} else if len(secretBytes) > 0 {
			return secretBytes, nil
		}
	}
	if !lm.opts.DisableAmbientEnv {
		// Ambient environment fallback for ambient secrets when explicitly enabled (not MCP)
		if val := os.Getenv(secretName); val != "" {
			return []byte(val), nil
		}
	}
	if lm.store == nil {
		return nil, errors.New("locksmith secret store not configured")
	}
	if lm.opts.DisableAmbientEnv {
		return nil, fmt.Errorf("secret %q not found in vault", secretName)
	}
	return nil, fmt.Errorf("secret %q not found in vault or ambient environment", secretName)
}

func (lm *LeaseManager) calculateTTL(reqTTL time.Duration) time.Duration {
	ttl := reqTTL
	if ttl <= 0 {
		ttl = lm.opts.DefaultTTL
	}
	if ttl > lm.opts.MaxTTL {
		ttl = lm.opts.MaxTTL
	}
	return ttl
}

// RevokeLease cancels an active lease, zeroing any residual tracking.
func (lm *LeaseManager) RevokeLease(req *protocol.RevokeRequest, peer *protocol.PeerCredentials) (*protocol.RevokeResponse, error) {
	if req.LeaseID == "" {
		return &protocol.RevokeResponse{Success: false, Error: "lease_id required"}, nil
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	lease, exists := lm.activeLeases[req.LeaseID]
	if !exists {
		// Already revoked or expired
		return &protocol.RevokeResponse{Success: true}, nil
	}

	// Ensure only the owner PID or privileged supervisor can revoke
	if peer != nil && peer.PID != lease.ClientPID {
		return &protocol.RevokeResponse{
			Success: false,
			Error:   fmt.Sprintf("unauthorized revocation: caller PID %d != lease PID %d", peer.PID, lease.ClientPID),
		}, nil
	}

	lm.revokeLocked(lease)
	delete(lm.activeLeases, req.LeaseID)
	lm.logLeaseRevoked(lease, "Lease revoked by client")

	return &protocol.RevokeResponse{Success: true}, nil
}

func (lm *LeaseManager) revokeLocked(lease *ActiveLease) {
	if lease == nil || lease.Revoked {
		return
	}
	lease.Revoked = true
	if lease.cancelWatcher != nil {
		lease.cancelWatcher()
	}
}

// CreateSession allocates a session ticket allowing multiple sub-commands to proceed.
func (lm *LeaseManager) CreateSession(pgid int, ttl time.Duration, allowedSecrets []string) (*protocol.SessionTicket, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if len(allowedSecrets) == 0 {
		allowedSecrets = []string{"*"}
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ticketID := "sess-" + hex.EncodeToString(b)

	now := time.Now()
	ticket := &protocol.SessionTicket{
		TicketID:       ticketID,
		PGID:           pgid,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		AllowedSecrets: allowedSecrets,
	}

	lm.mu.Lock()
	lm.sessionTokens[ticketID] = ticket
	lm.mu.Unlock()

	return ticket, nil
}

// RevokeSession immediately voids an active session ticket.
func (lm *LeaseManager) RevokeSession(ticketID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.sessionTokens, ticketID)
	return nil
}

// ActiveCount returns current active leases.
func (lm *LeaseManager) ActiveCount() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.activeLeases)
}

// ListLeases returns snapshots of all currently active ephemeral leases.
func (lm *LeaseManager) ListLeases() []*ActiveLease {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	leases := make([]*ActiveLease, 0, len(lm.activeLeases))
	for _, lease := range lm.activeLeases {
		cp := *lease
		leases = append(leases, &cp)
	}
	return leases
}

// GetLease returns a snapshot of an active lease (for testing and audit).
func (lm *LeaseManager) GetLease(leaseID string) (*ActiveLease, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	lease, exists := lm.activeLeases[leaseID]
	if !exists {
		return nil, false
	}
	cp := *lease
	return &cp, true
}

// watchLeaseLiveness runs in a goroutine to proactively scavenge orphaned leases (VAL-05).
func (lm *LeaseManager) watchLeaseLiveness(leaseID string, pid int, startTime int64, expiresAt time.Time, stopChan <-chan struct{}) {
	ticker := time.NewTicker(lm.opts.WatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-lm.stopChan:
			return
		case now := <-ticker.C:
			// Check expiration
			if now.After(expiresAt) {
				lm.expireLease(leaseID, "Lease TTL expired")
				return
			}

			// Check process liveness
			if !isProcessAlive(pid, startTime) {
				lm.expireLease(leaseID, "Client process terminated")
				return
			}
		}
	}
}

func (lm *LeaseManager) expireLease(leaseID string, reason string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lease, exists := lm.activeLeases[leaseID]; exists {
		lm.revokeLocked(lease)
		delete(lm.activeLeases, leaseID)
		lm.logLeaseRevoked(lease, reason)
	}
}

func (lm *LeaseManager) logLeaseGranted(req *protocol.LeaseRequest, peer *protocol.PeerCredentials, ttl time.Duration) {
	identity := req.SpiffeID
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
		identity = "etx:lease"
	}
	_ = audit.Log(audit.Event{
		SecretName: req.SecretName,
		ClientPID:  peerPID,
		BinaryPath: peerPath,
		BinaryHash: peerHash,
		Identity:   identity,
		Outcome:    audit.OutcomeGranted,
		Reason:     fmt.Sprintf("ETX lease granted (TTL: %s)", ttl),
	})
}

func (lm *LeaseManager) logLeaseDenied(req *protocol.LeaseRequest, peer *protocol.PeerCredentials, reason string) {
	secretName := ""
	identity := ""
	peerPID := 0
	peerPath := ""
	peerHash := ""
	if req != nil {
		secretName = req.SecretName
		identity = req.SpiffeID
	}
	if peer != nil {
		peerPID = peer.PID
		peerPath = peer.ExePath
		peerHash = peer.ExeHash
		if identity == "" {
			identity = fmt.Sprintf("pid:%d", peer.PID)
		}
	}
	if identity == "" {
		identity = "etx:lease"
	}
	_ = audit.Log(audit.Event{
		SecretName: secretName,
		ClientPID:  peerPID,
		BinaryPath: peerPath,
		BinaryHash: peerHash,
		Identity:   identity,
		Outcome:    audit.OutcomeDenied,
		Reason:     reason,
	})
}

func (lm *LeaseManager) logLeaseRevoked(lease *ActiveLease, reason string) {
	if lease == nil {
		return
	}
	identity := lease.SpiffeID
	if identity == "" {
		identity = fmt.Sprintf("pid:%d", lease.ClientPID)
	}
	_ = audit.Log(audit.Event{
		SecretName: lease.SecretName,
		ClientPID:  lease.ClientPID,
		BinaryPath: lease.ClientBinaryPath,
		BinaryHash: lease.ClientBinaryHash,
		Identity:   identity,
		Outcome:    audit.OutcomeRevoked,
		Reason:     reason,
	})
}

// Close stops all active lease monitors.
func (lm *LeaseManager) Close() error {
	lm.mu.Lock()
	if lm.closed {
		lm.mu.Unlock()
		return nil
	}
	lm.closed = true
	close(lm.stopChan)

	for _, lease := range lm.activeLeases {
		lm.revokeLocked(lease)
	}
	lm.activeLeases = make(map[string]*ActiveLease)
	lm.sessionTokens = make(map[string]*protocol.SessionTicket)
	lm.mu.Unlock()
	return nil
}

