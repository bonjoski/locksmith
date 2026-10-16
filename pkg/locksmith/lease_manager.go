package locksmith

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// ActiveLease represents an in-flight ephemeral credential lease.
type ActiveLease struct {
	LeaseID          string
	SecretName       string
	ClientPID        int
	ProcessStartTime int64
	ClientBinaryHash string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	MaxUses          int
	UsesCount        int
	SessionTicketID  string
	Revoked          bool
	cancelWatcher    func()
}

// LeaseManagerOptions configures the lease lifecycle parameters.
type LeaseManagerOptions struct {
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	WatchInterval  time.Duration
	RequireBioAuth bool
}

// SecretGetter abstracts the secret retrieval source (e.g. *Locksmith).
type SecretGetter interface {
	Get(key string) ([]byte, error)
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

// RequestLease evaluates a lease request against peer credentials and policy.
func (lm *LeaseManager) RequestLease(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) (*protocol.LeaseResponse, error) {
	if err := req.Validate(); err != nil {
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	if err := validatePeerCreds(req, peer); err != nil {
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.closed {
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: "lease manager is shutting down"}, nil
	}

	if req.SessionTicket != "" {
		if err := lm.verifySessionTicket(req.SessionTicket, req.SecretName); err != nil {
			return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
		}
	}

	secretBytes, err := lm.fetchSecret(req.SecretName)
	if err != nil {
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: err.Error()}, nil
	}

	ttl := lm.calculateTTL(req.LeaseTTL)
	leaseID, err := generateLeaseID()
	if err != nil {
		return &protocol.LeaseResponse{Status: protocol.StatusDenied, Error: "failed to generate lease ID"}, nil
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	active := &ActiveLease{
		LeaseID:          leaseID,
		SecretName:       req.SecretName,
		ClientPID:        peer.PID,
		ProcessStartTime: peer.StartTime,
		ClientBinaryHash: peer.ExeHash,
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

	go lm.watchLeaseLiveness(leaseID, peer.PID, peer.StartTime, expiresAt, watcherStop)

	lm.activeLeases[leaseID] = active

	return &protocol.LeaseResponse{
		Status:        protocol.StatusGranted,
		LeaseID:       leaseID,
		SecretValue:   secretBytes,
		ExpiresAt:     expiresAt,
		SessionTicket: req.SessionTicket,
	}, nil
}

func validatePeerCreds(req *protocol.LeaseRequest, peer *protocol.PeerCredentials) error {
	if peer == nil {
		return errors.New("peer credentials required")
	}
	// ADV-01: Peer PID validation (Kernel vs Payload)
	if peer.PID != req.ClientPID {
		return fmt.Errorf("peer PID spoofing detected: kernel PID %d != payload PID %d", peer.PID, req.ClientPID)
	}
	// ADV-02: PID Recycling protection via StartTime
	if peer.StartTime > 0 && req.ProcessStartTime > 0 && peer.StartTime != req.ProcessStartTime {
		return fmt.Errorf("process start time mismatch: kernel %d != payload %d (possible PID recycling)", peer.StartTime, req.ProcessStartTime)
	}
	return nil
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

func (lm *LeaseManager) fetchSecret(secretName string) ([]byte, error) {
	if lm.store == nil {
		return nil, errors.New("locksmith secret store not configured")
	}
	secretBytes, err := lm.store.Get(secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}
	if secretBytes == nil {
		return nil, fmt.Errorf("secret %q not found", secretName)
	}
	return secretBytes, nil
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
				lm.expireLease(leaseID)
				return
			}

			// Check process liveness
			if !isProcessAlive(pid, startTime) {
				lm.expireLease(leaseID)
				return
			}
		}
	}
}

func (lm *LeaseManager) expireLease(leaseID string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lease, exists := lm.activeLeases[leaseID]; exists {
		lm.revokeLocked(lease)
		delete(lm.activeLeases, leaseID)
	}
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

// isProcessAlive returns true if the PID exists and hasn't been recycled.
func isProcessAlive(pid int, recordedStartTime int64) bool {
	if pid <= 0 {
		return false
	}

	// 1. Send signal 0 to test process existence
	err := syscall.Kill(pid, 0)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			// Process does not exist
			return false
		}
		// If err is EPERM, process exists but belongs to another user
	}

	// 2. Cross-verify start time to guard against PID recycling (VAL-02)
	if recordedStartTime > 0 {
		currStartTime, err := protocol.GetProcessStartTime(pid)
		if err != nil || currStartTime != recordedStartTime {
			return false
		}
	}

	return true
}
