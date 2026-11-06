package spiffe

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"golang.org/x/time/rate"
)

type contextKey string

const (
	identityContextKey    contextKey = "caller_identity"
	attestErrContextKey   contextKey = "attest_error"
	tcpBridgeContextKey   contextKey = "tcp_bridge"
	bridgeDomainSeparator            = "locksmith-spiffe-bridge-v1:cid:"
)

// BridgeTokenDeriver computes and verifies domain-separated CID bridge tokens.
type BridgeTokenDeriver struct {
	masterKey []byte
}

// NewBridgeTokenDeriver creates a deriver with a defensive copy of the master key.
// The masterKey must be at least 32 bytes to ensure cryptographic security.
func NewBridgeTokenDeriver(masterKey []byte) (*BridgeTokenDeriver, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master key must be at least 32 bytes (got %d)", len(masterKey))
	}
	keyCopy := make([]byte, len(masterKey))
	copy(keyCopy, masterKey)
	return &BridgeTokenDeriver{masterKey: keyCopy}, nil
}

// DeriveToken calculates the authoritative HMAC-SHA256 token for a given microVM CID.
func (d *BridgeTokenDeriver) DeriveToken(cid uint32) string {
	if d == nil || len(d.masterKey) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, d.masterKey)
	h.Write([]byte(bridgeDomainSeparator + strconv.FormatUint(uint64(cid), 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyToken verifies whether candidateToken matches cid in constant time.
func (d *BridgeTokenDeriver) VerifyToken(cid uint32, candidateToken string) bool {
	if d == nil || len(d.masterKey) == 0 || candidateToken == "" {
		return false
	}
	expected := d.DeriveToken(cid)
	return subtle.ConstantTimeCompare([]byte(candidateToken), []byte(expected)) == 1
}

// ServerConfig configures the SPIFFE Workload API listener.
type ServerConfig struct {
	SocketPath             string
	VsockPort              uint32
	BridgeToken            string
	BridgeKey              []byte     // 32-byte master HMAC key for per-CID token derivation
	AllowSharedBridgeToken bool       // Permit static BridgeToken across multiple CIDs
	TrustDomain            string
	Policy                 *Policy
	Attestor               WorkloadAttestor
	CA                     *ca.CA
	RateLimit              rate.Limit // requests per second per UID
	BurstLimit             int
}

// WorkloadServer serves the SPIFFE Workload API over a Unix Domain Socket and optional vsock bridge.
type WorkloadServer struct {
	cfg           ServerConfig
	deriver       *BridgeTokenDeriver
	listener      net.Listener
	vsockListener net.Listener
	httpServer    *http.Server
	vsockServer   *http.Server
	rateMu        sync.Mutex
	rateLimiters  map[uint32]*rate.Limiter
}

func applyDefaultSocketPath(cfg *ServerConfig) error {
	if cfg.SocketPath != "" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to determine user home directory: %w", err)
	}
	cfg.SocketPath = filepath.Join(home, ".locksmith", "spiffe", "workload.sock")
	return nil
}

func applyDefaultLimitsAndKeys(cfg *ServerConfig) {
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = rate.Limit(10) // 10 requests per second
	}
	if cfg.BurstLimit <= 0 {
		cfg.BurstLimit = 20
	}
	if cfg.VsockPort > 0 && len(cfg.BridgeKey) == 0 && cfg.BridgeToken == "" {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err == nil {
			cfg.BridgeKey = keyBytes
		}
	}
}

func applyDefaultServerConfig(cfg *ServerConfig) error {
	if cfg.CA == nil {
		return errors.New("root CA is required for SPIFFE Workload Server")
	}
	if err := applyDefaultSocketPath(cfg); err != nil {
		return err
	}
	if cfg.Attestor == nil {
		cfg.Attestor = NewAttestor()
	}
	if cfg.Policy == nil {
		cfg.Policy = NewDefaultPolicy(cfg.TrustDomain)
	}
	applyDefaultLimitsAndKeys(cfg)
	return nil
}

func parseVsockAddr(addr net.Addr) (uint32, error) {
	if addr == nil {
		return 0, errors.New("missing vsock peer address")
	}
	addrStr := strings.TrimSpace(addr.String())
	clean := addrStr
	if strings.HasPrefix(clean, "vsock://") {
		clean = strings.TrimPrefix(clean, "vsock://")
	} else if strings.HasPrefix(clean, "vsock:") {
		clean = strings.TrimPrefix(clean, "vsock:")
	}
	clean = strings.Trim(clean, "<> ")
	if strings.HasPrefix(clean, "vm(") {
		if idx := strings.Index(clean, ")"); idx != -1 {
			clean = clean[3:idx] + clean[idx+1:]
		}
	}
	parts := strings.Split(clean, ":")
	if len(parts) >= 1 {
		cidPart := strings.TrimSpace(parts[0])
		if parsed, err := strconv.ParseUint(cidPart, 10, 32); err == nil && parsed >= 3 {
			return uint32(parsed), nil
		}
	}
	return 0, fmt.Errorf("unable to determine peer CID from vsock address %q", addrStr)
}

func (ws *WorkloadServer) connContext(ctx context.Context, c net.Conn) context.Context {
	if c.RemoteAddr() != nil {
		switch c.RemoteAddr().Network() {
		case "tcp":
			return context.WithValue(ctx, tcpBridgeContextKey, true)
		case "vsock":
			cid, err := parseVsockAddr(c.RemoteAddr())
			if err != nil {
				return context.WithValue(ctx, attestErrContextKey, fmt.Errorf("%w: %v", ErrAttestationFailed, err))
			}
			identity := &CallerIdentity{
				VsockCID:  cid,
				Comm:      "vsock-vm",
				StartTime: time.Now(),
			}
			return context.WithValue(ctx, identityContextKey, identity)
		}
	}
	identity, err := ws.cfg.Attestor.AttestPeer(c)
	if err != nil {
		return context.WithValue(ctx, attestErrContextKey, err)
	}
	return context.WithValue(ctx, identityContextKey, identity)
}

// NewWorkloadServer creates a new WorkloadServer instance.
func NewWorkloadServer(cfg ServerConfig) (*WorkloadServer, error) {
	if err := applyDefaultServerConfig(&cfg); err != nil {
		return nil, err
	}

	ws := &WorkloadServer{
		cfg:          cfg,
		rateLimiters: make(map[uint32]*rate.Limiter),
	}
	if len(cfg.BridgeKey) > 0 {
		deriver, err := NewBridgeTokenDeriver(cfg.BridgeKey)
		if err != nil {
			return nil, fmt.Errorf("invalid BridgeKey: %w", err)
		}
		ws.deriver = deriver
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", ws.handleHealth)
	mux.HandleFunc("/v1/bundle", ws.handleBundle)
	mux.HandleFunc("/v1/svid", ws.handleSVID)

	ws.httpServer = &http.Server{
		Handler:     mux,
		ConnContext: ws.connContext,
	}

	return ws, nil
}

// BridgeKey returns a copy of the active master HMAC key for CID token derivation.
func (ws *WorkloadServer) BridgeKey() []byte {
	if len(ws.cfg.BridgeKey) == 0 {
		return nil
	}
	keyCopy := make([]byte, len(ws.cfg.BridgeKey))
	copy(keyCopy, ws.cfg.BridgeKey)
	return keyCopy
}

// DeriveBridgeToken returns the authoritative token for cid.
func (ws *WorkloadServer) DeriveBridgeToken(cid uint32) string {
	if ws.deriver != nil {
		return ws.deriver.DeriveToken(cid)
	}
	return ws.cfg.BridgeToken
}

// BridgeToken returns the active authentication token for loopback TCP bridge requests.
func (ws *WorkloadServer) BridgeToken() string {
	if ws.deriver != nil && len(ws.cfg.Policy.AllowedCIDs) > 0 {
		return ws.deriver.DeriveToken(ws.cfg.Policy.AllowedCIDs[0])
	}
	return ws.cfg.BridgeToken
}

func (ws *WorkloadServer) checkRateLimit(uid uint32) bool {
	ws.rateMu.Lock()
	defer ws.rateMu.Unlock()

	limiter, exists := ws.rateLimiters[uid]
	if !exists {
		limiter = rate.NewLimiter(ws.cfg.RateLimit, ws.cfg.BurstLimit)
		ws.rateLimiters[uid] = limiter
	}
	return limiter.Allow()
}

func (ws *WorkloadServer) verifyBridgeTokenForCID(cid uint32, token string) bool {
	if token == "" {
		return false
	}
	if ws.deriver != nil && ws.deriver.VerifyToken(cid, token) {
		return true
	}
	if ws.cfg.BridgeToken != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(ws.cfg.BridgeToken)) == 1 {
			if len(ws.cfg.Policy.AllowedCIDs) <= 1 || ws.cfg.AllowSharedBridgeToken {
				return true
			}
		}
	}
	return false
}

func (ws *WorkloadServer) resolveBridgeCID(r *http.Request) (uint32, error) {
	cidHeader := r.Header.Get("X-Locksmith-CID")
	if cidHeader != "" {
		parsed, err := strconv.ParseUint(cidHeader, 10, 32)
		if err != nil || parsed == 0 {
			return 0, fmt.Errorf("%w: invalid X-Locksmith-CID %q", ErrUnauthorizedWorkload, cidHeader)
		}
		return uint32(parsed), nil
	}
	if len(ws.cfg.Policy.AllowedCIDs) == 1 {
		return ws.cfg.Policy.AllowedCIDs[0], nil
	}
	return 0, fmt.Errorf("%w: ambiguous microVM identity: X-Locksmith-CID is required when multiple CIDs are configured", ErrUnauthorizedWorkload)
}

func (ws *WorkloadServer) getTCPBridgeIdentity(r *http.Request) (*CallerIdentity, error) {
	token := r.Header.Get("X-Locksmith-Bridge-Token")
	if token == "" {
		return nil, fmt.Errorf("%w: missing X-Locksmith-Bridge-Token header", ErrUnauthorizedWorkload)
	}

	cid, err := ws.resolveBridgeCID(r)
	if err != nil {
		return nil, err
	}

	if !ws.cfg.Policy.isCIDAllowed(cid) {
		return nil, fmt.Errorf("%w: microVM CID %d not permitted by policy", ErrUnauthorizedWorkload, cid)
	}

	if !ws.verifyBridgeTokenForCID(cid, token) {
		return nil, fmt.Errorf("%w: invalid or unauthorized bridge token for microVM CID %d", ErrUnauthorizedWorkload, cid)
	}

	return &CallerIdentity{
		VsockCID:  cid,
		Comm:      "aegisbox-vm",
		StartTime: time.Now(),
	}, nil
}

func (ws *WorkloadServer) getIdentity(r *http.Request) (*CallerIdentity, error) {
	if isTCPBridge, _ := r.Context().Value(tcpBridgeContextKey).(bool); isTCPBridge {
		return ws.getTCPBridgeIdentity(r)
	}
	if errVal := r.Context().Value(attestErrContextKey); errVal != nil {
		if err, ok := errVal.(error); ok {
			return nil, err
		}
		return nil, ErrAttestationFailed
	}
	idVal := r.Context().Value(identityContextKey)
	if idVal == nil {
		return nil, ErrAttestationFailed
	}
	identity, ok := idVal.(*CallerIdentity)
	if !ok {
		return nil, ErrAttestationFailed
	}
	return identity, nil
}

func (ws *WorkloadServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (ws *WorkloadServer) handleBundle(w http.ResponseWriter, r *http.Request) {
	identity, err := ws.getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !ws.checkRateLimit(identity.UID) {
		http.Error(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	resp := BundleResponse{
		TrustDomain: ws.cfg.Policy.TrustDomain,
		CAPEM:       string(ws.cfg.CA.CertPEM),
	}
	if len(ws.cfg.CA.PQCCertPEM) > 0 {
		resp.PQCCAPEM = string(ws.cfg.CA.PQCCertPEM)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (ws *WorkloadServer) parseSVIDTTL(r *http.Request) time.Duration {
	ttlStr := r.URL.Query().Get("ttl")
	if ttlStr == "" {
		return ca.DefaultSVIDTTL
	}
	d, err := time.ParseDuration(ttlStr)
	if err != nil || d <= 0 {
		return ca.DefaultSVIDTTL
	}
	return d
}

func (ws *WorkloadServer) handleSVID(w http.ResponseWriter, r *http.Request) {
	identity, err := ws.getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !ws.checkRateLimit(identity.UID) {
		http.Error(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	reqSPIFFE := r.URL.Query().Get("spiffe_id")
	spiffeID, err := ws.cfg.Policy.ResolveSPIFFEID(identity, reqSPIFFE)
	if err != nil {
		http.Error(w, fmt.Sprintf("unauthorized: %v", err), http.StatusForbidden)
		return
	}

	ttl := ws.parseSVIDTTL(r)
	profile := &ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      ttl,
	}

	bundle, err := ws.cfg.CA.IssueDualSVID(profile)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to mint SVID: %v", err), http.StatusInternalServerError)
		return
	}

	// Zeroize private key in memory once served
	defer ca.ZeroBytes(bundle.KeyPEM)

	fp := fmt.Sprintf("%x", sha256.Sum256(bundle.CertPEM))
	resp := SVIDResponse{
		SPIFFEID:    spiffeID.String(),
		CertPEM:     string(bundle.CertPEM),
		KeyPEM:      string(bundle.KeyPEM),
		ChainPEM:    string(bundle.DualCertPEM),
		ExpiresAt:   time.Now().Add(ttl),
		Fingerprint: fp,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Start binds the Unix Domain Socket and begins serving requests.
func (ws *WorkloadServer) Start() error {
	socketDir := filepath.Dir(ws.cfg.SocketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory %s: %w", socketDir, err)
	}

	// Clean up stale socket file if it exists
	if err := os.Remove(ws.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket %s: %w", ws.cfg.SocketPath, err)
	}

	l, err := net.Listen("unix", ws.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", ws.cfg.SocketPath, err)
	}

	// Restrict permissions to user-owned 0600 (or 0660)
	if err := os.Chmod(ws.cfg.SocketPath, 0600); err != nil {
		if closeErr := l.Close(); closeErr != nil {
			return fmt.Errorf("failed to set socket permissions %s: %w (close error: %v)", ws.cfg.SocketPath, err, closeErr)
		}
		return fmt.Errorf("failed to set socket permissions %s: %w", ws.cfg.SocketPath, err)
	}

	ws.listener = l

	if ws.cfg.VsockPort > 0 {
		vl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ws.cfg.VsockPort))
		if err != nil {
			if closeErr := l.Close(); closeErr != nil {
				return fmt.Errorf("failed to listen on vsock bridge port %d: %w (close error: %v)", ws.cfg.VsockPort, err, closeErr)
			}
			return fmt.Errorf("failed to listen on vsock bridge port %d: %w", ws.cfg.VsockPort, err)
		}
		ws.vsockListener = vl
		ws.vsockServer = &http.Server{
			Handler:     ws.httpServer.Handler,
			ConnContext: ws.httpServer.ConnContext,
		}
		go func() {
			if serveErr := ws.vsockServer.Serve(vl); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				log.Printf("vsock bridge server exited: %v", serveErr)
			}
		}()
	}

	return ws.httpServer.Serve(l)
}

func shutdownServer(ctx context.Context, s *http.Server) error {
	if s == nil {
		return nil
	}
	return s.Shutdown(ctx)
}

func closeListener(l net.Listener) error {
	if l == nil {
		return nil
	}
	err := l.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Stop shuts down the server gracefully and removes the socket file.
func (ws *WorkloadServer) Stop(ctx context.Context) error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	record(shutdownServer(ctx, ws.vsockServer))
	record(shutdownServer(ctx, ws.httpServer))
	record(closeListener(ws.vsockListener))
	record(closeListener(ws.listener))

	if rmErr := os.Remove(ws.cfg.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
		record(rmErr)
	}
	return firstErr
}

// SocketPath returns the configured socket filesystem path.
func (ws *WorkloadServer) SocketPath() string {
	return ws.cfg.SocketPath
}

// VsockPort returns the configured vsock bridge port.
func (ws *WorkloadServer) VsockPort() uint32 {
	return ws.cfg.VsockPort
}
