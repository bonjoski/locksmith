package spiffe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"golang.org/x/time/rate"
)

type contextKey string

const (
	identityContextKey  contextKey = "caller_identity"
	attestErrContextKey contextKey = "attest_error"
	tcpBridgeContextKey contextKey = "tcp_bridge"
)

// ServerConfig configures the SPIFFE Workload API listener.
type ServerConfig struct {
	SocketPath  string
	VsockPort   uint32
	BridgeToken string
	TrustDomain string
	Policy      *Policy
	Attestor    WorkloadAttestor
	CA          *ca.CA
	RateLimit   rate.Limit // requests per second per UID
	BurstLimit  int
}

// WorkloadServer serves the SPIFFE Workload API over a Unix Domain Socket and optional vsock bridge.
type WorkloadServer struct {
	cfg           ServerConfig
	listener      net.Listener
	vsockListener net.Listener
	httpServer    *http.Server
	vsockServer   *http.Server
	rateMu        sync.Mutex
	rateLimiters  map[uint32]*rate.Limiter
}

func applyDefaultServerConfig(cfg *ServerConfig) error {
	if cfg.CA == nil {
		return errors.New("Root CA is required for SPIFFE Workload Server")
	}
	if cfg.SocketPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to determine user home directory: %w", err)
		}
		cfg.SocketPath = filepath.Join(home, ".locksmith", "spiffe", "workload.sock")
	}
	if cfg.Attestor == nil {
		cfg.Attestor = NewAttestor()
	}
	if cfg.Policy == nil {
		cfg.Policy = NewDefaultPolicy(cfg.TrustDomain)
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = rate.Limit(10) // 10 requests per second
	}
	if cfg.BurstLimit <= 0 {
		cfg.BurstLimit = 20
	}
	if cfg.VsockPort > 0 && cfg.BridgeToken == "" {
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err == nil {
			cfg.BridgeToken = hex.EncodeToString(tokenBytes)
		}
	}
	return nil
}

func (ws *WorkloadServer) connContext(ctx context.Context, c net.Conn) context.Context {
	if c.RemoteAddr() != nil {
		switch c.RemoteAddr().Network() {
		case "tcp":
			return context.WithValue(ctx, tcpBridgeContextKey, true)
		case "vsock":
			identity := &CallerIdentity{
				VsockCID:  3,
				Comm:      "aegisbox-vm",
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

// BridgeToken returns the active authentication token for loopback TCP bridge requests.
func (ws *WorkloadServer) BridgeToken() string {
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

func (ws *WorkloadServer) getIdentity(r *http.Request) (*CallerIdentity, error) {
	if isTCPBridge, _ := r.Context().Value(tcpBridgeContextKey).(bool); isTCPBridge {
		token := r.Header.Get("X-Locksmith-Bridge-Token")
		if ws.cfg.BridgeToken == "" || token != ws.cfg.BridgeToken {
			return nil, fmt.Errorf("%w: unauthenticated vsock bridge TCP request (missing or invalid X-Locksmith-Bridge-Token)", ErrUnauthorizedWorkload)
		}
		var cid uint32 = 3
		cidHeader := r.Header.Get("X-Locksmith-CID")
		if cidHeader != "" {
			if parsed, err := strconv.ParseUint(cidHeader, 10, 32); err == nil {
				cid = uint32(parsed)
			}
		} else if len(ws.cfg.Policy.AllowedCIDs) > 0 {
			cid = ws.cfg.Policy.AllowedCIDs[0]
		}
		if !ws.cfg.Policy.isCIDAllowed(cid) {
			return nil, fmt.Errorf("%w: microVM CID %d not permitted by policy", ErrUnauthorizedWorkload, cid)
		}
		return &CallerIdentity{
			VsockCID:  cid,
			Comm:      "aegisbox-vm",
			StartTime: time.Now(),
		}, nil
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
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	_ = json.NewEncoder(w).Encode(resp)
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
	_ = json.NewEncoder(w).Encode(resp)
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
		_ = l.Close()
		return fmt.Errorf("failed to set socket permissions %s: %w", ws.cfg.SocketPath, err)
	}

	ws.listener = l

	if ws.cfg.VsockPort > 0 {
		vl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ws.cfg.VsockPort))
		if err != nil {
			_ = l.Close()
			return fmt.Errorf("failed to listen on vsock bridge port %d: %w", ws.cfg.VsockPort, err)
		}
		ws.vsockListener = vl
		ws.vsockServer = &http.Server{
			Handler:     ws.httpServer.Handler,
			ConnContext: ws.httpServer.ConnContext,
		}
		go func() {
			_ = ws.vsockServer.Serve(vl)
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
