package locksmith

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/stepup"
)

// DefaultSocketPath returns the standard user-scoped Unix socket path.
func DefaultSocketPath() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "locksmithd.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("locksmithd-%d.sock", os.Getuid()))
}

// DaemonServer manages the local IPC socket listener and routes incoming
// requests to the LeaseManager.
type DaemonServer struct {
	mu                sync.Mutex
	lm                *LeaseManager
	socketPath        string
	listener          net.Listener
	closed            bool
	StepUpPublicKey   ed25519.PublicKey
	SessionAuthorizer func(peer *protocol.PeerCredentials, allowedSecrets []string) error
	usedStepUpJTIs    map[string]int64
}

// NewDaemonServer initializes a DaemonServer with the provided LeaseManager.
func NewDaemonServer(lm *LeaseManager, socketPath string) *DaemonServer {
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	return &DaemonServer{
		lm:             lm,
		socketPath:     socketPath,
		usedStepUpJTIs: make(map[string]int64),
	}
}

// SocketPath returns the configured socket location.
func (s *DaemonServer) SocketPath() string {
	return s.socketPath
}

func removeIfExists(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListenAndServe creates the socket and serves client connections until ctx is cancelled.
func setupCompatSymlink(dir, socketPath string) string {
	base := filepath.Base(socketPath)
	var compatSymlink string
	if base == "locksmithd.sock" {
		compatSymlink = filepath.Join(dir, "locksmith.sock")
	} else if base == "locksmith.sock" {
		compatSymlink = filepath.Join(dir, "locksmithd.sock")
	}
	if compatSymlink != "" {
		if rmErr := removeIfExists(compatSymlink); rmErr == nil {
			if symErr := os.Symlink(base, compatSymlink); symErr != nil {
				return ""
			}
			return compatSymlink
		}
	}
	return ""
}

func setupSocketListener(socketPath string) (net.Listener, string, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", fmt.Errorf("daemon: failed to create socket dir %q: %w", dir, err)
	}

	// Remove stale socket if not active
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		if conn, dialErr := net.Dial("unix", socketPath); dialErr == nil {
			_ = conn.Close()
			return nil, "", fmt.Errorf("daemon: another Locksmith daemon is already running at %s", socketPath)
		}
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, "", fmt.Errorf("daemon: failed to listen on socket %s: %w", socketPath, err)
	}

	// Restrict permissions to owner-only (0600); fail closed if Chmod fails
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = l.Close()
		_ = removeIfExists(socketPath)
		return nil, "", fmt.Errorf("daemon: failed to restrict socket permissions on %s: %w", socketPath, err)
	}

	compatSymlink := setupCompatSymlink(dir, socketPath)
	return l, compatSymlink, nil
}

func (s *DaemonServer) ListenAndServe(ctx context.Context) error {
	l, compatSymlink, err := setupSocketListener(s.socketPath)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	defer func() {
		_ = removeIfExists(compatSymlink)
		_ = l.Close()
		_ = removeIfExists(s.socketPath)
	}()

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *DaemonServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set connection deadline to prevent socket starvation
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	peer, err := protocol.GetPeerInfo(conn)
	if err != nil {
		writeJSONError(conn, fmt.Sprintf("failed to authenticate peer: %v", err))
		return
	}

	// Limit request buffer to 64KB (ADV-05: Payload exhaustion mitigation)
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(conn, "failed to read request")
		return
	}
	if n == 0 {
		return
	}

	payload := buf[:n]

	// Determine action
	var baseReq struct {
		Action protocol.Action `json:"action"`
	}
	if err := json.Unmarshal(payload, &baseReq); err != nil {
		writeJSONError(conn, "malformed JSON request")
		return
	}

	s.dispatchAction(conn, baseReq.Action, payload, peer)
}

func (s *DaemonServer) dispatchAction(conn net.Conn, action protocol.Action, payload []byte, peer *protocol.PeerCredentials) {
	switch action {
	case protocol.ActionPing:
		s.handlePing(conn)
	case protocol.ActionRequestLease:
		s.handleRequestLease(conn, payload, peer)
	case protocol.ActionRevokeLease:
		s.handleRevokeLease(conn, payload, peer)
	case protocol.ActionCreateSession:
		s.handleCreateSession(conn, payload, peer)
	case protocol.ActionRevokeSession:
		s.handleRevokeSession(conn, payload)
	case protocol.ActionListLeases:
		s.handleListLeases(conn)
	default:
		writeJSONError(conn, fmt.Sprintf("unsupported action %q", action))
	}
}

func (s *DaemonServer) handlePing(conn net.Conn) {
	_ = json.NewEncoder(conn).Encode(map[string]string{
		"status":  "PONG",
		"version": protocol.ProtocolVersion,
	})
}

func (s *DaemonServer) handleRequestLease(conn net.Conn, payload []byte, peer *protocol.PeerCredentials) {
	var req protocol.LeaseRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		writeJSONError(conn, "invalid lease request payload")
		return
	}
	resp, err := s.lm.RequestLease(&req, peer)
	if err != nil {
		writeJSONError(conn, err.Error())
		return
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *DaemonServer) handleRevokeLease(conn net.Conn, payload []byte, peer *protocol.PeerCredentials) {
	var req protocol.RevokeRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		writeJSONError(conn, "invalid revoke request payload")
		return
	}
	resp, err := s.lm.RevokeLease(&req, peer)
	if err != nil {
		writeJSONError(conn, err.Error())
		return
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *DaemonServer) authorizeSessionCreation(peer *protocol.PeerCredentials, stepUpToken string, allowedSecrets []string) error {
	if peer == nil || peer.PID <= 0 {
		return errors.New("peer credentials required to create session")
	}

	if strings.TrimSpace(stepUpToken) != "" {
		pubKey := s.StepUpPublicKey
		if len(pubKey) == 0 {
			var err error
			pubKey, err = stepup.GetAttestationPublicKey()
			if err != nil {
				return fmt.Errorf("failed to load step-up attestation public key: %w", err)
			}
		}
		tok, err := stepup.Verify(stepUpToken, pubKey)
		if err != nil {
			return fmt.Errorf("invalid step_up_token: %w", err)
		}
		jti := tok.Claims.TokenID
		if jti == "" {
			return errors.New("step_up_token missing jti claim")
		}

		nowUnix := time.Now().Unix()
		s.mu.Lock()
		if s.usedStepUpJTIs == nil {
			s.usedStepUpJTIs = make(map[string]int64)
		}
		for k, exp := range s.usedStepUpJTIs {
			if nowUnix > exp {
				delete(s.usedStepUpJTIs, k)
			}
		}
		if _, replay := s.usedStepUpJTIs[jti]; replay {
			s.mu.Unlock()
			return errors.New("step_up_token replay detected")
		}
		s.usedStepUpJTIs[jti] = tok.Claims.ExpiresAt
		s.mu.Unlock()
		return nil
	}

	if s.SessionAuthorizer != nil {
		return s.SessionAuthorizer(peer, allowedSecrets)
	}

	return errors.New("unauthorized: create_session requires step_up_token or interactive biometric authorization")
}

func (s *DaemonServer) handleCreateSession(conn net.Conn, payload []byte, peer *protocol.PeerCredentials) {
	var req struct {
		PGID           int           `json:"pgid"`
		TTL            time.Duration `json:"ttl"`
		AllowedSecrets []string      `json:"allowed_secrets"`
		StepUpToken    string        `json:"step_up_token,omitempty"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		writeJSONError(conn, "invalid session create payload")
		return
	}
	if err := s.authorizeSessionCreation(peer, req.StepUpToken, req.AllowedSecrets); err != nil {
		writeJSONError(conn, err.Error())
		return
	}
	pgid := req.PGID
	if pgid <= 0 && peer != nil {
		pgid = peer.PID
	}
	ticket, err := s.lm.CreateSession(pgid, req.TTL, req.AllowedSecrets)
	if err != nil {
		writeJSONError(conn, err.Error())
		return
	}
	_ = json.NewEncoder(conn).Encode(ticket)
}

func (s *DaemonServer) handleRevokeSession(conn net.Conn, payload []byte) {
	var req struct {
		TicketID string `json:"ticket_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		writeJSONError(conn, "invalid session revoke payload")
		return
	}
	_ = s.lm.RevokeSession(req.TicketID)
	_ = json.NewEncoder(conn).Encode(map[string]bool{"success": true})
}

func (s *DaemonServer) handleListLeases(conn net.Conn) {
	leases := []*ActiveLease{}
	if s.lm != nil {
		leases = s.lm.ListLeases()
	}
	_ = json.NewEncoder(conn).Encode(map[string]any{
		"status": "OK",
		"leases": leases,
	})
}

func writeJSONError(conn net.Conn, msg string) {
	_ = json.NewEncoder(conn).Encode(map[string]any{
		"status": protocol.StatusDenied,
		"error":  msg,
	})
}

// Close gracefully stops the listener and lease manager.
func (s *DaemonServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.mu.Unlock()

	if s.lm != nil {
		_ = s.lm.Close()
	}
	return err
}
