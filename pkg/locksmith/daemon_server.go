package locksmith

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// DefaultSocketPath returns the standard user-scoped Unix socket path.
func DefaultSocketPath() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "locksmith.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
}

// DaemonServer manages the local IPC socket listener and routes incoming
// requests to the LeaseManager.
type DaemonServer struct {
	mu         sync.Mutex
	lm         *LeaseManager
	socketPath string
	listener   net.Listener
	closed     bool
}

// NewDaemonServer initializes a DaemonServer with the provided LeaseManager.
func NewDaemonServer(lm *LeaseManager, socketPath string) *DaemonServer {
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	return &DaemonServer{
		lm:         lm,
		socketPath: socketPath,
	}
}

// SocketPath returns the configured socket location.
func (s *DaemonServer) SocketPath() string {
	return s.socketPath
}

// ListenAndServe creates the socket and serves client connections until ctx is cancelled.
func (s *DaemonServer) ListenAndServe(ctx context.Context) error {
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("daemon: failed to create socket dir %q: %w", dir, err)
	}

	// Remove stale socket if not active
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		// Check if another daemon is already serving
		if conn, dialErr := net.Dial("unix", s.socketPath); dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("daemon: another Locksmith daemon is already running at %s", s.socketPath)
		}
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("daemon: failed to listen on socket %s: %w", s.socketPath, err)
	}

	// Restrict permissions to owner-only (0600)
	_ = os.Chmod(s.socketPath, 0600)

	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	defer func() {
		_ = l.Close()
		_ = os.Remove(s.socketPath)
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
		s.handleCreateSession(conn, payload)
	case protocol.ActionRevokeSession:
		s.handleRevokeSession(conn, payload)
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

func (s *DaemonServer) handleCreateSession(conn net.Conn, payload []byte) {
	var req struct {
		PGID           int           `json:"pgid"`
		TTL            time.Duration `json:"ttl"`
		AllowedSecrets []string      `json:"allowed_secrets"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		writeJSONError(conn, "invalid session create payload")
		return
	}
	ticket, err := s.lm.CreateSession(req.PGID, req.TTL, req.AllowedSecrets)
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
