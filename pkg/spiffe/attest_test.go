package spiffe_test

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
)

func TestAttestPeer_LocalConnection(t *testing.T) {
	sockPath := shortTempSock(t, "attest")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on socket %s: %v", sockPath, err)
	}
	defer listener.Close()

	attestor := spiffe.NewAttestor()
	attestChan := make(chan *spiffe.CallerIdentity, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		defer conn.Close()

		id, err := attestor.AttestPeer(conn)
		if err != nil {
			errChan <- err
			return
		}
		attestChan <- id
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial test socket: %v", err)
	}
	defer clientConn.Close()

	select {
	case id := <-attestChan:
		if id.PID != os.Getpid() {
			t.Errorf("attested PID = %d, expected current PID %d", id.PID, os.Getpid())
		}
		if id.UID != uint32(os.Getuid()) {
			t.Errorf("attested UID = %d, expected current UID %d", id.UID, os.Getuid())
		}
		if id.Comm == "" {
			t.Errorf("expected non-empty process comm name")
		}
		if id.StartTime.After(time.Now()) {
			t.Errorf("process start time is in the future: %v", id.StartTime)
		}
		t.Logf("PASS: Peer attested successfully: PID=%d, UID=%d, Comm=%s, StartTime=%v", id.PID, id.UID, id.Comm, id.StartTime)
	case err := <-errChan:
		t.Fatalf("attestation error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for peer attestation")
	}
}
