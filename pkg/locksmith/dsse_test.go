package locksmith

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

func startTestDaemon(t *testing.T, store SecretGetter) (string, *LeaseManager, func()) {
	t.Helper()
	sockPath := fmt.Sprintf("/tmp/ls-dsse-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1000000)
	lm := NewLeaseManager(store, LeaseManagerOptions{
		DefaultTTL:        5 * time.Minute,
		MaxTTL:            5 * time.Minute,
		DisableAmbientEnv: true,
	})
	server := NewDaemonServer(lm, sockPath)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ListenAndServe(ctx)
	}()

	ready := false
	for i := 0; i < 40; i++ {
		conn, err := net.DialTimeout("unix", sockPath, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatalf("daemon socket %s did not become ready", sockPath)
	}

	cleanup := func() {
		cancel()
		<-done
		_ = lm.Close()
		_ = os.Remove(sockPath)
	}
	return sockPath, lm, cleanup
}

func sendDaemonJSON(t *testing.T, sockPath string, req any, resp any) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial daemon socket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	if err := json.NewDecoder(conn).Decode(resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestDaemon_ActionSignDSSEAmortized(t *testing.T) {
	sockPath, _, cleanup := startTestDaemon(t, &mockSecretStore{secrets: map[string][]byte{}})
	defer cleanup()

	sessionID := "sess_01JDX9J00AMORTIZED"
	wantKeyID := "spiffe://bonjoski.local/session/" + sessionID
	pae1 := []byte("DSSEv1 28 application/vnd.in-toto+json 18 {\"receipt\":\"one\"}")
	pae2 := []byte("DSSEv1 28 application/vnd.in-toto+json 18 {\"receipt\":\"two\"}")

	resp1, pub1 := signAndVerifyDSSE(t, sockPath, sessionID, wantKeyID, pae1)
	resp2, _ := signAndVerifyDSSE(t, sockPath, sessionID, wantKeyID, pae2)
	if resp2.PubKeyB64 != resp1.PubKeyB64 {
		t.Fatalf("expected amortized leaf pubkey reuse, got %q vs %q", resp2.PubKeyB64, resp1.PubKeyB64)
	}
	assertSessionPubKeyMatches(t, sockPath, sessionID, wantKeyID, resp1.PubKeyB64, pub1)
	assertDistinctSessionUsesDistinctKey(t, sockPath, pae1, resp1.PubKeyB64)
	assertMalformedDSSERequestsDenied(t, sockPath, sessionID, pae1)
}

func signAndVerifyDSSE(t *testing.T, sockPath, sessionID, wantKeyID string, pae []byte) (protocol.SignDSSEResponse, ed25519.PublicKey) {
	t.Helper()
	var resp protocol.SignDSSEResponse
	sendDaemonJSON(t, sockPath, &protocol.SignDSSERequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE,
		SessionID: sessionID, PAEB64: base64.StdEncoding.EncodeToString(pae),
	}, &resp)
	if resp.Status != protocol.StatusGranted || resp.KeyID != wantKeyID {
		t.Fatalf("unexpected sign_dsse response: %+v", resp)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(resp.PubKeyB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("invalid pubkey_b64: err=%v len=%d", err, len(pubBytes))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(resp.SigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
		t.Fatalf("DSSE signature verification failed: err=%v", err)
	}
	return resp, ed25519.PublicKey(pubBytes)
}

func assertSessionPubKeyMatches(t *testing.T, sockPath, sessionID, wantKeyID, wantPubB64 string, _ ed25519.PublicKey) {
	t.Helper()
	var pubResp protocol.GetSessionPubKeyResponse
	sendDaemonJSON(t, sockPath, &protocol.GetSessionPubKeyRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionGetSessionPubKey, SessionID: sessionID,
	}, &pubResp)
	if pubResp.Status != protocol.StatusGranted || pubResp.KeyID != wantKeyID || pubResp.PubKeyB64 != wantPubB64 {
		t.Fatalf("get_session_pubkey mismatch: %+v", pubResp)
	}
}

func assertDistinctSessionUsesDistinctKey(t *testing.T, sockPath string, pae []byte, firstPubB64 string) {
	t.Helper()
	var otherResp protocol.SignDSSEResponse
	sendDaemonJSON(t, sockPath, &protocol.SignDSSERequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE,
		SessionID: "sess_01JDX9J00DISTINCT", PAEB64: base64.StdEncoding.EncodeToString(pae),
	}, &otherResp)
	if otherResp.Status != protocol.StatusGranted || otherResp.PubKeyB64 == firstPubB64 {
		t.Fatalf("distinct sessions must use distinct Ed25519 keys: %+v", otherResp)
	}
}

func assertMalformedDSSERequestsDenied(t *testing.T, sockPath, sessionID string, pae []byte) {
	t.Helper()
	badReqs := []protocol.SignDSSERequest{
		{Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE, SessionID: "bad_prefix", PAEB64: base64.StdEncoding.EncodeToString(pae)},
		{Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE, SessionID: "sess_../traversal", PAEB64: base64.StdEncoding.EncodeToString(pae)},
		{Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE, SessionID: sessionID, PAEB64: ""},
		{Version: protocol.ProtocolVersion, Action: protocol.ActionSignDSSE, SessionID: sessionID, PAEB64: "%%%notbase64%%%"},
		{Version: "9.9", Action: protocol.ActionSignDSSE, SessionID: sessionID, PAEB64: base64.StdEncoding.EncodeToString(pae)},
	}
	for i, bad := range badReqs {
		var badResp protocol.SignDSSEResponse
		sendDaemonJSON(t, sockPath, &bad, &badResp)
		if badResp.Status != protocol.StatusDenied || badResp.SigB64 != "" {
			t.Errorf("bad case %d: expected DENIED without sig, got %+v", i, badResp)
		}
	}
}

func TestConcurrentDSSE_N8NoRace(t *testing.T) {
	sockPath, _, cleanup := startTestDaemon(t, &mockSecretStore{secrets: map[string][]byte{}})
	defer cleanup()

	const (
		workers   = 8
		perWorker = 15
	)
	sessionID := "sess_01JN8CONCURRENT01"

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		pubKeys = make(map[string]struct{})
		errCh   = make(chan error, workers*perWorker)
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				pae := []byte(fmt.Sprintf("DSSEv1 28 application/vnd.in-toto+json %d {\"w\":%d,\"i\":%d}", 13, workerID, i))
				conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
				if err != nil {
					errCh <- fmt.Errorf("worker %d iter %d dial: %w", workerID, i, err)
					return
				}
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				req := &protocol.SignDSSERequest{
					Version:   protocol.ProtocolVersion,
					Action:    protocol.ActionSignDSSE,
					SessionID: sessionID,
					PAEB64:    base64.StdEncoding.EncodeToString(pae),
				}
				if err := json.NewEncoder(conn).Encode(req); err != nil {
					_ = conn.Close()
					errCh <- fmt.Errorf("worker %d iter %d encode: %w", workerID, i, err)
					return
				}
				var resp protocol.SignDSSEResponse
				if err := json.NewDecoder(conn).Decode(&resp); err != nil {
					_ = conn.Close()
					errCh <- fmt.Errorf("worker %d iter %d decode: %w", workerID, i, err)
					return
				}
				_ = conn.Close()

				if resp.Status != protocol.StatusGranted {
					errCh <- fmt.Errorf("worker %d iter %d denied: %s", workerID, i, resp.Error)
					return
				}
				pub, err := base64.StdEncoding.DecodeString(resp.PubKeyB64)
				if err != nil || len(pub) != ed25519.PublicKeySize {
					errCh <- fmt.Errorf("worker %d iter %d invalid pubkey", workerID, i)
					return
				}
				sig, err := base64.StdEncoding.DecodeString(resp.SigB64)
				if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), pae, sig) {
					errCh <- fmt.Errorf("worker %d iter %d signature verification failed", workerID, i)
					return
				}
				mu.Lock()
				pubKeys[resp.PubKeyB64] = struct{}{}
				mu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
	if len(pubKeys) != 1 {
		t.Fatalf("expected exactly 1 amortized leaf pubkey across N=8 workers, got %d distinct keys", len(pubKeys))
	}

	var pubResp protocol.GetSessionPubKeyResponse
	sendDaemonJSON(t, sockPath, &protocol.GetSessionPubKeyRequest{
		Version:   protocol.ProtocolVersion,
		Action:    protocol.ActionGetSessionPubKey,
		SessionID: sessionID,
	}, &pubResp)
	if pubResp.Status != protocol.StatusGranted {
		t.Fatalf("get_session_pubkey failed: %s", pubResp.Error)
	}
	if _, ok := pubKeys[pubResp.PubKeyB64]; !ok {
		t.Fatal("get_session_pubkey did not match amortized worker pubkey")
	}
}
