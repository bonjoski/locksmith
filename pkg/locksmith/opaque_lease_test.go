package locksmith

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

func TestOpaqueLease_CrossSessionHijackAndReplayBlocked(t *testing.T) {
	const canary = "sk-canary-opaque-secret-998877665544"
	store := &mockSecretStore{secrets: map[string][]byte{"STRIPE_TEST_KEY": []byte(canary)}}
	sockPath, lm, cleanup := startTestDaemon(t, store)
	defer cleanup()

	sessionA, sessionB := "sess_01JALPHA0001", "sess_01JBETA00002"
	myPID := os.Getpid()
	myStartTime, _ := protocol.GetProcessStartTime(myPID)

	mintResp := mintAndAssertOpaqueWireClean(t, sockPath, sessionA, myPID, myStartTime, canary)
	internalBufRef := captureOpaqueLeaseBuffer(t, lm, mintResp.LeaseID)

	assertRedeemDenied(t, sockPath, mintResp.LeaseID, sessionB, myPID, myStartTime, "cross-session hijack")
	assertCrossUIDRedeemDenied(t, lm, mintResp.LeaseID, sessionA, myPID, myStartTime)
	assertValidRedeemAndZeroize(t, sockPath, mintResp.LeaseID, sessionA, myPID, myStartTime, canary, internalBufRef)
	assertRedeemDenied(t, sockPath, mintResp.LeaseID, sessionA, myPID, myStartTime, "double-redemption replay")
	assertExpiredLeaseZeroized(t, sockPath, lm, sessionA, myPID, myStartTime)
	assertInvalidMintRequestsDenied(t, sockPath, sessionA)
}

func mintAndAssertOpaqueWireClean(t *testing.T, sockPath, sessionID string, pid int, startTime int64, canary string) protocol.MintOpaqueLeaseResponse {
	t.Helper()
	canaryB64 := base64.StdEncoding.EncodeToString([]byte(canary))
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mintReq := &protocol.MintOpaqueLeaseRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionMintOpaqueLease,
		SessionID: sessionID, SecretName: "STRIPE_TEST_KEY", TargetEnvVar: "STRIPE_API_KEY",
		LeaseTTL: 120 * time.Second, ClientPID: pid, ProcessStartTime: startTime,
	}
	if err := json.NewEncoder(conn).Encode(mintReq); err != nil {
		_ = conn.Close()
		t.Fatalf("encode mint failed: %v", err)
	}
	rawMintBuf := make([]byte, 8192)
	n, err := conn.Read(rawMintBuf)
	_ = conn.Close()
	if err != nil && n == 0 {
		t.Fatalf("read mint response failed: %v", err)
	}
	rawMintJSON := string(rawMintBuf[:n])
	if strings.Contains(rawMintJSON, canary) || strings.Contains(rawMintJSON, canaryB64) {
		t.Fatalf("CRITICAL: mint_opaque_lease leaked raw secret bytes: %s", rawMintJSON)
	}
	var mintResp protocol.MintOpaqueLeaseResponse
	if err := json.Unmarshal([]byte(rawMintJSON), &mintResp); err != nil {
		t.Fatalf("unmarshal mint response: %v", err)
	}
	if mintResp.Status != protocol.StatusGranted || !strings.HasPrefix(mintResp.LeaseID, "lease_") || len(mintResp.LeaseID) < 38 {
		t.Fatalf("unexpected mint response: %+v", mintResp)
	}
	if mintResp.EnvVar != "STRIPE_API_KEY" || mintResp.Delivery != protocol.DeliveryModeFD3Slice {
		t.Fatalf("unexpected env_var/delivery: %+v", mintResp)
	}
	return mintResp
}

func captureOpaqueLeaseBuffer(t *testing.T, lm *LeaseManager, leaseID string) []byte {
	t.Helper()
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	ol, exists := lm.opaqueLeases[leaseID]
	if !exists || ol == nil {
		t.Fatal("expected opaque lease stored in daemon memory")
	}
	return ol.secretBytes
}

func assertBufferZeroed(t *testing.T, buf []byte, label string) {
	t.Helper()
	for idx, b := range buf {
		if b != 0 {
			t.Fatalf("CRITICAL: %s byte at index %d not zeroed (0x%x)", label, idx, b)
		}
	}
}

func assertRedeemDenied(t *testing.T, sockPath, leaseID, sessionID string, pid int, startTime int64, label string) {
	t.Helper()
	var resp protocol.RedeemOpaqueLeaseResponse
	sendDaemonJSON(t, sockPath, &protocol.RedeemOpaqueLeaseRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionRedeemOpaqueLease,
		LeaseID: leaseID, SessionID: sessionID, ClientPID: pid, ProcessStartTime: startTime,
	}, &resp)
	if resp.Status != protocol.StatusDenied || resp.SecretB64 != "" {
		t.Fatalf("CRITICAL: %s was not blocked! resp=%+v", label, resp)
	}
}

func assertCrossUIDRedeemDenied(t *testing.T, lm *LeaseManager, leaseID, sessionID string, pid int, startTime int64) {
	t.Helper()
	uidResp, err := lm.RedeemOpaqueLease(&protocol.RedeemOpaqueLeaseRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionRedeemOpaqueLease,
		LeaseID: leaseID, SessionID: sessionID, ClientPID: pid, ProcessStartTime: startTime,
	}, &protocol.PeerCredentials{PID: pid, UID: uint32(os.Getuid()) + 1, StartTime: startTime})
	if err != nil || uidResp.Status != protocol.StatusDenied || uidResp.SecretB64 != "" {
		t.Fatalf("CRITICAL: cross-UID hijack succeeded! resp=%+v err=%v", uidResp, err)
	}
}

func assertValidRedeemAndZeroize(t *testing.T, sockPath, leaseID, sessionID string, pid int, startTime int64, canary string, internalBufRef []byte) {
	t.Helper()
	var redeemResp protocol.RedeemOpaqueLeaseResponse
	sendDaemonJSON(t, sockPath, &protocol.RedeemOpaqueLeaseRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionRedeemOpaqueLease,
		LeaseID: leaseID, SessionID: sessionID, ClientPID: pid, ProcessStartTime: startTime,
	}, &redeemResp)
	if redeemResp.Status != protocol.StatusGranted || redeemResp.EnvVar != "STRIPE_API_KEY" {
		t.Fatalf("expected valid redemption GRANTED, got %+v", redeemResp)
	}
	decoded, err := base64.StdEncoding.DecodeString(redeemResp.SecretB64)
	if err != nil || string(decoded) != canary {
		t.Fatalf("redeemed secret mismatch: err=%v got=%q", err, string(decoded))
	}
	assertBufferZeroed(t, internalBufRef, "redeemed lease secret")
}

func assertExpiredLeaseZeroized(t *testing.T, sockPath string, lm *LeaseManager, sessionID string, pid int, startTime int64) {
	t.Helper()
	var expMint protocol.MintOpaqueLeaseResponse
	sendDaemonJSON(t, sockPath, &protocol.MintOpaqueLeaseRequest{
		Version: protocol.ProtocolVersion, Action: protocol.ActionMintOpaqueLease,
		SessionID: sessionID, SecretName: "STRIPE_TEST_KEY", TargetEnvVar: "STRIPE_API_KEY",
		LeaseTTL: 1 * time.Second, ClientPID: pid, ProcessStartTime: startTime,
	}, &expMint)
	if expMint.Status != protocol.StatusGranted {
		t.Fatalf("failed to mint short-lived lease: %+v", expMint)
	}
	lm.mu.Lock()
	expOL := lm.opaqueLeases[expMint.LeaseID]
	expBufRef := expOL.secretBytes
	expOL.expiresAt = time.Now().Add(-10 * time.Millisecond)
	lm.mu.Unlock()

	assertRedeemDenied(t, sockPath, expMint.LeaseID, sessionID, pid, startTime, "expired opaque lease")
	assertBufferZeroed(t, expBufRef, "expired lease secret")
}

func assertInvalidMintRequestsDenied(t *testing.T, sockPath, sessionID string) {
	t.Helper()
	invalidMints := []protocol.MintOpaqueLeaseRequest{
		{Version: protocol.ProtocolVersion, Action: protocol.ActionMintOpaqueLease, SessionID: sessionID, SecretName: "STRIPE_TEST_KEY", LeaseTTL: 500 * time.Millisecond},
		{Version: protocol.ProtocolVersion, Action: protocol.ActionMintOpaqueLease, SessionID: sessionID, SecretName: "STRIPE_TEST_KEY", LeaseTTL: 301 * time.Second},
		{Version: protocol.ProtocolVersion, Action: protocol.ActionMintOpaqueLease, SessionID: "bad_sess", SecretName: "STRIPE_TEST_KEY", LeaseTTL: 60 * time.Second},
	}
	for i, inv := range invalidMints {
		var r protocol.MintOpaqueLeaseResponse
		sendDaemonJSON(t, sockPath, &inv, &r)
		if r.Status != protocol.StatusDenied {
			t.Errorf("invalid mint %d: expected DENIED, got %s", i, r.Status)
		}
	}
}

func TestOpaqueLease_N8ConcurrentMintAndRedeem(t *testing.T) {
	secrets := make(map[string][]byte, 8)
	for i := 0; i < 8; i++ {
		secrets[fmt.Sprintf("AGENT_SECRET_%d", i)] = []byte(fmt.Sprintf("sk-agent-secret-value-%d", i))
	}
	sockPath, _, cleanup := startTestDaemon(t, &mockSecretStore{secrets: secrets})
	defer cleanup()

	myPID := os.Getpid()
	myStartTime, _ := protocol.GetProcessStartTime(myPID)

	var wg sync.WaitGroup
	errCh := make(chan error, 8)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessID := fmt.Sprintf("sess_01JN8WORKER_%02d", idx)
			secretName := fmt.Sprintf("AGENT_SECRET_%d", idx)
			wantVal := fmt.Sprintf("sk-agent-secret-value-%d", idx)

			conn1, err := net.DialTimeout("unix", sockPath, 3*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			_ = conn1.SetDeadline(time.Now().Add(3 * time.Second))
			_ = json.NewEncoder(conn1).Encode(&protocol.MintOpaqueLeaseRequest{
				Version:          protocol.ProtocolVersion,
				Action:           protocol.ActionMintOpaqueLease,
				SessionID:        sessID,
				SecretName:       secretName,
				TargetEnvVar:     "TARGET_KEY",
				LeaseTTL:         60 * time.Second,
				ClientPID:        myPID,
				ProcessStartTime: myStartTime,
			})
			var mintResp protocol.MintOpaqueLeaseResponse
			if err := json.NewDecoder(conn1).Decode(&mintResp); err != nil {
				_ = conn1.Close()
				errCh <- err
				return
			}
			_ = conn1.Close()
			if mintResp.Status != protocol.StatusGranted {
				errCh <- fmt.Errorf("worker %d mint denied: %s", idx, mintResp.Error)
				return
			}

			conn2, err := net.DialTimeout("unix", sockPath, 3*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			_ = conn2.SetDeadline(time.Now().Add(3 * time.Second))
			_ = json.NewEncoder(conn2).Encode(&protocol.RedeemOpaqueLeaseRequest{
				Version:          protocol.ProtocolVersion,
				Action:           protocol.ActionRedeemOpaqueLease,
				LeaseID:          mintResp.LeaseID,
				SessionID:        sessID,
				ClientPID:        myPID,
				ProcessStartTime: myStartTime,
			})
			var redeemResp protocol.RedeemOpaqueLeaseResponse
			if err := json.NewDecoder(conn2).Decode(&redeemResp); err != nil {
				_ = conn2.Close()
				errCh <- err
				return
			}
			_ = conn2.Close()
			if redeemResp.Status != protocol.StatusGranted {
				errCh <- fmt.Errorf("worker %d redeem denied: %s", idx, redeemResp.Error)
				return
			}
			dec, err := base64.StdEncoding.DecodeString(redeemResp.SecretB64)
			if err != nil || string(dec) != wantVal {
				errCh <- fmt.Errorf("worker %d secret cross-talk: got %q want %q", idx, string(dec), wantVal)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
