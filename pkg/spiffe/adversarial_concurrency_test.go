package spiffe_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
	"golang.org/x/time/rate"
)

// ADV-SPIFFE-CONC-01: Multi-Agent Concurrency & Contention Stress (N=16)
// Simulates 16 autonomous subagents concurrently performing cryptographic token derivation,
// bundle retrieval, and attestation under heavy load.
func TestAdversarial_MultiAgentConcurrencyStress(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root CA", "Bonjoski", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	sockPath := shortTempSock(t, "conc")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}

	deriver, err := spiffe.NewBridgeTokenDeriver(masterKey)
	if err != nil {
		t.Fatalf("NewBridgeTokenDeriver failed: %v", err)
	}

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		BridgeKey:   masterKey,
		CA:          rootCA,
		RateLimit:   rate.Limit(5000),
		Attestor: &MockAttestor{
			Identity: &spiffe.CallerIdentity{
				UID:       501,
				Comm:      "worker-agent",
				StartTime: time.Now(),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewWorkloadServer failed: %v", err)
	}

	go func() { _ = ws.Start() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ws.Stop(ctx)
	}()

	client := newUnixHTTPClient(sockPath)
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	numWorkers := 16
	iterations := 50
	errChan := make(chan error, numWorkers*iterations)

	for w := 0; w < numWorkers; w++ {
		workerID := w
		wg.Add(1)
		go func(cid uint32) {
			defer wg.Done()
			token := deriver.DeriveToken(cid)

			for i := 0; i < iterations; i++ {
				// 1. Verify token matches authoritative CID
				if !deriver.VerifyToken(cid, token) {
					errChan <- fmt.Errorf("worker %d: token verification failed for matching CID %d", workerID, cid)
					return
				}

				// 2. Verify token strictly rejects transposed CID
				if deriver.VerifyToken(cid+1, token) {
					errChan <- fmt.Errorf("worker %d: CRITICAL transposition bug: token for CID %d accepted for CID %d", workerID, cid, cid+1)
					return
				}

				// 3. Query bundle concurrently
				bResp, err := client.Get("http://localhost/v1/bundle")
				if err != nil {
					errChan <- fmt.Errorf("worker %d: GET /v1/bundle failed: %w", workerID, err)
					return
				}
				bResp.Body.Close()
				if bResp.StatusCode != http.StatusOK {
					errChan <- fmt.Errorf("worker %d: unexpected status %d from bundle", workerID, bResp.StatusCode)
					return
				}
			}
		}(uint32(3 + workerID))
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrency error: %v", err)
	}
}

// ADV-SPIFFE-SMUGGLE-01: Header Smuggling Defense over Unix Domain Socket
// Asserts that an attacker cannot smuggle X-Locksmith-Bridge-Token or X-Locksmith-CID
// over the Unix domain socket to claim microVM CID identities.
func TestAdversarial_HeaderSmugglingOverUnixSocket(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root CA", "Bonjoski", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	sockPath := shortTempSock(t, "smuggle")
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)

	deriver, _ := spiffe.NewBridgeTokenDeriver(masterKey)
	validCID4Token := deriver.DeriveToken(4)

	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		BridgeKey:   masterKey,
		CA:          rootCA,
		RateLimit:   rate.Limit(100),
		Attestor: &MockAttestor{
			Identity: &spiffe.CallerIdentity{
				UID:       501,
				Comm:      "local-process",
				StartTime: time.Now(),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewWorkloadServer failed: %v", err)
	}

	go func() { _ = ws.Start() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ws.Stop(ctx)
	}()

	client := newUnixHTTPClient(sockPath)
	time.Sleep(50 * time.Millisecond)

	// Attempt to smuggle CID 4 bridge credentials over the local Unix domain socket
	req, err := http.NewRequest("GET", "http://localhost/v1/svid", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Locksmith-Bridge-Token", validCID4Token)
	req.Header.Set("X-Locksmith-CID", "4")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/svid failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}

	var svid spiffe.SVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&svid); err != nil {
		t.Fatalf("failed decoding SVID response: %v", err)
	}

	// Must issue SVID for the kernel-attested process ("local-process"), NOT the smuggled microVM CID (4)!
	if strings.Contains(svid.SPIFFEID, "cid") || strings.Contains(svid.SPIFFEID, "/4") {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Smuggled CID 4 header was accepted! Got %q", svid.SPIFFEID)
	}
	expectedID := "spiffe://bonjoski.local/workload/local-process"
	if svid.SPIFFEID != expectedID {
		t.Fatalf("Unexpected SPIFFE ID: got %q, want %q", svid.SPIFFEID, expectedID)
	}
	t.Logf("PASS: Header smuggling over Unix socket strictly ignored; kernel peer attestation enforced.")
}

// ADV-SPIFFE-TOKEN-01: Domain Separated Token Verification Integrity
// Asserts that tokens of varied lengths, empty tokens, and malformed inputs fail closed.
func TestAdversarial_BridgeTokenIntegrity(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(0xAA)
	}

	deriver, err := spiffe.NewBridgeTokenDeriver(masterKey)
	if err != nil {
		t.Fatal(err)
	}

	cid := uint32(5)
	validToken := deriver.DeriveToken(cid)

	t.Run("valid token verifies", func(t *testing.T) {
		if !deriver.VerifyToken(cid, validToken) {
			t.Fatal("expected valid token to verify")
		}
	})

	t.Run("empty token rejected", func(t *testing.T) {
		if deriver.VerifyToken(cid, "") {
			t.Fatal("CRITICAL: empty token was accepted!")
		}
	})

	t.Run("truncated token rejected", func(t *testing.T) {
		if len(validToken) > 10 && deriver.VerifyToken(cid, validToken[:len(validToken)-4]) {
			t.Fatal("CRITICAL: truncated token was accepted!")
		}
	})

	t.Run("extended token rejected", func(t *testing.T) {
		if deriver.VerifyToken(cid, validToken+"extra") {
			t.Fatal("CRITICAL: extended token was accepted!")
		}
	})

	t.Run("cross CID transposition rejected", func(t *testing.T) {
		for otherCID := uint32(3); otherCID <= 10; otherCID++ {
			if otherCID == cid {
				continue
			}
			if deriver.VerifyToken(otherCID, validToken) {
				t.Fatalf("CRITICAL: token for CID %d verified for CID %d!", cid, otherCID)
			}
		}
	})
}
