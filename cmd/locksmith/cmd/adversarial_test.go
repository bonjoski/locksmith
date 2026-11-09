//go:build locksmith_admin

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type syncMockCache struct {
	mu      sync.RWMutex
	secrets map[string]locksmith.Secret
}

func (c *syncMockCache) Set(key string, secret locksmith.Secret, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := secret
	cp.Value = append([]byte(nil), secret.Value...)
	c.secrets[key] = cp
	return nil
}

func (c *syncMockCache) Get(key string) (*locksmith.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.secrets[key]
	if !ok {
		return nil, nil
	}
	cp := s
	cp.Value = append([]byte(nil), s.Value...)
	return &cp, nil
}

func (c *syncMockCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.secrets, key)
	return nil
}

func (c *syncMockCache) IsExpired(key string, ttl time.Duration) bool {
	return false
}

type syncMockBackend struct {
	cache *syncMockCache
}

func (b *syncMockBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	var sec locksmith.Secret
	if err := json.Unmarshal(data, &sec); err != nil {
		sec = locksmith.Secret{
			Value:     append([]byte(nil), data...),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	return b.cache.Set(account, sec, time.Hour)
}

func (b *syncMockBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	sec, err := b.cache.Get(account)
	if err != nil || sec == nil {
		return nil, fmt.Errorf("secret %q not found", account)
	}
	return json.Marshal(sec)
}

func (b *syncMockBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return b.cache.Delete(account)
}

func (b *syncMockBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	b.cache.mu.RLock()
	defer b.cache.mu.RUnlock()
	out := make([]string, 0, len(b.cache.secrets))
	for k := range b.cache.secrets {
		out = append(out, k)
	}
	return out, nil
}

// TestAdversarial_LCK01_MCPConcurrentOptionsIsolationAndEnvBlock verifies:
// 1. Concurrent MCP tool calls never mutate shared Locksmith.Options.RequireBiometrics.
// 2. Host environment variables cannot be exfiltrated via locksmith_get_secret or locksmith_checkout_lease.
// 3. Checked-out MCP leases are tracked in LeaseManager and revocable.
func verifyLCK01EnvLeak(ctx context.Context, session *mcp.ClientSession, t *testing.T) {
	t.Helper()
	envGet, envGetErr := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "locksmith_get_secret",
		Arguments: map[string]any{"name": "ADV_MCP_HOST_ENV_SECRET"},
	})
	if envGetErr == nil && !envGet.IsError {
		t.Errorf("CRITICAL (LCK-01): locksmith_get_secret leaked host env var")
	}

	envLease, envLeaseErr := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "locksmith_checkout_lease",
		Arguments: map[string]any{
			"secret_name": "ADV_MCP_HOST_ENV_SECRET",
			"ttl_seconds": 60,
		},
	})
	if envLeaseErr == nil && !envLease.IsError {
		t.Errorf("CRITICAL (LCK-01): locksmith_checkout_lease leaked host env var")
	}
}

func runLCK01Worker(ctx context.Context, session *mcp.ClientSession, lsTest *locksmith.Locksmith, worker int, leasesMu *sync.Mutex, leaseIDs *[]string, t *testing.T) {
	t.Helper()
	if !lsTest.Options.RequireBiometrics {
		t.Errorf("worker %d observed mutated RequireBiometrics=false", worker)
	}

	getRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "locksmith_get_secret",
		Arguments: map[string]any{"name": "vault/api-token"},
	})
	if err != nil || getRes.IsError {
		t.Errorf("worker %d get_secret failed: err=%v res=%+v", worker, err, getRes)
		return
	}

	leaseRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "locksmith_checkout_lease",
		Arguments: map[string]any{
			"secret_name": "vault/api-token",
			"ttl_seconds": 90,
			"spiffe_id":   "spiffe://bonjoski.local/workload/agent",
		},
	})
	if err != nil || leaseRes.IsError {
		t.Errorf("worker %d checkout_lease failed: err=%v res=%+v", worker, err, leaseRes)
		return
	}

	var payload map[string]any
	text := leaseRes.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Errorf("worker %d invalid lease JSON: %v", worker, err)
		return
	}
	id, ok := payload["lease_id"].(string)
	if !ok || !strings.HasPrefix(id, "ls-lease-") {
		t.Errorf("worker %d invalid lease_id: %v", worker, payload["lease_id"])
		return
	}

	leasesMu.Lock()
	*leaseIDs = append(*leaseIDs, id)
	leasesMu.Unlock()

	verifyLCK01EnvLeak(ctx, session, t)
}

func TestAdversarial_LCK01_MCPConcurrentOptionsIsolationAndEnvBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Setenv("ADV_MCP_HOST_ENV_SECRET", "must-never-leak-via-mcp")

	mc := &syncMockCache{secrets: make(map[string]locksmith.Secret)}
	if err := mc.Set("vault/api-token", locksmith.Secret{
		Value:     []byte("vault-only-secret-token"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Hour); err != nil {
		t.Fatalf("failed seeding cache: %v", err)
	}

	lsTest := locksmith.NewWithCache(mc)
	lsTest.Backend = &syncMockBackend{cache: mc}
	lsTest.Options.RequireBiometrics = true

	server, lm := newMCPServerWithLeaseManager(lsTest)
	defer lm.Close()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() {
		if err := server.Run(ctx, serverTransport); err != nil && err != context.Canceled {
			t.Errorf("MCP server error: %v", err)
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "adv-mcp-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("failed connecting MCP client: %v", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			t.Logf("session close: %v", closeErr)
		}
	}()

	var (
		wg       sync.WaitGroup
		leasesMu sync.Mutex
		leaseIDs []string
	)

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			runLCK01Worker(ctx, session, lsTest, worker, &leasesMu, &leaseIDs, t)
		}(i)
	}
	wg.Wait()

	if !lsTest.Options.RequireBiometrics {
		t.Fatal("CRITICAL (LCK-01): lsTest.Options.RequireBiometrics was mutated to false")
	}

	if len(leaseIDs) != 16 {
		t.Fatalf("expected 16 tracked leases, got %d", len(leaseIDs))
	}
	myPID := os.Getpid()
	for _, id := range leaseIDs {
		if _, ok := lm.GetLease(id); !ok {
			t.Fatalf("CRITICAL (LCK-01): lease %q missing from LeaseManager registry", id)
		}
		revResp, err := lm.RevokeLease(&protocol.RevokeRequest{LeaseID: id}, &protocol.PeerCredentials{PID: myPID})
		if err != nil || !revResp.Success {
			t.Fatalf("failed revoking tracked MCP lease %q: err=%v resp=%+v", id, err, revResp)
		}
		if _, ok := lm.GetLease(id); ok {
			t.Fatalf("revoked MCP lease %q remained active in LeaseManager", id)
		}
	}
}

// TestAdversarial_LCK02_GitCredentialTraversalAndNewlineInjection verifies that
// git credential helper actions and `add --git` reject path traversal, slashes,
// NUL bytes, empty hosts, and CR/LF protocol newline injection.
func TestAdversarial_LCK02_GitCredentialTraversalAndNewlineInjection(t *testing.T) {
	mc := &syncMockCache{secrets: make(map[string]locksmith.Secret)}
	origLS := ls
	lsTest := locksmith.NewWithCache(mc)
	lsTest.Backend = &syncMockBackend{cache: mc}
	ls = lsTest
	defer func() {
		ls = origLS
		credentialCmd.SetIn(nil)
		credentialCmd.SetOut(nil)
		credentialCmd.SetErr(nil)
	}()

	// Seed a victim non-git secret in vault to prove `git/../../victim` cannot reach it.
	if err := mc.Set("victim", locksmith.Secret{
		Value:     []byte("top-secret-victim-token"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Hour); err != nil {
		t.Fatalf("failed seeding victim secret: %v", err)
	}

	adversarialInputs := []string{
		"protocol=https\nhost=\n\n",
		"protocol=https\nhost=../../victim\n\n",
		"protocol=https\nhost=github.com/../../victim\n\n",
		"protocol=https\nhost=github.com\nusername=../../victim\n\n",
		"protocol=https\nhost=github.com\\..\\victim\n\n",
		"protocol=https/..\nhost=github.com\n\n",
		"protocol=https\nhost=github.com\x00evil\n\n",
		"protocol=https\nhost=github.com\revil\nusername=alice\n\n",
	}

	for _, action := range []string{"get", "store", "erase"} {
		for _, rawInput := range adversarialInputs {
			var out bytes.Buffer
			credentialCmd.SetIn(strings.NewReader(rawInput))
			credentialCmd.SetOut(&out)
			credentialCmd.SetErr(&out)

			err := credentialCmd.RunE(credentialCmd, []string{action})
			if err == nil {
				t.Fatalf("CRITICAL (LCK-02): action=%q accepted adversarial input %q", action, rawInput)
			}
			if strings.Contains(out.String(), "top-secret-victim-token") {
				t.Fatalf("CRITICAL (LCK-02): victim secret leaked on action=%q input=%q", action, rawInput)
			}
		}
	}

	// Verify output newline injection defense if stored secret or metadata contains CR/LF.
	if err := mc.Set("git/github.com/alice", locksmith.Secret{
		Value:     []byte("tok123\nquit=1\nurl=https://evil.example"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Hour); err != nil {
		t.Fatalf("failed seeding poisoned secret: %v", err)
	}

	var getOut bytes.Buffer
	credentialCmd.SetIn(strings.NewReader("protocol=https\nhost=github.com\nusername=alice\n\n"))
	credentialCmd.SetOut(&getOut)
	if err := credentialCmd.RunE(credentialCmd, []string{"get"}); err == nil {
		t.Fatalf("CRITICAL (LCK-02): handleGet emitted secret containing embedded newlines: %q", getOut.String())
	}
	if strings.Contains(getOut.String(), "quit=1") {
		t.Fatalf("CRITICAL (LCK-02): newline-injected git credential attribute written to stdout")
	}
}
