//go:build locksmith_admin

package cmd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPServer(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Mock Locksmith
	mc := &mockCache{secrets: make(map[string]locksmith.Secret)}
	lsTest := locksmith.NewWithCache(mc)
	lsTest.Backend = &mockBackendWithList{cache: mc}
	lsTest.Options.RequireBiometrics = true

	// Seed data
	mc.secrets["test-key"] = locksmith.Secret{
		Value:     []byte("test-value"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// 2. Initialize MCP Server and Client
	server := newMCPServer(lsTest)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	go func() {
		if err := server.Run(ctx, serverTransport); err != nil && err != context.Canceled {
			t.Errorf("MCP Server exited with error: %v", err)
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Failed to connect client: %v", err)
	}
	defer session.Close()

	// 3. Test Tool: locksmith_get_secret
	t.Run("get_secret", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "locksmith_get_secret",
			Arguments: map[string]string{"name": "test-key"},
		})
		if err != nil {
			t.Fatalf("CallTool failed: %v", err)
		}
		if res.IsError {
			t.Fatalf("Tool returned error content: %+v", res.Content)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if text != "\"test-value\"" {
			t.Errorf("Expected '\"test-value\"', got '%s'", text)
		}
	})

	// 5. Test Tool: locksmith_list_secrets
	t.Run("list_secrets", func(t *testing.T) {
		testListSecrets(t, ctx, session)
	})

	// 6. Test Tool: locksmith_checkout_lease
	t.Run("checkout_lease", func(t *testing.T) {
		testCheckoutLease(t, ctx, session)
	})
}

func testCheckoutLease(t *testing.T, ctx context.Context, session *mcp.ClientSession) {
	// Test checkout from vault
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "locksmith_checkout_lease",
		Arguments: map[string]any{
			"secret_name": "test-key",
			"ttl_seconds": 120,
			"spiffe_id":   "spiffe://aegisbox.local/workload/microvm",
		},
	})
	if err != nil {
		t.Fatalf("CallTool locksmith_checkout_lease failed: %v", err)
	}
	if res.IsError {
		t.Fatalf("Tool returned error content: %+v", res.Content)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	var leaseData map[string]any
	if err := json.Unmarshal([]byte(text), &leaseData); err != nil {
		t.Fatalf("Failed to parse json: %v", err)
	}
	if leaseData["secret_value"] != "test-value" {
		t.Errorf("Expected 'test-value', got '%v'", leaseData["secret_value"])
	}
	if leaseData["spiffe_id"] != "spiffe://aegisbox.local/workload/microvm" {
		t.Errorf("Expected spiffe ID echoed, got '%v'", leaseData["spiffe_id"])
	}
	if int(leaseData["ttl_seconds"].(float64)) != 120 {
		t.Errorf("Expected ttl 120, got %v", leaseData["ttl_seconds"])
	}

	// Test checkout ambient env secret
	t.Setenv("OPENAI_API_KEY", "sk-mcp-ambient-test")
	res2, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "locksmith_checkout_lease",
		Arguments: map[string]any{
			"secret_name": "OPENAI_API_KEY",
			"ttl_seconds": 600, // should clamp to 300
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res2.IsError {
		t.Fatalf("Tool returned error content: %+v", res2.Content)
	}
	text2 := res2.Content[0].(*mcp.TextContent).Text
	var leaseData2 map[string]any
	if err := json.Unmarshal([]byte(text2), &leaseData2); err != nil {
		t.Fatalf("Failed to parse json: %v", err)
	}
	if leaseData2["secret_value"] != "sk-mcp-ambient-test" {
		t.Errorf("Expected 'sk-mcp-ambient-test', got '%v'", leaseData2["secret_value"])
	}
	if int(leaseData2["ttl_seconds"].(float64)) != 300 {
		t.Errorf("Expected clamped ttl 300, got %v", leaseData2["ttl_seconds"])
	}
}

func testListSecrets(t *testing.T, ctx context.Context, session *mcp.ClientSession) {
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "locksmith_list_secrets",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		t.Fatalf("Tool returned error content: %+v", res.Content)
	}

	text := res.Content[0].(*mcp.TextContent).Text
	var names []string
	if err := json.Unmarshal([]byte(text), &names); err != nil {
		t.Fatalf("Failed to unmarshal names from '%s': %v", text, err)
	}

	foundTest := false
	for _, n := range names {
		if n == "test-key" {
			foundTest = true
		}
	}
	if !foundTest {
		t.Errorf("test-key not found in %v", names)
	}
}

// mockBackendWithList is a mock backend that can list keys from a mock cache.
type mockBackendWithList struct {
	mockBackend
	cache *mockCache
}

func (m *mockBackendWithList) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	var keys []string
	for k := range m.cache.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}
