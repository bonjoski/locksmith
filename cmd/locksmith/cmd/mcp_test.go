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

	// 4. Test Tool: locksmith_set_secret
	t.Run("set_secret", func(t *testing.T) {
		testSetSecret(t, ctx, session, mc)
	})

	// 5. Test Tool: locksmith_list_secrets
	t.Run("list_secrets", func(t *testing.T) {
		testListSecrets(t, ctx, session)
	})

	// 6. Test Tool: locksmith_delete_secret
	t.Run("delete_secret", func(t *testing.T) {
		testDeleteSecret(t, ctx, session, mc)
	})
}

func testSetSecret(t *testing.T, ctx context.Context, session *mcp.ClientSession, mc *mockCache) {
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "locksmith_set_secret",
		Arguments: map[string]interface{}{
			"name":     "new-key",
			"value":    "new-value",
			"ttl_days": 1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		t.Fatalf("Tool returned error content: %+v", res.Content)
	}

	// Verify in mock cache
	s, ok := mc.secrets["new-key"]
	if !ok {
		t.Fatal("Secret was not saved to cache")
	}
	if string(s.Value) != "new-value" {
		t.Errorf("Expected 'new-value', got '%s'", string(s.Value))
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

	foundTest, foundNew := false, false
	for _, n := range names {
		if n == "test-key" {
			foundTest = true
		}
		if n == "new-key" {
			foundNew = true
		}
	}
	if !foundTest {
		t.Errorf("test-key not found in %v", names)
	}
	if !foundNew {
		t.Errorf("new-key not found in %v", names)
	}
}

func testDeleteSecret(t *testing.T, ctx context.Context, session *mcp.ClientSession, mc *mockCache) {
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "locksmith_delete_secret",
		Arguments: map[string]string{"name": "new-key"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		t.Fatalf("Tool returned error content: %+v", res.Content)
	}

	// Verify in mock cache
	if _, ok := mc.secrets["new-key"]; ok {
		t.Error("Secret was not deleted from cache")
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
