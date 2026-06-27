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

	// 5. Test Tool: locksmith_list_secrets
	t.Run("list_secrets", func(t *testing.T) {
		testListSecrets(t, ctx, session)
	})
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
