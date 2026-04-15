package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start Locksmith as an MCP server",
	Long: `Start Locksmith as a Model Context Protocol (MCP) server over stdio.
This allows AI assistants to interact with Locksmith as a tool.
Biometric authentication is strictly enforced for all tool calls.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Initialize Locksmith with strict security
		opts := locksmith.Options{
			RequireBiometrics: true,
			PromptMessage:     "AI is requesting access to '%s'. Touch ID to permit.",
		}
		lsMcp, err := locksmith.NewWithOptions(opts)
		if err != nil {
			return fmt.Errorf("failed to initialize locksmith: %w", err)
		}

		// 2. Initialize and Run MCP Server
		server := newMCPServer(lsMcp)
		transport := &mcp.StdioTransport{}
		return server.Run(context.Background(), transport)
	},
}

// newMCPServer creates and configures a new MCP server for Locksmith.
// Extracted to a helper function for testability.
func newMCPServer(lsMcp *locksmith.Locksmith) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "locksmith",
			Version: locksmith.Version,
		},
		nil,
	)

	// Register Tools (prefixed with locksmith_)

	// locksmith_get_secret
	type GetSecretInput struct {
		Name string `json:"name" jsonschema:"The name of the secret to retrieve"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_get_secret",
		Description: "Retrieve a secret by its name. Requires biometric authentication.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in GetSecretInput) (*mcp.CallToolResult, any, error) {
		val, err := lsMcp.Get(in.Name)
		if err != nil {
			return nil, nil, err
		}
		return nil, string(val), nil
	})

	// locksmith_set_secret
	type SetSecretInput struct {
		Name    string `json:"name" jsonschema:"The name of the secret"`
		Value   string `json:"value" jsonschema:"The secret value to store"`
		TTLDays int    `json:"ttl_days,omitempty" jsonschema:"Time to live in days,default=90"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_set_secret",
		Description: "Store a new secret or update an existing one. Requires biometric authentication.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in SetSecretInput) (*mcp.CallToolResult, any, error) {
		ttl := in.TTLDays
		if ttl == 0 {
			ttl = 90
		}
		expiresAt := time.Now().AddDate(0, 0, ttl)
		err := lsMcp.Set(in.Name, []byte(in.Value), expiresAt)
		if err != nil {
			return nil, nil, err
		}
		return nil, fmt.Sprintf("Successfully saved secret '%s' (expires in %d days)", in.Name, ttl), nil
	})

	// locksmith_list_secrets
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_list_secrets",
		Description: "List all secret names. Requires biometric authentication.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		secrets, err := lsMcp.List()
		if err != nil {
			return nil, nil, err
		}
		var names []string
		for name := range secrets {
			names = append(names, name)
		}
		return nil, names, nil
	})

	// locksmith_delete_secret
	type DeleteSecretInput struct {
		Name string `json:"name" jsonschema:"The name of the secret to delete"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_delete_secret",
		Description: "Delete a secret by its name. Requires biometric authentication.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in DeleteSecretInput) (*mcp.CallToolResult, any, error) {
		err := lsMcp.Delete(in.Name)
		if err != nil {
			return nil, nil, err
		}
		return nil, fmt.Sprintf("Successfully deleted secret '%s'", in.Name), nil
	})

	return server
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
