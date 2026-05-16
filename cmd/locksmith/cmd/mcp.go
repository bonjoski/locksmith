package cmd

import (
	"context"
	"fmt"

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
			BypassCache:       true,
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

	return server
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
