package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
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

	// locksmith_checkout_lease: headless non-interactive ephemeral lease checkout with SPIFFE workload identity
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_checkout_lease",
		Description: "Request a short-lived ephemeral lease (60-300s TTL) for ambient secrets (e.g. GITHUB_TOKEN, OPENAI_API_KEY) using SPIFFE workload identities non-interactively.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in CheckoutLeaseInput) (*mcp.CallToolResult, any, error) {
		out, err := handleCheckoutLease(lsMcp, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})

	return server
}

type CheckoutLeaseInput struct {
	SecretName string `json:"secret_name" jsonschema:"The name of the secret to lease (e.g. GITHUB_TOKEN, OPENAI_API_KEY)"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"Lease duration in seconds (60-300s, default 300)"`
	SpiffeID   string `json:"spiffe_id,omitempty" jsonschema:"SPIFFE workload identity (e.g. spiffe://aegisbox.local/workload/microvm)"`
}

type CheckoutLeaseOutput struct {
	Status      string `json:"status"`
	LeaseID     string `json:"lease_id"`
	SecretName  string `json:"secret_name"`
	SecretValue string `json:"secret_value"`
	ExpiresAt   string `json:"expires_at"`
	TTLSeconds  int    `json:"ttl_seconds"`
	SpiffeID    string `json:"spiffe_id"`
}

func handleCheckoutLease(lsMcp *locksmith.Locksmith, in CheckoutLeaseInput) (*CheckoutLeaseOutput, error) {
	if strings.TrimSpace(in.SecretName) == "" {
		return nil, errors.New("secret_name is required")
	}
	spiffeID := in.SpiffeID
	if spiffeID == "" {
		spiffeID = "spiffe://aegisbox.local/workload/microvm"
	} else if err := protocol.ValidateSpiffeID(spiffeID); err != nil {
		return nil, fmt.Errorf("invalid spiffe_id: %w", err)
	}

	ttlSec := normalizeLeaseTTL(in.TTLSeconds)
	valBytes, err := fetchMCPSecretBytes(lsMcp, in.SecretName)
	if err != nil {
		return nil, err
	}

	leaseID := fmt.Sprintf("ls-lease-mcp-%d", time.Now().UnixNano())
	expiresAt := time.Now().Add(time.Duration(ttlSec) * time.Second)

	return &CheckoutLeaseOutput{
		Status:      string(protocol.StatusGranted),
		LeaseID:     leaseID,
		SecretName:  in.SecretName,
		SecretValue: string(valBytes),
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
		TTLSeconds:  ttlSec,
		SpiffeID:    spiffeID,
	}, nil
}

func normalizeLeaseTTL(ttlSec int) int {
	if ttlSec <= 0 || ttlSec > 300 {
		return 300
	}
	if ttlSec < 60 {
		return 60
	}
	return ttlSec
}

func fetchMCPSecretBytes(lsMcp *locksmith.Locksmith, secretName string) ([]byte, error) {
	var valBytes []byte
	var err error
	if lsMcp != nil {
		prevBio := lsMcp.Options.RequireBiometrics
		lsMcp.Options.RequireBiometrics = false
		valBytes, err = lsMcp.Get(secretName)
		lsMcp.Options.RequireBiometrics = prevBio
	}
	if (err != nil || len(valBytes) == 0) && os.Getenv(secretName) != "" {
		valBytes = []byte(os.Getenv(secretName))
		err = nil
	}
	if err != nil && len(valBytes) == 0 {
		return nil, fmt.Errorf("secret %q not found in vault or ambient environment", secretName)
	}
	return valBytes, nil
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
