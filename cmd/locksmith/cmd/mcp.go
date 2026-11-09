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
			AuditIdentity:     "mcp:tools",
		}
		lsMcp, err := locksmith.NewWithOptions(opts)
		if err != nil {
			return fmt.Errorf("failed to initialize locksmith: %w", err)
		}

		// 2. Initialize and Run MCP Server with tracked LeaseManager
		server, lm := newMCPServerWithLeaseManager(lsMcp)
		defer func() {
			_ = lm.Close()
		}()
		transport := &mcp.StdioTransport{}
		return server.Run(context.Background(), transport)
	},
}

type mcpVaultStore struct {
	ls *locksmith.Locksmith
}

func (s *mcpVaultStore) Get(key string) ([]byte, error) {
	if s == nil || s.ls == nil {
		return nil, errors.New("locksmith store is not initialized")
	}
	// Derive a call-scoped Options value copy; NEVER mutate shared s.ls.Options (LCK-01)
	opts := s.ls.Options
	opts.RequireBiometrics = false
	if opts.AuditIdentity == "" || opts.AuditIdentity == "mcp:tools" {
		opts.AuditIdentity = "mcp:checkout_lease"
	}
	return s.ls.GetWithOptions(key, opts)
}

func newMCPServerWithLeaseManager(lsMcp *locksmith.Locksmith) (*mcp.Server, *locksmith.LeaseManager) {
	lm := locksmith.NewLeaseManager(&mcpVaultStore{ls: lsMcp}, locksmith.LeaseManagerOptions{
		DefaultTTL:        5 * time.Minute,
		MaxTTL:            5 * time.Minute,
		DisableAmbientEnv: true,
	})

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

	// locksmith_checkout_lease: headless non-interactive ephemeral lease checkout backed by LeaseManager
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_checkout_lease",
		Description: "Request a short-lived ephemeral lease (60-300s TTL) for vault secrets using SPIFFE workload identities non-interactively.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in CheckoutLeaseInput) (*mcp.CallToolResult, any, error) {
		out, err := handleCheckoutLease(lm, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})

	return server, lm
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

func handleCheckoutLease(lm *locksmith.LeaseManager, in CheckoutLeaseInput) (*CheckoutLeaseOutput, error) {
	if lm == nil {
		return nil, errors.New("lease manager is not initialized")
	}
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
	pid := os.Getpid()
	startTime, err := protocol.GetProcessStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve caller process start time: %w", err)
	}
	exePath, err := protocol.GetProcessExecutablePath(pid)
	if err != nil {
		exePath = ""
	}
	var exeHash string
	if exePath != "" {
		if h, err := protocol.HashFile(exePath); err == nil {
			exeHash = h
		}
	}

	peer := &protocol.PeerCredentials{
		PID:       pid,
		UID:       uint32(os.Getuid()),
		GID:       uint32(os.Getgid()),
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}

	resp, err := lm.RequestLease(&protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        pid,
		ProcessStartTime: startTime,
		ClientBinaryHash: exeHash,
		SecretName:       in.SecretName,
		LeaseTTL:         time.Duration(ttlSec) * time.Second,
		SpiffeID:         spiffeID,
	}, peer)
	if err != nil {
		return nil, err
	}
	if resp.Status != protocol.StatusGranted {
		return nil, fmt.Errorf("lease checkout denied: %s", resp.Error)
	}
	defer resp.Zero()

	return &CheckoutLeaseOutput{
		Status:      string(resp.Status),
		LeaseID:     resp.LeaseID,
		SecretName:  in.SecretName,
		SecretValue: string(resp.SecretValue),
		ExpiresAt:   resp.ExpiresAt.UTC().Format(time.RFC3339),
		TTLSeconds:  int(resp.TTLSeconds),
		SpiffeID:    resp.SpiffeID,
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

func init() {
	rootCmd.AddCommand(mcpCmd)
}
