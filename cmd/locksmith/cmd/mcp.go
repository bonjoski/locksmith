package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
	"github.com/bonjoski/locksmith/v2/pkg/ux"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var mcpAllowRawAgentSecrets bool

// MCPServerOptions controls security posture and daemon routing for the Locksmith MCP server.
type MCPServerOptions struct {
	AllowRawAgentSecrets bool
	DaemonSocketPath     string
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start Locksmith as an MCP server",
	Long: `Start Locksmith as a Model Context Protocol (MCP) server over stdio.
Autonomous agents receive opaque ephemeral lease handles (locksmith_checkout_lease)
rather than raw plaintext secrets. Raw secret retrieval (locksmith_get_secret) is
disabled by default unless --allow-raw-agent-secrets is explicitly passed.`,
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

		// 2. Initialize and Run MCP Server with tracked LeaseManager.
		// If a resident locksmith daemon socket is reachable, route opaque lease minting
		// through it so airlock_exec / aegisbox_exec can redeem the lease_id over UDS.
		mcpOpts := MCPServerOptions{
			AllowRawAgentSecrets: mcpAllowRawAgentSecrets,
			DaemonSocketPath:     detectReachableDaemonSocket(),
		}
		server, lm := newMCPServerWithOptions(lsMcp, mcpOpts)
		defer func() {
			_ = lm.Close()
		}()
		transport := &mcp.StdioTransport{}
		return server.Run(context.Background(), transport)
	},
}

func detectReachableDaemonSocket() string {
	sock := locksmith.DefaultSocketPath()
	if sock == "" {
		return ""
	}
	conn, err := net.DialTimeout("unix", sock, 250*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	if err := json.NewEncoder(conn).Encode(map[string]any{"action": protocol.ActionPing}); err != nil {
		return ""
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || resp.Status != "PONG" {
		return ""
	}
	return sock
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
	return newMCPServerWithOptions(lsMcp, MCPServerOptions{})
}

func newMCPServerWithOptions(lsMcp *locksmith.Locksmith, mcpOpts MCPServerOptions) (*mcp.Server, *locksmith.LeaseManager) {
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

	// locksmith_get_secret (disabled by default for AI agents per UB-MCP-v1)
	type GetSecretInput struct {
		Name string `json:"name" jsonschema:"The name of the secret to retrieve"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_get_secret",
		Description: "Human-only raw secret retrieval (disabled by default for AI agents; use locksmith_checkout_lease for zero-exposure opaque handles).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in GetSecretInput) (*mcp.CallToolResult, any, error) {
		if !mcpOpts.AllowRawAgentSecrets {
			return buildRawSecretBlockedResult(in.Name), nil, nil
		}
		if strings.TrimSpace(in.Name) == "" {
			return buildUBMCPErrorResult(&ux.UBMCPError{
				SchemaVersion:  "ub-cli-v2",
				Tool:           "locksmith",
				Code:           "LOCKSMITH_INVALID_INPUT",
				ExitCode:       ux.ExitPolicyDeny,
				Retryable:      true,
				Summary:        "Secret name is required.",
				RemediationCmd: "locksmith_checkout_lease",
				Why:            "Locksmith cannot look up an empty secret name.",
			}), nil, nil
		}
		val, err := lsMcp.Get(in.Name)
		if err != nil {
			return classifyLocksmithMCPError(err, in.Name), nil, nil
		}
		defer slice.ExplicitBzero(val)
		return nil, string(val), nil
	})

	// locksmith_list_secrets
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_list_secrets",
		Description: "List all secret names stored in the local Locksmith vault.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		secrets, err := lsMcp.List()
		if err != nil {
			return classifyLocksmithMCPError(err, ""), nil, nil
		}
		names := make([]string, 0, len(secrets))
		for name := range secrets {
			names = append(names, name)
		}
		return nil, names, nil
	})

	// locksmith_checkout_lease: zero-exposure opaque ephemeral lease handle (UB-MCP-v1)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "locksmith_checkout_lease",
		Description: "Mint an opaque short-lived secret lease handle (60-300s TTL) for sandboxed FD=3 injection via airlock_exec or aegisbox_exec. Never returns raw secret bytes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in CheckoutLeaseInput) (*mcp.CallToolResult, any, error) {
		out, errRes := handleCheckoutLease(lm, mcpOpts.DaemonSocketPath, in)
		if errRes != nil {
			return errRes, nil, nil
		}
		return nil, out, nil
	})

	return server, lm
}

type CheckoutLeaseInput struct {
	SecretName   string `json:"secret_name" jsonschema:"The name of the secret to lease (e.g. GITHUB_TOKEN, OPENAI_API_KEY)"`
	TargetEnvVar string `json:"target_env_var,omitempty" jsonschema:"Target environment variable name inside the sandbox (defaults to secret_name)"`
	TTLSeconds   int    `json:"ttl_seconds,omitempty" jsonschema:"Lease duration in seconds (60-300s, default 300)"`
	SessionID    string `json:"session_id,omitempty" jsonschema:"Fabrial session ID binding the opaque lease (e.g. sess_01J...)"`
	SpiffeID     string `json:"spiffe_id,omitempty" jsonschema:"SPIFFE workload identity (e.g. spiffe://aegisbox.local/workload/microvm)"`
}

// CheckoutLeaseOutput strictly returns opaque handle metadata — NEVER raw secret bytes.
type CheckoutLeaseOutput struct {
	LeaseID   string `json:"lease_id"`
	EnvVar    string `json:"env_var"`
	ExpiresAt string `json:"expires_at"`
	Delivery  string `json:"delivery"`
}

func handleCheckoutLease(lm *locksmith.LeaseManager, daemonSocketPath string, in CheckoutLeaseInput) (*CheckoutLeaseOutput, *mcp.CallToolResult) {
	if lm == nil && daemonSocketPath == "" {
		return nil, buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_UNINITIALIZED",
			ExitCode:       ux.ExitRuntimeErr,
			Retryable:      false,
			Summary:        "Locksmith lease manager is not initialized.",
			RemediationCmd: "locksmith daemon",
			Why:            "No in-process lease manager or daemon socket is available to mint opaque leases.",
		})
	}
	spiffeID, sessionID, targetEnvVar, errRes := validateCheckoutLeaseInput(in)
	if errRes != nil {
		return nil, errRes
	}
	mintReq, peer, err := buildOpaqueLeaseMintRequest(in, spiffeID, sessionID, targetEnvVar)
	if err != nil {
		return nil, classifyLocksmithMCPError(err, in.SecretName)
	}
	resp, err := dispatchOpaqueLeaseMint(lm, daemonSocketPath, mintReq, peer)
	if err != nil {
		return nil, classifyLocksmithMCPError(err, in.SecretName)
	}
	return &CheckoutLeaseOutput{
		LeaseID:   resp.LeaseID,
		EnvVar:    resp.EnvVar,
		ExpiresAt: resp.ExpiresAt.UTC().Format(time.RFC3339),
		Delivery:  resp.Delivery,
	}, nil
}

func validateCheckoutLeaseInput(in CheckoutLeaseInput) (string, string, string, *mcp.CallToolResult) {
	if strings.TrimSpace(in.SecretName) == "" {
		return "", "", "", buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_INVALID_INPUT",
			ExitCode:       ux.ExitPolicyDeny,
			Retryable:      true,
			Summary:        "secret_name is required to mint an opaque lease.",
			RemediationCmd: "locksmith list",
			Why:            "Specify a vault secret name from locksmith_list_secrets.",
		})
	}
	spiffeID := strings.TrimSpace(in.SpiffeID)
	if spiffeID == "" {
		spiffeID = "spiffe://aegisbox.local/workload/microvm"
	} else if err := protocol.ValidateSpiffeID(spiffeID); err != nil {
		return "", "", "", buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_INVALID_SPIFFE_ID",
			ExitCode:       ux.ExitPolicyDeny,
			Retryable:      true,
			Summary:        fmt.Sprintf("Invalid spiffe_id: %v", err),
			RemediationCmd: "locksmith_checkout_lease",
			Why:            "Workload identities must use the canonical spiffe://<trust-domain>/<path> format.",
		})
	}
	sessionID, err := resolveMCPSessionID(in.SessionID)
	if err != nil {
		return "", "", "", buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_INVALID_SESSION_ID",
			ExitCode:       ux.ExitPolicyDeny,
			Retryable:      true,
			Summary:        "Invalid session_id format for opaque lease binding.",
			RemediationCmd: "fabrial session begin",
			Why:            "Opaque leases require a valid session_id matching ^sess_[0-9A-Za-z_-]{4,64}$.",
		})
	}
	targetEnvVar := strings.TrimSpace(in.TargetEnvVar)
	if targetEnvVar == "" {
		targetEnvVar = strings.TrimSpace(in.SecretName)
	}
	return spiffeID, sessionID, targetEnvVar, nil
}

func buildOpaqueLeaseMintRequest(in CheckoutLeaseInput, spiffeID, sessionID, targetEnvVar string) (*protocol.MintOpaqueLeaseRequest, *protocol.PeerCredentials, error) {
	pid := os.Getpid()
	startTime, err := protocol.GetProcessStartTime(pid)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve caller process start time: %w", err)
	}
	exePath, _ := protocol.GetProcessExecutablePath(pid)
	var exeHash string
	if exePath != "" {
		if h, hErr := protocol.HashFile(exePath); hErr == nil {
			exeHash = h
		}
	}
	req := &protocol.MintOpaqueLeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionMintOpaqueLease,
		SessionID:        sessionID,
		SecretName:       in.SecretName,
		TargetEnvVar:     targetEnvVar,
		LeaseTTL:         time.Duration(normalizeLeaseTTL(in.TTLSeconds)) * time.Second,
		ClientPID:        pid,
		ProcessStartTime: startTime,
		ClientBinaryHash: exeHash,
		SpiffeID:         spiffeID,
	}
	peer := &protocol.PeerCredentials{
		PID:       pid,
		UID:       uint32(os.Getuid()),
		GID:       uint32(os.Getgid()),
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}
	return req, peer, nil
}

func dispatchOpaqueLeaseMint(lm *locksmith.LeaseManager, daemonSocketPath string, req *protocol.MintOpaqueLeaseRequest, peer *protocol.PeerCredentials) (*protocol.MintOpaqueLeaseResponse, error) {
	var (
		resp *protocol.MintOpaqueLeaseResponse
		err  error
	)
	if daemonSocketPath != "" {
		resp, err = mintOpaqueLeaseViaDaemon(daemonSocketPath, req)
	}
	if resp == nil && lm != nil {
		resp, err = lm.MintOpaqueLease(req, peer)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Status != protocol.StatusGranted {
		errMsg := "opaque lease checkout denied"
		if resp != nil && resp.Error != "" {
			errMsg = resp.Error
		}
		return nil, errors.New(errMsg)
	}
	return resp, nil
}

func mintOpaqueLeaseViaDaemon(sockPath string, req *protocol.MintOpaqueLeaseRequest) (*protocol.MintOpaqueLeaseResponse, error) {
	conn, err := net.DialTimeout("unix", sockPath, 1*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp protocol.MintOpaqueLeaseResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func resolveMCPSessionID(requested string) (string, error) {
	if s := strings.TrimSpace(requested); s != "" {
		if err := protocol.ValidateSessionID(s); err != nil {
			return "", err
		}
		return s, nil
	}
	if envSess := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")); envSess != "" {
		if err := protocol.ValidateSessionID(envSess); err == nil {
			return envSess, nil
		}
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sess_mcp_" + hex.EncodeToString(b), nil
}

func buildRawSecretBlockedResult(secretName string) *mcp.CallToolResult {
	suggestedArgs := map[string]any{
		"ttl_seconds": 120,
	}
	if ux.ValidateRemediationToken(secretName) {
		suggestedArgs["secret_name"] = secretName
	}
	return buildUBMCPErrorResult(&ux.UBMCPError{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "locksmith",
		Code:           "LOCKSMITH_RAW_SECRET_BLOCKED",
		ExitCode:       ux.ExitSecretGuardBlock,
		Retryable:      true,
		Summary:        "Raw plaintext secret retrieval is blocked for AI agents.",
		RemediationCmd: "locksmith_checkout_lease",
		Why:            "Exposing raw credentials in LLM context risks leakage; mint an opaque lease handle for FD=3 sandbox injection instead.",
		SelfHeal: &ux.SelfHealSuggestion{
			SuggestedTool:         "locksmith_checkout_lease",
			SuggestedArgs:         suggestedArgs,
			RequiresHumanApproval: false,
		},
	})
}

func containsAnyPattern(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func classifyLocksmithMCPError(err error, secretName string) *mcp.CallToolResult {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	lower := strings.ToLower(msg)

	if containsAnyPattern(lower, "biometric", "touch id", "user canceled", "user interaction", "headless", "laerror", "authentication required") {
		return buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_BIOMETRIC_REQUIRED",
			ExitCode:       ux.ExitBiometricReq,
			Retryable:      true,
			Summary:        "Biometric approval is required before accessing this vault secret.",
			RemediationCmd: "fabrial session begin",
			Why:            "Headless agent calls fail fast instead of hanging on Touch ID; start an amortized local session first.",
		})
	}

	if containsAnyPattern(lower, "access control", "allowed list", "denied", "spoofing", "mismatch", "unauthorized") {
		return buildUBMCPErrorResult(&ux.UBMCPError{
			SchemaVersion:  "ub-cli-v2",
			Tool:           "locksmith",
			Code:           "LOCKSMITH_POLICY_DENIED",
			ExitCode:       ux.ExitPolicyDeny,
			Retryable:      false,
			Summary:        fmt.Sprintf("Locksmith denied secret access: %s", ux.SanitizeTerminalText(msg)),
			RemediationCmd: "locksmith_checkout_lease",
			Why:            "Local binary, session, or vault access policy rejected this credential request.",
		})
	}

	summary := "Locksmith could not fulfill the secret request."
	if clean := strings.TrimSpace(ux.SanitizeTerminalText(msg)); clean != "" {
		summary = clean
	}
	remediation := "locksmith list"
	if ux.ValidateRemediationToken(secretName) {
		remediation = "locksmith add " + secretName
	}
	return buildUBMCPErrorResult(&ux.UBMCPError{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "locksmith",
		Code:           "LOCKSMITH_SECRET_ERROR",
		ExitCode:       ux.ExitRuntimeErr,
		Retryable:      false,
		Summary:        summary,
		RemediationCmd: remediation,
		Why:            "Verify the secret exists in your local Locksmith vault and the vault is unlocked.",
	})
}

func buildUBMCPErrorResult(ubErr *ux.UBMCPError) *mcp.CallToolResult {
	sanitized := ubErr.Sanitized()
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: sanitized.HumanText(),
			},
		},
		StructuredContent: sanitized,
	}
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
	mcpCmd.Flags().BoolVar(&mcpAllowRawAgentSecrets, "allow-raw-agent-secrets", false, "Allow locksmith_get_secret to return plaintext secrets over MCP (disabled by default for zero-exposure agent workflows)")
	rootCmd.AddCommand(mcpCmd)
}
