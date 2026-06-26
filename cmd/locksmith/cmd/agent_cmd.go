package cmd

import (
	"crypto"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/agent"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage the locksmith SSH and GPG agent",
}

var agentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the locksmith SSH agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		socketPath := filepath.Join(home, ".locksmith", "ssh-agent.sock")

		// Ensure socket directory exists
		if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
			return err
		}

		// Delete existing socket if it exists
		if _, err := os.Stat(socketPath); err == nil {
			_ = os.Remove(socketPath)
		}

		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("failed to listen on socket %s: %w", socketPath, err)
		}
		defer listener.Close()

		fmt.Printf("Locksmith SSH Agent listening on UNIX socket: %s\n", socketPath)
		fmt.Printf("To use this agent, run:\n  export SSH_AUTH_SOCK=%s\n", socketPath)

		sshAgent := agent.NewLocksmithAgent(ls)
		return sshAgent.Serve(listener)
	},
}

var agentAddCmd = &cobra.Command{
	Use:   "add <keyname> <path-to-private-key>",
	Short: "Add a private key to the Locksmith vault and register it with the agent",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		keyName := args[0]
		privPath := args[1]

		privBytes, err := os.ReadFile(filepath.Clean(privPath))
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		defer func() {
			for i := range privBytes {
				privBytes[i] = 0
			}
		}()

		// Parse and validate the private key
		privKey, err := ssh.ParseRawPrivateKey(privBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		signer, ok := privKey.(crypto.Signer)
		if !ok {
			return fmt.Errorf("private key does not support public key derivation")
		}

		// Derive public key
		pubKey, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return fmt.Errorf("failed to derive public key: %w", err)
		}
		pubKeyStr := string(ssh.MarshalAuthorizedKey(pubKey))

		// Store private key in locksmith vault (with 10-year expiry)
		secretName := "ssh/" + keyName
		forever := time.Now().Add(365 * 24 * time.Hour * 10)
		if err := ls.SetWithBiometrics(secretName, privBytes, forever, globalBiometricReqs); err != nil {
			return fmt.Errorf("failed to store private key: %w", err)
		}

		// Update agent public keys file
		records, err := agent.LoadSSHKeyRecords()
		if err != nil {
			return fmt.Errorf("failed to load public key records: %w", err)
		}

		// Check if record already exists, update it if so
		exists := false
		for i, record := range records {
			if record.Name == keyName {
				records[i].PublicKey = pubKeyStr
				exists = true
				break
			}
		}
		if !exists {
			records = append(records, agent.SSHKeyRecord{
				Name:      keyName,
				PublicKey: pubKeyStr,
			})
		}

		if err := agent.SaveSSHKeyRecords(records); err != nil {
			return fmt.Errorf("failed to save public key records: %w", err)
		}

		fmt.Printf("Successfully added key '%s' to Locksmith agent.\n", keyName)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentStartCmd)
	agentCmd.AddCommand(agentAddCmd)
}
