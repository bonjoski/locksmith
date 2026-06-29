package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/sync"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	syncFile        string
	syncPassphrase  string
	syncMergePolicy string
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize secrets across devices using zero-knowledge encryption",
}

var syncExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all secrets to an encrypted zero-knowledge file payload",
	RunE: func(cmd *cobra.Command, args []string) error {
		pass, err := getPassphrase(cmd, syncPassphrase, "Enter encryption passphrase: ")
		if err != nil {
			return err
		}
		if len(pass) == 0 {
			return fmt.Errorf("passphrase cannot be empty")
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Retrieving secrets from vault... (You may be prompted for biometrics)")

		plaintext, err := sync.ExportVault(ls)
		if err != nil {
			return fmt.Errorf("failed to export vault secrets: %w", err)
		}
		defer func() {
			for i := range plaintext {
				plaintext[i] = 0
			}
		}()

		ciphertext, err := sync.EncryptPayload(plaintext, pass)
		if err != nil {
			return fmt.Errorf("failed to encrypt vault payload: %w", err)
		}

		err = os.WriteFile(syncFile, ciphertext, 0600)
		if err != nil {
			return fmt.Errorf("failed to write encrypted file: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully exported encrypted vault to %s\n", syncFile)
		return nil
	},
}

var syncImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import and merge secrets from an encrypted zero-knowledge file payload",
	RunE: func(cmd *cobra.Command, args []string) error {
		pass, err := getPassphrase(cmd, syncPassphrase, "Enter decryption passphrase: ")
		if err != nil {
			return err
		}
		if len(pass) == 0 {
			return fmt.Errorf("passphrase cannot be empty")
		}

		ciphertext, err := os.ReadFile(syncFile)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", syncFile, err)
		}

		plaintext, err := sync.DecryptPayload(ciphertext, pass)
		if err != nil {
			return fmt.Errorf("failed to decrypt file (invalid passphrase or corrupted data): %w", err)
		}
		defer func() {
			for i := range plaintext {
				plaintext[i] = 0
			}
		}()

		policy := strings.ToLower(syncMergePolicy)
		count, err := sync.ImportVault(ls, plaintext, policy)
		if err != nil {
			return fmt.Errorf("failed to merge and import secrets: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully imported %d secrets from %s\n", count, syncFile)
		return nil
	},
}

func getPassphrase(cmd *cobra.Command, flagValue string, promptMsg string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}

	_, _ = fmt.Fprint(cmd.OutOrStdout(), promptMsg)
	var passBytes []byte
	var err error

	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		passBytes, err = term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	} else {
		var passStr string
		_, err = fmt.Fscanln(cmd.InOrStdin(), &passStr)
		passBytes = []byte(passStr)
	}

	if err != nil {
		return "", fmt.Errorf("error reading passphrase: %w", err)
	}

	return string(passBytes), nil
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncExportCmd)
	syncCmd.AddCommand(syncImportCmd)

	syncExportCmd.Flags().StringVarP(&syncFile, "file", "f", "", "Output file path (required)")
	_ = syncExportCmd.MarkFlagRequired("file")
	syncExportCmd.Flags().StringVarP(&syncPassphrase, "passphrase", "p", "", "Passphrase for encryption (optional, prompts securely if omitted)")

	syncImportCmd.Flags().StringVarP(&syncFile, "file", "f", "", "Input file path (required)")
	_ = syncImportCmd.MarkFlagRequired("file")
	syncImportCmd.Flags().StringVarP(&syncPassphrase, "passphrase", "p", "", "Passphrase for decryption (optional, prompts securely if omitted)")
	syncImportCmd.Flags().StringVarP(&syncMergePolicy, "policy", "m", "latest-wins", "Conflict resolution policy (latest-wins, overwrite, keep-local)")
}
