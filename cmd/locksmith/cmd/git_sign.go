package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/gitsign"
	"github.com/spf13/cobra"
)

var gitSignCmd = &cobra.Command{
	Use:   "git-sign",
	Short: "Hardware-enclosed Git signing helper (drop-in git gpg.program)",
	Long: `Drop-in helper for Git commit signing backed by the local hardware enclave.
Configure Git to use Locksmith:
  git config gpg.program "locksmith git-sign"
  git commit -S -m "signed commit"`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, arg := range args {
			if arg == "--help" || arg == "-h" {
				return cmd.Help()
			}
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("git-sign: failed to access enclave key: %w", err)
		}

		exitCode, err := gitsign.HandleGitInvocation(args, os.Stdin, os.Stdout, os.Stderr, priv, &priv.PublicKey)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(gitSignCmd)
}
