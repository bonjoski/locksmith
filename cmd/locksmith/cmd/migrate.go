package cmd

import (
	"errors"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/migrate"
	"github.com/bonjoski/locksmith/v2/pkg/ux"
	"github.com/spf13/cobra"
)

var (
	migrateProject    string
	migrateDir        string
	migrateKeepSource bool
	migrateJSON       bool
	migrateExpiresIn  string
)

var migrateCmd = &cobra.Command{
	Use:   "migrate [env-file]",
	Short: "Import plaintext .env secrets into Locksmith keychain, harden .gitignore, and shred .env",
	Long: `One-command migration from a workspace plaintext .env file into Touch ID / TPM keychain storage.

Security invariants:
  • Opens .env strictly via os.OpenRoot(workspaceRoot) + Lstat (rejects symlinks fail-closed).
  • Enforces a strict 1MB cap and rejects binary files.
  • Never logs secret values; zeroizes all in-memory buffers via slice.ExplicitBzero.
  • Single-session amortized batch write under namespace project/<repo>/<KEY>.
  • Appends .env, .env.*, and !.env.example to .gitignore.
  • Zero-overwrites, syncs, and removes .env (unless --keep-source is passed).`,
	Example: "  locksmith migrate .env\n  locksmith migrate .env --project my-app --why\n  locksmith migrate .env --json --keep-source",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer func() {
			migrateProject = ""
			migrateDir = "."
			migrateKeepSource = false
			migrateJSON = false
			migrateExpiresIn = ""
			_ = cmd.Flags().Set("project", "")
			_ = cmd.Flags().Set("dir", ".")
			_ = cmd.Flags().Set("keep-source", "false")
			_ = cmd.Flags().Set("json", "false")
			_ = cmd.Flags().Set("expires-in", "")
		}()

		envPath := ".env"
		if len(args) == 1 {
			envPath = args[0]
		}

		ttl := migrate.DefaultSecretTTL
		if migrateExpiresIn != "" {
			parsed, err := locksmith.ParseDuration(migrateExpiresIn)
			if err != nil {
				ffe := &ux.FixForwardError{
					Tool:           "locksmith",
					Code:           "LOCKSMITH_INVALID_EXPIRES_IN",
					Summary:        "Invalid --expires-in duration value",
					RemediationCmd: "locksmith migrate .env --expires-in 30d",
					WhyOneLiner:    "Use a standard duration such as 24h, 30d, or 90d.",
					ExitCode:       1,
				}
				_ = ffe.Render(cmd.ErrOrStderr(), migrateJSON, showWhy)
				return ffe
			}
			ttl = parsed
		}

		adapter := &migrate.LocksmithAdapter{
			LS:                ls,
			RequireBiometrics: globalBiometricReqs && !nonInteractive,
		}
		if nonInteractive && globalBiometricReqs {
			adapter.RequireBiometrics = true
		}

		res, err := migrate.MigrateEnv(cmd.Context(), migrate.Options{
			WorkspaceRoot:     migrateDir,
			EnvFile:           envPath,
			ProjectName:       migrateProject,
			KeepSource:        migrateKeepSource,
			NonInteractive:    nonInteractive,
			HasAmbientSession: migrate.HasAmbientSessionTicket(),
			ExpiresIn:         ttl,
			Store:             adapter,
		})
		if err != nil {
			var ffe *ux.FixForwardError
			if errors.As(err, &ffe) {
				_ = ffe.Render(cmd.ErrOrStderr(), migrateJSON, showWhy)
				return ffe
			}
			return err
		}

		return res.Render(cmd.OutOrStdout(), migrateJSON, showWhy)
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.Flags().StringVar(&migrateProject, "project", "", "Project namespace under project/<name>/<KEY> (defaults to workspace directory name)")
	migrateCmd.Flags().StringVar(&migrateDir, "dir", ".", "Workspace root directory containing the .env file")
	migrateCmd.Flags().BoolVar(&migrateKeepSource, "keep-source", false, "Keep plaintext .env on disk instead of securely shredding it")
	migrateCmd.Flags().BoolVar(&migrateJSON, "json", false, "Emit structured UB-CLI-v2 JSON output")
	migrateCmd.Flags().StringVar(&migrateExpiresIn, "expires-in", "", "Expiration duration for imported secrets (e.g., 30d, 90d)")
}
