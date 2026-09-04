package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var secretType string
var ownerApplication string
var sourceURL string
var addGit bool
var expiresIn string

const defaultAddTTL = 30 * 24 * time.Hour

var addCmd = &cobra.Command{
	Use:     "add <key> <secret>",
	Short:   "Store a secret",
	Long:    "Store a secret.\n\nIf key/secret args are omitted, locksmith prompts interactively. During interactive add,\noptional rotation metadata is also prompted:\n- secret type: password | api_key | oauth_token | token\n- owner app: provider/application identifier (for example: github, gitlab)\n- source URL: rotation endpoint URL\n\nAll metadata fields are optional and may be left blank.",
	Example: "  locksmith add my/key my-secret\n  locksmith add my/key my-secret --type oauth_token --owner-app github --source-url https://api.github.com\n  locksmith add\n  locksmith add github.com myuser --git",
	Args:    cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if addGit {
			host := ""
			username := ""
			password := ""

			reader := bufio.NewReader(cmd.InOrStdin())

			if len(args) > 0 {
				host = args[0]
			}
			if len(args) > 1 {
				username = args[1]
			}

			if host == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Git host (e.g. github.com): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading git host: %w", err)
				}
				host = strings.TrimSpace(input)
			}
			if host == "" {
				return fmt.Errorf("git host cannot be empty")
			}

			// If username was not provided as arg, prompt for it
			if len(args) < 2 {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Git username (optional): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading git username: %w", err)
				}
				username = strings.TrimSpace(input)
			}

			// Prompt for password/token
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Password/Token: ")
			if term.IsTerminal(int(os.Stdin.Fd())) {
				secretInput, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("error reading password/token: %w", err)
				}
				password = string(secretInput)
				_, _ = fmt.Fprintln(cmd.OutOrStdout())
			} else {
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading password/token: %w", err)
				}
				password = strings.TrimRight(input, "\r\n")
			}
			if password == "" {
				return fmt.Errorf("password/token cannot be empty")
			}

			// Construct key
			var key string
			if username != "" {
				key = fmt.Sprintf("git/%s/%s", host, username)
			} else {
				key = fmt.Sprintf("git/%s", host)
			}

			secretBytes := []byte(password)
			defer func() {
				for i := range secretBytes {
					secretBytes[i] = 0
				}
			}()

			metadata := map[string]string{
				"protocol": "https",
				"host":     host,
			}
			if username != "" {
				metadata["username"] = username
			}

			// Determine expiration: custom --expires-in or default 30 days
			expiresAt := time.Time{}
			if expiresIn != "" {
				duration, err := locksmith.ParseDuration(expiresIn)
				if err != nil {
					return fmt.Errorf("invalid --expires-in value: %w", err)
				}
				expiresAt = time.Now().Add(duration)
			} else {
				// Default: 30 days for git credentials
				expiresAt = time.Now().Add(defaultAddTTL)
			}

			if err := ls.SetWithContext(
				key,
				secretBytes,
				expiresAt,
				globalBiometricReqs,
				locksmith.SecretTypePassword,
				"git",
				fmt.Sprintf("https://%s", host),
				metadata,
			); err != nil {
				return fmt.Errorf("error saving git secret: %w", err)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully saved git credential '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
			return nil
		}

		key := ""
		secret := ""
		promptMode := false

		if len(args) > 0 {
			key = args[0]
		}
		if len(args) > 1 {
			secret = args[1]
		}

		reader := bufio.NewReader(cmd.InOrStdin())
		if key == "" {
			promptMode = true
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Key: ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading key: %w", err)
			}
			key = strings.TrimSpace(input)
		}

		if secret == "" {
			promptMode = true
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Secret: ")

			// Use masked input if stdin is a terminal, otherwise fall back to normal input (for tests)
			if term.IsTerminal(int(os.Stdin.Fd())) {
				secretInput, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("error reading secret: %w", err)
				}
				secret = string(secretInput)
			} else {
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading secret: %w", err)
				}
				secret = strings.TrimRight(input, "\r\n")
			}
		}

		if promptMode {
			if secretType == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Secret type (optional: password|api_key|oauth_token|token): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading secret type: %w", err)
				}
				secretType = strings.TrimSpace(input)
			}

			if ownerApplication == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Owner app (optional, example: github): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading owner app: %w", err)
				}
				ownerApplication = strings.TrimSpace(input)
			}

			if sourceURL == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Source URL (optional): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading source URL: %w", err)
				}
				sourceURL = strings.TrimSpace(input)
			}
		}

		secretBytes := []byte(secret)

		if key == "" {
			return fmt.Errorf("key cannot be empty")
		}
		if len(secretBytes) == 0 {
			return fmt.Errorf("secret cannot be empty")
		}

		// Determine expiration: custom --expires-in or default 30 days
		expiresAt := time.Now().Add(defaultAddTTL)
		if expiresIn != "" {
			duration, err := locksmith.ParseDuration(expiresIn)
			if err != nil {
				return fmt.Errorf("invalid --expires-in value: %w", err)
			}
			expiresAt = time.Now().Add(duration)
		}
		typedSecretType := locksmith.ParseSecretType(secretType)
		// Use SetWithContext to persist secret metadata used for rotator auto-loading.
		if err := ls.SetWithContext(
			key,
			secretBytes,
			expiresAt,
			globalBiometricReqs,
			typedSecretType,
			ownerApplication,
			sourceURL,
			nil,
		); err != nil {
			return fmt.Errorf("error saving secret: %w", err)
		}

		// Zero the secret bytes after use
		for i := range secretBytes {
			secretBytes[i] = 0
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully saved secret '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVar(&secretType, "type", "", "Optional secret type for rotator selection: password|api_key|oauth_token|token")
	addCmd.Flags().StringVar(&ownerApplication, "owner-app", "", "Optional owner application/provider identifier (for example: github, gitlab)")
	addCmd.Flags().StringVar(&sourceURL, "source-url", "", "Optional source endpoint URL used by rotator selection")
	addCmd.Flags().BoolVar(&addGit, "git", false, "Store a Git credential (format: add <host> <username> --git)")
	addCmd.Flags().StringVar(&expiresIn, "expires-in", "", "Expiration duration (e.g., 30d, 1y, 90d). Defaults to 30 days if not specified.")
}
