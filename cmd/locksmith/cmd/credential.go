package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:   "credential <get|store|erase>",
	Short: "Git credential helper capability",
	Long:  "Acts as a Git credential helper by reading key=value pairs from stdin and returning matching credentials on stdout.",
	Args:  cobra.ExactArgs(1),
	PreRun: func(cmd *cobra.Command, args []string) {
		// Enable OnlyCached mode for git credential operations to avoid blocking biometric prompts.
		// This makes the helper read from cache only - cache misses return nil instead of prompting.
		// Git will then prompt the user for password and call "store" to cache it.
		if ls != nil {
			ls.Options.OnlyCached = true
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		action := strings.ToLower(args[0])

		inputs, err := readGitCredentialInput(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("error reading git credential input: %w", err)
		}

		switch action {
		case "get":
			return handleGet(cmd, inputs)
		case "store":
			return handleStore(cmd, inputs)
		case "erase":
			return handleErase(cmd, inputs)
		default:
			return fmt.Errorf("unsupported action '%s'. Supported actions: get, store, erase", action)
		}
	},
}

func readGitCredentialInput(r io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(r)
	inputs := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			inputs[parts[0]] = parts[1]
		}
	}
	return inputs, scanner.Err()
}

func findGitUserSecret(host, username string) (*locksmith.Secret, string) {
	if username != "" {
		key := fmt.Sprintf("git/%s/%s", host, username)
		secret, err := ls.GetWithMetadata(key)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			return secret, key
		}
	}
	return nil, ""
}

func findGitGenericSecret(host string) (*locksmith.Secret, string) {
	key := fmt.Sprintf("git/%s", host)
	secret, err := ls.GetWithMetadata(key)
	if err == nil && secret != nil && len(secret.Value) > 0 {
		return secret, key
	}
	return nil, ""
}

func findGitIntegrationSecret(host string) (*locksmith.Secret, string) {
	if host == "github.com" {
		key := "github/gh/token"
		secret, err := ls.GetWithMetadata(key)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			return secret, key
		}
	} else if host == "gitlab.com" {
		key := "gitlab/glab/token"
		secret, err := ls.GetWithMetadata(key)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			return secret, key
		}
	}
	return nil, ""
}

func findGitSingleUserSecret(host string) (*locksmith.Secret, string, string) {
	keys, err := ls.ListKeyNames()
	if err != nil {
		return nil, "", ""
	}
	prefix := fmt.Sprintf("git/%s/", host)
	var matchingKeys []string
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			matchingKeys = append(matchingKeys, k)
		}
	}
	if len(matchingKeys) == 1 {
		key := matchingKeys[0]
		secret, err := ls.GetWithMetadata(key)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			return secret, key, strings.TrimPrefix(key, prefix)
		}
	}
	return nil, "", ""
}

func handleGet(cmd *cobra.Command, inputs map[string]string) error {
	host := inputs["host"]
	username := inputs["username"]

	if host == "" {
		return nil
	}

	var matchedSecret *locksmith.Secret
	var matchedKey string

	// 1. Try git/<host>/<username> if username is provided
	matchedSecret, matchedKey = findGitUserSecret(host, username)

	// 2. Try git/<host>
	if matchedSecret == nil {
		matchedSecret, matchedKey = findGitGenericSecret(host)
	}

	// 3. Fallbacks
	if matchedSecret == nil {
		matchedSecret, matchedKey = findGitIntegrationSecret(host)
	}

	// 4. Try matching multiple git/<host>/<some_username> keys if username is empty
	if matchedSecret == nil && username == "" {
		var matchedUser string
		matchedSecret, matchedKey, matchedUser = findGitSingleUserSecret(host)
		if matchedSecret != nil {
			username = matchedUser
		}
	}

	if matchedSecret == nil {
		return nil
	}

	// Determine username to output
	outUsername := username
	if outUsername == "" {
		if matchedSecret.Metadata != nil && matchedSecret.Metadata["username"] != "" {
			outUsername = matchedSecret.Metadata["username"]
		} else if matchedKey == "github/gh/token" || matchedKey == "gitlab/glab/token" {
			outUsername = "oauth2"
		} else {
			outUsername = "git"
		}
	}

	// Output to stdout
	fmt.Fprintf(cmd.OutOrStdout(), "username=%s\n", outUsername)
	fmt.Fprintf(cmd.OutOrStdout(), "password=%s\n", string(matchedSecret.Value))
	return nil
}

func handleStore(cmd *cobra.Command, inputs map[string]string) error {
	protocol := inputs["protocol"]
	host := inputs["host"]
	username := inputs["username"]
	password := inputs["password"]

	if host == "" || password == "" {
		return nil
	}

	var key string
	if username != "" {
		key = fmt.Sprintf("git/%s/%s", host, username)
	} else {
		key = fmt.Sprintf("git/%s", host)
	}

	metadata := map[string]string{
		"protocol": protocol,
		"host":     host,
	}
	if username != "" {
		metadata["username"] = username
	}
	if inputs["path"] != "" {
		metadata["path"] = inputs["path"]
	}

	err := ls.SetWithContext(
		key,
		[]byte(password),
		time.Time{}, // no expiration
		globalBiometricReqs,
		locksmith.SecretTypePassword,
		"git",
		fmt.Sprintf("%s://%s", protocol, host),
		metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	return nil
}

func handleErase(cmd *cobra.Command, inputs map[string]string) error {
	host := inputs["host"]
	username := inputs["username"]

	if host == "" {
		return nil
	}

	keysToDelete := []string{}
	if username != "" {
		key := fmt.Sprintf("git/%s/%s", host, username)
		keysToDelete = append(keysToDelete, key)
	} else {
		keysToDelete = append(keysToDelete, fmt.Sprintf("git/%s", host))
		keys, err := ls.List()
		if err == nil {
			prefix := fmt.Sprintf("git/%s/", host)
			for k := range keys {
				if strings.HasPrefix(k, prefix) {
					keysToDelete = append(keysToDelete, k)
				}
			}
		}
	}

	for _, k := range keysToDelete {
		// Check if it exists first
		secret, err := ls.GetWithMetadata(k)
		if err == nil && secret != nil {
			if err := ls.Delete(k); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to delete key %s: %v\n", k, err)
			}
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(credentialCmd)
}
