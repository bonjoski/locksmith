package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	envNoCache    bool
	envClearCache bool
	envShell      string
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Export secrets as shell environment variables",
	Long: `Export secrets defined under shell.env in ~/.locksmith/config.yml as shell
export statements. Designed to be eval'd in your shell profile:

  eval "$(locksmith env)"

Values are cached per boot session — biometric authentication is only
requested once per reboot. The cache is stored in a mode-600 temp file
keyed to the system boot time and is automatically invalidated on reboot.

Example ~/.locksmith/config.yml:

  shell:
    env:
      MY_API_KEY: locksmith://api/key
      DB_PASSWORD: locksmith://db/password`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if envClearCache {
			path, err := cacheFilePath()
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to clear cache: %w", err)
			}
			fmt.Fprintln(os.Stderr, "locksmith: env cache cleared")
			return nil
		}

		if len(cfg.Shell.Env) == 0 {
			fmt.Fprintln(os.Stderr, "locksmith: no shell.env entries configured in ~/.locksmith/config.yml")
			return nil
		}

		shell := detectShell(envShell)

		if !envNoCache {
			cached, err := loadCache()
			if err == nil {
				printEnv(cmd, cached, shell)
				return nil
			}
		}

		resolved, err := ls.ResolveShellEnv(cfg.Shell.Env)
		if err != nil {
			return err
		}

		if !envNoCache {
			if err := writeCache(resolved); err != nil {
				fmt.Fprintf(os.Stderr, "locksmith: warning: could not write env cache: %v\n", err)
			}
		}

		printEnv(cmd, resolved, shell)
		return nil
	},
}

func printEnv(cmd *cobra.Command, env map[string]string, shell string) {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := env[k]
		switch shell {
		case "fish":
			fmt.Fprintf(cmd.OutOrStdout(), "set -gx %s %s;\n", k, fishQuote(v))
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "export %s=%s\n", k, shQuote(v))
		}
	}
}

// shQuote wraps v in single quotes, escaping any existing single quotes.
func shQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'"
}

// fishQuote wraps v in single quotes for fish shell.
func fishQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "\\'") + "'"
}

func detectShell(override string) string {
	if override != "" {
		return strings.ToLower(override)
	}
	shell := os.Getenv("SHELL")
	switch {
	case strings.Contains(shell, "fish"):
		return "fish"
	default:
		return "sh"
	}
}

// cacheFilePath returns a per-user, per-boot temp file path.
func cacheFilePath() (string, error) {
	boot, err := bootTime()
	if err != nil {
		return "", fmt.Errorf("could not determine boot time: %w", err)
	}
	name := fmt.Sprintf("locksmith_env_%d_%d", os.Getuid(), boot.Unix())
	return filepath.Join(os.TempDir(), name), nil
}

func loadCache() (map[string]string, error) {
	path, err := cacheFilePath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	return env, scanner.Err()
}

func writeCache(env map[string]string) error {
	path, err := cacheFilePath()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w := bufio.NewWriter(f)
	for _, k := range keys {
		fmt.Fprintf(w, "%s=%s\n", k, env[k])
	}
	return w.Flush()
}


func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().BoolVar(&envNoCache, "no-cache", false, "Skip the session cache and re-fetch all secrets")
	envCmd.Flags().BoolVar(&envClearCache, "clear-cache", false, "Delete the session cache and exit")
	envCmd.Flags().StringVar(&envShell, "shell", "", "Output format: sh, bash, zsh, fish (default: auto-detect from $SHELL)")
}
