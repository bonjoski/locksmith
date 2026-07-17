package locksmith

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

type integrationSpec struct {
	command string
	env     map[string]string
}

var builtinIntegrations = map[string]integrationSpec{
	"acli": {
		command: "acli",
		env: map[string]string{
			"ATLASSIAN_API_TOKEN": "locksmith://atlassian/acli/token",
		},
	},
	"gh": {
		command: "gh",
		env: map[string]string{
			"GH_TOKEN": "locksmith://github/gh/token",
		},
	},
	"glab": {
		command: "glab",
		env: map[string]string{
			"GITLAB_TOKEN": "locksmith://gitlab/glab/token",
		},
	},
}

// Run executes a command with secrets injected into its environment
func (l *Locksmith) Run(args []string, envFile string) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	var envFileVars map[string]string
	if envFile != "" {
		var err error
		envFileVars, err = parseEnvFile(envFile)
		if err != nil {
			return 1, fmt.Errorf("failed to read env file: %w", err)
		}
	}

	env, err := l.ResolveEnvironment(os.Environ(), envFileVars)
	if err != nil {
		return 1, err
	}

	return runCommandWithEnv(args[0], args[1:], env)
}

// RunIntegration executes a configured integration command with locksmith-backed env vars.
func (l *Locksmith) RunIntegration(name string, args []string) (int, error) {
	profile, err := l.integrationProfile(name)
	if err != nil {
		return 1, err
	}

	env, err := l.ResolveEnvironment(os.Environ(), profile.env)
	if err != nil {
		return 1, err
	}

	return runCommandWithEnv(profile.command, args, env)
}

// ResolveIntegrationEnvironment returns the environment used for a named integration.
func (l *Locksmith) ResolveIntegrationEnvironment(name string, hostEnv []string) ([]string, error) {
	profile, err := l.integrationProfile(name)
	if err != nil {
		return nil, err
	}

	return l.ResolveEnvironment(hostEnv, profile.env)
}

func (l *Locksmith) integrationProfile(name string) (integrationSpec, error) {
	key := strings.TrimSpace(strings.ToLower(name))
	if key == "" {
		return integrationSpec{}, fmt.Errorf("integration name is required")
	}

	// Start from builtin defaults.
	profile, ok := builtinIntegrations[key]
	if !ok {
		profile = integrationSpec{}
	}

	// Allow user config overrides.
	if l != nil && l.Config != nil && l.Config.Integrations != nil {
		if cfgProfile, exists := l.Config.Integrations[key]; exists {
			if strings.TrimSpace(cfgProfile.Command) != "" {
				profile.command = strings.TrimSpace(cfgProfile.Command)
			}
			if len(cfgProfile.Env) > 0 {
				profile.env = copyStringMap(cfgProfile.Env)
			}
		}
	}

	if profile.command == "" {
		return integrationSpec{}, fmt.Errorf("integration '%s' is not configured", key)
	}

	profile.env = normalizeIntegrationEnv(profile.env)
	return profile, nil
}

func normalizeIntegrationEnv(env map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range env {
		envName := strings.TrimSpace(k)
		secretRef := strings.TrimSpace(v)
		if envName == "" || secretRef == "" {
			continue
		}
		if strings.HasPrefix(secretRef, "locksmith://") {
			out[envName] = secretRef
			continue
		}
		out[envName] = "locksmith://" + secretRef
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func runCommandWithEnv(command string, args []string, env []string) (int, error) {
	cmd := exec.Command(command, args...) // #nosec G204 // nosem
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Forward signals to child process
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, forwardedSignals...)
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	defer signal.Stop(sigChan)

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("failed to start command: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// ResolveEnvironment resolves secrets defined in the environment or envFileVars
func (l *Locksmith) ResolveEnvironment(hostEnv []string, envFileVars map[string]string) ([]string, error) {
	resolved := make(map[string]string)

	// 1. Load host environment
	for _, item := range hostEnv {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			resolved[parts[0]] = parts[1]
		}
	}

	// 2. Load env file vars (overriding host env if they overlap)
	for k, v := range envFileVars {
		resolved[k] = v
	}

	// 3. Separate regular env vars and secret-defining vars
	regularVars := make(map[string]string)
	secretVars := make(map[string]string)

	for k, v := range resolved {
		if strings.HasPrefix(k, "LOCKSMITH_SECRET_") {
			newKey := strings.TrimPrefix(k, "LOCKSMITH_SECRET_")
			secretVars[newKey] = v
		} else if strings.HasPrefix(v, "locksmith://") {
			secretKey := strings.TrimPrefix(v, "locksmith://")
			secretVars[k] = secretKey
		} else {
			regularVars[k] = v
		}
	}

	// 4. Build final environment map starting with regular variables
	finalEnvMap := make(map[string]string)
	for k, v := range regularVars {
		finalEnvMap[k] = v
	}

	// 5. Resolve secrets and overwrite regular variables on conflict
	var secretsToZero [][]byte
	defer func() {
		for _, s := range secretsToZero {
			for i := range s {
				s[i] = 0
			}
		}
	}()

	for k, secretKey := range secretVars {
		valBytes, err := l.Get(secretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get secret '%s': %w", secretKey, err)
		}
		secretsToZero = append(secretsToZero, valBytes)
		finalEnvMap[k] = string(valBytes)
	}

	// 6. Build the final OS env array
	var finalEnv []string
	for k, v := range finalEnvMap {
		// Clean up the original LOCKSMITH_SECRET_* variables so they are not leaked
		if strings.HasPrefix(k, "LOCKSMITH_SECRET_") {
			continue
		}
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}

	return finalEnv, nil
}

func parseEnvFile(filepath string) (map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Strip quotes if present
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			val = val[1 : len(val)-1]
		}
		env[key] = val
	}
	return env, scanner.Err()
}
