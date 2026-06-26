package locksmith

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

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

	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 // nosem
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
