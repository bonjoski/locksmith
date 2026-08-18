package locksmith

import "fmt"

// ResolveShellEnv resolves a map of ENV_NAME -> locksmith://key (or bare key)
// into a map of ENV_NAME -> plaintext value. Intended for shell export use cases.
func (l *Locksmith) ResolveShellEnv(envMap map[string]string) (map[string]string, error) {
	normalized := normalizeIntegrationEnv(envMap)
	out := make(map[string]string, len(normalized))
	for envName, ref := range normalized {
		key := ref[len("locksmith://"):]
		val, err := l.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s (locksmith://%s): %w", envName, key, err)
		}
		out[envName] = string(val)
	}
	return out, nil
}
