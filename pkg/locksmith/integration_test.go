package locksmith

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func zeroTestBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newTestSecret(value string) Secret {
	raw := []byte(value)
	defer zeroTestBytes(raw)

	valCopy := make([]byte, len(raw))
	copy(valCopy, raw)
	return Secret{Value: valCopy, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
}

func TestResolveIntegrationEnvironmentBuiltins(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}

	ghSecret := newTestSecret("gh-token-123")
	defer zeroTestBytes(ghSecret.Value)
	glabSecret := newTestSecret("glab-token-456")
	defer zeroTestBytes(glabSecret.Value)
	ghData, _ := json.Marshal(ghSecret)
	defer zeroTestBytes(ghData)
	glabData, _ := json.Marshal(glabSecret)
	defer zeroTestBytes(glabData)

	mb := &testBackend{
		secrets: map[string][]byte{
			"github/gh/token":   ghData,
			"gitlab/glab/token": glabData,
		},
	}

	ls := NewWithCache(mc)
	ls.Backend = mb

	hostEnv := []string{"PATH=/usr/bin", "EXISTING=value"}

	ghEnv, err := ls.ResolveIntegrationEnvironment("gh", hostEnv)
	if err != nil {
		t.Fatalf("ResolveIntegrationEnvironment(gh) failed: %v", err)
	}
	ghMap := envSliceToMap(ghEnv)
	if ghMap["GH_TOKEN"] != "gh-token-123" {
		t.Fatalf("expected GH_TOKEN from vault, got %q", ghMap["GH_TOKEN"])
	}

	glabEnv, err := ls.ResolveIntegrationEnvironment("glab", hostEnv)
	if err != nil {
		t.Fatalf("ResolveIntegrationEnvironment(glab) failed: %v", err)
	}
	glabMap := envSliceToMap(glabEnv)
	if glabMap["GITLAB_TOKEN"] != "glab-token-456" {
		t.Fatalf("expected GITLAB_TOKEN from vault, got %q", glabMap["GITLAB_TOKEN"])
	}
}

func TestResolveIntegrationEnvironmentConfigOverride(t *testing.T) {
	mc := &MockCache{secrets: make(map[string]Secret)}

	overrideSecret := newTestSecret("override-token")
	defer zeroTestBytes(overrideSecret.Value)
	overrideData, _ := json.Marshal(overrideSecret)
	defer zeroTestBytes(overrideData)

	mb := &testBackend{secrets: map[string][]byte{"custom/gh/token": overrideData}}

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Config = &Config{
		Integrations: map[string]IntegrationConfig{
			"gh": {
				Command: "gh",
				Env: map[string]string{
					"GH_TOKEN": "custom/gh/token",
				},
			},
		},
	}

	env, err := ls.ResolveIntegrationEnvironment("gh", []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("ResolveIntegrationEnvironment with override failed: %v", err)
	}
	envMap := envSliceToMap(env)
	if envMap["GH_TOKEN"] != "override-token" {
		t.Fatalf("expected override GH_TOKEN from vault, got %q", envMap["GH_TOKEN"])
	}
}

func TestResolveIntegrationEnvironmentUnknownIntegration(t *testing.T) {
	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	_, err := ls.ResolveIntegrationEnvironment("unknown", []string{"PATH=/usr/bin"})
	if err == nil {
		t.Fatal("expected unknown integration to fail")
	}
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, item := range env {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
