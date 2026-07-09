package githubrotator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
	"golang.org/x/crypto/ssh"
)

func TestAppInstallationTokenSupports(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	if !r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "api_key"}) {
		t.Fatal("expected github api_key selector to be supported")
	}
	if !r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "token"}) {
		t.Fatal("expected github token selector to be supported")
	}
	if r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "oauth_token"}) {
		t.Fatal("expected oauth_token selector to be unsupported")
	}
	if r.Supports(rotator.RotationSelector{OwnerApplication: "gitlab", SecretType: "api_key"}) {
		t.Fatal("expected non-github owner to be unsupported")
	}
}

func TestInstallationIDFromEndpoint(t *testing.T) {
	endpoint := "https://api.github.com/app/installations/123456/access_tokens"
	if got := installationIDFromEndpoint(endpoint); got != "123456" {
		t.Fatalf("installationIDFromEndpoint() = %q, want %q", got, "123456")
	}
	if got := installationIDFromEndpoint("https://api.github.com/other/path"); got != "" {
		t.Fatalf("expected empty installation id, got %q", got)
	}
}

func TestAppInstallationTokenRotateSuccess(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	privateKeyPEM := testRSAPrivateKeyPEM(t)
	expiresAt := time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339)
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.clientid")
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", privateKeyPEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		if req.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("unexpected Accept header")
		}
		if req.Header.Get("X-GitHub-Api-Version") != defaultGitHubAPIVersion {
			t.Fatalf("unexpected API version")
		}
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("expected bearer auth, got %q", auth)
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			t.Fatalf("jwt should have 3 segments")
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode jwt payload: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			t.Fatalf("failed to unmarshal jwt payload: %v", err)
		}
		if payload["iss"] != "Iv1.clientid" {
			t.Fatalf("expected jwt iss to use client id, got %#v", payload["iss"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_installation_token",
			"expires_at": expiresAt,
		})
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        server.URL + "/app/installations/123456/access_tokens",
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != "ghs_installation_token" {
		t.Fatalf("token mismatch: got %q", string(out.NewValue))
	}
	if out.TTL <= 0 {
		t.Fatalf("expected positive TTL, got %v", out.TTL)
	}
}

func TestAppInstallationTokenRotateFallbackToAppID(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	privateKeyPEM := testRSAPrivateKeyPEM(t)
	expiresAt := time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339)
	t.Setenv("GITHUB_APP_CLIENT_ID", "")
	t.Setenv("GITHUB_CLIENT_ID", "")
	t.Setenv("GITHUB_APP_ID", "12345")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", privateKeyPEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			t.Fatalf("jwt should have 3 segments")
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode jwt payload: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			t.Fatalf("failed to unmarshal jwt payload: %v", err)
		}
		if payload["iss"] != "12345" {
			t.Fatalf("expected jwt iss to fallback to app id, got %#v", payload["iss"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_installation_token",
			"expires_at": expiresAt,
		})
	}))
	defer server.Close()

	if _, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        server.URL + "/app/installations/123456/access_tokens",
		},
	}); err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
}

func TestAppInstallationTokenRotateMissingPrivateKey(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	t.Setenv("GITHUB_APP_ID", "12345")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        "https://api.github.com/app/installations/123456/access_tokens",
		},
	})
	if err == nil {
		t.Fatal("expected missing private key error")
	}
}

func TestAppInstallationTokenRotateDiscoversInstallationID(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	privateKeyPEM := testRSAPrivateKeyPEM(t)
	expiresAt := time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339)
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.clientid")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/app/installations":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":123456,"account":{"login":"bonjoski"}}]`))
		case "/app/installations/123456/access_tokens":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":      "ghs_installation_token",
				"expires_at": expiresAt,
			})
		default:
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        server.URL,
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != "ghs_installation_token" {
		t.Fatalf("token mismatch: got %q", string(out.NewValue))
	}
}

func TestAppInstallationTokenRotateMultipleInstallationsRequiresSelector(t *testing.T) {
	r := NewAppInstallationTokenRotator()
	privateKeyPEM := testRSAPrivateKeyPEM(t)
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.clientid")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/app/installations" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1,"account":{"login":"org-a"}},{"id":2,"account":{"login":"org-b"}}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        server.URL,
		},
	})
	if err == nil {
		t.Fatal("expected error when multiple installations exist without selector")
	}

	_, err = r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "token",
			SourceURL:        server.URL,
			Metadata: map[string]string{
				"github_installation_account": "org-b",
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected second call to select installation account and reach token endpoint, got err=%v", err)
	}
}

func testRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(key, "test-key")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(blk))
}
