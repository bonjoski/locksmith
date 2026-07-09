package githubrotator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

func TestClientIDFromGitHubEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "empty", endpoint: "", want: ""},
		{name: "non github style path", endpoint: "https://example.com/rotate", want: ""},
		{name: "github endpoint", endpoint: "https://api.github.com/applications/Iv1.abc123/token", want: "Iv1.abc123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clientIDFromGitHubEndpoint(tc.endpoint)
			if got != tc.want {
				t.Fatalf("clientIDFromGitHubEndpoint(%q) = %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestOAuthResetRotatorRotateSuccess(t *testing.T) {
	r := NewOAuthResetRotator()
	oldToken := "gho_old_token"
	newToken := "gho_new_token"
	clientID := "Iv1.testclient"
	clientSecret := "super-secret"
	expiresAt := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	t.Setenv("GITHUB_CLIENT_SECRET", clientSecret)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPatch {
			t.Fatalf("expected PATCH, got %s", req.Method)
		}
		if req.Header.Get("Authorization") != basicAuthHeader(clientID, clientSecret) {
			t.Fatalf("unexpected Authorization header")
		}
		if req.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("unexpected Accept header")
		}
		if req.Header.Get("X-GitHub-Api-Version") != defaultGitHubAPIVersion {
			t.Fatalf("unexpected API version header")
		}

		var body struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.AccessToken != oldToken {
			t.Fatalf("unexpected access_token in request")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_at":"` + expiresAt + `"}`))
	}))
	defer server.Close()

	result, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "oauth_token",
			OwnerApplication: "github",
			SourceURL:        server.URL + "/applications/" + clientID + "/token",
		},
	})
	if err != nil {
		t.Fatalf("Rotate returned error: %v", err)
	}
	if string(result.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(result.NewValue), newToken)
	}
	if result.TTL <= time.Hour || result.TTL > 3*time.Hour {
		t.Fatalf("unexpected ttl: %v", result.TTL)
	}
}

func TestOAuthResetRotatorRotateMissingClientSecret(t *testing.T) {
	r := NewOAuthResetRotator()
	t.Setenv("GITHUB_CLIENT_SECRET", "")
	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("gho_old_token"),
		Selector: rotator.RotationSelector{
			SecretType:       "oauth_token",
			OwnerApplication: "github",
			SourceURL:        "https://api.github.com/applications/Iv1.testclient/token",
		},
	})
	if err == nil {
		t.Fatal("expected error when client_secret is missing")
	}
}
