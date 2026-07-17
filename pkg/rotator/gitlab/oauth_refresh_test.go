package gitlabrotator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

func TestResolveOAuthRefreshEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "base host", in: "https://gitlab.example.com", want: "https://gitlab.example.com/oauth/token"},
		{name: "api root", in: "https://gitlab.example.com/api/v4", want: "https://gitlab.example.com/oauth/token"},
		{name: "full oauth endpoint", in: "https://gitlab.example.com/oauth/token", want: "https://gitlab.example.com/oauth/token"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveOAuthRefreshEndpoint(tc.in)
			if err != nil {
				t.Fatalf("resolveOAuthRefreshEndpoint error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthRefreshRotateSuccess(t *testing.T) {
	r := NewOAuthRefreshRotator()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		if req.URL.Path != "/oauth/token" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("failed reading request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		if values.Get("grant_type") != "refresh_token" {
			t.Fatalf("expected grant_type refresh_token, got %q", values.Get("grant_type"))
		}
		if values.Get("refresh_token") != "refresh-abc" {
			t.Fatalf("unexpected refresh_token: %q", values.Get("refresh_token"))
		}
		if values.Get("client_id") != "cid" {
			t.Fatalf("unexpected client_id: %q", values.Get("client_id"))
		}
		if values.Get("client_secret") != "csecret" {
			t.Fatalf("unexpected client_secret: %q", values.Get("client_secret"))
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"new-access-xyz","expires_in":3600}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "oauth_token",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
			Metadata: map[string]string{
				"gitlab_refresh_token": "refresh-abc",
				"gitlab_client_id":     "cid",
				"gitlab_client_secret": "csecret",
			},
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != "new-access-xyz" {
		t.Fatalf("unexpected access token: %q", string(out.NewValue))
	}
	if out.TTL != time.Hour {
		t.Fatalf("expected TTL 1h, got %v", out.TTL)
	}
}

func TestOAuthRefreshSupports(t *testing.T) {
	r := NewOAuthRefreshRotator()
	if !r.Supports(rotator.RotationSelector{SecretType: "oauth_token", OwnerApplication: "gitlab"}) {
		t.Fatal("expected oauth gitlab selector to be supported")
	}
	if r.Supports(rotator.RotationSelector{SecretType: "api_key", OwnerApplication: "gitlab"}) {
		t.Fatal("expected api_key selector to be unsupported")
	}
	if r.Supports(rotator.RotationSelector{SecretType: "oauth_token", OwnerApplication: "github"}) {
		t.Fatal("expected non-gitlab owner to be unsupported")
	}
}

func TestOAuthRefreshMissingMetadata(t *testing.T) {
	r := NewOAuthRefreshRotator()
	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "oauth_token",
			OwnerApplication: "gitlab",
		},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "refresh token") {
		t.Fatalf("expected refresh token error, got %v", err)
	}
}

func TestOAuthRefreshRotateWithoutClientCredentials(t *testing.T) {
	r := NewOAuthRefreshRotator()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("failed reading request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		if values.Get("grant_type") != "refresh_token" {
			t.Fatalf("expected grant_type refresh_token, got %q", values.Get("grant_type"))
		}
		if values.Get("refresh_token") != "refresh-only-abc" {
			t.Fatalf("unexpected refresh_token: %q", values.Get("refresh_token"))
		}
		if values.Get("client_id") != "" {
			t.Fatalf("expected empty client_id, got %q", values.Get("client_id"))
		}
		if values.Get("client_secret") != "" {
			t.Fatalf("expected empty client_secret, got %q", values.Get("client_secret"))
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"new-access-no-client","expires_in":1200}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		Timeout: 5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "oauth_token",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
			Metadata: map[string]string{
				"gitlab_refresh_token": "refresh-only-abc",
			},
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != "new-access-no-client" {
		t.Fatalf("unexpected access token: %q", string(out.NewValue))
	}
}
