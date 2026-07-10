package gitlabrotator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

func TestResolveSelfRotateEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "default host appends api path", in: "https://gitlab.example.com", want: "https://gitlab.example.com/api/v4/personal_access_tokens/self/rotate"},
		{name: "api root appends self rotate", in: "https://gitlab.example.com/api/v4", want: "https://gitlab.example.com/api/v4/personal_access_tokens/self/rotate"},
		{name: "full endpoint passthrough", in: "https://gitlab.example.com/api/v4/personal_access_tokens/self/rotate", want: "https://gitlab.example.com/api/v4/personal_access_tokens/self/rotate"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSelfRotateEndpoint(tc.in)
			if err != nil {
				t.Fatalf("resolveSelfRotateEndpoint error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPATSelfRotateSuccess(t *testing.T) {
	r := NewPATSelfRotateRotator()
	oldToken := "glpat-old"
	newToken := "glpat-new"
	expiresAt := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		if req.URL.Path != "/api/v4/personal_access_tokens/self/rotate" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		if req.Header.Get("PRIVATE-TOKEN") != oldToken {
			t.Fatalf("missing PRIVATE-TOKEN header")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_at":"` + expiresAt + `"}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(out.NewValue), newToken)
	}
	if out.TTL <= 0 {
		t.Fatalf("expected positive ttl, got %v", out.TTL)
	}
}

func TestPATSelfRotateWithExpiresAt(t *testing.T) {
	r := NewPATSelfRotateRotator()
	oldToken := "glpat-old"
	newToken := "glpat-new"
	expiresAt := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		if req.URL.Path != "/api/v4/personal_access_tokens/self/rotate" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		if got := values.Get("expires_at"); got != expiresAt {
			t.Fatalf("expected expires_at %q, got %q", expiresAt, got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_at":"` + expiresAt + `"}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
			Metadata: map[string]string{
				"gitlab_expires_at": expiresAt,
			},
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(out.NewValue), newToken)
	}
}

func TestPATSelfRotateWithDesiredTTL(t *testing.T) {
	r := NewPATSelfRotateRotator()
	oldToken := "glpat-old"
	newToken := "glpat-new"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		expiresAt := values.Get("expires_at")
		if expiresAt == "" {
			t.Fatal("expected expires_at to be set from DesiredTTL")
		}
		if _, err := time.Parse("2006-01-02", expiresAt); err != nil {
			t.Fatalf("expected valid expires_at date, got %q", expiresAt)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_at":"` + expiresAt + `"}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		DesiredTTL:   7 * 24 * time.Hour,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(out.NewValue), newToken)
	}
}

func TestPATSelfRotateMetadataExpiresAtOverridesDesiredTTL(t *testing.T) {
	r := NewPATSelfRotateRotator()
	oldToken := "glpat-old"
	newToken := "glpat-new"
	metadataExpiresAt := time.Now().UTC().Add(3 * 24 * time.Hour).Format("2006-01-02")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		if got := values.Get("expires_at"); got != metadataExpiresAt {
			t.Fatalf("expected metadata expires_at %q to override desired ttl, got %q", metadataExpiresAt, got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_at":"` + metadataExpiresAt + `"}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		DesiredTTL:   10 * 24 * time.Hour,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
			Metadata: map[string]string{
				"gitlab_expires_at": metadataExpiresAt,
			},
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(out.NewValue), newToken)
	}
}

func TestPATSelfRotateInvalidExpiresAt(t *testing.T) {
	r := NewPATSelfRotateRotator()
	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("glpat-old"),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        "https://gitlab.example.com",
			Metadata: map[string]string{
				"gitlab_expires_at": "07-17-2026",
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid expires_at error")
	}
}

func TestPATSelfRotateMissingToken(t *testing.T) {
	r := NewPATSelfRotateRotator()
	_, err := r.Rotate(t.Context(), rotator.RotationInput{})
	if err == nil {
		t.Fatal("expected error for missing current token")
	}
}

func TestPATSelfRotateSupports(t *testing.T) {
	r := NewPATSelfRotateRotator()
	if !r.Supports(rotator.RotationSelector{SecretType: "api_key", OwnerApplication: "gitlab"}) {
		t.Fatal("expected gitlab api_key selector to be supported")
	}
	if r.Supports(rotator.RotationSelector{SecretType: "password", OwnerApplication: "gitlab"}) {
		t.Fatal("expected password selector to be unsupported")
	}
	if r.Supports(rotator.RotationSelector{SecretType: "api_key", OwnerApplication: "github"}) {
		t.Fatal("expected non-gitlab owner to be unsupported")
	}
}

func TestPATSelfRotateDecodeError(t *testing.T) {
	r := NewPATSelfRotateRotator()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("glpat-old"),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
		},
	})
	if err == nil {
		t.Fatal("expected JSON decode error")
	}
}

func TestPATSelfRotateStatusError(t *testing.T) {
	r := NewPATSelfRotateRotator()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer server.Close()

	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("glpat-old"),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
		},
	})
	if err == nil {
		t.Fatal("expected non-200 status error")
	}
}

func TestPATSelfRotateIgnoresUnknownFields(t *testing.T) {
	r := NewPATSelfRotateRotator()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		resp := map[string]any{
			"token":      "glpat-new",
			"expires_at": time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02"),
			"id":         42,
		}
		b, _ := json.Marshal(resp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer server.Close()

	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("glpat-old"),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			SecretType:       "api_key",
			OwnerApplication: "gitlab",
			SourceURL:        server.URL,
		},
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}
