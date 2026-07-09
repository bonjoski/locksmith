package githubrotator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

func TestFGPATReplaceSupports(t *testing.T) {
	r := NewFGPATReplaceRotator()
	if !r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "api_key"}) {
		t.Fatal("expected github api_key selector to be supported")
	}
	if !r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "token"}) {
		t.Fatal("expected github token selector to be supported")
	}
	if r.Supports(rotator.RotationSelector{OwnerApplication: "github", SecretType: "oauth_token"}) {
		t.Fatal("expected oauth_token selector to be unsupported for fgpat replace")
	}
	if r.Supports(rotator.RotationSelector{OwnerApplication: "gitlab", SecretType: "api_key"}) {
		t.Fatal("expected non-github owner to be unsupported")
	}
}

func TestFGPATReplaceRotateSuccess(t *testing.T) {
	r := NewFGPATReplaceRotator()
	oldToken := "github_pat_old"
	newToken := "github_pat_new"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["action"] != "replace" {
			t.Fatalf("unexpected action: %s", body["action"])
		}
		if body["current_token"] != oldToken {
			t.Fatal("expected current_token to be sent")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"` + newToken + `","expires_in":"30d"}`))
	}))
	defer server.Close()

	out, err := r.Rotate(t.Context(), rotator.RotationInput{
		Key:          "github/pat",
		CurrentValue: []byte(oldToken),
		Timeout:      5 * time.Second,
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "api_key",
			SourceURL:        server.URL,
		},
	})
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	if string(out.NewValue) != newToken {
		t.Fatalf("new token mismatch: got %q, want %q", string(out.NewValue), newToken)
	}
	if out.TTL < 29*24*time.Hour {
		t.Fatalf("expected ttl around 30d, got %v", out.TTL)
	}
}

func TestFGPATReplaceRotateMissingEndpoint(t *testing.T) {
	r := NewFGPATReplaceRotator()
	_, err := r.Rotate(t.Context(), rotator.RotationInput{
		CurrentValue: []byte("github_pat_old"),
		Selector: rotator.RotationSelector{
			OwnerApplication: "github",
			SecretType:       "api_key",
		},
	})
	if err == nil {
		t.Fatal("expected missing endpoint error")
	}
}

func TestParseDurationWithCalendarUnits(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"1mo", 30 * 24 * time.Hour},
		{"1y", 365 * 24 * time.Hour},
	}
	for _, tc := range tests {
		got, err := parseDurationWithCalendarUnits(tc.in)
		if err != nil {
			t.Fatalf("parseDurationWithCalendarUnits(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseDurationWithCalendarUnits(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
