package aiprovider

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestMockProvider(t *testing.T) {
	mock := NewMockProvider("test-mock", "Default response")
	mock.SetReply("explain_error", "The error occurred because permission was denied on /etc/passwd")

	ctx := context.Background()

	resp, err := mock.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "Hello world"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "Default response" {
		t.Errorf("expected default response, got: %s", resp.Content)
	}

	resp2, err := mock.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "Please explain_error in sandbox"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp2.Content, "permission was denied") {
		t.Errorf("expected custom reply, got: %s", resp2.Content)
	}

	if mock.CallCount() != 2 {
		t.Errorf("expected 2 calls, got %d", mock.CallCount())
	}
}

func TestEmptyPromptValidation(t *testing.T) {
	mock := NewMockProvider("", "")
	_, err := mock.Complete(context.Background(), Request{})
	if !errors.Is(err, ErrEmptyPrompt) {
		t.Errorf("expected ErrEmptyPrompt, got %v", err)
	}
}

func TestAdversarial_SSRFAndURLValidation(t *testing.T) {
	blockedIPs := []string{
		"169.254.169.254",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"100.64.0.1",
		"::1",
		"fd00:ec2::254",
		"64:ff9b::a9fe:a9fe",
		"fe80::1",
	}
	for _, raw := range blockedIPs {
		addr := netip.MustParseAddr(raw)
		if err := CheckSafeIP(addr, false); !errors.Is(err, ErrUnsafeUpstreamIP) {
			t.Errorf("expected CheckSafeIP(%s, false) to block with ErrUnsafeUpstreamIP, got %v", raw, err)
		}
	}

	badURLs := []string{
		"",
		"file:///etc/passwd",
		"http://api.openai.com/v1",
		"https://user:pass@api.openai.com/v1",
		"https://api.openai.com/v1?key=leak",
		"https://169.254.169.254/latest/meta-data",
	}
	for _, u := range badURLs {
		if _, err := ValidateBaseURL(u, false, true); err == nil {
			t.Errorf("expected ValidateBaseURL(%q) to fail closed", u)
		}
	}

	badModels := []string{"", "../admin", "gpt-4o/../../evil", "model?key=1", "model\nheader"}
	for _, m := range badModels {
		if err := ValidateModelName(m); !errors.Is(err, ErrInvalidModelName) {
			t.Errorf("expected ValidateModelName(%q) to reject with ErrInvalidModelName, got %v", m, err)
		}
	}

	if _, err := ReadBoundedBody(bytes.NewReader(make([]byte, 1025)), 1024); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("expected ReadBoundedBody to fail closed with ErrResponseTooLarge, got %v", err)
	}
}
