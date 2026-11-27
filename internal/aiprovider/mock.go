package aiprovider

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// MockProvider provides deterministic responses for offline/local advisory and testing without network requests.
type MockProvider struct {
	mu            sync.RWMutex
	name          string
	customReplies map[string]string
	defaultReply  string
	callCount     int
}

// NewMockProvider creates a mock provider with an optional default response.
func NewMockProvider(name string, defaultReply string) *MockProvider {
	if name == "" {
		name = "mock"
	}
	if defaultReply == "" {
		defaultReply = "Mock completion successfully processed."
	}
	return &MockProvider{
		name:          name,
		customReplies: make(map[string]string),
		defaultReply:  defaultReply,
	}
}

func (m *MockProvider) Name() string {
	return m.name
}

// SetReply registers a customized response when a prompt contains a substring match.
func (m *MockProvider) SetReply(matchSubstring string, reply string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customReplies[matchSubstring] = reply
}

func (m *MockProvider) CallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCount
}

func (m *MockProvider) Complete(_ context.Context, req Request) (*Response, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}

	lastMsg := req.Messages[len(req.Messages)-1].Content

	m.mu.RLock()
	defer m.mu.RUnlock()

	reply := m.defaultReply
	for match, custom := range m.customReplies {
		if strings.Contains(lastMsg, match) {
			reply = custom
			break
		}
	}

	return &Response{
		Content:      reply,
		Model:        fmt.Sprintf("%s-v1", m.name),
		FinishReason: "stop",
		Usage: TokenUsage{
			InputTokens:  len(lastMsg) / 4,
			OutputTokens: len(reply) / 4,
		},
	}, nil
}
