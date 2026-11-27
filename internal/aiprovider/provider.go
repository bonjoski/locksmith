package aiprovider

import (
	"context"
	"errors"
	"os"
)

var (
	ErrEmptyPrompt     = errors.New("aiprovider: prompt content cannot be empty")
	ErrProviderFailed  = errors.New("aiprovider: remote inference call failed")
	ErrInvalidResponse = errors.New("aiprovider: malformed response from upstream AI")
)

// Role constants for conversational messages.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message represents a single turn in a conversational completion.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// TokenUsage holds token consumption metadata.
type TokenUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Request contains the payload for an AI completion.
type Request struct {
	Model        string    `json:"model"`
	SystemPrompt string    `json:"system_prompt,omitempty"`
	Messages     []Message `json:"messages"`
	Temperature  float64   `json:"temperature,omitempty"`
	MaxTokens    int       `json:"max_tokens,omitempty"`
}

// Response represents the completed AI completion.
type Response struct {
	Content      string     `json:"content"`
	Model        string     `json:"model"`
	FinishReason string     `json:"finish_reason,omitempty"`
	Usage        TokenUsage `json:"usage"`
}

// Provider defines the pluggable interface for LLM inference engines.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (*Response, error)
}

// NewFromEnv inspects environment variables and returns the most suitable Provider.
// Falls back to MockProvider if no cloud API keys or local LLM instances are detected.
func NewFromEnv() Provider {
	if key := os.Getenv("GEMINI_API_KEY"); key != "" {
		return NewGeminiProvider(key, os.Getenv("GEMINI_MODEL"))
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return NewClaudeProvider(key, os.Getenv("ANTHROPIC_MODEL"))
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return NewOpenAIProvider(key, os.Getenv("OPENAI_MODEL"), os.Getenv("OPENAI_BASE_URL"))
	}
	if host := os.Getenv("OLLAMA_HOST"); host != "" {
		model := os.Getenv("OLLAMA_MODEL")
		if model == "" {
			model = "llama3"
		}
		return NewOllamaProvider(host, model)
	}
	return NewMockProvider("local-advisor", "Recommendation: Store raw API tokens in Locksmith or hardware enclave; scrub plaintext files.")
}
