package rotator

import (
	"context"
	"time"
)

// RotationSelector describes the secret context used to auto-select a rotation handler.
type RotationSelector struct {
	Key              string
	SecretType       string
	OwnerApplication string
	SourceURL        string
	Metadata         map[string]string
}

// RotationInput is the runtime input passed to Go-based rotation handlers.
type RotationInput struct {
	Key          string
	CurrentValue []byte
	Selector     RotationSelector
	Timeout      time.Duration
	DesiredTTL   time.Duration
}

// RotationOutput is the runtime result produced by Go-based rotation handlers.
type RotationOutput struct {
	NewValue []byte
	TTL      time.Duration
}

// Handler rotates a secret using in-process Go code.
type Handler interface {
	// ID returns the unique handler identifier (e.g., "url-json").
	ID() string

	// Supports returns true when the handler can rotate the secret described by selector.
	Supports(selector RotationSelector) bool

	// Rotate performs rotation and returns the newly generated secret value.
	Rotate(ctx context.Context, input RotationInput) (RotationOutput, error)
}
