package rotator

import (
	"fmt"
	"sort"
	"sync"
)

// HandlerRegistry manages in-process Go rotation handlers.
type HandlerRegistry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{handlers: make(map[string]Handler)}
}

func (r *HandlerRegistry) Register(handler Handler) error {
	if handler == nil {
		return fmt.Errorf("rotator handler cannot be nil")
	}
	id := handler.ID()
	if id == "" {
		return fmt.Errorf("rotator handler id cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[id] = handler
	return nil
}

func (r *HandlerRegistry) ResolveByID(id string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[id]
	return h, ok
}

func (r *HandlerRegistry) Resolve(selector RotationSelector) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.handlers))
	for id := range r.handlers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		h := r.handlers[id]
		if h.Supports(selector) {
			return h, true
		}
	}

	return nil, false
}
