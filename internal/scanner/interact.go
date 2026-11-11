package scanner

import "context"

// Interactor is reserved for future protocol-specific interaction with a
// pipe (for example, an RPC bind). Nothing in pipescry implements or calls
// it; the scanner never writes to a pipe.
type Interactor interface {
	Name() string
	Matches(pipe string) bool
	Interact(ctx context.Context, pipe string) (map[string]any, error)
}
