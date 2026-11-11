package scanner

import (
	"context"
	"fmt"
)

// Call runs fn and returns when it finishes or ctx ends. Neither go-smb nor
// the Win32 calls take a context, so a timed-out fn keeps running; callers
// must make fn release its own resources.
func Call[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := fn()
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("timed out: %w", ctx.Err())
	}
}
