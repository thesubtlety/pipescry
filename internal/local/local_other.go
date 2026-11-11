//go:build !windows

package local

import (
	"fmt"
	"runtime"

	"github.com/thesubtlety/pipescry/internal/scanner"
)

func New() (scanner.Collector, error) {
	return nil, fmt.Errorf("local mode unsupported on %s: it requires Windows NPFS", runtime.GOOS)
}
