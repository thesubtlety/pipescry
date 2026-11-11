//go:build integration

package remote

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/scanner"
)

// Run with:
//
//	PIPESCRY_IT_TARGET=host PIPESCRY_IT_USER=user PIPESCRY_IT_PASS=... \
//	  [PIPESCRY_IT_DOMAIN=CORP] [PIPESCRY_IT_PORT=445] [PIPESCRY_IT_WINDOWS=1] \
//	  go test -tags integration ./internal/remote
//
// PIPESCRY_IT_WINDOWS=1 asserts behavior only Windows servers provide
// (IPC$ enumeration, pipe security descriptors).
func TestRemoteIntegration(t *testing.T) {
	host := os.Getenv("PIPESCRY_IT_TARGET")
	if host == "" {
		t.Skip("PIPESCRY_IT_TARGET not set")
	}
	port := 445
	if p := os.Getenv("PIPESCRY_IT_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	windows := os.Getenv("PIPESCRY_IT_WINDOWS") == "1"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c, err := Connect(ctx, Options{
		Host: host, Port: port, User: os.Getenv("PIPESCRY_IT_USER"),
		Password: os.Getenv("PIPESCRY_IT_PASS"), Domain: os.Getenv("PIPESCRY_IT_DOMAIN"),
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r := scanner.Run(ctx, c, scanner.Config{
		Mode: model.ModeRemote, Enumerate: true, AccessTest: true,
		Names:   []string{"srvsvc", "pipescry-does-not-exist"},
		Timeout: 10 * time.Second, Concurrency: 4,
	})
	byName := map[string]model.Pipe{}
	for _, p := range r.Pipes {
		byName[p.Name] = p
	}

	missing := byName["pipescry-does-not-exist"]
	for _, at := range missing.AccessTests {
		if at.Result != model.ResultError || at.Status == nil || at.Status.Code != 0xC0000034 {
			t.Errorf("missing pipe %s: %+v", at.Name, at)
		}
	}
	srv := byName["srvsvc"]
	for _, at := range srv.AccessTests {
		if at.Result == model.ResultError {
			t.Errorf("srvsvc %s: %+v", at.Name, at)
		}
		if at.Result == model.ResultAllowed && (at.Closed == nil || !*at.Closed) {
			t.Errorf("srvsvc %s handle not closed: %+v", at.Name, at)
		}
	}
	if windows {
		if r.Collection.Enumeration != model.EnumComplete || r.Collection.PipesEnumerated == 0 {
			t.Errorf("enumeration = %s (%d)", r.Collection.Enumeration, r.Collection.PipesEnumerated)
		}
		if srv.Security.State != model.SDCollected {
			t.Errorf("srvsvc descriptor = %s %+v", srv.Security.State, srv.Security.Error)
		}
	} else if srv.Security.State != model.SDCollected && srv.Security.State != model.SDUnavailable {
		t.Errorf("srvsvc descriptor = %s %+v", srv.Security.State, srv.Security.Error)
	}
}
