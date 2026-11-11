//go:build windows && integration

package local

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/scanner"
)

// serve creates n listening instances of a pipe with the given SDDL. Each
// successful client open consumes one instance.
func serve(t *testing.T, name, sddl string, n int) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(24), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(pipeRoot + name)
	for i := 0; i < n; i++ {
		h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sa)
		if err != nil {
			t.Fatalf("CreateNamedPipe %s: %v", name, err)
		}
		t.Cleanup(func() { windows.CloseHandle(h) })
	}
}

func TestLocalIntegration(t *testing.T) {
	base := fmt.Sprintf("pipescry-it-%d", os.Getpid())
	open, nulld, empty, ro := base+"-open", base+"-null", base+"-empty", base+"-ro"
	serve(t, open, "D:(A;;GA;;;SY)(A;;0x12019b;;;WD)", 8)
	serve(t, nulld, "D:NO_ACCESS_CONTROL", 8)
	serve(t, empty, "D:", 8)
	serve(t, ro, "D:(A;;GA;;;SY)(A;;0x120089;;;WD)", 8)

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := scanner.Run(ctx, c, scanner.Config{
		Mode: model.ModeLocal, Enumerate: true, AccessTest: true,
		Timeout: 5 * time.Second, Concurrency: 1,
		Names: []string{open, nulld, empty, ro},
	})
	// Wine's NPFS does not implement directory listing.
	wantEnum := os.Getenv("PIPESCRY_IT_NO_ENUM") != "1"
	if wantEnum && r.Collection.Enumeration != model.EnumComplete {
		t.Fatalf("enumeration %s %+v", r.Collection.Enumeration, r.Collection.EnumerationError)
	}
	got := map[string]model.Pipe{}
	for _, p := range r.Pipes {
		got[p.Name] = p
	}
	for _, n := range []string{open, nulld, empty, ro} {
		p, ok := got[n]
		if !ok || (wantEnum && len(p.Sources) != 2) {
			t.Fatalf("%s not enumerated: %+v", n, p.Sources)
		}
	}

	op := got[open]
	if op.Security.State != model.SDCollected {
		t.Fatalf("open: %+v", op.Security.Error)
	}
	var everyone *model.ACE
	for i, a := range op.Security.Descriptor.DACL.ACEs {
		if a.Trustee.Value == "S-1-1-0" {
			everyone = &op.Security.Descriptor.DACL.ACEs[i]
		}
	}
	if everyone == nil || everyone.Mask != 0x0012019B {
		t.Fatalf("Everyone ACE: %+v", everyone)
	}
	wantResults(t, op, model.ResultAllowed, model.ResultAllowed, model.ResultAllowed)

	if s := got[nulld].Security.Descriptor; s == nil || s.DACL.State != model.DACLNull {
		t.Errorf("null DACL: state %s raw %s", stateOf(got[nulld]), got[nulld].Security.RawHex)
	}
	// The owner keeps implicit READ_CONTROL on an empty DACL.
	if s := got[empty].Security.Descriptor; s == nil || s.DACL.State != model.DACLEmpty {
		t.Errorf("empty DACL: state %s raw %s", stateOf(got[empty]), got[empty].Security.RawHex)
	}
	wantResults(t, got[empty], model.ResultAllowed, model.ResultDenied, model.ResultDenied)
	wantResults(t, got[ro], model.ResultAllowed, model.ResultAllowed, model.ResultDenied)

	for _, at := range got[ro].AccessTests {
		if at.Result == model.ResultDenied && (at.Status == nil || at.Status.Code != 5) {
			t.Errorf("denied without ERROR_ACCESS_DENIED: %+v", at)
		}
	}
}

func wantResults(t *testing.T, p model.Pipe, want ...model.Result) {
	t.Helper()
	for i, w := range want {
		if p.AccessTests[i].Result != w {
			t.Errorf("%s %s = %s (%s), want %s", p.Name, p.AccessTests[i].Name, p.AccessTests[i].Result, p.AccessTests[i].Status, w)
		}
	}
}

func stateOf(p model.Pipe) string {
	if p.Security.Descriptor == nil {
		return string(p.Security.State)
	}
	return string(p.Security.Descriptor.DACL.State)
}
