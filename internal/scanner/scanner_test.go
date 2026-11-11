package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/security"
	tf "github.com/thesubtlety/pipescry/internal/testfixture"
)

type fake struct {
	enum    []EnumEntry
	status  model.EnumerationStatus
	sds     map[string][]byte
	sdErr   map[string]*model.OpError
	opens   map[string]map[uint32]OpenOutcome
	mu      sync.Mutex
	queried []string
	opened  []uint32
	block   string
}

func (f *fake) Target() string { return "host" }
func (f *fake) Identity() model.Identity {
	return model.Identity{Name: "LAB\\auditor", AuthMethod: "ntlm"}
}
func (f *fake) Transport() *model.Transport { return nil }
func (f *fake) Resolver() security.Resolver { return nil }
func (f *fake) Enumerate(context.Context) ([]EnumEntry, model.EnumerationStatus, *model.OpError) {
	return f.enum, f.status, nil
}
func (f *fake) QuerySecurity(ctx context.Context, p string) ([]byte, *model.OpError) {
	f.mu.Lock()
	f.queried = append(f.queried, p)
	f.mu.Unlock()
	if p == f.block {
		<-ctx.Done()
		return nil, &model.OpError{Op: "query_security", Target: p, Message: "timed out"}
	}
	if e := f.sdErr[p]; e != nil {
		return nil, e
	}
	return f.sds[p], nil
}
func (f *fake) OpenTest(_ context.Context, p string, access uint32) OpenOutcome {
	f.mu.Lock()
	f.opened = append(f.opened, access)
	f.mu.Unlock()
	if o, ok := f.opens[p][access]; ok {
		return o
	}
	return OpenOutcome{Result: model.ResultDenied, Status: model.NTStatus(0xC0000022)}
}

func TestRunMergesSortsAndRecordsEvidence(t *testing.T) {
	sd := tf.SD("S-1-5-18", "S-1-5-18", true, tf.ACL([]tf.ACE{tf.A(0, 0, 0x0012019F, "S-1-1-0")}))
	f := &fake{
		enum:   []EnumEntry{{Name: "spoolss"}, {Name: "Alpha"}},
		status: model.EnumComplete,
		sds:    map[string][]byte{"spoolss": sd, "Alpha": sd, "extra": {1, 2, 3}},
		sdErr: map[string]*model.OpError{
			"gone":  {Op: "open", Target: "gone", Message: "not found", Status: model.NTStatus(0xC0000034)},
			"samba": {Op: "query_info", Target: "samba", Message: "not supported", Status: model.NTStatus(0xC00000BB)},
		},
		opens: map[string]map[uint32]OpenOutcome{
			"spoolss": {security.ReadControl: {Result: model.ResultAllowed, Status: model.NTStatus(0)}},
		},
	}
	r := Run(context.Background(), f, Config{
		Mode: model.ModeRemote, Enumerate: true, AccessTest: true, Timeout: time.Second, Concurrency: 3,
		Names: []string{`\\host\pipe\SPOOLSS`, "extra", "gone", "samba", ""},
	})

	var names []string
	for _, p := range r.Pipes {
		names = append(names, p.Name)
	}
	want := []string{"Alpha", "extra", "gone", "samba", "spoolss"}
	if len(names) != len(want) {
		t.Fatalf("pipes = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("pipes = %v, want %v", names, want)
		}
	}
	if r.Collection.PipesEnumerated != 2 || r.Collection.PipesSupplied != 4 || r.Collection.PipesTotal != 5 {
		t.Fatalf("collection = %+v", r.Collection)
	}
	spool := r.Pipes[4]
	if len(spool.Sources) != 2 {
		t.Fatalf("SPOOLSS from names list must merge into enumerated spoolss: %v", spool.Sources)
	}
	if spool.Security.State != model.SDCollected || len(spool.Indicators) == 0 {
		t.Fatalf("spoolss security = %+v", spool.Security)
	}
	if spool.AccessTests[0].Result != model.ResultAllowed || spool.AccessTests[1].Result != model.ResultDenied {
		t.Fatalf("tests = %+v", spool.AccessTests)
	}
	if spool.AccessTests[1].Status.Name != "STATUS_ACCESS_DENIED" {
		t.Fatalf("raw status not preserved: %+v", spool.AccessTests[1].Status)
	}
	states := map[string]model.DescriptorState{}
	for _, p := range r.Pipes {
		states[p.Name] = p.Security.State
	}
	if states["extra"] != model.SDUnparsed || states["gone"] != model.SDFailed || states["samba"] != model.SDUnavailable {
		t.Fatalf("states = %v", states)
	}
	if r.Pipes[1].Security.RawHex != "010203" {
		t.Fatal("unparsed descriptor must keep raw bytes")
	}
	if r.Collection.TestsByResult["allowed"] != 1 || r.Collection.TestsByResult["denied"] != 14 {
		t.Fatalf("tests by result = %v", r.Collection.TestsByResult)
	}
}

func TestRunWithoutAccessTestOpensOnlyForDescriptor(t *testing.T) {
	f := &fake{status: model.EnumComplete, sds: map[string][]byte{}}
	r := Run(context.Background(), f, Config{Names: []string{"a"}, Timeout: time.Second})
	if len(f.opened) != 0 {
		t.Fatalf("open tests ran without --access-test: %v", f.opened)
	}
	if len(r.Pipes[0].AccessTests) != 3 {
		t.Fatal("not-tested entries must be explicit")
	}
	for _, at := range r.Pipes[0].AccessTests {
		if at.Result != model.ResultNotTested {
			t.Fatalf("result = %s", at.Result)
		}
	}
	if r.Collection.Enumeration != model.EnumSkipped {
		t.Fatalf("enumeration = %s", r.Collection.Enumeration)
	}
}

func TestRunTimeoutIsBounded(t *testing.T) {
	f := &fake{block: "slow", sds: map[string][]byte{}}
	start := time.Now()
	r := Run(context.Background(), f, Config{Names: []string{"slow"}, Timeout: 50 * time.Millisecond})
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not applied")
	}
	if r.Pipes[0].Security.State != model.SDFailed {
		t.Fatalf("state = %s", r.Pipes[0].Security.State)
	}
}

func TestPartialEnumerationWarns(t *testing.T) {
	f := &fake{enum: []EnumEntry{{Name: "a"}}, status: model.EnumPartial, sds: map[string][]byte{}}
	r := Run(context.Background(), f, Config{Enumerate: true, Timeout: time.Second})
	if r.Collection.Enumeration != model.EnumPartial || len(r.Collection.Warnings) != 1 {
		t.Fatalf("collection = %+v", r.Collection)
	}
}

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		`\\.\pipe\lsass`:          "lsass",
		`\\srv01\PIPE\srvsvc`:     "srvsvc",
		`\pipe\a\b`:               `a\b`,
		`pipe\x`:                  "x",
		`  spoolss `:              "spoolss",
		`//./pipe/Winsock2\Cat-1`: `Winsock2\Cat-1`,
	}
	for in, want := range cases {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
