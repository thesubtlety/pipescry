// Package scanner runs the collection steps shared by remote and local modes.
package scanner

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/security"
)

type EnumEntry struct {
	Name             string
	CurrentInstances *uint64
	MaxInstances     *int64
}

type OpenOutcome struct {
	Result   model.Result
	Status   *model.Status
	NTStatus *model.Status
	Err      string
	Closed   *bool
	CloseErr string
}

// Collector is one transport (SMB or native Win32). Implementations must
// honor ctx deadlines and must only open and close handles.
type Collector interface {
	Target() string
	Identity() model.Identity
	Transport() *model.Transport
	Resolver() security.Resolver
	Enumerate(ctx context.Context) ([]EnumEntry, model.EnumerationStatus, *model.OpError)
	QuerySecurity(ctx context.Context, pipe string) ([]byte, *model.OpError)
	OpenTest(ctx context.Context, pipe string, access uint32) OpenOutcome
}

type AccessTestSpec struct {
	Name   string
	Access uint32
}

var DefaultTests = []AccessTestSpec{
	{"READ_CONTROL", security.ReadControl},
	{"FILE_READ_DATA", security.FileReadData},
	{"FILE_WRITE_DATA", security.FileWriteData},
}

// SecurityQueryAccess is the only right requested to read the DACL. Owner,
// group, and DACL are readable with READ_CONTROL; the SACL is not requested.
const SecurityQueryAccess = security.ReadControl

type Config struct {
	Mode        model.Mode
	Version     string
	Enumerate   bool
	Names       []string
	AccessTest  bool
	Timeout     time.Duration
	Concurrency int
	Progress    func(format string, args ...any)
	Now         func() time.Time
}

func Run(ctx context.Context, c Collector, cfg Config) *model.Report {
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	progress := cfg.Progress
	if progress == nil {
		progress = func(string, ...any) {}
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	testNames := make([]string, len(DefaultTests))
	for i, t := range DefaultTests {
		testNames[i] = t.Name
	}

	r := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: "pipescry", Version: cfg.Version},
		Mode:          cfg.Mode,
		Target:        c.Target(),
		StartedAt:     now(),
		Identity:      c.Identity(),
		Transport:     c.Transport(),
		Options: model.ScanOptions{
			Enumerate:     cfg.Enumerate,
			NamesSupplied: len(cfg.Names),
			AccessTest:    cfg.AccessTest,
			AccessTests:   testNames,
			TimeoutMS:     cfg.Timeout.Milliseconds(),
			Concurrency:   cfg.Concurrency,
		},
		Collection: model.Collection{
			Enumeration:        model.EnumSkipped,
			DescriptorsByState: map[string]int{},
			TestsByResult:      map[string]int{},
			Errors:             []model.OpError{},
			Warnings:           []string{},
		},
		Pipes: []model.Pipe{},
	}

	pipes := map[string]*model.Pipe{}
	var order []string
	add := func(e EnumEntry, source string) {
		name := NormalizeName(e.Name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		p, ok := pipes[key]
		if !ok {
			p = &model.Pipe{Name: name, Sources: []string{}}
			pipes[key] = p
			order = append(order, key)
		}
		for _, s := range p.Sources {
			if s == source {
				return
			}
		}
		p.Sources = append(p.Sources, source)
		if e.CurrentInstances != nil {
			p.CurrentInstances = e.CurrentInstances
		}
		if e.MaxInstances != nil {
			p.MaxInstances = e.MaxInstances
		}
	}

	if cfg.Enumerate {
		progress("enumerating pipes on %s", c.Target())
		ectx, cancel := withTimeout(ctx, enumTimeout(cfg.Timeout))
		entries, status, err := c.Enumerate(ectx)
		cancel()
		r.Collection.Enumeration = status
		r.Collection.EnumerationError = err
		r.Collection.PipesEnumerated = len(entries)
		for _, e := range entries {
			add(e, "enumeration")
		}
		if status != model.EnumComplete {
			r.Collection.Warnings = append(r.Collection.Warnings,
				"pipe enumeration "+string(status)+"; pipes absent from the listing were not observed")
		}
	}
	for _, n := range cfg.Names {
		if NormalizeName(n) != "" {
			r.Collection.PipesSupplied++
		}
		add(EnumEntry{Name: n}, "names_list")
	}

	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	work := make([]*model.Pipe, len(order))
	for i, k := range order {
		work[i] = pipes[k]
	}
	r.Collection.PipesTotal = len(work)

	resolve := c.Resolver()
	id := c.Identity()
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, p := range work {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p *model.Pipe) {
			defer wg.Done()
			defer func() { <-sem }()
			progress("[%d/%d] %s", i+1, len(work), p.Name)
			collectPipe(ctx, c, cfg, p, id, resolve, now)
		}(i, p)
	}
	wg.Wait()
	if ctx.Err() != nil {
		r.Collection.Warnings = append(r.Collection.Warnings, "scan interrupted: "+ctx.Err().Error())
	}

	for _, p := range work {
		if p.ObservedAt.IsZero() {
			// Not reached because the scan was interrupted.
			p.Security.State = model.SDFailed
			p.Security.Error = &model.OpError{Op: "query_security", Target: p.Name, Message: "not attempted: scan interrupted"}
			p.AccessTests = notTested(id, cfg)
			p.Indicators = []model.Indicator{}
		}
		r.Collection.DescriptorsByState[string(p.Security.State)]++
		if p.Security.Error != nil {
			r.Collection.Errors = append(r.Collection.Errors, *p.Security.Error)
		}
		for _, t := range p.AccessTests {
			r.Collection.TestsByResult[string(t.Result)]++
		}
		r.Pipes = append(r.Pipes, *p)
	}
	r.FinishedAt = now()
	return r
}

func collectPipe(ctx context.Context, c Collector, cfg Config, p *model.Pipe, id model.Identity, resolve security.Resolver, now func() time.Time) {
	p.ObservedAt = now()
	p.Security.RequestedAccess = SecurityQueryAccess
	p.Security.RequestedHex = model.Hex32(SecurityQueryAccess)

	qctx, cancel := withTimeout(ctx, cfg.Timeout)
	raw, err := c.QuerySecurity(qctx, p.Name)
	cancel()
	switch {
	case err != nil:
		p.Security.State = model.SDFailed
		if err.Status != nil && unsupported(err.Status) {
			p.Security.State = model.SDUnavailable
		}
		p.Security.Error = err
	default:
		p.Security.RawHex = hex.EncodeToString(raw)
		d, perr := security.Parse(raw, resolve)
		if perr != nil {
			p.Security.State = model.SDUnparsed
			p.Security.Error = &model.OpError{Op: "parse_security_descriptor", Target: p.Name, Message: perr.Error()}
		} else {
			p.Security.State = model.SDCollected
			p.Security.Descriptor = d
		}
	}
	p.Indicators = security.Indicators(p.Security.Descriptor)

	if !cfg.AccessTest {
		p.AccessTests = notTested(id, cfg)
		return
	}
	for _, spec := range DefaultTests {
		t := model.AccessTest{
			Name: spec.Name, RequestedAccess: spec.Access, RequestedHex: model.Hex32(spec.Access),
			Identity: id.Name, IdentitySID: id.SID, StartedAt: now(),
		}
		octx, cancel := withTimeout(ctx, cfg.Timeout)
		o := c.OpenTest(octx, p.Name, spec.Access)
		cancel()
		t.DurationMS = now().Sub(t.StartedAt).Milliseconds()
		t.Result, t.Status, t.NTStatus, t.Error, t.Closed, t.CloseError = o.Result, o.Status, o.NTStatus, o.Err, o.Closed, o.CloseErr
		p.AccessTests = append(p.AccessTests, t)
	}
}

func unsupported(s *model.Status) bool {
	if s.Kind == "win32" {
		return model.ClassifyWin32(s.Code) == model.ResultUnsupported
	}
	return model.ClassifyNTStatus(s.Code) == model.ResultUnsupported
}

func notTested(id model.Identity, cfg Config) []model.AccessTest {
	out := make([]model.AccessTest, 0, len(DefaultTests))
	for _, spec := range DefaultTests {
		out = append(out, model.AccessTest{
			Name: spec.Name, RequestedAccess: spec.Access, RequestedHex: model.Hex32(spec.Access),
			Identity: id.Name, IdentitySID: id.SID, Result: model.ResultNotTested,
		})
	}
	return out
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// Enumeration is a single directory listing that can be long on busy hosts.
func enumTimeout(op time.Duration) time.Duration {
	if op <= 0 {
		return 0
	}
	return op * 6
}

// NormalizeName strips UNC and device prefixes so names from enumeration,
// files, and other tools compare equal.
func NormalizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "/", "\\")
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "\\\\"):
		rest := s[2:]
		if i := strings.Index(strings.ToLower(rest), "\\pipe\\"); i >= 0 {
			s = rest[i+len("\\pipe\\"):]
		}
	case strings.HasPrefix(lower, "\\pipe\\"):
		s = s[len("\\pipe\\"):]
	case strings.HasPrefix(lower, "pipe\\"):
		s = s[len("pipe\\"):]
	}
	return strings.TrimLeft(s, "\\")
}
