package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/security"
	tf "github.com/thesubtlety/pipescry/internal/testfixture"
)

func fixture(t *testing.T) *model.Report {
	t.Helper()
	sd := tf.SD("S-1-5-18", "S-1-5-18", true, tf.ACL([]tf.ACE{
		tf.A(0, 0, security.FileAllAccess, "S-1-5-18"),
		tf.A(0, 0, 0x0012019F, "S-1-1-0"),
		tf.A(0, 0, security.GenericWrite, "S-1-5-21-1-2-3-1105"),
		tf.A(1, 0, security.FileWriteData, "S-1-5-7"),
	}))
	d, err := security.Parse(sd, nil)
	if err != nil {
		t.Fatal(err)
	}
	null, _ := security.Parse(tf.SD("S-1-5-18", "S-1-5-18", true, nil), nil)
	ts := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	test := func(name string, access uint32, res model.Result, st uint32) model.AccessTest {
		return model.AccessTest{Name: name, RequestedAccess: access, RequestedHex: model.Hex32(access),
			Identity: "LAB\\auditor", Result: res, Status: model.NTStatus(st), StartedAt: ts}
	}
	tests := []model.AccessTest{
		test("READ_CONTROL", security.ReadControl, model.ResultAllowed, 0),
		test("FILE_READ_DATA", security.FileReadData, model.ResultBusy, 0xC00000AE),
		test("FILE_WRITE_DATA", security.FileWriteData, model.ResultDenied, 0xC0000022),
	}
	return &model.Report{
		SchemaVersion: model.SchemaVersion, Mode: model.ModeRemote, Target: "host",
		StartedAt: ts, FinishedAt: ts.Add(time.Second),
		Identity: model.Identity{Name: "LAB\\auditor", AuthMethod: "ntlm"},
		Collection: model.Collection{Enumeration: model.EnumComplete, PipesTotal: 3,
			DescriptorsByState: map[string]int{"collected": 2, "failed": 1}, TestsByResult: map[string]int{"allowed": 1}},
		Options: model.ScanOptions{AccessTest: true},
		Pipes: []model.Pipe{
			{Name: "alpha", Sources: []string{"enumeration"}, Security: model.SecurityEvidence{State: model.SDCollected, Descriptor: d, RequestedHex: "0x00020000"},
				AccessTests: tests, Indicators: security.Indicators(d)},
			{Name: "beta", Sources: []string{"names_list"}, Security: model.SecurityEvidence{State: model.SDFailed,
				Error: &model.OpError{Op: "open", Target: "beta", Message: "open beta on host: STATUS_ACCESS_DENIED", Status: model.NTStatus(0xC0000022)}},
				AccessTests: tests[:1]},
			{Name: "gamma", Sources: []string{"enumeration"}, Security: model.SecurityEvidence{State: model.SDCollected, Descriptor: null},
				AccessTests: nil, Indicators: security.Indicators(null)},
		},
	}
}

func render(t *testing.T, r *model.Report, principals, perms []string, evidence string, results []string) string {
	t.Helper()
	f, err := NewFilter(principals, perms, evidence, results)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	WriteText(&b, r, TextOptions{Filter: f})
	return b.String()
}

var aceLine = regexp.MustCompile(`(?m)^\s+\d+ (ALLOW|DENY)`)

func TestFilterPrincipal(t *testing.T) {
	out := render(t, fixture(t), []string{"everyone"}, nil, "", nil)
	if got := aceLine.FindAllString(out, -1); len(got) != 1 || !strings.Contains(out, "S-1-1-0 Everyone") {
		t.Fatalf("want only the Everyone ACE:\n%s", out)
	}
	if strings.Contains(out, "beta") {
		t.Fatalf("pipes without matching evidence shown:\n%s", out)
	}
	out = render(t, fixture(t), []string{"auditor"}, nil, "", nil)
	if aceLine.MatchString(out) || !strings.Contains(out, "READ_CONTROL") || !strings.Contains(out, "beta") {
		t.Fatalf("principal must match tested identity by account name:\n%s", out)
	}
}

func TestFilterPermissionUsesGenericMapping(t *testing.T) {
	out := render(t, fixture(t), nil, []string{"FILE_WRITE_DATA"}, "dacl", nil)
	got := aceLine.FindAllString(out, -1)
	// SYSTEM full control, Everyone 0x19F, GENERIC_WRITE domain user, and the deny ACE.
	if len(got) != 4 {
		t.Fatalf("got %d ACE lines:\n%s", len(got), out)
	}
	out = render(t, fixture(t), nil, []string{"WRITE_DAC"}, "dacl", nil)
	if got := aceLine.FindAllString(out, -1); len(got) != 1 {
		t.Fatalf("WRITE_DAC should match only SYSTEM full control:\n%s", out)
	}
}

func TestFilterCategoriesAND(t *testing.T) {
	out := render(t, fixture(t), []string{"S-1-1-0"}, []string{"WRITE_DAC"}, "", nil)
	if strings.Contains(out, "alpha") {
		t.Fatalf("Everyone lacks WRITE_DAC; nothing should match:\n%s", out)
	}
	out = render(t, fixture(t), []string{"S-1-1-0", "S-1-5-18"}, []string{"WRITE_DAC"}, "", nil)
	if got := aceLine.FindAllString(out, -1); len(got) != 1 {
		t.Fatalf("OR within principal, AND with permission:\n%s", out)
	}
}

func TestFilterResultAndEvidence(t *testing.T) {
	out := render(t, fixture(t), nil, nil, "", []string{"denied", "busy"})
	if aceLine.MatchString(out) || !strings.Contains(out, "FILE_WRITE_DATA") || !strings.Contains(out, "FILE_READ_DATA") || strings.Contains(out, "  READ_CONTROL") {
		t.Fatalf("result filter:\n%s", out)
	}
	out = render(t, fixture(t), nil, nil, "open", nil)
	if strings.Contains(out, "owner") || aceLine.MatchString(out) {
		t.Fatalf("--evidence open must hide DACL evidence:\n%s", out)
	}
	if _, err := NewFilter(nil, nil, "acl", nil); err == nil {
		t.Fatal("accepted bad evidence")
	}
	if _, err := NewFilter(nil, nil, "", []string{"maybe"}); err == nil {
		t.Fatal("accepted bad result")
	}
}

func TestUnfilteredShowsStateDistinctions(t *testing.T) {
	out := render(t, fixture(t), nil, nil, "", nil)
	for _, want := range []string{"query failed", "STATUS_ACCESS_DENIED", "NULL DACL", "null_dacl", "broad_principal_grant", "STATUS_PIPE_BUSY"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color emitted with Color=false")
	}
}

func TestJSONDeterministicAndFactual(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteJSON(&a, fixture(t)); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, fixture(t)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("JSON not deterministic")
	}
	var back model.Report
	if err := json.Unmarshal(a.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Pipes) != 3 || back.Pipes[0].Security.Descriptor.DACL.ACEs[1].Mask != 0x0012019F {
		t.Fatal("round trip lost evidence")
	}
	text := strings.ToLower(a.String() + render(t, fixture(t), nil, nil, "", nil))
	for _, w := range []string{"risk", "severity", "vulnerab", "recommend", "exploit"} {
		if strings.Contains(text, w) {
			t.Errorf("output contains subjective term %q", w)
		}
	}
}

func TestNullDACLMatchesPrincipalAndPermission(t *testing.T) {
	out := render(t, fixture(t), []string{"S-1-1-0"}, []string{"WRITE_DAC"}, "", nil)
	if !strings.Contains(out, "gamma") || !strings.Contains(out, "NULL DACL") {
		t.Fatalf("NULL DACL pipe must match DACL filters:\n%s", out)
	}
	out = render(t, fixture(t), nil, nil, "", []string{"allowed"})
	if strings.Contains(out, "gamma") {
		t.Fatalf("--result must not match DACL state:\n%s", out)
	}
}

func TestCompare(t *testing.T) {
	a, b := fixture(t), fixture(t)
	var out bytes.Buffer
	if n := Compare(&out, a, b); n != 0 {
		t.Fatalf("identical reports differ:\n%s", out.String())
	}

	b.Mode = model.ModeLocal
	b.Pipes[0].Security.RawHex = "00"
	aces := b.Pipes[0].Security.Descriptor.DACL.ACEs
	b.Pipes[0].Security.Descriptor = &model.Descriptor{Owner: a.Pipes[0].Security.Descriptor.Owner,
		Group: a.Pipes[0].Security.Descriptor.Group, DACL: model.ACL{State: model.DACLPresent, ACEs: aces[:3]}}
	b.Pipes[0].AccessTests = append([]model.AccessTest(nil), b.Pipes[0].AccessTests...)
	b.Pipes[0].AccessTests[2].Result = model.ResultAllowed
	b.Pipes = append(b.Pipes[:1], b.Pipes[2], model.Pipe{Name: "delta"})
	out.Reset()
	if n := Compare(&out, a, b); n != 1 {
		t.Fatalf("differ = %d:\n%s", n, out.String())
	}
	s := out.String()
	for _, want := range []string{"ACE only in A: ACCESS_DENIED S-1-5-7 0x00000002", "open FILE_WRITE_DATA: A denied", "only in A (1): beta", "only in B (1): delta"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
}
