package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/thesubtlety/pipescry/internal/model"
)

func ReadJSONFile(path string) (*model.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var r model.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if r.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("%s: schema_version %q, want %q", path, r.SchemaVersion, model.SchemaVersion)
	}
	return &r, nil
}

// Compare writes per-pipe differences between two reports and returns the
// number of differing pipes. Descriptors are compared by raw bytes; open
// tests by result. Pipes only one side observed are listed separately,
// since enumeration only shows pipes that had a listening instance.
func Compare(w io.Writer, a, b *model.Report) int {
	label := func(r *model.Report) string { return fmt.Sprintf("%s:%s", r.Mode, r.Target) }
	la, lb := label(a), label(b)
	fmt.Fprintf(w, "A %s as %s (%s)\nB %s as %s (%s)\n", la, a.Identity.Name, a.StartedAt.Format("2006-01-02T15:04:05Z"),
		lb, b.Identity.Name, b.StartedAt.Format("2006-01-02T15:04:05Z"))

	pa, pb := index(a), index(b)
	keys := map[string]bool{}
	for k := range pa {
		keys[k] = true
	}
	for k := range pb {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var onlyA, onlyB []string
	same, differ := 0, 0
	for _, k := range sorted {
		x, okA := pa[k]
		y, okB := pb[k]
		switch {
		case !okA:
			onlyB = append(onlyB, y.Name)
			continue
		case !okB:
			onlyA = append(onlyA, x.Name)
			continue
		}
		lines := diffPipe(x, y)
		if len(lines) == 0 {
			same++
			continue
		}
		differ++
		fmt.Fprintf(w, "\n%s\n", x.Name)
		for _, l := range lines {
			fmt.Fprintf(w, "  %s\n", l)
		}
	}
	if len(onlyA) > 0 {
		fmt.Fprintf(w, "\nonly in A (%d): %s\n", len(onlyA), strings.Join(onlyA, ", "))
	}
	if len(onlyB) > 0 {
		fmt.Fprintf(w, "\nonly in B (%d): %s\n", len(onlyB), strings.Join(onlyB, ", "))
	}
	fmt.Fprintf(w, "\n%d pipes in both: %d identical, %d differ; %d only in A, %d only in B\n",
		same+differ, same, differ, len(onlyA), len(onlyB))
	return differ
}

func index(r *model.Report) map[string]*model.Pipe {
	m := make(map[string]*model.Pipe, len(r.Pipes))
	for i := range r.Pipes {
		m[strings.ToLower(r.Pipes[i].Name)] = &r.Pipes[i]
	}
	return m
}

func diffPipe(a, b *model.Pipe) []string {
	var out []string
	sa, sb := a.Security, b.Security
	switch {
	case sa.State != sb.State:
		out = append(out, fmt.Sprintf("descriptor state: A %s%s, B %s%s", sa.State, errSuffix(sa.Error), sb.State, errSuffix(sb.Error)))
	case sa.RawHex != sb.RawHex:
		out = append(out, "descriptor bytes differ")
		out = append(out, aceDiff(sa.Descriptor, sb.Descriptor)...)
	}
	tb := map[string]model.AccessTest{}
	for _, t := range b.AccessTests {
		tb[t.Name] = t
	}
	for _, t := range a.AccessTests {
		u, ok := tb[t.Name]
		if !ok || t.Result == u.Result {
			continue
		}
		out = append(out, fmt.Sprintf("open %s: A %s %s, B %s %s", t.Name, t.Result, t.Status, u.Result, u.Status))
	}
	return out
}

func errSuffix(e *model.OpError) string {
	if e == nil || e.Status == nil {
		return ""
	}
	return " (" + e.Status.String() + ")"
}

func aceKey(a model.ACE) string {
	sid := ""
	if a.Trustee != nil {
		sid = a.Trustee.Value
	}
	return fmt.Sprintf("%s %s %s flags=0x%02X", a.TypeName, sid, a.MaskHex, a.Flags)
}

func aceDiff(a, b *model.Descriptor) []string {
	if a == nil || b == nil {
		return nil
	}
	var out []string
	if sidValue(a.Owner) != sidValue(b.Owner) {
		out = append(out, fmt.Sprintf("owner: A %s, B %s", sidValue(a.Owner), sidValue(b.Owner)))
	}
	if sidValue(a.Group) != sidValue(b.Group) {
		out = append(out, fmt.Sprintf("group: A %s, B %s", sidValue(a.Group), sidValue(b.Group)))
	}
	if a.DACL.State != b.DACL.State {
		out = append(out, fmt.Sprintf("dacl: A %s, B %s", a.DACL.State, b.DACL.State))
	}
	count := func(d *model.Descriptor) map[string]int {
		m := map[string]int{}
		for _, x := range d.DACL.ACEs {
			m[aceKey(x)]++
		}
		return m
	}
	ca, cb := count(a), count(b)
	for _, x := range a.DACL.ACEs {
		if k := aceKey(x); cb[k] == 0 {
			out = append(out, "ACE only in A: "+k)
		} else {
			cb[k]--
		}
	}
	for _, x := range b.DACL.ACEs {
		if k := aceKey(x); ca[k] == 0 {
			out = append(out, "ACE only in B: "+k)
		} else {
			ca[k]--
		}
	}
	return out
}

func sidValue(s *model.SID) string {
	if s == nil {
		return "(none)"
	}
	return s.Value
}
