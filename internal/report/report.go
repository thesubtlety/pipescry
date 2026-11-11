// Package report writes the evidence document as JSON and as terminal text.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/security"
)

func WriteJSON(w io.Writer, r *model.Report) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// WriteJSONFile writes to a temp file and renames so a failed write never
// leaves a truncated evidence file at path.
func WriteJSONFile(path string, r *model.Report) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if err := WriteJSON(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}

type TextOptions struct {
	Color       bool
	Verbose     bool
	SummaryOnly bool
	Filter      Filter
}

type printer struct {
	w   io.Writer
	opt TextOptions
}

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cCyan   = "\x1b[36m"
)

func (p *printer) c(code, s string) string {
	if !p.opt.Color || s == "" {
		return s
	}
	return code + s + cReset
}

func (p *printer) f(format string, a ...any) { fmt.Fprintf(p.w, format, a...) }

func WriteText(w io.Writer, r *model.Report, opt TextOptions) {
	p := &printer{w: w, opt: opt}
	p.summary(r)
	if opt.SummaryOnly {
		return
	}
	shown := 0
	for i := range r.Pipes {
		if p.pipe(r, &r.Pipes[i]) {
			shown++
		}
	}
	if opt.Filter.Active() || opt.Filter.Evidence != EvidenceAll {
		p.f("\n%d of %d pipes match display filters\n", shown, len(r.Pipes))
	}
}

func (p *printer) summary(r *model.Report) {
	label := func(s string) string { return p.c(cBold, fmt.Sprintf("%-12s", s)) }
	p.f("%s %s scan of %s\n", label("pipescry"), r.Mode, r.Target)
	id := r.Identity.Name
	if r.Identity.SID != "" {
		id += " " + r.Identity.SID
	}
	extra := []string{r.Identity.AuthMethod}
	if r.Identity.Guest {
		extra = append(extra, "server mapped session to guest")
	}
	if r.Identity.Elevated != nil {
		extra = append(extra, fmt.Sprintf("elevated=%t", *r.Identity.Elevated))
	}
	p.f("%s %s (%s)\n", label("identity"), id, strings.Join(extra, ", "))
	if t := r.Transport; t != nil {
		switch t.Protocol {
		case "smb2":
			sign := "unknown"
			if t.SigningRequired != nil {
				sign = map[bool]string{true: "required", false: "not required"}[*t.SigningRequired]
			}
			ci := t.CipherNegotiated
			if ci == "" {
				ci = "none"
			}
			p.f("%s SMB %s to %s:%d\\%s, signing %s, cipher negotiated %s\n", label("transport"), t.Dialect, t.Host, t.Port, t.Share, sign, ci)
		default:
			p.f("%s %s\n", label("transport"), t.Protocol)
		}
	}
	p.f("%s %s, duration %s\n", label("started"), r.StartedAt.Format(time.RFC3339), r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	c := r.Collection
	enum := string(c.Enumeration)
	if c.EnumerationError != nil {
		enum += " (" + c.EnumerationError.Message + ")"
	}
	p.f("%s %d total, %d enumerated, %d from names list; enumeration %s\n", label("pipes"), c.PipesTotal, c.PipesEnumerated, c.PipesSupplied, enum)
	p.f("%s %s\n", label("descriptors"), counts(c.DescriptorsByState, []string{"collected", "unavailable", "failed", "unparsed"}))
	results := make([]string, len(model.AllResults))
	for i, v := range model.AllResults {
		results[i] = string(v)
	}
	p.f("%s %s\n", label("open tests"), counts(c.TestsByResult, results))
	ind := map[string]int{}
	for _, pp := range r.Pipes {
		for _, i := range pp.Indicators {
			ind[i.Kind]++
		}
	}
	if len(ind) > 0 {
		p.f("%s %s\n", label("indicators"), counts(ind, nil))
	}
	for _, w := range c.Warnings {
		p.f("%s %s\n", label("warning"), p.c(cYellow, w))
	}
}

// counts prints keys in the given order, then any others sorted.
func counts(m map[string]int, order []string) string {
	seen := map[string]bool{}
	var parts []string
	for _, k := range order {
		seen[k] = true
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func sdSource(m model.Mode) string {
	if m == model.ModeLocal {
		return "GetSecurityInfo"
	}
	return "SMB2 QUERY_INFO/SECURITY"
}

func openSource(m model.Mode) string {
	if m == model.ModeLocal {
		return "CreateFileW"
	}
	return "SMB2 CREATE"
}

func (p *printer) pipe(r *model.Report, pp *model.Pipe) bool {
	fl := p.opt.Filter
	var aces []model.ACE
	var tests []model.AccessTest
	if pp.Security.Descriptor != nil {
		for _, a := range pp.Security.Descriptor.DACL.ACEs {
			if fl.MatchACE(a) {
				aces = append(aces, a)
			}
		}
	}
	for _, t := range pp.AccessTests {
		if fl.MatchTest(t) {
			tests = append(tests, t)
		}
	}
	grantAll := pp.Security.Descriptor != nil && fl.MatchGrantAll(pp.Security.Descriptor.DACL.State)
	if fl.Active() && len(aces) == 0 && len(tests) == 0 && !grantAll {
		return false
	}

	head := fmt.Sprintf("\n%s  [%s]", p.c(cBold+cCyan, pp.Name), strings.Join(pp.Sources, ","))
	if pp.CurrentInstances != nil {
		head += fmt.Sprintf("  instances=%d", *pp.CurrentInstances)
	}
	if pp.MaxInstances != nil {
		head += fmt.Sprintf(" max=%s", maxInstances(*pp.MaxInstances))
	}
	p.f("%s\n", head)

	if fl.ShowDACL() {
		p.dacl(r, pp, aces)
	}
	if fl.ShowOpen() {
		p.tests(r, pp, tests)
	}
	return true
}

func maxInstances(v int64) string {
	if uint32(v) == 0xFFFFFFFF {
		return "unlimited"
	}
	return fmt.Sprint(v)
}

func (p *printer) dacl(r *model.Report, pp *model.Pipe, aces []model.ACE) {
	sec := pp.Security
	src := fmt.Sprintf("%s, opened with %s", sdSource(r.Mode), sec.RequestedHex)
	switch sec.State {
	case model.SDFailed, model.SDUnavailable:
		label := "query failed"
		if sec.State == model.SDUnavailable {
			label = "unavailable"
		}
		p.f("  dacl   %s  %s\n", p.c(cRed, label), sec.Error.Message)
		p.f("         %s\n", p.c(cDim, "source: "+src+"; no DACL evidence collected"))
		return
	case model.SDUnparsed:
		p.f("  dacl   %s  %s\n", p.c(cRed, "unparsed"), sec.Error.Message)
		p.f("         raw %s\n", sec.RawHex)
		return
	}
	d := sec.Descriptor
	p.f("  owner  %s\n", sidStr(d.Owner))
	p.f("  group  %s\n", sidStr(d.Group))
	state := string(d.DACL.State)
	switch d.DACL.State {
	case model.DACLPresent:
		state = fmt.Sprintf("present, %d ACEs", len(d.DACL.ACEs))
	case model.DACLNull:
		state = p.c(cYellow, "NULL DACL (no ACL; grants all access)")
	case model.DACLNotPresent:
		state = p.c(cYellow, "not present (SE_DACL_PRESENT clear; treated as NULL DACL)")
	case model.DACLEmpty:
		state = p.c(cYellow, "empty (zero ACEs; grants no access)")
	}
	p.f("  dacl   %s  %s\n", state, p.c(cDim, "source: "+src+", control "+d.ControlHex))
	if p.opt.Verbose {
		p.f("         control %s\n", strings.Join(d.ControlFlags, "|"))
		p.f("         raw %s\n", sec.RawHex)
	}
	if len(aces) > 0 {
		w := 0
		for _, a := range aces {
			if n := len(sidStr(a.Trustee)); n > w {
				w = n
			}
		}
		for _, a := range aces {
			p.ace(a, w)
		}
	}
	if !p.opt.Filter.Active() {
		for _, in := range pp.Indicators {
			where := ""
			if in.ACEIndex != nil {
				where = fmt.Sprintf(" ace %d", *in.ACEIndex)
			}
			p.f("  %s %s%s: %s\n", p.c(cYellow, "indicator"), in.Kind, where, in.Evidence)
		}
	}
}

var notable = map[string]bool{"WRITE_DAC": true, "WRITE_OWNER": true, "FILE_CREATE_PIPE_INSTANCE": true, "GENERIC_ALL": true, "GENERIC_WRITE": true}

func (p *printer) ace(a model.ACE, w int) {
	typ := a.TypeName
	switch {
	case security.IsAllowType(a.Type):
		typ = p.c(cGreen, "ALLOW")
	case security.IsDenyType(a.Type):
		typ = p.c(cRed, "DENY ")
	}
	var rights string
	if a.MaskHex == "" {
		rights = "unparsed ACE " + a.RawHex
	} else if security.IsFullControl(a.Mask) {
		rights = p.c(cYellow, "FULL_CONTROL")
		if a.Mask != security.FileAllAccess {
			rights += " (" + p.names(a.Rights) + ")"
		}
	} else {
		rights = p.names(a.Rights)
		if a.MappedMask != a.Mask {
			rights += " => " + a.MappedHex + " " + p.names(a.MappedRights)
		}
	}
	flags := ""
	if a.InheritOnly {
		flags = p.c(cDim, " [inherit-only]")
	} else if a.Flags&0x10 != 0 {
		flags = p.c(cDim, " [inherited]")
	}
	if p.opt.Verbose && len(a.FlagNames) > 0 {
		flags = p.c(cDim, " ["+strings.Join(a.FlagNames, "|")+"]")
	}
	p.f("    %2d %s %-*s %s %s%s\n", a.Index, typ, w, sidStr(a.Trustee), a.MaskHex, rights, flags)
}

func (p *printer) names(rs []string) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		if notable[r] {
			out[i] = p.c(cYellow, r)
		} else {
			out[i] = r
		}
	}
	return strings.Join(out, "|")
}

func (p *printer) tests(r *model.Report, pp *model.Pipe, tests []model.AccessTest) {
	if !r.Options.AccessTest && !p.opt.Filter.Active() {
		p.f("  open   %s\n", p.c(cDim, "not_tested (run with --access-test)"))
		return
	}
	if len(tests) == 0 {
		return
	}
	p.f("  open   %s\n", p.c(cDim, "source: "+openSource(r.Mode)+" then close, as "+tests[0].Identity))
	for _, t := range tests {
		res := string(t.Result)
		switch t.Result {
		case model.ResultAllowed:
			res = p.c(cGreen, res)
		case model.ResultDenied:
			res = p.c(cRed, res)
		case model.ResultBusy, model.ResultError, model.ResultUnsupported:
			res = p.c(cYellow, res)
		}
		status := t.Status.String()
		if t.NTStatus != nil {
			status += " / " + t.NTStatus.String()
		}
		if status == "" && t.Error != "" {
			status = t.Error
		}
		p.f("    %-16s %s  %-11s %s\n", t.Name, t.RequestedHex, res, status)
		if t.CloseError != "" {
			p.f("    %s\n", p.c(cRed, t.CloseError))
		}
		if p.opt.Verbose && t.Error != "" && t.Status != nil {
			p.f("    %s\n", p.c(cDim, t.Error))
		}
	}
}

func sidStr(s *model.SID) string {
	if s == nil {
		return "(none)"
	}
	if s.Name != "" {
		return s.Value + " " + s.Name
	}
	return s.Value
}
