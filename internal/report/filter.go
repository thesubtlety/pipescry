package report

import (
	"fmt"
	"strings"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/security"
)

type Evidence string

const (
	EvidenceAll  Evidence = "all"
	EvidenceDACL Evidence = "dacl"
	EvidenceOpen Evidence = "open"
)

// Filter selects what the terminal report displays. Categories combine with
// AND; values inside a category combine with OR. It never touches the
// report data itself.
type Filter struct {
	Principals  []string
	Permissions []uint32
	Evidence    Evidence
	Results     []model.Result
	RPC         RPC
}

type RPC string

const (
	RPCAny     RPC = ""
	RPCKnown   RPC = "known"
	RPCUnknown RPC = "unknown"
)

func NewFilter(principals, permissions []string, evidence string, results []string, rpc string) (Filter, error) {
	f := Filter{Principals: principals, Evidence: Evidence(strings.ToLower(evidence)), RPC: RPC(strings.ToLower(rpc))}
	switch f.RPC {
	case RPCAny, RPCKnown, RPCUnknown:
	default:
		return f, fmt.Errorf("--rpc %q: want known or unknown", rpc)
	}
	if f.Evidence == "" {
		f.Evidence = EvidenceAll
	}
	switch f.Evidence {
	case EvidenceAll, EvidenceDACL, EvidenceOpen:
	default:
		return f, fmt.Errorf("--evidence %q: want all, dacl, or open", evidence)
	}
	for _, p := range permissions {
		m, err := security.ParseRight(p)
		if err != nil {
			return f, fmt.Errorf("--permission: %w", err)
		}
		f.Permissions = append(f.Permissions, m)
	}
	for _, r := range results {
		res := model.Result(strings.ToLower(r))
		ok := false
		for _, v := range model.AllResults {
			ok = ok || v == res
		}
		if !ok {
			return f, fmt.Errorf("--result %q: want allowed, denied, busy, error, unsupported, or not_tested", r)
		}
		f.Results = append(f.Results, res)
	}
	return f, nil
}

// Active reports whether any item-level filter is set. Evidence alone only
// hides sections.
func (f Filter) Active() bool {
	return len(f.Principals) > 0 || len(f.Permissions) > 0 || len(f.Results) > 0
}

// MatchPipe applies the pipe-level --rpc filter.
func (f Filter) MatchPipe(p *model.Pipe) bool {
	switch f.RPC {
	case RPCKnown:
		return len(p.RPCProtocols) > 0
	case RPCUnknown:
		return len(p.RPCProtocols) == 0
	}
	return true
}

func (f Filter) ShowDACL() bool { return f.Evidence != EvidenceOpen && len(f.Results) == 0 }
func (f Filter) ShowOpen() bool { return f.Evidence != EvidenceDACL }

// MatchACE ignores inherit-only ACEs for --permission because they grant
// nothing on the pipe itself.
func (f Filter) MatchACE(a model.ACE) bool {
	if !f.ShowDACL() {
		return false
	}
	if len(f.Principals) > 0 && (a.Trustee == nil || !matchPrincipal(f.Principals, a.Trustee.Value, a.Trustee.Name)) {
		return false
	}
	if len(f.Permissions) > 0 && (a.InheritOnly || !matchMask(f.Permissions, a.MappedMask)) {
		return false
	}
	return true
}

// MatchGrantAll reports whether a NULL or absent DACL satisfies the DACL
// filters. Such a DACL has no ACEs but grants every right to every caller.
func (f Filter) MatchGrantAll(state model.DACLState) bool {
	return f.ShowDACL() && (state == model.DACLNull || state == model.DACLNotPresent)
}

func (f Filter) MatchTest(t model.AccessTest) bool {
	if !f.ShowOpen() {
		return false
	}
	if len(f.Results) > 0 {
		ok := false
		for _, r := range f.Results {
			ok = ok || r == t.Result
		}
		if !ok {
			return false
		}
	} else if f.Active() && t.Result == model.ResultNotTested {
		return false
	}
	if len(f.Principals) > 0 && !matchPrincipal(f.Principals, t.IdentitySID, t.Identity) {
		return false
	}
	if len(f.Permissions) > 0 && !matchMask(f.Permissions, security.MapGeneric(t.RequestedAccess)) {
		return false
	}
	return true
}

func matchMask(want []uint32, have uint32) bool {
	for _, w := range want {
		if have&w == w {
			return true
		}
	}
	return false
}

// matchPrincipal accepts a SID, a full name, or the account part of
// DOMAIN\account, case-insensitively.
func matchPrincipal(want []string, sid, name string) bool {
	acct := name
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		acct = name[i+1:]
	}
	for _, w := range want {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if (sid != "" && strings.EqualFold(w, sid)) || (name != "" && (strings.EqualFold(w, name) || strings.EqualFold(w, acct))) {
			return true
		}
	}
	return false
}
