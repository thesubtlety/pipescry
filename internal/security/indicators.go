package security

import "github.com/thesubtlety/pipescry/internal/model"

const (
	IndNullDACL           = "null_dacl"
	IndDACLNotPresent     = "dacl_not_present"
	IndEmptyDACL          = "empty_dacl"
	IndBroadGrant         = "broad_principal_grant"
	IndWriteDAC           = "write_dac_grant"
	IndWriteOwner         = "write_owner_grant"
	IndFullControl        = "full_control_grant"
	IndCreatePipeInstance = "create_pipe_instance_grant"
)

// SYSTEM and Administrators hold these rights on nearly every pipe, so
// per-right indicators skip them. Their ACEs remain in the evidence.
var rightIndicatorExempt = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
}

// Indicators lists DACL facts worth review. Allow ACEs are reported as
// written; they do not account for deny ACE ordering, privileges, integrity
// labels, or the server's own checks, so they do not establish effective access.
func Indicators(d *model.Descriptor) []model.Indicator {
	out := []model.Indicator{}
	if d == nil {
		return out
	}
	switch d.DACL.State {
	case model.DACLNull:
		out = append(out, model.Indicator{Kind: IndNullDACL, Rights: []string{},
			Evidence: "SE_DACL_PRESENT is set and the DACL pointer is NULL; the access check grants every request"})
	case model.DACLNotPresent:
		out = append(out, model.Indicator{Kind: IndDACLNotPresent, Rights: []string{},
			Evidence: "SE_DACL_PRESENT is clear; the access check treats this as a NULL DACL"})
	case model.DACLEmpty:
		out = append(out, model.Indicator{Kind: IndEmptyDACL, Rights: []string{},
			Evidence: "DACL contains zero ACEs; it grants no access (the owner keeps implicit READ_CONTROL and WRITE_DAC unless OWNER RIGHTS overrides)"})
	}
	for i := range d.DACL.ACEs {
		a := &d.DACL.ACEs[i]
		if !IsAllowType(a.Type) || a.InheritOnly || a.Trustee == nil {
			continue
		}
		add := func(kind string, mask uint32, ev string) {
			idx := a.Index
			out = append(out, model.Indicator{
				Kind: kind, ACEIndex: &idx, Trustee: a.Trustee,
				Mask: mask, MaskHex: model.Hex32(mask), Rights: RightNames(mask), Evidence: ev,
			})
		}
		m := a.MappedMask
		if IsBroadPrincipal(a.Trustee.Value) && m != 0 {
			add(IndBroadGrant, m, "allow ACE "+a.MaskHex+" for broad principal "+a.Trustee.Value)
		}
		if rightIndicatorExempt[a.Trustee.Value] {
			continue
		}
		if IsFullControl(m) {
			add(IndFullControl, m, "allow ACE mask "+a.MaskHex+" maps to FILE_ALL_ACCESS")
			continue
		}
		if m&WriteDAC != 0 {
			add(IndWriteDAC, WriteDAC, "allow ACE mask "+a.MaskHex+" includes WRITE_DAC")
		}
		if m&WriteOwner != 0 {
			add(IndWriteOwner, WriteOwner, "allow ACE mask "+a.MaskHex+" includes WRITE_OWNER")
		}
		if m&FileCreatePipeInstance != 0 {
			add(IndCreatePipeInstance, FileCreatePipeInstance, "allow ACE mask "+a.MaskHex+" includes bit 0x4 (FILE_CREATE_PIPE_INSTANCE on pipes)")
		}
	}
	return out
}
