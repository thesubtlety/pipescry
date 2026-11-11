package security

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/thesubtlety/pipescry/internal/model"
)

const (
	seDACLPresent  uint16 = 0x0004
	seSelfRelative uint16 = 0x8000
)

var controlNames = []struct {
	bit  uint16
	name string
}{
	{0x0001, "SE_OWNER_DEFAULTED"},
	{0x0002, "SE_GROUP_DEFAULTED"},
	{0x0004, "SE_DACL_PRESENT"},
	{0x0008, "SE_DACL_DEFAULTED"},
	{0x0010, "SE_SACL_PRESENT"},
	{0x0020, "SE_SACL_DEFAULTED"},
	{0x0100, "SE_DACL_AUTO_INHERIT_REQ"},
	{0x0200, "SE_SACL_AUTO_INHERIT_REQ"},
	{0x0400, "SE_DACL_AUTO_INHERITED"},
	{0x0800, "SE_SACL_AUTO_INHERITED"},
	{0x1000, "SE_DACL_PROTECTED"},
	{0x2000, "SE_SACL_PROTECTED"},
	{0x4000, "SE_RM_CONTROL_VALID"},
	{0x8000, "SE_SELF_RELATIVE"},
}

var aceFlagNames = []struct {
	bit  uint8
	name string
}{
	{0x01, "OBJECT_INHERIT_ACE"},
	{0x02, "CONTAINER_INHERIT_ACE"},
	{0x04, "NO_PROPAGATE_INHERIT_ACE"},
	{0x08, "INHERIT_ONLY_ACE"},
	{0x10, "INHERITED_ACE"},
	{0x40, "SUCCESSFUL_ACCESS_ACE_FLAG"},
	{0x80, "FAILED_ACCESS_ACE_FLAG"},
}

const (
	AceAccessAllowed         uint8 = 0x00
	AceAccessDenied          uint8 = 0x01
	AceAccessAllowedObject   uint8 = 0x05
	AceAccessDeniedObject    uint8 = 0x06
	AceAccessAllowedCallback uint8 = 0x09
	AceAccessDeniedCallback  uint8 = 0x0A
	AceAllowedCallbackObject uint8 = 0x0B
	AceDeniedCallbackObject  uint8 = 0x0C
)

var aceTypeNames = map[uint8]string{
	0x00: "ACCESS_ALLOWED",
	0x01: "ACCESS_DENIED",
	0x02: "SYSTEM_AUDIT",
	0x03: "SYSTEM_ALARM",
	0x04: "ACCESS_ALLOWED_COMPOUND",
	0x05: "ACCESS_ALLOWED_OBJECT",
	0x06: "ACCESS_DENIED_OBJECT",
	0x07: "SYSTEM_AUDIT_OBJECT",
	0x08: "SYSTEM_ALARM_OBJECT",
	0x09: "ACCESS_ALLOWED_CALLBACK",
	0x0A: "ACCESS_DENIED_CALLBACK",
	0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
	0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
	0x0D: "SYSTEM_AUDIT_CALLBACK",
	0x0E: "SYSTEM_ALARM_CALLBACK",
	0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
	0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
	0x11: "SYSTEM_MANDATORY_LABEL",
	0x12: "SYSTEM_RESOURCE_ATTRIBUTE",
	0x13: "SYSTEM_SCOPED_POLICY_ID",
}

func IsAllowType(t uint8) bool {
	return t == AceAccessAllowed || t == AceAccessAllowedObject || t == AceAccessAllowedCallback || t == AceAllowedCallbackObject
}

func IsDenyType(t uint8) bool {
	return t == AceAccessDenied || t == AceAccessDeniedObject || t == AceAccessDeniedCallback || t == AceDeniedCallbackObject
}

func isObjectType(t uint8) bool {
	switch t {
	case 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10:
		return true
	}
	return false
}

// Parse decodes a self-relative security descriptor. resolve may be nil.
func Parse(b []byte, resolve Resolver) (*model.Descriptor, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("security descriptor truncated: %d bytes", len(b))
	}
	ctl := binary.LittleEndian.Uint16(b[2:4])
	if ctl&seSelfRelative == 0 {
		return nil, fmt.Errorf("security descriptor is not self-relative (control 0x%04X)", ctl)
	}
	d := &model.Descriptor{
		Revision:     b[0],
		Control:      ctl,
		ControlHex:   fmt.Sprintf("0x%04X", ctl),
		ControlFlags: []string{},
	}
	for _, c := range controlNames {
		if ctl&c.bit != 0 {
			d.ControlFlags = append(d.ControlFlags, c.name)
		}
	}
	offOwner := binary.LittleEndian.Uint32(b[4:8])
	offGroup := binary.LittleEndian.Uint32(b[8:12])
	offDACL := binary.LittleEndian.Uint32(b[16:20])

	var err error
	if d.Owner, err = sidAt(b, offOwner, resolve); err != nil {
		return nil, fmt.Errorf("owner: %w", err)
	}
	if d.Group, err = sidAt(b, offGroup, resolve); err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}

	d.DACL.ACEs = []model.ACE{}
	switch {
	case ctl&seDACLPresent == 0:
		d.DACL.State = model.DACLNotPresent
	case offDACL == 0:
		d.DACL.State = model.DACLNull
	default:
		if int(offDACL) >= len(b) {
			return nil, fmt.Errorf("DACL offset %d beyond descriptor length %d", offDACL, len(b))
		}
		if err := parseACL(b[offDACL:], &d.DACL, resolve); err != nil {
			return nil, fmt.Errorf("DACL: %w", err)
		}
	}
	return d, nil
}

func sidAt(b []byte, off uint32, resolve Resolver) (*model.SID, error) {
	if off == 0 {
		return nil, nil
	}
	if int(off) >= len(b) {
		return nil, fmt.Errorf("offset %d beyond descriptor length %d", off, len(b))
	}
	s, _, err := ParseSID(b[off:])
	if err != nil {
		return nil, err
	}
	return NamedSID(s, resolve), nil
}

// NamedSID attaches a name, preferring the resolver over the well-known table.
func NamedSID(s string, resolve Resolver) *model.SID {
	out := &model.SID{Value: s}
	if resolve != nil {
		if n, ok := resolve(s); ok {
			out.Name, out.NameSource = n, "lookup"
			return out
		}
	}
	if n, ok := WellKnownName(s); ok {
		out.Name, out.NameSource = n, "well_known"
	}
	return out
}

func parseACL(b []byte, acl *model.ACL, resolve Resolver) error {
	if len(b) < 8 {
		return fmt.Errorf("ACL header truncated")
	}
	acl.Revision = b[0]
	size := int(binary.LittleEndian.Uint16(b[2:4]))
	count := int(binary.LittleEndian.Uint16(b[4:6]))
	if size < 8 || size > len(b) {
		return fmt.Errorf("ACL size %d invalid for %d available bytes", size, len(b))
	}
	b = b[:size]
	off := 8
	for i := 0; i < count; i++ {
		if off+4 > len(b) {
			return fmt.Errorf("ACE %d header truncated", i)
		}
		aceSize := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		if aceSize < 4 || off+aceSize > len(b) {
			return fmt.Errorf("ACE %d size %d invalid", i, aceSize)
		}
		ace, err := parseACE(i, b[off:off+aceSize], resolve)
		if err != nil {
			return fmt.Errorf("ACE %d: %w", i, err)
		}
		acl.ACEs = append(acl.ACEs, ace)
		off += aceSize
	}
	if count == 0 {
		acl.State = model.DACLEmpty
	} else {
		acl.State = model.DACLPresent
	}
	return nil
}

func parseACE(idx int, b []byte, resolve Resolver) (model.ACE, error) {
	a := model.ACE{
		Index:     idx,
		Type:      b[0],
		TypeName:  aceTypeNames[b[0]],
		Flags:     b[1],
		FlagNames: []string{},
		Rights:    []string{},
	}
	if a.TypeName == "" {
		a.TypeName = fmt.Sprintf("UNKNOWN_0x%02X", b[0])
	}
	for _, f := range aceFlagNames {
		if a.Flags&f.bit != 0 {
			a.FlagNames = append(a.FlagNames, f.name)
		}
	}
	a.InheritOnly = a.Flags&0x08 != 0
	if _, known := aceTypeNames[a.Type]; !known || a.Type == 0x04 {
		a.RawHex = hex.EncodeToString(b)
		return a, nil
	}
	if len(b) < 8 {
		return a, fmt.Errorf("ACE body truncated")
	}
	a.Mask = binary.LittleEndian.Uint32(b[4:8])
	a.MaskHex = model.Hex32(a.Mask)
	a.Rights = RightNames(a.Mask)
	a.MappedMask = MapGeneric(a.Mask)
	a.MappedHex = model.Hex32(a.MappedMask)
	a.MappedRights = RightNames(a.MappedMask)

	sidOff := 8
	if isObjectType(a.Type) {
		if len(b) < 12 {
			return a, fmt.Errorf("object ACE truncated")
		}
		objFlags := binary.LittleEndian.Uint32(b[8:12])
		sidOff = 12
		if objFlags&0x1 != 0 {
			sidOff += 16
		}
		if objFlags&0x2 != 0 {
			sidOff += 16
		}
		a.RawHex = hex.EncodeToString(b)
	}
	if sidOff >= len(b) {
		return a, fmt.Errorf("ACE trustee SID missing")
	}
	s, n, err := ParseSID(b[sidOff:])
	if err != nil {
		return a, err
	}
	if sidOff+n < len(b) && a.RawHex == "" && (a.Type == AceAccessAllowedCallback || a.Type == AceAccessDeniedCallback || a.Type >= 0x0D) {
		// Callback, label, and attribute ACEs carry application data after the SID.
		a.RawHex = hex.EncodeToString(b)
	}
	a.Trustee = NamedSID(s, resolve)
	return a, nil
}
