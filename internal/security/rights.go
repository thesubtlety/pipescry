// Package security parses self-relative security descriptors and decodes
// access masks using named-pipe (NPFS) semantics.
package security

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

const (
	FileReadData           uint32 = 0x00000001
	FileWriteData          uint32 = 0x00000002
	FileCreatePipeInstance uint32 = 0x00000004 // same bit as FILE_APPEND_DATA on regular files
	FileReadEA             uint32 = 0x00000008
	FileWriteEA            uint32 = 0x00000010
	FileExecute            uint32 = 0x00000020
	FileDeleteChild        uint32 = 0x00000040
	FileReadAttributes     uint32 = 0x00000080
	FileWriteAttributes    uint32 = 0x00000100
	Delete                 uint32 = 0x00010000
	ReadControl            uint32 = 0x00020000
	WriteDAC               uint32 = 0x00040000
	WriteOwner             uint32 = 0x00080000
	Synchronize            uint32 = 0x00100000
	AccessSystemSecurity   uint32 = 0x01000000
	MaximumAllowed         uint32 = 0x02000000
	GenericAll             uint32 = 0x10000000
	GenericExecute         uint32 = 0x20000000
	GenericWrite           uint32 = 0x40000000
	GenericRead            uint32 = 0x80000000

	// NPFS uses the I/O manager's file generic mapping.
	FileGenericRead    uint32 = 0x00120089
	FileGenericWrite   uint32 = 0x00120116
	FileGenericExecute uint32 = 0x001200A0
	FileAllAccess      uint32 = 0x001F01FF
)

// Bit 0x4 is decoded as FILE_CREATE_PIPE_INSTANCE. On a pipe it allows a
// caller to create a new server instance of an existing pipe name, not to
// append to a message stream. FILE_GENERIC_WRITE includes it.
var rightNames = []struct {
	bit  uint32
	name string
}{
	{FileReadData, "FILE_READ_DATA"},
	{FileWriteData, "FILE_WRITE_DATA"},
	{FileCreatePipeInstance, "FILE_CREATE_PIPE_INSTANCE"},
	{FileReadEA, "FILE_READ_EA"},
	{FileWriteEA, "FILE_WRITE_EA"},
	{FileExecute, "FILE_EXECUTE"},
	{FileDeleteChild, "FILE_DELETE_CHILD"},
	{FileReadAttributes, "FILE_READ_ATTRIBUTES"},
	{FileWriteAttributes, "FILE_WRITE_ATTRIBUTES"},
	{Delete, "DELETE"},
	{ReadControl, "READ_CONTROL"},
	{WriteDAC, "WRITE_DAC"},
	{WriteOwner, "WRITE_OWNER"},
	{Synchronize, "SYNCHRONIZE"},
	{AccessSystemSecurity, "ACCESS_SYSTEM_SECURITY"},
	{MaximumAllowed, "MAXIMUM_ALLOWED"},
	{GenericAll, "GENERIC_ALL"},
	{GenericExecute, "GENERIC_EXECUTE"},
	{GenericWrite, "GENERIC_WRITE"},
	{GenericRead, "GENERIC_READ"},
}

var aliases = map[string]uint32{
	"FULL_CONTROL":         FileAllAccess,
	"FILE_ALL_ACCESS":      FileAllAccess,
	"FILE_APPEND_DATA":     FileCreatePipeInstance,
	"FILE_GENERIC_READ":    FileGenericRead,
	"FILE_GENERIC_WRITE":   FileGenericWrite,
	"FILE_GENERIC_EXEC":    FileGenericExecute,
	"FILE_GENERIC_EXECUTE": FileGenericExecute,
}

// MapGeneric expands GENERIC_* bits with the file generic mapping and clears them.
func MapGeneric(mask uint32) uint32 {
	out := mask &^ (GenericAll | GenericRead | GenericWrite | GenericExecute)
	if mask&GenericRead != 0 {
		out |= FileGenericRead
	}
	if mask&GenericWrite != 0 {
		out |= FileGenericWrite
	}
	if mask&GenericExecute != 0 {
		out |= FileGenericExecute
	}
	if mask&GenericAll != 0 {
		out |= FileAllAccess
	}
	return out
}

func IsFullControl(mask uint32) bool {
	return MapGeneric(mask)&FileAllAccess == FileAllAccess
}

// RightNames lists each set bit in ascending order; unnamed bits appear as hex.
func RightNames(mask uint32) []string {
	out := []string{}
	for m := mask; m != 0; m &= m - 1 {
		bit := uint32(1) << bits.TrailingZeros32(m)
		out = append(out, rightName(bit))
	}
	return out
}

func rightName(bit uint32) string {
	for _, r := range rightNames {
		if r.bit == bit {
			return r.name
		}
	}
	return fmt.Sprintf("0x%08X", bit)
}

// ParseRight accepts a right name, alias, or numeric mask and returns the
// generic-mapped mask it denotes.
func ParseRight(s string) (uint32, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "" {
		return 0, fmt.Errorf("empty right")
	}
	if v, ok := aliases[u]; ok {
		return MapGeneric(v), nil
	}
	for _, r := range rightNames {
		if r.name == u {
			return MapGeneric(r.bit), nil
		}
	}
	if v, err := strconv.ParseUint(strings.ToLower(u), 0, 32); err == nil && v != 0 {
		return MapGeneric(uint32(v)), nil
	}
	return 0, fmt.Errorf("unknown access right %q", s)
}
