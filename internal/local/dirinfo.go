package local

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/thesubtlety/pipescry/internal/scanner"
)

// parseDirectoryInfo decodes a FILE_DIRECTORY_INFORMATION chain. It is
// platform-neutral so it can be tested off Windows.
func parseDirectoryInfo(b []byte) ([]scanner.EnumEntry, error) {
	var out []scanner.EnumEntry
	off := 0
	for off < len(b) {
		if off+64 > len(b) {
			return out, fmt.Errorf("directory entry at offset %d truncated", off)
		}
		e := b[off:]
		next := int(binary.LittleEndian.Uint32(e[0:4]))
		cur := binary.LittleEndian.Uint64(e[40:48])
		max := int64(binary.LittleEndian.Uint64(e[48:56]))
		nameLen := int(binary.LittleEndian.Uint32(e[60:64]))
		if nameLen%2 != 0 || 64+nameLen > len(e) {
			return out, fmt.Errorf("directory entry at offset %d has name length %d beyond buffer", off, nameLen)
		}
		u := make([]uint16, nameLen/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(e[64+2*i:])
		}
		out = append(out, scanner.EnumEntry{
			Name:             string(utf16.Decode(u)),
			CurrentInstances: &cur,
			MaxInstances:     &max,
		})
		if next == 0 {
			break
		}
		if next < 64 {
			return out, fmt.Errorf("directory entry at offset %d has invalid NextEntryOffset %d", off, next)
		}
		off += next
	}
	return out, nil
}
