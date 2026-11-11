package local

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func entry(name string, cur, max uint64, last bool) []byte {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 64+2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[64+2*i:], c)
	}
	// NextEntryOffset is 8-byte aligned in real buffers.
	pad := (8 - len(b)%8) % 8
	b = append(b, make([]byte, pad)...)
	if !last {
		binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))
	}
	binary.LittleEndian.PutUint64(b[40:], cur)
	binary.LittleEndian.PutUint64(b[48:], max)
	binary.LittleEndian.PutUint32(b[60:], uint32(2*len(u)))
	return b
}

func TestParseDirectoryInfo(t *testing.T) {
	buf := append(entry("lsass", 3, 0xFFFFFFFF, false), entry(`Winsock2\CatalogChangeListener-1f0-0`, 1, 1, true)...)
	got, err := parseDirectoryInfo(buf)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].Name != "lsass" || *got[0].CurrentInstances != 3 || *got[0].MaxInstances != 0xFFFFFFFF {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Name != `Winsock2\CatalogChangeListener-1f0-0` {
		t.Fatalf("%q", got[1].Name)
	}
	bad := entry("x", 1, 1, true)
	binary.LittleEndian.PutUint32(bad[60:], 4000)
	if _, err := parseDirectoryInfo(bad); err == nil {
		t.Fatal("accepted name length beyond buffer")
	}
	loop := entry("x", 1, 1, true)
	binary.LittleEndian.PutUint32(loop[0:], 8)
	if _, err := parseDirectoryInfo(loop); err == nil {
		t.Fatal("accepted NextEntryOffset smaller than an entry header")
	}
}
