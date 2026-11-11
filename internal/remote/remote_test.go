package remote

import (
	"encoding/binary"
	"testing"
)

func response(status uint32, off uint16, data []byte, pad int) []byte {
	b := make([]byte, 64+8+pad)
	copy(b, "\xfeSMB")
	binary.LittleEndian.PutUint32(b[8:], status)
	binary.LittleEndian.PutUint16(b[64:], 9)
	binary.LittleEndian.PutUint16(b[66:], off)
	binary.LittleEndian.PutUint32(b[68:], uint32(len(data)))
	return append(b, data...)
}

func TestParseQueryInfoResponse(t *testing.T) {
	sd := []byte{1, 0, 4, 0x80, 0, 0, 0, 0}
	st, got, err := parseQueryInfoResponse(response(0, 72, sd, 0))
	if err != nil || st != 0 || string(got) != string(sd) {
		t.Fatalf("got %x %x %v", st, got, err)
	}
	if st, _, err := parseQueryInfoResponse(response(0xC0000023, 0, nil, 0)); err != nil || st != 0xC0000023 {
		t.Fatalf("error status not surfaced: %x %v", st, err)
	}
	bad := response(0, 72, sd, 0)
	binary.LittleEndian.PutUint32(bad[68:], 4096)
	if _, _, err := parseQueryInfoResponse(bad); err == nil {
		t.Fatal("accepted out-of-bounds length")
	}
	if _, _, err := parseQueryInfoResponse(make([]byte, 10)); err == nil {
		t.Fatal("accepted truncated header")
	}
}
