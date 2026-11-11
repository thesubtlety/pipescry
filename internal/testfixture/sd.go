// Package testfixture builds synthetic security descriptors for tests.
package testfixture

import (
	"encoding/binary"
	"strconv"
	"strings"
)

func SID(s string) []byte {
	parts := strings.Split(s, "-")
	auth, _ := strconv.ParseUint(parts[2], 10, 48)
	subs := parts[3:]
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auth >> (8 * (5 - i)))
	}
	for _, p := range subs {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			panic(err)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return b
}

type ACE struct {
	Type, Flags uint8
	Mask        uint32
	SID         string
}

func ACL(aces []ACE) []byte {
	var body []byte
	for _, a := range aces {
		s := SID(a.SID)
		ace := []byte{a.Type, a.Flags, 0, 0}
		ace = binary.LittleEndian.AppendUint32(ace, a.Mask)
		ace = append(ace, s...)
		binary.LittleEndian.PutUint16(ace[2:], uint16(len(ace)))
		body = append(body, ace...)
	}
	h := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[2:], uint16(8+len(body)))
	binary.LittleEndian.PutUint16(h[4:], uint16(len(aces)))
	return append(h, body...)
}

// SD lays out a self-relative descriptor. dacl == nil with present == true is a NULL DACL.
func SD(owner, group string, present bool, dacl []byte) []byte {
	ctl := uint16(0x8000)
	if present {
		ctl |= 0x0004
	}
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], ctl)
	o := SID(owner)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b = append(b, o...)
	g := SID(group)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	b = append(b, g...)
	if dacl != nil {
		binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
		b = append(b, dacl...)
	}
	return b
}

func A(typ, flags uint8, mask uint32, sid string) ACE {
	return ACE{Type: typ, Flags: flags, Mask: mask, SID: sid}
}
