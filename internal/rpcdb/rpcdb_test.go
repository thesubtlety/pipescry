package rpcdb

import "testing"

func TestLookup(t *testing.T) {
	ps := Lookup("SpoolSS")
	if len(ps) != 1 || ps[0].ID != "MS-RPRN" || ps[0].Name == "" {
		t.Fatalf("spoolss: %+v", ps)
	}
	if ps := Lookup("lsarpc"); len(ps) < 2 {
		t.Fatalf("lsarpc should map to several protocols: %+v", ps)
	}
	if ps := Lookup("vendor_pipe"); ps == nil || len(ps) != 0 {
		t.Fatalf("unknown pipe: %#v", ps)
	}
}
