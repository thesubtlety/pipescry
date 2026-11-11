package security

import (
	"encoding/binary"
	"testing"

	"github.com/thesubtlety/pipescry/internal/model"
	tf "github.com/thesubtlety/pipescry/internal/testfixture"
)

func kinds(in []model.Indicator) map[string]int {
	m := map[string]int{}
	for _, i := range in {
		m[i.Kind]++
	}
	return m
}

func TestParseTypicalPipeDACL(t *testing.T) {
	sd := tf.SD("S-1-5-18", "S-1-5-18", true, tf.ACL([]tf.ACE{
		tf.A(0x00, 0, FileAllAccess, "S-1-5-18"),
		tf.A(0x00, 0, FileAllAccess, "S-1-5-32-544"),
		tf.A(0x00, 0, 0x0012019F, "S-1-1-0"),
		tf.A(0x01, 0, FileWriteData, "S-1-5-7"),
		tf.A(0x00, 0x08, GenericAll, "S-1-3-0"),
	}))
	d, err := Parse(sd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner.Value != "S-1-5-18" || d.Owner.Name != "NT AUTHORITY\\SYSTEM" {
		t.Fatalf("owner = %+v", d.Owner)
	}
	if d.DACL.State != model.DACLPresent || len(d.DACL.ACEs) != 5 {
		t.Fatalf("dacl = %+v", d.DACL)
	}
	ev := d.DACL.ACEs[2]
	if ev.Mask != 0x0012019F || ev.Trustee.Name != "Everyone" || ev.TypeName != "ACCESS_ALLOWED" {
		t.Fatalf("everyone ace = %+v", ev)
	}
	if !contains(ev.Rights, "FILE_CREATE_PIPE_INSTANCE") || contains(ev.Rights, "FILE_APPEND_DATA") {
		t.Fatalf("bit 0x4 must decode as FILE_CREATE_PIPE_INSTANCE: %v", ev.Rights)
	}
	if d.DACL.ACEs[3].TypeName != "ACCESS_DENIED" {
		t.Fatal("deny ACE type")
	}
	co := d.DACL.ACEs[4]
	if !co.InheritOnly || co.MappedMask != FileAllAccess {
		t.Fatalf("inherit-only generic ACE = %+v", co)
	}

	k := kinds(Indicators(d))
	want := map[string]int{IndBroadGrant: 1, IndCreatePipeInstance: 1}
	for kind, n := range want {
		if k[kind] != n {
			t.Errorf("indicator %s = %d, want %d (all: %v)", kind, k[kind], n, k)
		}
	}
	if k[IndFullControl] != 0 {
		t.Errorf("SYSTEM/Administrators and inherit-only ACEs must not yield full_control_grant: %v", k)
	}
}

func TestNullVersusEmptyVersusAbsentDACL(t *testing.T) {
	cases := []struct {
		name    string
		present bool
		dacl    []byte
		state   model.DACLState
		ind     string
	}{
		{"null", true, nil, model.DACLNull, IndNullDACL},
		{"empty", true, tf.ACL(nil), model.DACLEmpty, IndEmptyDACL},
		{"not_present", false, nil, model.DACLNotPresent, IndDACLNotPresent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Parse(tf.SD("S-1-5-18", "S-1-5-18", c.present, c.dacl), nil)
			if err != nil {
				t.Fatal(err)
			}
			if d.DACL.State != c.state {
				t.Fatalf("state = %s, want %s", d.DACL.State, c.state)
			}
			if k := kinds(Indicators(d)); k[c.ind] != 1 || len(k) != 1 {
				t.Fatalf("indicators = %v", k)
			}
		})
	}
}

func TestGenericWriteGrantsCreatePipeInstance(t *testing.T) {
	d, err := Parse(tf.SD("S-1-5-18", "S-1-5-18", true, tf.ACL([]tf.ACE{
		tf.A(0x00, 0, GenericWrite|GenericRead, "S-1-5-11"),
		tf.A(0x00, 0, WriteDAC|ReadControl, "S-1-5-21-1-2-3-1105"),
		tf.A(0x00, 0, GenericAll, "S-1-5-32-545"),
	})), nil)
	if err != nil {
		t.Fatal(err)
	}
	au := d.DACL.ACEs[0]
	if au.MappedMask != FileGenericRead|FileGenericWrite {
		t.Fatalf("mapped = %s", au.MappedHex)
	}
	k := kinds(Indicators(d))
	if k[IndBroadGrant] != 2 || k[IndCreatePipeInstance] != 1 || k[IndWriteDAC] != 1 || k[IndFullControl] != 1 {
		t.Fatalf("indicators = %v", k)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good := tf.SD("S-1-5-18", "S-1-5-18", true, tf.ACL([]tf.ACE{tf.A(0, 0, 1, "S-1-1-0")}))
	for n := 0; n < len(good); n++ {
		if _, err := Parse(good[:n], nil); err == nil && n < 20 {
			t.Fatalf("accepted %d-byte prefix", n)
		}
	}
	bad := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(bad[16:], 0xFFFF)
	if _, err := Parse(bad, nil); err == nil {
		t.Fatal("accepted out-of-range DACL offset")
	}
	abs := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(abs[2:], seDACLPresent)
	if _, err := Parse(abs, nil); err == nil {
		t.Fatal("accepted absolute descriptor")
	}
}

func TestParseRight(t *testing.T) {
	cases := map[string]uint32{
		"FILE_WRITE_DATA":  FileWriteData,
		"file_append_data": FileCreatePipeInstance,
		"GENERIC_WRITE":    FileGenericWrite,
		"full_control":     FileAllAccess,
		"0x40000":          WriteDAC,
	}
	for in, want := range cases {
		got, err := ParseRight(in)
		if err != nil || got != want {
			t.Errorf("ParseRight(%q) = %#x, %v; want %#x", in, got, err, want)
		}
	}
	if _, err := ParseRight("WRITE_EVERYTHING"); err == nil {
		t.Error("accepted unknown right")
	}
}

func TestResolverPreferredOverWellKnown(t *testing.T) {
	r := func(s string) (string, bool) { return "HOST\\Everybody", s == "S-1-1-0" }
	s := NamedSID("S-1-1-0", r)
	if s.Name != "HOST\\Everybody" || s.NameSource != "lookup" {
		t.Fatalf("%+v", s)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
