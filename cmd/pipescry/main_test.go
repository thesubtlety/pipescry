package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestNoPasswordFlag(t *testing.T) {
	code, _, stderr := runCLI(t, "", "scan", "--target", "h", "--username", "u", "--password", "secret")
	if code != exitUsage || !strings.Contains(stderr, "flag provided but not defined: -password") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{"scan"},
		{"scan", "--local", "--target", "h"},
		{"scan", "--target", "h"},
		{"scan", "--target", "h", "--username", "u"},
		{"scan", "--target", "h", "--anonymous", "--username", "u"},
		{"scan", "--local", "--username", "u"},
		{"scan", "--local", "--format", "xml"},
		{"scan", "--local", "--evidence", "acl"},
		{"scan", "--local", "--permission", "NOPE"},
		{"scan", "--local", "--no-enumerate"},
		{"scan", "--local", "--timeout", "0s"},
	}
	for _, c := range cases {
		if code, _, _ := runCLI(t, "", c...); code != exitUsage {
			t.Errorf("%v: code %d, want %d", c, code, exitUsage)
		}
	}
}

func TestCredentials(t *testing.T) {
	t.Setenv("PS_TEST_PASS", "hunter2")
	t.Setenv("PS_TEST_HASH", "8846F7EAEE8FB117AD06BDD830B7586C")

	f := scanFlags{target: "h", port: 445, username: `CORP\alice`, passwordEnv: "PS_TEST_PASS"}
	o, err := credentials(&f, nil)
	if err != nil || o.Domain != "CORP" || o.User != "alice" || o.Password != "hunter2" {
		t.Fatalf("%+v %v", o, err)
	}
	f = scanFlags{target: "h", username: "bob@corp.local", passwordStdin: true}
	o, err = credentials(&f, strings.NewReader("s3cret\r\nignored\n"))
	if err != nil || o.Domain != "corp.local" || o.User != "bob" || o.Password != "s3cret" {
		t.Fatalf("%+v %v", o, err)
	}
	f = scanFlags{target: "h", username: "carol", hashEnv: "PS_TEST_HASH"}
	o, err = credentials(&f, nil)
	if err != nil || len(o.NTHash) != 16 || o.Password != "" {
		t.Fatalf("%+v %v", o, err)
	}
	f = scanFlags{target: "h", username: "dave", passwordEnv: "PS_TEST_PASS", hashEnv: "PS_TEST_HASH"}
	if _, err := credentials(&f, nil); err == nil {
		t.Fatal("accepted two secret sources")
	}
	f = scanFlags{target: "h", username: `A\x`, domain: "B", passwordEnv: "PS_TEST_PASS"}
	if _, err := credentials(&f, nil); err == nil {
		t.Fatal("accepted conflicting domains")
	}
	t.Setenv("PS_TEST_HASH", "zz")
	f = scanFlags{target: "h", username: "carol", hashEnv: "PS_TEST_HASH"}
	if _, err := credentials(&f, nil); err == nil || strings.Contains(err.Error(), "zz") {
		t.Fatalf("bad hash error must not echo the value: %v", err)
	}
}

func TestReadNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipes.txt")
	os.WriteFile(p, []byte("# comment\nspoolss\n\n  lsarpc  # trailing\n\\\\.\\pipe\\srvsvc\n"), 0o600)
	got, err := readNames(p)
	if err != nil || strings.Join(got, ",") != `spoolss,lsarpc,\\.\pipe\srvsvc` {
		t.Fatalf("%q %v", got, err)
	}
}
