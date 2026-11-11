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

func TestPasswordFlagNotEchoed(t *testing.T) {
	// Port 1 refuses the connection, so this exercises the failure path.
	code, out, stderr := runCLI(t, "", "scan", "--target", "127.0.0.1", "--port", "1", "--timeout", "2s",
		"--username", "u", "--password", "s3cret-value", "--verbose", "--proxy", "socks5h://pu:proxy-secret@127.0.0.1:1")
	if code != exitScan || strings.Contains(out+stderr, "s3cret-value") || strings.Contains(out+stderr, "proxy-secret") {
		t.Fatalf("code=%d output contains password or wrong code:\n%s%s", code, out, stderr)
	}
	f := scanFlags{target: "h", username: "u", password: "p", passwordEnv: "X"}
	if _, err := credentials(&f, nil); err == nil {
		t.Fatal("accepted --password with --password-env")
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
		{"scan", "--local", "--timeout", "0s"},
		{"scan", "--local", "--evidence", "dacl", "--result", "denied"},
		{"scan", "--local", "--proxy", "socks5://h"},
		{"scan", "--target", "h", "--anonymous", "--proxy", "http://h:8080"},
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
	f = scanFlags{target: "h", username: "carol", ntHashEnv: "PS_TEST_HASH"}
	o, err = credentials(&f, nil)
	if err != nil || len(o.NTHash) != 16 || o.Password != "" {
		t.Fatalf("%+v %v", o, err)
	}
	f = scanFlags{target: "h", username: "erin", ntHash: "8846F7EAEE8FB117AD06BDD830B7586C"}
	o, err = credentials(&f, nil)
	if err != nil || len(o.NTHash) != 16 || o.Password != "" {
		t.Fatalf("--nt-hash: %+v %v", o, err)
	}
	f = scanFlags{target: "h", username: "dave", passwordEnv: "PS_TEST_PASS", ntHashEnv: "PS_TEST_HASH"}
	if _, err := credentials(&f, nil); err == nil {
		t.Fatal("accepted two secret sources")
	}
	f = scanFlags{target: "h", username: `A\x`, domain: "B", passwordEnv: "PS_TEST_PASS"}
	if _, err := credentials(&f, nil); err == nil {
		t.Fatal("accepted conflicting domains")
	}
	t.Setenv("PS_TEST_HASH", "zz")
	f = scanFlags{target: "h", username: "carol", ntHashEnv: "PS_TEST_HASH"}
	if _, err := credentials(&f, nil); err == nil || strings.Contains(err.Error(), "zz") {
		t.Fatalf("bad hash error must not echo the value: %v", err)
	}
	f = scanFlags{target: "h", username: "carol", ntHash: "nothex-but-secret"}
	if _, err := credentials(&f, nil); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("bad --nt-hash error must not echo the value: %v", err)
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
