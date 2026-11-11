package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/thesubtlety/pipescry/internal/local"
	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/remote"
	"github.com/thesubtlety/pipescry/internal/report"
	"github.com/thesubtlety/pipescry/internal/scanner"
)

var version = "0.1.0-dev"

const (
	exitOK    = 0
	exitScan  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usageTop = `Usage: pipescry <command> [flags]

Commands:
  scan      Collect named-pipe security descriptors and optional open tests
  compare   Compare two JSON reports (e.g. local vs remote); exit 1 if pipes differ
  version   Print version

Run "pipescry scan -h" for scan flags.
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageTop)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdin, stdout, stderr)
	case "compare":
		return compare(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "pipescry %s\n", version)
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageTop)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageTop)
	return exitUsage
}

func compare(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "Usage: pipescry compare A.json B.json\n\nCompares descriptor bytes and open-test results per pipe. Exit 0 if no pipe present in both differs, 1 if any does, 2 on error.")
		return exitUsage
	}
	a, err := report.ReadJSONFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "compare: %v\n", err)
		return exitUsage
	}
	b, err := report.ReadJSONFile(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "compare: %v\n", err)
		return exitUsage
	}
	if report.Compare(stdout, a, b) > 0 {
		return exitScan
	}
	return exitOK
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

type scanFlags struct {
	target, username, domain, password, passwordEnv, ntHash, ntHashEnv, proxy string
	port                                                                      int
	passwordStdin, anonymous, local                                           bool
	namesFile                                                                 string
	names                                                                     listFlag
	noEnumerate, accessTest                                                   bool
	timeout                                                                   time.Duration
	concurrency                                                               int
	jsonPath, format                                                          string
	summary, quiet, noColor, verbose                                          bool
	principals, permissions, results                                          listFlag
	evidence                                                                  string
}

func scan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&f.target, "target", "", "remote host name or IP; scans \\\\host\\IPC$ over SMB2/3")
	fs.IntVar(&f.port, "port", 445, "remote SMB TCP port")
	fs.StringVar(&f.proxy, "proxy", "", "SOCKS proxy URL: socks4, socks4a, socks5, or socks5h://[user[:pass]@]host[:port]; the a/h forms resolve --target at the proxy")
	fs.StringVar(&f.username, "username", "", "account name; accepts DOMAIN\\user or user@domain")
	fs.StringVar(&f.domain, "domain", "", "account domain; empty or \".\" authenticates as a local account on the target")
	fs.StringVar(&f.password, "password", "", "password; visible in process listings and shell history, prefer --password-env")
	fs.StringVar(&f.passwordEnv, "password-env", "", "read the password from this environment variable")
	fs.BoolVar(&f.passwordStdin, "password-stdin", false, "read the password from the first line of stdin")
	fs.StringVar(&f.ntHash, "nt-hash", "", "32-char hex NT hash for pass-the-hash; visible in process listings and shell history, prefer --nt-hash-env")
	fs.StringVar(&f.ntHashEnv, "nt-hash-env", "", "read a hex NT hash from this environment variable instead of a password")
	fs.BoolVar(&f.anonymous, "anonymous", false, "use an anonymous (null) NTLM session")
	fs.BoolVar(&f.local, "local", false, "scan the local NPFS with Win32 APIs (Windows only)")
	fs.StringVar(&f.namesFile, "names-file", "", "file with one pipe name per line; '#' starts a comment")
	fs.Var(&f.names, "names", "comma-separated pipe names to scan; repeatable")
	fs.BoolVar(&f.noEnumerate, "no-enumerate", false, "skip directory enumeration and scan only supplied names")
	fs.BoolVar(&f.accessTest, "access-test", false, "open and close each pipe separately with READ_CONTROL, FILE_READ_DATA, FILE_WRITE_DATA")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Second, "per-operation timeout; enumeration gets 6x")
	fs.IntVar(&f.concurrency, "concurrency", 4, "pipes processed in parallel (1-64)")
	fs.StringVar(&f.jsonPath, "json", "", "write the complete evidence document to this path")
	fs.StringVar(&f.jsonPath, "output", "", "alias for --json")
	fs.StringVar(&f.format, "format", "text", "stdout format: text or json (json writes the complete evidence document)")
	fs.BoolVar(&f.summary, "summary", false, "text output: print only the scan summary")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress progress and diagnostics on stderr")
	fs.BoolVar(&f.noColor, "no-color", false, "disable ANSI colors (also disabled when stdout is not a terminal or NO_COLOR is set)")
	fs.BoolVar(&f.verbose, "verbose", false, "text output: add raw descriptors and ACE flags; stderr: SMB library debug log")
	fs.Var(&f.principals, "principal", "display only ACEs whose trustee, or tests whose identity, matches this SID or name; repeatable")
	fs.Var(&f.permissions, "permission", "display only ACEs (allow or deny) whose mask, or tests whose request, contains this right after generic mapping (e.g. FILE_WRITE_DATA, WRITE_DAC, 0x4); NULL DACLs always match; repeatable")
	fs.StringVar(&f.evidence, "evidence", "all", "display evidence type: all, dacl, or open")
	fs.Var(&f.results, "result", "display only open tests with this result: allowed, denied, busy, error, unsupported, not_tested; repeatable")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: pipescry scan (--target HOST | --local) [flags]

Read-only by default: pipes are opened with READ_CONTROL to read the security
descriptor and closed. --access-test adds one open/close per tested right.
No data is read from or written to any pipe. Display filters affect text
output only; JSON always contains all collected evidence.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "scan: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	filter, err := report.NewFilter(f.principals, f.permissions, f.evidence, f.results)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitUsage
	}
	if err := validate(&f); err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitUsage
	}
	names := []string(f.names)
	if f.namesFile != "" {
		more, err := readNames(f.namesFile)
		if err != nil {
			fmt.Fprintf(stderr, "scan: read names file %s: %v\n", f.namesFile, err)
			return exitUsage
		}
		names = append(names, more...)
	}
	if f.noEnumerate && len(names) == 0 {
		fmt.Fprintln(stderr, "scan: --no-enumerate requires --names or --names-file")
		return exitUsage
	}

	diag := func(format string, a ...any) {
		if !f.quiet {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}
	if f.verbose && !f.quiet {
		remote.ConfigureLogging(stderr, true)
	} else {
		remote.ConfigureLogging(io.Discard, false)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Restore default handling after the first interrupt so a second one exits.
	go func() { <-ctx.Done(); stop() }()

	var col scanner.Collector
	mode := model.ModeRemote
	if f.local {
		mode = model.ModeLocal
		c, err := local.New()
		if err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitScan
		}
		col = c
	} else {
		opt, err := credentials(&f, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitUsage
		}
		if opt.Proxy != nil {
			diag("connecting to %s:%d via %s", f.target, f.port, opt.Proxy)
		} else {
			diag("connecting to %s:%d", f.target, f.port)
		}
		cctx, cancel := context.WithTimeout(ctx, f.timeout*3)
		c, err := remote.Connect(cctx, opt)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitScan
		}
		defer c.Close()
		col = c
	}

	progress := func(string, ...any) {}
	if f.verbose && !f.quiet {
		progress = diag
	}
	r := scanner.Run(ctx, col, scanner.Config{
		Mode:        mode,
		Version:     version,
		Enumerate:   !f.noEnumerate,
		Names:       names,
		AccessTest:  f.accessTest,
		Timeout:     f.timeout,
		Concurrency: f.concurrency,
		Progress:    progress,
	})
	diag("scanned %d pipes on %s", len(r.Pipes), r.Target)

	code := exitOK
	if f.jsonPath != "" {
		if err := report.WriteJSONFile(f.jsonPath, r); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			code = exitScan
		} else {
			diag("wrote %s", f.jsonPath)
		}
	}
	if f.format == "json" {
		if err := report.WriteJSON(stdout, r); err != nil {
			fmt.Fprintf(stderr, "scan: write JSON to stdout: %v\n", err)
			return exitScan
		}
		return code
	}
	report.WriteText(stdout, r, report.TextOptions{
		Color:       !f.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout),
		Verbose:     f.verbose,
		SummaryOnly: f.summary,
		Filter:      filter,
	})
	return code
}

func validate(f *scanFlags) error {
	switch {
	case f.local && f.target != "":
		return errors.New("--local and --target are mutually exclusive")
	case !f.local && f.target == "":
		return errors.New("one of --target or --local is required")
	case f.local && (f.username != "" || f.anonymous || f.password != "" || f.passwordEnv != "" || f.ntHash != "" || f.ntHashEnv != "" || f.passwordStdin):
		return errors.New("credential flags apply only to --target; --local uses the current process token")
	case f.local && f.proxy != "":
		return errors.New("--proxy applies only to --target")
	case f.format != "text" && f.format != "json":
		return fmt.Errorf("--format %q: want text or json", f.format)
	case len(f.results) > 0 && strings.EqualFold(f.evidence, "dacl"):
		return errors.New("--result filters open tests and cannot be combined with --evidence dacl")
	case f.timeout <= 0:
		return errors.New("--timeout must be positive")
	case f.concurrency < 1 || f.concurrency > 64:
		return errors.New("--concurrency must be between 1 and 64")
	case f.port < 1 || f.port > 65535:
		return errors.New("--port must be between 1 and 65535")
	}
	return nil
}

func credentials(f *scanFlags, stdin io.Reader) (remote.Options, error) {
	opt := remote.Options{Host: f.target, Port: f.port, Domain: f.domain, DialTimeout: f.timeout}
	if f.proxy != "" {
		p, err := remote.ParseProxy(f.proxy)
		if err != nil {
			return opt, fmt.Errorf("--proxy: %w", err)
		}
		opt.Proxy = p
	}
	if f.anonymous {
		if f.username != "" || f.password != "" || f.passwordEnv != "" || f.ntHash != "" || f.ntHashEnv != "" || f.passwordStdin {
			return opt, errors.New("--anonymous cannot be combined with credentials")
		}
		opt.Anonymous = true
		return opt, nil
	}
	if f.username == "" {
		return opt, errors.New("--username or --anonymous is required for --target")
	}
	user := f.username
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		if opt.Domain != "" {
			return opt, errors.New("domain given in both --username and --domain")
		}
		opt.Domain, user = user[:i], user[i+1:]
	} else if i := strings.LastIndexByte(user, '@'); i >= 0 && opt.Domain == "" {
		user, opt.Domain = user[:i], user[i+1:]
	}
	opt.User = user

	sources := 0
	for _, b := range []bool{f.password != "", f.passwordEnv != "", f.passwordStdin, f.ntHash != "", f.ntHashEnv != ""} {
		if b {
			sources++
		}
	}
	if sources != 1 {
		return opt, errors.New("exactly one of --password, --password-env, --password-stdin, --nt-hash, or --nt-hash-env is required with --username")
	}
	switch {
	case f.password != "":
		opt.Password = f.password
	case f.passwordEnv != "":
		v, ok := os.LookupEnv(f.passwordEnv)
		if !ok {
			return opt, fmt.Errorf("--password-env: environment variable %s is not set", f.passwordEnv)
		}
		opt.Password = v
	case f.passwordStdin:
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return opt, fmt.Errorf("--password-stdin: read stdin: %w", err)
		}
		opt.Password = strings.TrimRight(line, "\r\n")
	case f.ntHash != "":
		h, err := decodeNTHash(f.ntHash)
		if err != nil {
			return opt, errors.New("--nt-hash is not a 32-character hex NT hash")
		}
		opt.NTHash = h
	case f.ntHashEnv != "":
		v, ok := os.LookupEnv(f.ntHashEnv)
		if !ok {
			return opt, fmt.Errorf("--nt-hash-env: environment variable %s is not set", f.ntHashEnv)
		}
		h, err := decodeNTHash(v)
		if err != nil {
			return opt, fmt.Errorf("--nt-hash-env: %s does not hold a 32-character hex NT hash", f.ntHashEnv)
		}
		opt.NTHash = h
	}

	return opt, nil
}

// decodeNTHash parses a 32-character hex NT hash. It never includes the input
// in the error, so a malformed secret is not echoed.
func decodeNTHash(s string) ([]byte, error) {
	h, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(h) != 16 {
		return nil, errors.New("not a 32-character hex NT hash")
	}
	return h, nil
}

func readNames(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableANSI(f)
}
