// Package remote collects named-pipe evidence over SMB2/3 via IPC$.
package remote

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/scanner"
	"github.com/thesubtlety/pipescry/internal/security"
)

const share = "IPC$"

type Options struct {
	Host        string
	Port        int
	Domain      string
	User        string
	Password    string
	NTHash      []byte
	Anonymous   bool
	DialTimeout time.Duration
}

type Collector struct {
	conn *smb.Connection
	opt  Options
	id   model.Identity
}

var _ scanner.Collector = (*Collector)(nil)

// ConfigureLogging routes go-smb's loggers, which default to stdout, to w.
func ConfigureLogging(w io.Writer, verbose bool) {
	level := golog.LevelNone
	if verbose {
		level = golog.LevelDebug
	}
	for _, pkg := range []string{"smb", "spnego", "ntlmssp", "gss", "krb5ssp", "smb/compress"} {
		golog.Get("github.com/jfjallid/go-smb/" + pkg).SetOutput(w).SetErrOutput(w).SetLogLevel(level)
	}
	golog.Get("").SetOutput(w).SetErrOutput(w).SetLogLevel(level)
}

func Connect(ctx context.Context, opt Options) (*Collector, error) {
	init := &spnego.NTLMInitiator{
		User:      opt.User,
		Password:  opt.Password,
		Hash:      opt.NTHash,
		Domain:    opt.Domain,
		LocalUser: opt.Domain == "" || opt.Domain == ".",
	}
	if opt.Anonymous {
		init = &spnego.NTLMInitiator{NullSession: true}
	}
	so := smb.Options{
		Host:        opt.Host,
		Port:        opt.Port,
		Initiator:   init,
		DialTimeout: opt.DialTimeout,
	}
	addr := fmt.Sprintf("%s:%d", opt.Host, opt.Port)
	conn, err := scanner.Call(ctx, func() (*smb.Connection, error) { return smb.NewConnection(so) })
	if err != nil {
		return nil, fmt.Errorf("SMB session setup to %s: %w", addr, err)
	}
	if _, err := scanner.Call(ctx, func() (struct{}, error) { return struct{}{}, conn.TreeConnect(share) }); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tree connect to \\\\%s\\%s: %w", opt.Host, share, err)
	}
	c := &Collector{conn: conn, opt: opt}
	c.id = c.identity()
	return c, nil
}

func (c *Collector) Close() {
	done := make(chan struct{})
	go func() {
		_ = c.conn.Logoff()
		c.conn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// go-smb's Close also waits on the server; give up and let process
		// exit tear down the TCP connection.
	}
}

func (c *Collector) Target() string { return c.opt.Host }

func (c *Collector) identity() model.Identity {
	id := model.Identity{AuthMethod: "ntlm"}
	switch {
	case c.conn.IsNullSession() || c.opt.Anonymous:
		id.Name, id.SID, id.AuthMethod, id.Anonymous = "NT AUTHORITY\\ANONYMOUS LOGON", "S-1-5-7", "anonymous", true
		return id
	case c.opt.Domain != "":
		id.Name = c.opt.Domain + "\\" + c.opt.User
	default:
		id.Name = c.opt.User
	}
	// The server decides guest mapping; the session flag is the only signal.
	if c.conn.IsGuestSession() {
		id.Guest = true
	}
	return id
}

func (c *Collector) Identity() model.Identity { return c.id }

func (c *Collector) Resolver() security.Resolver { return nil }

var cipherNames = map[uint16]string{
	0x0001: "AES-128-CCM",
	0x0002: "AES-128-GCM",
	0x0003: "AES-256-CCM",
	0x0004: "AES-256-GCM",
}

func (c *Collector) Transport() *model.Transport {
	signing := c.conn.IsSigningRequired()
	t := &model.Transport{
		Protocol:        "smb2",
		Host:            c.opt.Host,
		Port:            c.opt.Port,
		DialectRaw:      c.conn.Dialect(),
		Dialect:         smb.DialectString(c.conn.Dialect()),
		SigningRequired: &signing,
		Share:           share,
	}
	if ci := c.conn.Cipher(); ci != 0 {
		t.CipherNegotiated = cipherNames[ci]
		if t.CipherNegotiated == "" {
			t.CipherNegotiated = fmt.Sprintf("0x%04X", ci)
		}
	}
	return t
}

// Enumerate lists the IPC$ root. Windows serves this from NPFS, so it shows
// pipes with at least one server instance at the time of the query.
// Servers may refuse it (non-Windows SMB servers, hardened hosts).
func (c *Collector) Enumerate(ctx context.Context) ([]scanner.EnumEntry, model.EnumerationStatus, *model.OpError) {
	files, err := scanner.Call(ctx, func() ([]smb.SharedFile, error) { return c.conn.ListDirectory(share, "", "*") })
	out := make([]scanner.EnumEntry, 0, len(files))
	for _, f := range files {
		if f.Name == "." || f.Name == ".." || f.Name == "" {
			continue
		}
		// NPFS reports the current instance count in EndOfFile.
		n := f.Size
		out = append(out, scanner.EnumEntry{Name: f.Name, CurrentInstances: &n})
	}
	if err == nil {
		return out, model.EnumComplete, nil
	}
	oe := c.opError("enumerate", share, err)
	switch {
	case len(out) > 0:
		return out, model.EnumPartial, oe
	case oe.Status != nil && model.ClassifyNTStatus(oe.Status.Code) == model.ResultUnsupported:
		return out, model.EnumUnsupported, oe
	}
	return out, model.EnumFailed, oe
}

func (c *Collector) createOpts(access uint32) *smb.CreateReqOpts {
	o := smb.NewCreateReqOpts()
	o.DesiredAccess = access
	// Identification lets the pipe server learn the caller's identity but
	// not act as the caller.
	o.ImpersonationLevel = smb.ImpersonationLevelIdentification
	o.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	o.CreateDisp = smb.FileOpen
	o.CreateOpts = 0
	return o
}

func (c *Collector) QuerySecurity(ctx context.Context, pipe string) scanner.SDOutcome {
	o, err := scanner.Call(ctx, func() (scanner.SDOutcome, error) {
		f, err := c.conn.OpenFileExt(share, pipe, c.createOpts(scanner.SecurityQueryAccess))
		if err != nil {
			return scanner.SDOutcome{Err: c.opError("open(READ_CONTROL)", pipe, err)}, nil
		}
		var out scanner.SDOutcome
		if raw, err := c.querySecurityRaw(f); err != nil {
			out.Err = c.opError("query_info(SMB2_0_INFO_SECURITY)", pipe, err)
		} else {
			out.Raw = raw
		}
		out.Closed, out.CloseErr = c.closeFile(f, pipe)
		return out, nil
	})
	if err != nil {
		return scanner.SDOutcome{Err: c.opError("query_security", pipe, err)}
	}
	return o
}

func (c *Collector) closeFile(f *smb.File, pipe string) (*bool, string) {
	closed := true
	if err := f.CloseFile(); err != nil {
		closed = false
		return &closed, fmt.Sprintf("close %s on \\\\%s\\%s: %v", pipe, c.opt.Host, share, err)
	}
	return &closed, ""
}

// querySecurityRaw issues QUERY_INFO itself because go-smb only returns the
// parsed descriptor, and the evidence must keep the bytes the server sent.
func (c *Collector) querySecurityRaw(f *smb.File) ([]byte, error) {
	info := smb.OwnerSecurityInformation | smb.GroupSecurityInformation | smb.DACLSecurityInformation
	return queryWithRetry(func(size uint32) ([]byte, error) {
		req, err := f.NewQueryInfoReq(share, f.FileID(), smb.OInfoSecurity, 0, info, 0, size, nil)
		if err != nil {
			return nil, err
		}
		pdu, err := req.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return c.conn.SendRawPDU(pdu)
	})
}

// queryWithRetry retries once at 64 KiB when the server reports the
// descriptor does not fit.
func queryWithRetry(send func(size uint32) ([]byte, error)) ([]byte, error) {
	size := uint32(8192)
	for attempt := 0; attempt < 2; attempt++ {
		buf, err := send(size)
		if err != nil {
			return nil, err
		}
		status, data, err := parseQueryInfoResponse(buf)
		if err != nil {
			return nil, err
		}
		switch status {
		case 0:
			return data, nil
		case smb.StatusBufferTooSmall, smb.StatusBufferOverflow:
			size = 65536
			continue
		}
		return nil, &smb.NTStatusError{Op: "QueryInfo", Status: status, Err: smb.StatusMap[status]}
	}
	return nil, fmt.Errorf("security descriptor exceeds 65536 bytes")
}

// parseQueryInfoResponse reads the SMB2 header status and QUERY_INFO output
// buffer with bounds checks.
func parseQueryInfoResponse(buf []byte) (uint32, []byte, error) {
	const hdr = 64
	if len(buf) < hdr {
		return 0, nil, fmt.Errorf("QUERY_INFO response truncated: %d bytes", len(buf))
	}
	status := binary.LittleEndian.Uint32(buf[8:12])
	if status != 0 {
		return status, nil, nil
	}
	if len(buf) < hdr+8 {
		return 0, nil, fmt.Errorf("QUERY_INFO response body truncated: %d bytes", len(buf))
	}
	off := int(binary.LittleEndian.Uint16(buf[hdr+2:]))
	n := int(binary.LittleEndian.Uint32(buf[hdr+4:]))
	if n == 0 {
		return 0, nil, fmt.Errorf("QUERY_INFO returned an empty output buffer")
	}
	if off < hdr || off+n > len(buf) {
		return 0, nil, fmt.Errorf("QUERY_INFO output buffer offset %d length %d exceeds response length %d", off, n, len(buf))
	}
	return 0, append([]byte(nil), buf[off:off+n]...), nil
}

// OpenTest opens and closes in one goroutine so a handle opened after the
// deadline is still closed.
func (c *Collector) OpenTest(ctx context.Context, pipe string, access uint32) scanner.OpenOutcome {
	o, err := scanner.Call(ctx, func() (scanner.OpenOutcome, error) {
		f, err := c.conn.OpenFileExt(share, pipe, c.createOpts(access))
		if err != nil {
			oe := c.opError("open", pipe, err)
			out := scanner.OpenOutcome{Result: model.ResultError, Status: oe.Status, Err: oe.Message}
			// OpenFileExt may reconnect the tree first; only the CREATE's
			// own status says anything about the pipe.
			var nt *smb.NTStatusError
			if errors.As(err, &nt) && strings.HasPrefix(nt.Op, "Create") {
				out.Result = model.ClassifyNTStatus(nt.Status)
			}
			return out, nil
		}
		out := scanner.OpenOutcome{Result: model.ResultAllowed, Status: model.NTStatus(0)}
		out.Closed, out.CloseErr = c.closeFile(f, pipe)
		return out, nil
	})
	if err != nil {
		return scanner.OpenOutcome{Result: model.ResultError,
			Err: fmt.Sprintf("open %s on \\\\%s\\%s: %v; a late handle is closed when the open completes", pipe, c.opt.Host, share, err)}
	}
	return o
}

func (c *Collector) opError(op, target string, err error) *model.OpError {
	oe := &model.OpError{Op: op, Target: target, Message: fmt.Sprintf("%s %s on %s: %v", op, target, c.opt.Host, err)}
	var nt *smb.NTStatusError
	if errors.As(err, &nt) {
		oe.Status = model.NTStatus(nt.Status)
	}
	return oe
}
