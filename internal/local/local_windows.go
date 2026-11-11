//go:build windows

// Package local collects named-pipe evidence from the local NPFS with Win32
// and native APIs.
package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/thesubtlety/pipescry/internal/model"
	"github.com/thesubtlety/pipescry/internal/scanner"
	"github.com/thesubtlety/pipescry/internal/security"
)

const pipeRoot = `\\.\pipe\`

var (
	ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryDirectoryFile = ntdll.NewProc("NtQueryDirectoryFile")
	procRtlGetLastNtStatus   = ntdll.NewProc("RtlGetLastNtStatus")
)

const (
	fileDirectoryInformation = 1
	statusNoMoreFiles        = 0x80000006
	statusBufferOverflow     = 0x80000005
	fileListDirectory        = 0x1
)

type Collector struct {
	host  string
	id    model.Identity
	names sync.Map
}

var _ scanner.Collector = (*Collector)(nil)

func New() (scanner.Collector, error) {
	c := &Collector{}
	c.host, _ = os.Hostname()
	if c.host == "" {
		c.host = "localhost"
	}
	id, err := currentIdentity()
	if err != nil {
		return nil, fmt.Errorf("read process token: %w", err)
	}
	c.id = id
	return c, nil
}

// currentIdentity reports the process token. pipescry does not enable
// privileges or impersonate, so tests reflect this token as-is.
func currentIdentity() (model.Identity, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return model.Identity{}, err
	}
	id := model.Identity{AuthMethod: "process_token", SID: tu.User.Sid.String()}
	if acct, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		id.Name = dom + `\` + acct
	} else {
		id.Name = id.SID
	}
	elevated := tok.IsElevated()
	id.Elevated = &elevated
	id.Anonymous = id.SID == "S-1-5-7"
	id.Guest = id.SID == "S-1-5-32-546"
	return id, nil
}

func (c *Collector) Target() string              { return c.host }
func (c *Collector) Identity() model.Identity    { return c.id }
func (c *Collector) Transport() *model.Transport { return &model.Transport{Protocol: "npfs"} }

func (c *Collector) Resolver() security.Resolver {
	return func(s string) (string, bool) {
		if v, ok := c.names.Load(s); ok {
			n := v.(string)
			return n, n != ""
		}
		name := ""
		if sid, err := windows.StringToSid(s); err == nil {
			if acct, dom, _, err := sid.LookupAccount(""); err == nil {
				name = acct
				if dom != "" {
					name = dom + `\` + acct
				}
			}
		}
		c.names.Store(s, name)
		return name, name != ""
	}
}

// Enumerate reads the NPFS root directory. NPFS lists a name while at least
// one server instance exists; for each entry EndOfFile is the current
// instance count and AllocationSize the maximum (0xFFFFFFFF = unlimited).
func (c *Collector) Enumerate(ctx context.Context) ([]scanner.EnumEntry, model.EnumerationStatus, *model.OpError) {
	type res struct {
		entries []scanner.EnumEntry
		oe      *model.OpError
	}
	r, err := scanner.Call(ctx, func() (res, error) {
		e, oe := enumerate()
		return res{e, oe}, nil
	})
	if err != nil {
		return nil, model.EnumFailed, &model.OpError{Op: "enumerate", Target: pipeRoot, Message: fmt.Sprintf("enumerate %s: %v", pipeRoot, err)}
	}
	switch {
	case r.oe == nil:
		return r.entries, model.EnumComplete, nil
	case len(r.entries) > 0:
		return r.entries, model.EnumPartial, r.oe
	}
	return r.entries, model.EnumFailed, r.oe
}

func enumerate() ([]scanner.EnumEntry, *model.OpError) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, _ := windows.UTF16PtrFromString(pipeRoot)
	h, err := windows.CreateFile(root, fileListDirectory|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, win32Error("CreateFileW", pipeRoot, err)
	}
	defer windows.CloseHandle(h)

	var out []scanner.EnumEntry
	buf := make([]byte, 64*1024)
	restart := uintptr(1)
	for {
		var iosb windows.IO_STATUS_BLOCK
		r, _, _ := procNtQueryDirectoryFile.Call(uintptr(h), 0, 0, 0,
			uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			fileDirectoryInformation, 0, 0, restart)
		restart = 0
		st := uint32(r)
		if st == statusNoMoreFiles {
			return out, nil
		}
		if st != 0 && st != statusBufferOverflow {
			return out, &model.OpError{Op: "NtQueryDirectoryFile", Target: pipeRoot,
				Message: fmt.Sprintf("NtQueryDirectoryFile %s: %s", pipeRoot, model.NTStatus(st)), Status: model.NTStatus(st)}
		}
		entries, perr := parseDirectoryInfo(buf[:iosb.Information])
		out = append(out, entries...)
		if perr != nil {
			return out, &model.OpError{Op: "NtQueryDirectoryFile", Target: pipeRoot, Message: perr.Error()}
		}
		if iosb.Information == 0 {
			return out, nil
		}
	}
}

func pipePath(name string) *uint16 {
	p, _ := windows.UTF16PtrFromString(pipeRoot + name)
	return p
}

// openPipe requests SECURITY_IDENTIFICATION so the pipe server can identify
// but not impersonate this process. FILE_OPEN semantics (OPEN_EXISTING)
// never create a pipe instance.
func openPipe(name string, access uint32) (windows.Handle, error) {
	return windows.CreateFile(pipePath(name), access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
}

func (c *Collector) QuerySecurity(ctx context.Context, pipe string) ([]byte, *model.OpError) {
	type res struct {
		raw []byte
		oe  *model.OpError
	}
	r, err := scanner.Call(ctx, func() (res, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, err := openPipe(pipe, scanner.SecurityQueryAccess)
		if err != nil {
			return res{oe: win32Error("CreateFileW(READ_CONTROL)", pipeRoot+pipe, err)}, nil
		}
		defer windows.CloseHandle(h)
		sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return res{oe: win32Error("GetSecurityInfo", pipeRoot+pipe, err)}, nil
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
		return res{raw: append([]byte(nil), b...)}, nil
	})
	if err != nil {
		return nil, &model.OpError{Op: "query_security", Target: pipeRoot + pipe, Message: fmt.Sprintf("query security %s%s: %v", pipeRoot, pipe, err)}
	}
	return r.raw, r.oe
}

func (c *Collector) OpenTest(ctx context.Context, pipe string, access uint32) scanner.OpenOutcome {
	o, err := scanner.Call(ctx, func() (scanner.OpenOutcome, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, err := openPipe(pipe, access)
		if err != nil {
			oe := win32Error("CreateFileW", pipeRoot+pipe, err)
			out := scanner.OpenOutcome{Result: model.ResultError, Status: oe.Status, NTStatus: oe.NTStatus, Err: oe.Message}
			if oe.Status != nil {
				out.Result = model.ClassifyWin32(oe.Status.Code)
			}
			return out, nil
		}
		out := scanner.OpenOutcome{Result: model.ResultAllowed, Status: model.Win32(0)}
		closed := true
		if cerr := windows.CloseHandle(h); cerr != nil {
			closed = false
			out.CloseErr = fmt.Sprintf("CloseHandle %s%s: %v", pipeRoot, pipe, cerr)
		}
		out.Closed = &closed
		return out, nil
	})
	if err != nil {
		return scanner.OpenOutcome{Result: model.ResultError, Err: fmt.Sprintf("open %s%s: %v", pipeRoot, pipe, err)}
	}
	return o
}

// win32Error must run on the thread that made the failing call: it reads
// the NTSTATUS the kernel left in the TEB alongside the Win32 code.
func win32Error(op, target string, err error) *model.OpError {
	oe := &model.OpError{Op: op, Target: target, Message: fmt.Sprintf("%s %s: %v", op, target, err)}
	var errno windows.Errno
	if errors.As(err, &errno) {
		oe.Status = model.Win32(uint32(errno))
		if procRtlGetLastNtStatus.Find() == nil {
			r, _, _ := procRtlGetLastNtStatus.Call()
			if r != 0 {
				oe.NTStatus = model.NTStatus(uint32(r))
			}
		}
	}
	return oe
}
