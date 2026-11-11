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
	"strings"
	"sync"
	"time"
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

	haveRtlGetLastNtStatus = procRtlGetLastNtStatus.Find() == nil
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
	id.Guest = strings.HasPrefix(id.SID, "S-1-5-21-") && strings.HasSuffix(id.SID, "-501")
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
		// LookupAccountSid can block on an unreachable domain controller.
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		name, _ := scanner.Call(ctx, func() (string, error) { return lookupSID(s), nil })
		cancel()
		c.names.Store(s, name)
		return name, name != ""
	}
}

const lookupTimeout = 3 * time.Second

func lookupSID(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return ""
	}
	acct, dom, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if dom == "" {
		return acct
	}
	return dom + `\` + acct
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
	case r.oe.Status != nil && r.oe.Status.Kind == "ntstatus" && model.ClassifyNTStatus(r.oe.Status.Code) == model.ResultUnsupported:
		return r.entries, model.EnumUnsupported, r.oe
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
		return nil, win32Error("CreateFileW", pipeRoot, err, lastNTStatus())
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
// but not impersonate this process. OPEN_EXISTING never creates a pipe
// instance. The caller must hold its OS thread so nt belongs to this call.
func openPipe(name string, access uint32) (h windows.Handle, err error, nt *model.Status) {
	h, err = windows.CreateFile(pipePath(name), access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		nt = lastNTStatus()
	}
	return
}

func (c *Collector) QuerySecurity(ctx context.Context, pipe string) scanner.SDOutcome {
	o, err := scanner.Call(ctx, func() (scanner.SDOutcome, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, err, nt := openPipe(pipe, scanner.SecurityQueryAccess)
		if err != nil {
			return scanner.SDOutcome{Err: win32Error("CreateFileW(READ_CONTROL)", pipeRoot+pipe, err, nt)}, nil
		}
		// GetSecurityInfo returns its error without SetLastError, so the TEB
		// NTSTATUS is not recorded for it.
		sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		var out scanner.SDOutcome
		if err != nil {
			out.Err = win32Error("GetSecurityInfo", pipeRoot+pipe, err, nil)
		} else {
			b := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
			out.Raw = append([]byte(nil), b...)
		}
		out.Closed, out.CloseErr = closeHandle(h, pipe)
		return out, nil
	})
	if err != nil {
		return scanner.SDOutcome{Err: &model.OpError{Op: "query_security", Target: pipeRoot + pipe, Message: fmt.Sprintf("query security %s%s: %v", pipeRoot, pipe, err)}}
	}
	return o
}

func closeHandle(h windows.Handle, pipe string) (*bool, string) {
	closed := true
	if err := windows.CloseHandle(h); err != nil {
		closed = false
		return &closed, fmt.Sprintf("CloseHandle %s%s: %v", pipeRoot, pipe, err)
	}
	return &closed, ""
}

func (c *Collector) OpenTest(ctx context.Context, pipe string, access uint32) scanner.OpenOutcome {
	o, err := scanner.Call(ctx, func() (scanner.OpenOutcome, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h, err, nt := openPipe(pipe, access)
		if err != nil {
			oe := win32Error("CreateFileW", pipeRoot+pipe, err, nt)
			out := scanner.OpenOutcome{Result: model.ResultError, Status: oe.Status, NTStatus: oe.NTStatus, Err: oe.Message}
			if oe.Status != nil {
				out.Result = model.ClassifyWin32(oe.Status.Code, oe.NTStatus)
			}
			return out, nil
		}
		out := scanner.OpenOutcome{Result: model.ResultAllowed, Status: model.Win32(0)}
		out.Closed, out.CloseErr = closeHandle(h, pipe)
		return out, nil
	})
	if err != nil {
		return scanner.OpenOutcome{Result: model.ResultError, Err: fmt.Sprintf("open %s%s: %v", pipeRoot, pipe, err)}
	}
	return o
}

// lastNTStatus reads the NTSTATUS the kernel left in the TEB. It must run
// immediately after the failing call, on the same thread, before anything
// (including error formatting) can overwrite it.
func lastNTStatus() *model.Status {
	if !haveRtlGetLastNtStatus {
		return nil
	}
	r, _, _ := procRtlGetLastNtStatus.Call()
	if r == 0 {
		return nil
	}
	return model.NTStatus(uint32(r))
}

func win32Error(op, target string, err error, nt *model.Status) *model.OpError {
	oe := &model.OpError{Op: op, Target: target, Message: fmt.Sprintf("%s %s: %v", op, target, err), NTStatus: nt}
	var errno windows.Errno
	if errors.As(err, &errno) {
		oe.Status = model.Win32(uint32(errno))
	}
	return oe
}
