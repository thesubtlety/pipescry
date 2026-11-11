package model

import "fmt"

var ntStatusNames = map[uint32]string{
	0x00000000: "STATUS_SUCCESS",
	0x00000103: "STATUS_PENDING",
	0x80000005: "STATUS_BUFFER_OVERFLOW",
	0x80000006: "STATUS_NO_MORE_FILES",
	0xC0000001: "STATUS_UNSUCCESSFUL",
	0xC0000002: "STATUS_NOT_IMPLEMENTED",
	0xC0000003: "STATUS_INVALID_INFO_CLASS",
	0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
	0xC0000008: "STATUS_INVALID_HANDLE",
	0xC000000D: "STATUS_INVALID_PARAMETER",
	0xC000000F: "STATUS_NO_SUCH_FILE",
	0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
	0xC0000022: "STATUS_ACCESS_DENIED",
	0xC0000023: "STATUS_BUFFER_TOO_SMALL",
	0xC0000033: "STATUS_OBJECT_NAME_INVALID",
	0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
	0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
	0xC0000043: "STATUS_SHARING_VIOLATION",
	0xC00000AB: "STATUS_INSTANCE_NOT_AVAILABLE",
	0xC00000AC: "STATUS_PIPE_NOT_AVAILABLE",
	0xC00000AD: "STATUS_INVALID_PIPE_STATE",
	0xC00000AE: "STATUS_PIPE_BUSY",
	0xC00000B0: "STATUS_PIPE_DISCONNECTED",
	0xC00000B1: "STATUS_PIPE_CLOSING",
	0xC00000B5: "STATUS_IO_TIMEOUT",
	0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
	0xC00000BB: "STATUS_NOT_SUPPORTED",
	0xC00000CC: "STATUS_BAD_NETWORK_NAME",
	0xC000014B: "STATUS_PIPE_BROKEN",
	0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
	0xC000006D: "STATUS_LOGON_FAILURE",
	0xC0000072: "STATUS_ACCOUNT_DISABLED",
	0xC0000201: "STATUS_NETWORK_OPEN_RESTRICTION",
	0xC000035C: "STATUS_NETWORK_SESSION_EXPIRED",
	0xC0000203: "STATUS_USER_SESSION_DELETED",
}

var win32Names = map[uint32]string{
	0:    "ERROR_SUCCESS",
	1:    "ERROR_INVALID_FUNCTION",
	2:    "ERROR_FILE_NOT_FOUND",
	3:    "ERROR_PATH_NOT_FOUND",
	5:    "ERROR_ACCESS_DENIED",
	6:    "ERROR_INVALID_HANDLE",
	32:   "ERROR_SHARING_VIOLATION",
	50:   "ERROR_NOT_SUPPORTED",
	87:   "ERROR_INVALID_PARAMETER",
	122:  "ERROR_INSUFFICIENT_BUFFER",
	123:  "ERROR_INVALID_NAME",
	231:  "ERROR_PIPE_BUSY",
	232:  "ERROR_NO_DATA",
	233:  "ERROR_PIPE_NOT_CONNECTED",
	1307: "ERROR_INVALID_OWNER",
	1314: "ERROR_PRIVILEGE_NOT_HELD",
}

func NTStatus(code uint32) *Status {
	return &Status{Kind: "ntstatus", Code: code, Hex: fmt.Sprintf("0x%08X", code), Name: ntStatusNames[code]}
}

func Win32(code uint32) *Status {
	return &Status{Kind: "win32", Code: code, Hex: fmt.Sprintf("0x%08X", code), Name: win32Names[code]}
}

func (s *Status) String() string {
	if s == nil {
		return ""
	}
	if s.Name != "" {
		return fmt.Sprintf("%s (%s)", s.Name, s.Hex)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Hex)
}

// ClassifyNTStatus maps an open result to a test outcome. Only an explicit
// STATUS_ACCESS_DENIED counts as denied; everything unrecognized is error.
func ClassifyNTStatus(code uint32) Result {
	switch code {
	case 0x00000000:
		return ResultAllowed
	case 0xC0000022:
		return ResultDenied
	case 0xC00000AB, 0xC00000AC, 0xC00000AE:
		return ResultBusy
	case 0xC0000002, 0xC0000010, 0xC00000BB:
		return ResultUnsupported
	}
	return ResultError
}

// ClassifyWin32 needs nt because RtlNtStatusToDosError maps several
// non-access statuses (STATUS_DELETE_PENDING, STATUS_FILE_IS_A_DIRECTORY,
// ...) to ERROR_ACCESS_DENIED. Code 5 is denied only when no NTSTATUS was
// captured or the NTSTATUS is STATUS_ACCESS_DENIED.
func ClassifyWin32(code uint32, nt *Status) Result {
	switch code {
	case 0:
		return ResultAllowed
	case 5:
		if nt != nil && nt.Code != 0xC0000022 {
			return ResultError
		}
		return ResultDenied
	case 231:
		return ResultBusy
	case 1, 50:
		return ResultUnsupported
	}
	return ResultError
}

func Hex32(v uint32) string { return fmt.Sprintf("0x%08X", v) }
