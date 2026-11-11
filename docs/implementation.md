# Implementation notes

## Layout

| Package | Role |
|---|---|
| `cmd/pipescry` | Flags, credential sources, output selection. |
| `internal/scanner` | Name merging, worker pool, timeouts, report assembly. Defines `Collector`. |
| `internal/remote` | SMB2/3 collector built on `github.com/jfjallid/go-smb`. |
| `internal/local` | Windows collector (`//go:build windows`); stub elsewhere. |
| `internal/security` | Self-relative descriptor parser, NPFS access-mask decoding, indicators. |
| `internal/report` | JSON and text output; display filters. |
| `internal/model` | Output schema and status-code tables. |

`scanner.Interactor` is reserved for future protocol-specific interaction. Nothing implements or calls it.

## Access masks on pipes

NPFS uses the file-object generic mapping:

| Generic | Maps to |
|---|---|
| `GENERIC_READ` | `0x00120089` |
| `GENERIC_WRITE` | `0x00120116` |
| `GENERIC_EXECUTE` | `0x001200A0` |
| `GENERIC_ALL` | `0x001F01FF` |

Bit `0x4` is `FILE_APPEND_DATA` on files and `FILE_CREATE_PIPE_INSTANCE` on pipes. It controls whether a caller may create another server instance of an existing pipe name. It is not a message-write right. pipescry decodes it only as `FILE_CREATE_PIPE_INSTANCE`. `GENERIC_WRITE` includes it, so an ACE granting `GENERIC_WRITE` also grants instance creation.

`full_control_grant`, `write_dac_grant`, `write_owner_grant`, and `create_pipe_instance_grant` are not emitted for `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, which hold them on nearly every pipe. Their ACEs remain in the evidence. `broad_principal_grant` covers Everyone, Anonymous Logon, Authenticated Users, BUILTIN\Users, and BUILTIN\Guests.

## DACL states

| State | Descriptor | Access check |
|---|---|---|
| `present` | `SE_DACL_PRESENT`, ACL with ACEs | ACEs evaluated in order |
| `empty` | `SE_DACL_PRESENT`, ACL with zero ACEs | Nothing granted; the owner keeps implicit `READ_CONTROL` and `WRITE_DAC` |
| `null` | `SE_DACL_PRESENT`, DACL offset 0 | Everything granted |
| `not_present` | `SE_DACL_PRESENT` clear | Treated as NULL DACL |

## Remote collection

- Session: NTLM via SPNEGO, SMB 2.0.2–3.1.1 negotiated by go-smb. go-smb's loggers write to stdout by default; pipescry routes them to stderr (`--verbose`) or discards them.
- Enumeration: `CREATE` of the IPC$ root, then `QUERY_DIRECTORY` (`FileBothDirectoryInformation`). For pipes, `EndOfFile` is the current instance count. go-smb does not expose `AllocationSize` (maximum instances), so `max_instances` is `null` remotely.
- Descriptor: `CREATE` with `DesiredAccess = READ_CONTROL` exactly, then `QUERY_INFO` with `InfoType = SMB2_0_INFO_SECURITY` and `OWNER|GROUP|DACL`. go-smb's `QueryInfoSecurityRaw` returns only a parsed structure, so pipescry builds the request with `NewQueryInfoReq`, sends it with `SendRawPDU` (which applies message IDs, signing, and encryption), and keeps the returned bytes. `STATUS_BUFFER_TOO_SMALL`/`STATUS_BUFFER_OVERFLOW` triggers one retry at 64 KiB.
- Open tests: `CREATE` with the exact mask, `FILE_OPEN` disposition, share read/write, `ImpersonationLevel = Identification`, then `CLOSE`. Identification lets the pipe server identify the scanning account but not act as it.
- Timeouts: go-smb calls take no context. Each open-and-close runs in one goroutine; if the deadline passes, the result is recorded as `error` and the goroutine still closes any handle the late reply creates.
- Result mapping: `STATUS_SUCCESS` → allowed; `STATUS_ACCESS_DENIED` → denied; `STATUS_PIPE_BUSY`, `STATUS_PIPE_NOT_AVAILABLE`, `STATUS_INSTANCE_NOT_AVAILABLE` → busy; `STATUS_NOT_SUPPORTED`, `STATUS_INVALID_DEVICE_REQUEST`, `STATUS_NOT_IMPLEMENTED` → unsupported; everything else, including transport errors and timeouts, → error. Only an explicit access-denied status yields `denied`.
- Signing and cipher: `signing_required` and `cipher_negotiated` are what go-smb exposes. A negotiated cipher does not prove the session is encrypted; anonymous and guest sessions have no key.

## Local collection

- Enumeration: `CreateFileW("\\.\pipe\", FILE_LIST_DIRECTORY|SYNCHRONIZE)`, then `NtQueryDirectoryFile` with `FileDirectoryInformation` until `STATUS_NO_MORE_FILES`. NPFS reports current instances in `EndOfFile` and maximum instances in `AllocationSize` (`0xFFFFFFFF` = unlimited). `NtQueryDirectoryFile` is not in `x/sys/windows`; it is loaded from ntdll.
- Descriptor: `CreateFileW` with `READ_CONTROL`, `OPEN_EXISTING`, `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`, then `GetSecurityInfo(SE_KERNEL_OBJECT, OWNER|GROUP|DACL)`. `x/sys/windows` copies the self-relative descriptor into Go memory.
- Errors: the Win32 code from `GetLastError` and the NTSTATUS from `RtlGetLastNtStatus` are both recorded. The calling goroutine is locked to its OS thread so both values come from the same thread.
- Identity: the process token user, with `elevated` from `TokenElevation`. pipescry enables no privileges and does not impersonate.
- Result mapping: `ERROR_SUCCESS` → allowed; `ERROR_ACCESS_DENIED` → denied; `ERROR_PIPE_BUSY` → busy; `ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED` → unsupported; anything else → error.

## Local versus remote differences to expect

- Remote opens are checked against the network logon token, which includes `NETWORK` (S-1-5-2) and lacks `INTERACTIVE`. Local opens use the interactive token. The same account can get different results.
- Remote access to a pipe can also be restricted by `NullSessionPipes` and `RestrictNullSessAccess` for anonymous sessions, and by the server service before NPFS is reached.
- Remote SIDs are named from the built-in table; local SIDs use `LookupAccountSid` with `name_source: lookup`.
