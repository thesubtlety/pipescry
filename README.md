# pipescry

pipescry records Windows named-pipe security descriptors and handle-open results, remotely over SMB2/3 or locally through Win32 APIs.

## Supported platforms

| Build | Remote (SMB) | Local (NPFS) |
|---|---|---|
| linux/amd64 | yes | no |
| linux/arm64 | yes | no |
| windows/amd64 | yes | yes |
| windows/arm64 | yes | yes |

Binaries are static (`CGO_ENABLED=0`). No SMB client, Python, .NET, or agent is needed on either end.

## Build

Requires Go 1.24 or newer (`go.mod` selects the toolchain).

```
./scripts/build.sh          # dist/pipescry-{linux,windows}-{amd64,arm64}[.exe]
go build -o pipescry ./cmd/pipescry
go test ./...
```

## Usage

Remote scan with enumeration, JSON written to a file, text to stdout:

```
export PIPESCRY_PASS='...'
pipescry scan --target 192.0.2.10 --username CORP\\auditor --password-env PIPESCRY_PASS --json report.json
```

Remote scan of a supplied name list with open tests, showing only opens that succeeded:

```
pipescry scan --target 192.0.2.10 --username auditor --password-env PIPESCRY_PASS \
  --names-file pipes.txt --access-test --result allowed
```

Remote scan through a SOCKS pivot, with the target name resolved by the proxy:

```
pipescry scan --target dc01.corp.local --proxy socks5h://127.0.0.1:1080 --username CORP\\auditor --password-env PIPESCRY_PASS
```

Local scan on Windows, showing Everyone ACEs whose mask contains `FILE_WRITE_DATA` (allow or deny), plus NULL-DACL pipes:

```
pipescry.exe scan --local --access-test --json local.json --principal S-1-1-0 --permission FILE_WRITE_DATA
```

## Flags

`pipescry scan (--target HOST | --local) [flags]`

| Flag | Default | Behavior |
|---|---|---|
| `--target HOST` | | Scan `\\HOST\IPC$` over SMB2/3. |
| `--port N` | 445 | SMB TCP port. |
| `--proxy URL` | | SOCKS proxy: `socks4://[userid@]host[:port]`, `socks4a://`, `socks5://[user:pass@]host[:port]`, `socks5h://`. Port defaults to 1080. `socks4a` and `socks5h` send `--target` to the proxy unresolved; `socks4` and `socks5` resolve it locally first. Proxy credentials in the URL are visible in process listings. |
| `--local` | | Scan the local NPFS. Windows only; other platforms exit with "local mode unsupported". |
| `--username U` | | Account. `DOMAIN\user` and `user@domain` set the domain. |
| `--domain D` | | Account domain. Empty or `.` authenticates as a local account on the target. |
| `--password P` | | Password. Visible in process listings and shell history; prefer `--password-env`. |
| `--password-env VAR` | | Read the password from an environment variable. |
| `--password-stdin` | | Read the password from the first line of stdin. |
| `--hash-env VAR` | | Read a 32-hex-character NT hash from an environment variable. |
| `--anonymous` | | Anonymous NTLM session. |
| `--names a,b` | | Pipe names to scan in addition to enumeration. Repeatable. |
| `--names-file PATH` | | One name per line; `#` starts a comment. `\\.\pipe\x` and `\\host\pipe\x` forms are accepted. |
| `--no-enumerate` | off | Skip the directory listing; requires `--names` or `--names-file`. |
| `--access-test` | off | Open and close each pipe three times, requesting exactly `READ_CONTROL`, `FILE_READ_DATA`, and `FILE_WRITE_DATA`. |
| `--timeout D` | 10s | Per-operation timeout. Enumeration uses 6x; connection setup 3x. |
| `--concurrency N` | 4 | Pipes processed in parallel, 1–64. Remote mode shares one SMB session. |
| `--json PATH`, `--output PATH` | | Write the complete evidence document. |
| `--format text\|json` | text | Stdout format. `json` writes the complete document and nothing else. |
| `--summary` | off | Text: print only the summary block. |
| `--quiet` | off | No progress or diagnostics on stderr, including the `--verbose` debug log. Fatal errors still print. |
| `--no-color` | off | No ANSI color. Color is also off when stdout is not a terminal or `NO_COLOR` is set. |
| `--verbose` | off | Text: raw descriptor hex, control flags, ACE flags. Stderr: per-pipe progress and go-smb debug log. |
| `--principal X` | | Display ACEs whose trustee, or tests whose identity, matches a SID, full name, or account name. Repeatable (OR). |
| `--permission R` | | Display ACEs whose generic-mapped mask contains R, or tests whose request contains R. Accepts right names, `FULL_CONTROL`, `FILE_GENERIC_*`, `FILE_APPEND_DATA` (= bit 0x4), or a number. Repeatable (OR). Inherit-only ACEs never match. Pipes with a NULL or absent DACL match every `--principal` and `--permission`. |
| `--evidence all\|dacl\|open` | all | Display DACL evidence, open-test evidence, or both. |
| `--result R` | | Display open tests with result R. Repeatable (OR). Implies open evidence only; rejected with `--evidence dacl`. |

Different filter flags combine with AND. Filters change only the text display; JSON output and summary counts always cover everything collected.

Passwords are never written to output or logs. Exit status: 0 scan completed (individual pipe failures are recorded in the output), 1 connection or output failure, 2 usage error.

`pipescry compare A.json B.json` prints per-pipe differences in descriptor bytes, ACEs, and open-test results, plus pipes only one report contains. It exits 0 when no shared pipe differs, 1 when one does, and 2 on error.

## Output schema

Top level (`schema_version` `1.0`):

| Field | Content |
|---|---|
| `tool`, `mode`, `target`, `started_at`, `finished_at` | Run metadata. Times are UTC RFC 3339. |
| `identity` | `name` (the requested account), `sid` (local only), `auth_method` (`ntlm`, `anonymous`, `process_token`), `anonymous`, `guest` (server mapped the session to Guest), `elevated` (local only). |
| `transport` | Remote: dialect, `signing_required`, `cipher_negotiated`, share, `proxy` (`scheme://host:port`, no credentials). Local: `{"protocol":"npfs"}`. |
| `options` | Settings that affect what was collected. |
| `collection` | `enumeration` (`complete`, `partial`, `failed`, `unsupported`, `skipped`), `enumeration_error`, pipe counts, `descriptors_by_state`, `tests_by_result`, `errors`, `warnings`. |
| `pipes[]` | Sorted case-insensitively by name. |

Each pipe:

| Field | Content |
|---|---|
| `name`, `sources` | `enumeration` and/or `names_list`. |
| `current_instances`, `max_instances` | From the directory entry; `null` when not reported. |
| `security.state` | `collected`, `unavailable` (server does not support the query), `failed`, or `unparsed`. |
| `security.raw_hex` | Descriptor bytes as returned, when any were returned. |
| `security.descriptor` | Owner, group, control flags, and `dacl.state` (`present`, `empty`, `null`, `not_present`) with `aces[]`. |
| `aces[]` | `type`/`type_name`, `flags`/`flag_names`, `inherit_only`, `mask`/`mask_hex`/`rights`, `mapped_mask` (after generic mapping), `trustee` (`sid`, `name`, `name_source`). |
| `security.handle_closed`, `security.close_error` | Whether the `READ_CONTROL` handle used for the query was closed. |
| `access_tests[]` | Always three entries. `identity` is `Guest` when the server mapped the session to Guest. `requested_access`, `identity`, `result` (`allowed`, `denied`, `busy`, `error`, `unsupported`, `not_tested`), `status` (`kind` `ntstatus` or `win32`, `code`, `hex`, `name`), local `ntstatus`, `handle_closed`, `error`. |
| `indicators[]` | DACL facts: `null_dacl`, `dacl_not_present`, `empty_dacl`, `broad_principal_grant`, `full_control_grant`, `write_dac_grant`, `write_owner_grant`, `create_pipe_instance_grant`, each with the ACE index, mask, and evidence text. |

Numeric fields keep the raw value; `*_hex` and name fields are derived from it.

## Known limitations

- Reading a descriptor requires opening the pipe, as does every access test. Each open connects to a listening server instance; the server process sees a client connect and disconnect. pipescry never reads or writes pipe data.
- A pipe whose instances are all connected returns busy. pipescry does not wait for an instance, so a busy pipe has no descriptor.
- Enumeration lists pipes that have a server instance at query time. Samba and some hardened hosts refuse the IPC$ listing; supply names with `--names-file`.
- Samba returns `STATUS_NOT_SUPPORTED` for pipe security queries; those are recorded as `unavailable`.
- Remote SIDs are named from a built-in well-known table only. No LSA lookup is performed. Local mode uses `LookupAccountSid`.
- Indicators and open results do not establish effective access for other principals or exploitability. Indicators ignore deny ACE ordering, privileges, integrity labels, and checks the server process performs after connecting.
- Open tests reflect only the scanning identity.
- SACLs and mandatory labels are not requested.
- Only NTLM authentication is wired. Kerberos is not exposed.
- DNS: the only lookup is for `--target` (and a proxy given by name), made by the local resolver unless `socks4a` or `socks5h` is used. NTLM itself does no DNS.
- Not yet validated on real Windows. Under Wine, local descriptor collection works, but Wine lacks NPFS listing and pipe access checks. See `docs/testing.md` for the lab runbook.

Implementation notes are in [`docs/`](docs/).
