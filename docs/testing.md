# Testing

## Unit tests

```
go test ./...
```

Run on any platform. They cover descriptor parsing from synthetic fixtures (`internal/testfixture`), NULL/empty/absent DACL handling, generic mapping, indicators, the QUERY_INFO response parser, the NPFS directory-entry parser, scan orchestration with a fake collector, display filters, JSON determinism, and credential handling.

## Remote integration

```
PIPESCRY_IT_TARGET=host PIPESCRY_IT_USER=user PIPESCRY_IT_PASS=... \
  [PIPESCRY_IT_DOMAIN=CORP] [PIPESCRY_IT_PORT=445] [PIPESCRY_IT_WINDOWS=1] \
  go test -tags integration ./internal/remote
```

Checks that a missing pipe yields `STATUS_OBJECT_NAME_NOT_FOUND` as `error` rather than `denied`, that `srvsvc` opens are closed, and, with `PIPESCRY_IT_WINDOWS=1`, that enumeration is complete and `srvsvc` returns a descriptor.

A Samba container exercises authentication, encryption, IPC$, and the error paths:

```
docker run -d --rm --name pipescry-samba -p 127.0.0.1:4445:445 dperson/samba -u "auditor;Passw0rd1"
PIPESCRY_IT_TARGET=127.0.0.1 PIPESCRY_IT_PORT=4445 PIPESCRY_IT_USER=auditor PIPESCRY_IT_PASS=Passw0rd1 \
  go test -tags integration ./internal/remote
```

Samba refuses the IPC$ listing and pipe security queries, so it cannot validate descriptor collection.

## Windows lab runbook

Build on any host, then copy `dist/` to the Windows machine. No Go toolchain is needed there.

```
./scripts/build.sh          # pipescry binaries
./scripts/build-tests.sh    # dist/tests/pipescry-{local,remote}-it-windows-{amd64,arm64}.exe
```

On the Windows host (match the binary to the CPU):

1. Local integration test. Creates four test pipes with known SDDL (normal, `NO_ACCESS_CONTROL`, empty, read-only for Everyone) and checks enumeration, the Everyone ACE mask, DACL states, and per-right open results:
   ```
   .\pipescry-local-it-windows-amd64.exe -test.v
   ```
2. Remote integration test against the host itself or another Windows target:
   ```
   $env:PIPESCRY_IT_TARGET="127.0.0.1"; $env:PIPESCRY_IT_USER="user"; $env:PIPESCRY_IT_PASS="..."; $env:PIPESCRY_IT_WINDOWS="1"
   .\pipescry-remote-it-windows-amd64.exe -test.v
   ```
3. Run both modes with the same account and compare:
   ```
   .\pipescry-windows-amd64.exe scan --local --access-test --json local.json
   .\pipescry-windows-amd64.exe scan --target 127.0.0.1 --username user --password-env P --access-test --json remote.json
   .\pipescry-windows-amd64.exe compare local.json remote.json
   ```
   Descriptor bytes should match. Open results may differ, because the network logon token differs from the interactive one (see `implementation.md`). Run the local scan both elevated and not.

Things only a real Windows host can confirm:

- NTSTATUS capture after `CreateFileW` (`ntstatus` is set on failed local opens).
- `denied` for local opens rejected by the DACL.
- NPFS enumeration and `max_instances`.
- IPC$ enumeration and `QUERY_INFO` security over SMB.

## Wine results (2026-11-11)

Under Wine 9 on Linux, `pipescry-local-it-windows-amd64.exe` with `PIPESCRY_IT_NO_ENUM=1`:

- Passed: pipe creation and open, `GetSecurityInfo`, descriptor parsing (Everyone `0x0012019B`), handle close, the empty DACL.
- Wine-only failures:
  - NPFS directory listing returns `STATUS_BAD_DEVICE_TYPE`.
  - `D:NO_ACCESS_CONTROL` is stored as an empty DACL instead of a NULL one.
  - Pipe access checks are not enforced, so every open is allowed.

The Windows build's remote mode, run under Wine against Samba, produced the same results as the Linux build.
