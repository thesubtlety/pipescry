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

## Local integration (Windows)

```
go test -tags integration ./internal/local
```

Creates four test pipes with known SDDL (normal, `NO_ACCESS_CONTROL`, empty, read-only for Everyone), scans them, and checks enumeration, the parsed Everyone ACE mask, DACL states, and per-right open results.

## Lab comparison

Not yet done. To compare modes, run both against the same host with the same account and diff the `pipes[].security.raw_hex` and `access_tests[].result` fields:

```
pipescry.exe scan --local --access-test --format json > local.json
pipescry scan --target HOST --username ACCOUNT --password-env P --access-test --format json > remote.json
```

Descriptor bytes should match. Open results may differ for the reasons in `implementation.md`.
