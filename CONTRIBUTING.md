# Contributing

## Build and test

```bash
make build   # builds the three binaries into bin/ with the version stamped in
make test    # go test ./...
make race    # go test -race ./...
```

## Linting and formatting

The toolchain:

- `gofmt` and `goimports` for formatting (`make fmt`).
- `go vet` for the standard checks.
- `staticcheck` and `golangci-lint` for static analysis (`make lint`).

Install the extra tools once:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/tools/cmd/goimports@latest
# golangci-lint: https://golangci-lint.run/welcome/install/
```

CI runs build, vet, gofmt, `go test -race`, and golangci-lint on every push and
pull request. Keep all of them green.

## Before opening a pull request

- `make fmt && make lint && make race` pass.
- New behavior has a test. The security-sensitive paths (identity binding,
  revoke teardown, the pairing handoff) are covered in
  `internal/coordinator/integration_test.go`; add to it when you touch them.
- Commits read as plain, human-written changes.

## Scope

Tessera is a consented, approval-gated access broker. Security-relevant changes
(authorization, the approval flow, certificate handling, audit) get extra
scrutiny. If a change weakens a control, say so in the PR and explain the
trade-off.
