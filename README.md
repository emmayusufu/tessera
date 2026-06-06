# Tessera

> Status: pre-1.0, no independent security review. Do not use it to guard
> production or sensitive systems without one. See [SECURITY.md](SECURITY.md).

Tessera is a consent-gated remote access broker for "give Alice access to my
local postgres, just for this debug session, with a paper trail, end it when
we're done."

`tessera share -port 5432` mints an 8-character code. Alice runs `tessera join
CODE`, you see a prompt at your terminal showing who is asking and why, type
`y`, and her local `127.0.0.1:13000` now forwards to your `5432` for as long as
either side holds the session. Every request, approval, and session close lands
in an append-only audit log.

Not a VPN, not a stable public URL, not a persistent account. The whole point
is that nothing lives between sessions: no token your teammate keeps, no port
left open, no record other than the audit line you wrote.

**Live coordinator:** [`tessera.jengahq.com`](https://tessera.jengahq.com/healthz)
(returns the current version; the actual data path is mTLS on `:8443`).

The name is the Roman *tessera hospitalis*, a token given to a guest as proof of
a trusted, welcomed relationship.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/emmayusufu/tessera/main/install.sh | bash
```

On first run, you'll be prompted to link to a coordinator (skip with `TESSERA_SKIP_LINK=1`).

Pulls the latest release binary for your OS and architecture. Falls back to `go install` if no release is published for your platform. Override the install location with `TESSERA_BINDIR`.

If you'd rather build manually:

```bash
git clone https://github.com/emmayusufu/tessera && cd tessera && make build
# binaries land in ./bin/{coordinator,agent,tessera}
```

## When you might use it

- **Pair programming across networks.** You want a teammate to hit your local
  dev server on `localhost:3000`. They run `tessera join`, you type `y` in your
  terminal, they reach it; Ctrl-C ends it.
- **Support sessions.** A customer can't reproduce a bug. They run `tessera
  share`, send you the code, you join, they watch and approve at their
  terminal. When the call's over, the share dies.
- **Database debugging.** A contractor needs to look at your staging postgres
  for fifteen minutes; you share the port, they connect, you see every request
  flow through the audit log.
- **One-off shell access.** Same shape with `tessera share -shell` for a PTY
  attached to your machine. Read the [SECURITY.md](SECURITY.md) section on what
  `-shell` actually exposes before you use it.

## How it works

Three small Go binaries. The agent dials *out* to the coordinator, so the
host's resource never accepts an inbound connection and nothing is exposed
until the host approves a specific request.

```mermaid
flowchart LR
    CLI["tessera (guest CLI)"]
    CO["coordinator<br/>(broker)"]
    AG["agent"]
    RES[("host resource<br/>db / web / rdp")]
    H(("host terminal"))

    CLI -- "mTLS" --> CO
    AG -- "mTLS, dials out" --> CO
    AG --> RES
    H -- "types y/n at the prompt" --> CO
```

- **coordinator**: runs on a public host. Accepts mutual-TLS connections from
  agents and guests, relays approved streams (as opaque ciphertext, since
  inner TLS terminates at the endpoints), and writes the audit log. Opens
  no access on its own.
- **agent**: runs on the host's side as a background service. Dials out
  to the coordinator and waits. Accepts nothing inbound. On an approved stream
  it connects to the approved local `host:port` and pipes.
- **tessera**: the guest CLI. Requests access, waits for approval, then
  forwards a local port through the coordinator to the resource.

## The flow

```mermaid
sequenceDiagram
    participant G as Guest
    participant K as Coordinator
    participant H as Host
    participant A as Agent
    participant R as Resource

    A->>K: register (dials out)
    G->>K: request access (target, reason)
    K-->>H: prompt over mTLS (tessera share)
    H->>K: y / n at the terminal
    K-->>G: approved + session
    G->>K: open stream (session)
    K->>A: open data (target)
    A->>R: dial target
    Note over G,A: inner TLS end to end. Coordinator sees only ciphertext.
    G->>R: tunneled traffic
```

## Access lifetime

Not permanent. A session lives only while it is held: either party ends it
instantly, it dies on disconnect, an idle stream times out after 30 minutes, and
every request, approval, session open and close is written to an append-only
audit log.

## Try it locally

```bash
make build
cd bin

# 1. generate a CA and certs (coordinator name = localhost for local testing)
./tessera ca --coordinator-name localhost

# 2. start the broker (mTLS on :8443, redeem/peek HTTP on :8080)
./coordinator -listen :8443 -http :8080 &

# 3. run an agent for share-id "demo", allowed to reach a local service
./agent -coordinator localhost:8443 -share-id demo -allow 127.0.0.1:5432 &

# 4. request access. The host approves at their terminal (tessera share prints
#    the prompt; type y to approve). For this single-binary demo, you can
#    simulate approval by running tessera share on the same machine.
./tessera connect -coordinator localhost:8443 -share-id demo \
  -target 127.0.0.1:5432 -reason "troubleshoot" -local 127.0.0.1:15432

# now 127.0.0.1:15432 forwards to the host's 127.0.0.1:5432 until you Ctrl-C
```

## Deploying

The coordinator needs to run on a host with a public address. Two ways: Docker
or a bare binary. Pick whichever feels lighter to maintain. The flags and env
vars are the same in both.

For step-by-step instructions (systemd unit, compose, operator token, upgrade
path), see [`deploy/DEPLOYING.md`](deploy/DEPLOYING.md). The bits below are the
short version.

### Run with Docker

The image is a single 18 MB static binary on distroless. One image holds all
three binaries (coordinator, agent, tessera). Compose runs the coordinator by
default; the others are available via `--entrypoint` if you want to run them
in containers too.

```bash
# Build the image (one-time)
docker build -t tessera .

# Generate a CA and certs (one-time, no local Go toolchain needed)
mkdir -p certs && cd certs
docker run --rm -v "$PWD:/work" -w /work --entrypoint /usr/local/bin/tessera \
  tessera ca --coordinator-name tessera.example.org
cd ..

# Edit docker-compose.yml to add HTTPS / operator-token lines as needed.

docker compose up -d
docker compose logs -f coordinator
```

The compose file mounts `./certs/` read-only and keeps the audit log in a named
volume. For HTTPS on the redeem/peek endpoints (recommended in production so
the guest's private key stays confidential in transit), mount your Let's
Encrypt directory and add the `-http-cert` / `-http-key` flags to the command
list.

### Run the bare binary

```bash
./coordinator -http-cert fullchain.pem -http-key privkey.pem
```

The host approves at their terminal where `tessera share` is running: every
inbound request prints a prompt and waits for `y` or `n`. No web page, no
out-of-band link.

Require an operator token for operator actions (revoke). Generate one when you
deploy the coordinator, then save it once on the host:

```bash
tessera token <token-hex>
```

That writes it to `~/.config/tessera/operator-token`. After that, `tessera share`
auto-reads it, so you don't have to re-export it per shell. For ad-hoc curl:

```bash
curl -X POST -H "Authorization: Bearer $(cat ~/.config/tessera/operator-token)" \
  https://tessera.example.org/s/<sessionID>/revoke
```

When no token is configured on the coordinator, revoke is disabled.

### What's not covered

You still need a public host (a $5 VPS is fine), a DNS A record pointing at it,
open inbound ports 8443 and 8080 on its firewall, and a TLS cert for the HTTP
endpoints if you want HTTPS (recommended in production to keep the redeem
response, which carries a guest private key, confidential in transit). Docker
doesn't change any of that. It just makes "run the coordinator process" boring.

### Verifying a release

Releases are produced by GitHub Actions on tag push. Each tag publishes 12
binaries (tessera, agent, coordinator for linux/{amd64,arm64} and
darwin/{amd64,arm64}) plus a multi-arch container image to GHCR.

Confirm what landed:

```bash
# Binary assets and digests
gh release view v0.3.0 --json assets --jq '.assets[] | "\(.size) \(.name)"'

# Image was published and reports the expected version
docker run --rm --entrypoint /usr/local/bin/tessera \
  ghcr.io/emmayusufu/tessera:0.3.0 version
# v0.3.0

# Multi-arch manifest
docker buildx imagetools inspect ghcr.io/emmayusufu/tessera:0.3.0
```

If the version baked into the image doesn't match the tag, the release
pipeline didn't run cleanly: check the workflow at `.github/workflows/release.yml`
and the run logs in the GitHub Actions tab.

Live coordinators also expose `/healthz` on the HTTP port. Point any uptime
monitor at it:

```bash
curl https://your-coordinator/healthz
# ok v0.3.0
```

A change in the version string is the cheapest signal that a redeploy
actually went through.

## What's enforced

- A session is bound to the approved guest's certificate. A different
  enrolled guest cannot ride someone else's session, even with the ID.
- Revoke force-closes in-flight streams, it does not just block new ones.
- Traffic is end-to-end encrypted: guest and agent run an inner TLS session
  directly through the coordinator, which relays only ciphertext (a test asserts
  a plaintext marker never appears on the relay path).
- The agent only reaches targets on its `-allow` list, which is required.
- Approval happens at the host's terminal over the same mTLS channel that
  carries everything else. There is no web endpoint to phish or MITM. Operator
  actions (revoke) require an operator bearer token.

## How it compares

Tessera is tiny and single-purpose. Teleport's free Community Edition does far
more (SSH, Kubernetes, databases, RDP, web, SSO, session recording, RBAC) and is
production-grade and audited; if you can run it, use it. The one thing Tessera
gives you that Teleport gates behind its paid Enterprise tier is the request and
human-approve, just-in-time access flow. Tessera also runs with no cluster or
SSO to operate, and is MIT-licensed rather than AGPL. Verify Teleport's current
edition split before relying on that distinction.

## Status

v1: generic TCP forward to one approved `host:port` (covers a database, an
internal web portal, an RDP desktop) or interactive shell, request,
approve-at-terminal, mutual revoke, audit log.

Not yet built: replayable session recording, RBAC, persistence.

## Security note

Tessera only makes sense as a consent-based tool: the host always approves,
access is scoped to a session, and everything is audited. It is not a backdoor.
Serve the redeem/peek endpoints over HTTPS (`-http-cert`/`-http-key`) in
production so the guest's bundle (which contains a private key) is not
sniffable in transit. For real production use, get the design
security-reviewed first.

## Develop

```bash
make test    # go test ./...
make race    # go test -race ./...
make lint    # staticcheck + golangci-lint
make fmt     # gofmt + goimports
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the toolchain.

### Pre-commit hooks

```bash
brew install pre-commit          # or: pip install pre-commit
pre-commit install               # wires .git/hooks/pre-commit
```

After install, every `git commit` runs gofmt, go vet, go test, plus a few project-specific checks (no em-dashes in tracked files or commit messages, no AI/Claude attribution in commit messages, no work-email leakage).

To run all hooks manually without committing:

```bash
pre-commit run --all-files
```

## License

MIT
