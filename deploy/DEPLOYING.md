# Deploying the coordinator

The coordinator runs on a host with a public address. Two reasonable
ways to run it: as a native binary under systemd, or as the published
container under docker-compose. Both produce identical behavior; the
choice is operational preference.

This directory ships the files for both. Pick one; don't mix.

## Prereqs (both paths)

1. A public host with ports `8443` and `8080` open, plus `22` for SSH.
2. A CA + coordinator cert + coordinator key. Generate locally with
   `tessera ca -coordinator-name <your-name>` and copy the three files
   to `/etc/tessera/` on the host. Mode `0o644` for the certs, `0o600`
   for the key.
3. An operator token used for the revoke endpoint. Mint it with any
   source of randomness:
   ```
   head -c 32 /dev/urandom | xxd -p -c 32
   ```
   Treat it like any bearer credential.
4. A `tessera` system user that owns `/var/lib/tessera` (writable, mode
   `0o700`) and can read `/etc/tessera` (read-only).

## Path A: native binary + systemd (current production)

1. Download `coordinator-linux-amd64` (or `-arm64`) from the latest
   GitHub release. Install to `/usr/local/bin/coordinator`, mode `0o755`,
   owner `root:root`.
2. Copy `tessera-coordinator.service` to
   `/etc/systemd/system/tessera-coordinator.service`.
3. Add the operator token via a drop-in:
   ```
   sudo systemctl edit tessera-coordinator
   ```
   In the editor:
   ```
   [Service]
   Environment=TESSERA_OPERATOR_TOKEN=<your token>
   ```
   This writes to `/etc/systemd/system/tessera-coordinator.service.d/override.conf`,
   which is not in version control.
4. Enable and start:
   ```
   sudo systemctl daemon-reload
   sudo systemctl enable --now tessera-coordinator
   sudo systemctl status tessera-coordinator
   ```
5. Verify:
   ```
   curl http://<host>:8080/healthz
   # ok v0.3.0
   ```

To upgrade: download the new binary, `sudo mv` it into place (Linux
allows replacing a running executable), `sudo systemctl restart
tessera-coordinator`.

## Path B: container + docker-compose

1. Install Docker on the host. On Debian/Ubuntu:
   ```
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $(whoami)
   ```
2. Copy `docker-compose.yml` to a working directory on the host, e.g.
   `/srv/tessera/docker-compose.yml`.
3. Create `tessera.env` next to it:
   ```
   TESSERA_OPERATOR_TOKEN=<your token>
   ```
   Mode `0o600`. This file is gitignored; don't check it in.
4. Make sure `/etc/tessera/` and `/var/lib/tessera/` exist and are owned
   appropriately. The compose bind-mounts them.
5. Start:
   ```
   cd /srv/tessera
   docker compose up -d
   docker compose logs -f
   ```
6. Verify the same way:
   ```
   curl http://<host>:8080/healthz
   # ok v0.3.0
   ```

To upgrade: bump the `image:` tag in `docker-compose.yml`,
`docker compose pull && docker compose up -d`. Old image stays cached
locally for instant rollback (`docker compose down && edit tag && up`).

## Image visibility

The published image lives at `ghcr.io/emmayusufu/tessera`. If the
package is public, `docker pull` works with no auth. If it's private,
authenticate first:
```
echo "$GHCR_TOKEN" | docker login ghcr.io -u <username> --password-stdin
```
where `GHCR_TOKEN` is a personal access token with `read:packages`.

## HTTPS for the HTTP endpoints (recommended in production)

`/redeem`, `/peek`, and `/s/{id}/revoke` are on plain HTTP by default.
The redeem response contains a guest private key; the revoke
Authorization header contains the operator token. Both are sniffable
on plain HTTP.

For production: either pass `-http-cert` and `-http-key` directly to
the coordinator (mount your cert files into the container too), or
front it with Caddy/nginx terminating TLS on `:443` and proxying to
the coordinator's `:8080`.

A Caddy fronting setup will land in this directory in a follow-up.

## Verifying a release

See the corresponding section in the top-level README.
