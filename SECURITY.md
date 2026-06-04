# Security

Tessera is pre-1.0 and has not had an independent security review. Do not use
it to guard production or sensitive systems without one.

## Reporting a vulnerability

Email kimaswaemma36@gmail.com with the details. Please do not open a public
issue for security problems.

## Threat model

Tessera is a consent-gated TCP broker. The host approves, the broker relays
only ciphertext, sessions are short-lived and audited.

The target audience is two devs pairing or an ad-hoc support session. It is
not a multi-tenant SaaS, and it is not a compliance product.

### What Tessera defends against

- Opportunistic internet scanners. The host opens no inbound ports; all
  traffic is dialed out to the coordinator.
- A guest who has the share-id and the connect command but no approval.
  Every session needs a fresh tap from the host.
- A guest who has a leaked approval URL but no live approver session.
- A coordinator operator who can see traffic content. They cannot. The
  inner TLS terminates at the guest and the agent, so the relay sees
  only ciphertext.
- A different enrolled guest trying to ride someone else's approved
  session. Certificate-fingerprint binding on the stream rejects them.

### What it does NOT defend against

- A phished or socially-engineered host. No protocol stops "the human
  said yes."
- A compromised guest laptop. Their key, their session.
- A rooted coordinator host. Plaintext sits at the outer TLS seam there,
  and a root user can rewrite the audit log.
- Supply-chain compromise of dependencies or the build pipeline.
- Zero-days in the underlying TLS or kernel stacks.
- Physical access to any endpoint.

### Architecture validation

The same shape (inner SSH/TLS tunneled over an outer relay that cannot
decrypt the inner stream) is what VS Code Live Share uses for its
collaboration sessions. See Microsoft's [Live Share security reference](https://learn.microsoft.com/en-us/visualstudio/liveshare/reference/security).
This is a known, reviewed pattern, not a novel design.

## Known limitations

- The approval API has no operator authentication. The approval link is a bearer
  capability, so deliver it over a trusted channel and serve the approval page
  over HTTPS.
- Coordinator state is in memory. A restart drops pending requests and live
  sessions.
- One CA with no revocation list. Removing a guest's access means rotating
  the CA, not revoking a single certificate.

These are tracked as future work, not oversights.

## Scope of `-shell` and tool escapes

`tessera share -shell` attaches the guest to a PTY running your login shell as
your user. There is no chroot, no namespace, no sandbox. The guest can read
anything you can read (`~/.ssh/`, `~/.config/gcloud/`, `~/.aws/`, repo
contents), write anywhere you can write, and run anything on your `PATH`.

If you do not want the guest to have that, do not use `-shell`. Use
`-port` or `-service` to expose a single TCP endpoint instead. Use `-shell`
only with people you would already trust at a terminal on your laptop.

Forwarding a single port is also not a sandbox. Most useful debugging tools
have a shell escape built in: `psql` has `\!`, `mysql` has `\!`, `kubectl
exec` runs arbitrary processes in pods you can reach, `vim`/`less`/`man`/
`git log` all spawn subshells, `redis-cli` can `DEBUG SLEEP` and run Lua. If
your threat model is "the guest must not reach a shell," do not rely on
"share access to tool X" as the boundary. Run the tool inside a container or
VM whose only mounts and credentials are the ones you want shared, and
share access to that.

Tessera does not provide that isolation and has no plans to. Cross-platform
sandboxing (chroot, Linux namespaces, macOS `sandbox-exec`) would move it
out of the "one Go binary you drop on a laptop" niche it is in.
