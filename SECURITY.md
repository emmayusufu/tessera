# Security

Tessera is experimental and has not had an independent security review. Do not
use it to guard production or sensitive systems without one.

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
- A guest who has a leaked approval URL but no live approver session
  (with the upcoming rate limits and fragment-based tokens).
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
- No rate limiting on the approval endpoint or stream lookups.

These are tracked as future work, not oversights.
