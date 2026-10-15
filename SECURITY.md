# Security policy

Reversi is a security-relevant project. Please report vulnerabilities privately, not in a public
issue.

**Report to:** security contact to be set before the repository is made public (replace this line
with an address or a GitHub private vulnerability reporting link).

Please include affected version, a description, and reproduction steps. We aim to acknowledge
reports within a few working days.

## Scope notes

- The ledger detects tampering; it does not prevent a writer who controls the whole file from
  forging a consistent one, or from cutting off the end. Anchor the head hash externally. See
  [docs/concepts/ledger.mdx](docs/concepts/ledger.mdx); this is a known limitation, not a vulnerability.
- Content checks (intent graphs, encoding detection) are not implemented. Do not rely on Reversi
  to block prompt injection today.
- Approval grants are held in server memory and are revoked on restart by design.
