# Security policy

Reversi is a security-relevant project. Please report vulnerabilities privately, not in a public issue.

**Report a vulnerability:** use GitHub's private vulnerability reporting. On the repository page open the
**Security** tab, then **Report a vulnerability**
(<https://github.com/multimindlab/Reversi/security/advisories/new>). Only the maintainers can see the report.

For a hardening question or an idea that is not sensitive (a missing check, a documentation gap), a normal public
issue is fine. If you are not sure which this is, use the private route.

Please include the affected version, a description, and reproduction steps. We aim to acknowledge reports within a few
working days.

## Scope notes

- The ledger detects tampering; it does not prevent a writer who controls the whole file or database
  from forging a consistent one, or from cutting off the end. Anchor the head hash externally. See
  [docs/concepts/evidence.mdx](docs/concepts/evidence.mdx); this is a known limitation, not a vulnerability.
- Content checks are heuristics (credentials, encoded payloads, injection phrasing, cumulative intent). Bypassing them with
  creative phrasing is a known limitation; a bypass of a *documented* pattern is a bug worth reporting.
- Approvals, API-key handling, OIDC validation, the console session and CSRF protection, Host/Origin validation on the
  gateway and the role separation between agent and operator endpoints are in scope. See
  [docs/threat-model.mdx](docs/threat-model.mdx).
