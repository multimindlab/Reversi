# Roadmap

See [docs/roadmap.mdx](docs/roadmap.mdx) for the full list of what is built, what is built but not yet verified against real
systems, and what is not built. In short:

- **Built:** the engine, manifest registry, policy (with simulation), approvals (quorum, delegation, break-glass), content
  checks, signed and anchored evidence, three stores, the server and console, the MCP gateway, the CLI and `reversi apply`,
  notifications, OpenTelemetry, retention and legal holds, fourteen connectors, Python framework adapters, Docker, Compose and
  a Helm chart.
- **Built, not verified against real systems:** the connectors, notification channels, framework adapters, Docker files, the
  Helm chart (never installed on a cluster) and the GitHub workflows.
- **Not built:** a Terraform provider, a Kubernetes operator, OIDC browser redirect login for the console, a hosted control
  plane, Go and Java SDKs, clustering with run hand-off, gateway passthrough of MCP resources, prompts and sampling, and an
  external security review.
