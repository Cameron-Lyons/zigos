# Security Policy

Zigos treats secure-by-design readiness as a release gate. A public release is
blocked until the secure-by-design controls in `spec/production_readiness.json`
are complete or an explicitly documented residual-risk exception is approved.

## Supported Scope

This policy covers the Zigos kernel, boot profiles, native services, userspace
runtime, build tooling, release artifacts, and repository-hosted scripts.

Until the first supported release is published, all versions are pre-release.
Security fixes should target `main` unless a release branch exists.

## Reporting A Vulnerability

Do not report suspected vulnerabilities in public issues.

Before a public release, maintainers must configure at least one monitored
private intake channel, such as GitHub private vulnerability reporting or a
dedicated security mailbox, and record that channel here. Shipping without that
private channel is a release blocker.

Reports should include:

- Affected component, branch, commit, or artifact digest.
- Reproduction steps, proof of concept, crash logs, or malformed input samples.
- Expected and observed security impact.
- Whether the issue appears to expose secrets, capabilities, private data, raw
  crash memory, or supply-chain metadata.
- Any disclosure timeline constraints.

## Handling Commitments

Maintainers should acknowledge valid private reports within 3 business days,
triage severity within 10 business days, and provide risk-prioritized status
updates until resolution.

Critical and high-impact vulnerabilities require a coordinated disclosure plan,
customer-facing advisory, CVE issuance path where applicable, and a CWE field in
the public record. Valid reports should be fixed in the supported branch or
clearly documented as not exploitable in Zigos.

## Good-Faith Research

Good-faith research that follows this policy is authorized for the covered
repository and release artifacts. Maintainers should not recommend or pursue
legal action for accidental, good-faith activity that avoids privacy violations,
service disruption, persistence, data destruction, extortion, and public release
of exploit details before coordinated disclosure.

## Release Blockers

The following are release blockers:

- No monitored private vulnerability reporting channel.
- No owner for CVE/CWE publication and advisory handling.
- Missing fuzzing, fault-injection, reproducible-build, SBOM/provenance,
  threat-model, memory-safety-audit, or crash-dump-redaction evidence.
- Any crash dump or diagnostic export path that includes secrets, capability
  tokens, private content, or raw memory by default.
