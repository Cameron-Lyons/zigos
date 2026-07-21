# Security Policy

Zigos treats secure-by-design readiness as a release gate. A public release is
blocked unless the secure-by-design controls in
`spec/production_readiness.json` are complete or an explicitly documented
residual-risk exception is approved.

## Supported Scope

This policy covers the Zigos kernel, boot profiles, native services, userspace
runtime, build tooling, release artifacts, and repository-hosted scripts.

Until the first supported release is published, all versions are pre-release.
Security fixes should target `main` unless a release branch exists.

## Reporting A Vulnerability

Do not report suspected vulnerabilities in public issues.

Use the primary private intake channel:

- GitHub private vulnerability reporting:
  https://github.com/Cameron-Lyons/zigos/security/advisories/new

Use the backup private intake channel if GitHub private reporting is
unavailable:

- security@zigos.dev

The `release-security-review` owner monitors both channels for release-bound
security reports and dry-runs the workflow through
`build/release-audit/vulnerability-disclosure-dry-run.json`.

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

CVE issuance is owned by `release-security-review` through GitHub Security
Advisory CVE request when applicable, or coordinated CNA handoff before public
advisory publication. CWE classification is required for public advisories and
not-exploitable decisions.

## Good-Faith Research

Good-faith research that follows this policy is authorized for the covered
repository and release artifacts. Maintainers should not recommend or pursue
legal action for accidental, good-faith activity that avoids privacy violations,
service disruption, persistence, data destruction, extortion, and public release
of exploit details before coordinated disclosure.

## Release Blockers

The following are release blockers:

- Private vulnerability reporting channel or backup mailbox unavailable.
- No active owner for CVE/CWE publication and advisory handling.
- Missing passing `release-security-preflight`, authenticated candidate
  creation/verification through `release-bundle-check`, or final verify-only
  `release-security-gate` evidence from the ordered ceremony in `README.md`.
- Missing current-commit `NUC11TNKi5` real-hardware proof run with the full
  external trust configuration and explicit fresh `-Dhardware-proof-dir`
  documented in `README.md`.
- Release provenance not signed through a hardware-backed TPM, secure enclave,
  HSM, or KMS key delegated by the independently pinned,
  threshold-authenticated trust policy.
- Customer verification bundle missing the exact signed 33-target manifest,
  root consistency evidence, signed trust policy, artifact digests, SPDX SBOM,
  DSSE in-toto/SLSA provenance, or reproducible-build evidence.
- Release verification performed without an independently distributed,
  SHA-256-pinned verifier, externally persisted rollback state, or root metadata
  and its pin obtained outside the downloaded bundle.
- Rollback state whose directory, state file, or adjacent lock file has unsafe
  mode bits or the wrong effective-user owner; on macOS, any extended ACL on
  those paths is also blocking.
- Pinned root metadata missing `minimumPolicyVersion`, or its authenticated
  trust policy missing `minimumReleaseSequence`, for first-use rollback floors.
- Candidate generation, finalization, or verification performed while an
  untrusted concurrent writer can replace the release bundle or any of its 33
  signed target files; authenticated inputs must remain private and quiescent
  or be staged read-only.
- Treating any locally computed commitment as a production FIPS 204 ML-DSA
  implementation; production PQC signatures must come from a separately
  validated ML-DSA provider.
- Authenticated release trust policy missing its ML-DSA-65 rollout mode,
  FIPS-validated provider requirement, or fail-closed verifier behavior for
  required ML-DSA signatures.
- Machine-readable release security policy missing the classical Ed25519
  migration baseline or the FIPS 203 ML-KEM and FIPS 205 SLH-DSA migration
  scopes for key establishment and signature diversity.
- Any crash dump or diagnostic export path that includes secrets, capability
  tokens, private content, or raw memory by default.
