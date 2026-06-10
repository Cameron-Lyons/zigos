# Contributing

Use the pinned toolchain and repo entrypoints:

- Run Zig commands through `./scripts/zig.sh`.

## Verification Matrix

| Command | Use it when |
| --- | --- |
| `./scripts/zig.sh build verify` | You want the default local gate: lint, kernel build, host tests, spec tests, and production-readiness checks. |
| `./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify` | You want `verify` plus the QEMU native smoke and benchmark gates. |
| `./scripts/zig.sh build lint` | You only need local lint checks: Zig formatting, optional zlint, ShellCheck, and optional actionlint. |
| `./scripts/zig.sh build fmt-check` | You only need tracked Zig formatting checks. |
| `./scripts/zig.sh build shell-lint` | You only need ShellCheck over repository shell scripts. |
| `./scripts/zig.sh build zig-lint` | You only need optional zlint over Zig sources. |
| `./scripts/zig.sh build action-lint` | You only need optional actionlint over GitHub workflows. |
| `./scripts/zig.sh build test-roots` | You need to confirm Zig test-bearing files are reachable from the build test roots. |
| `./scripts/zig.sh build kernel` | You need the default native kernel and embedded userspace archive. |
| `./scripts/zig.sh build kernel-zigos-native` | You need the native bootstrap kernel profile. |
| `./scripts/zig.sh build kernel-recovery` | You need the freestanding recovery kernel profile. |
| `./scripts/zig.sh build kernel-benchmark` | You need the benchmark kernel profile. |
| `./scripts/zig.sh build host-tests` | You need host coverage; this includes the root host suite, userspace runtime tests, and test-root reachability. |
| `./scripts/zig.sh build spec-tests` | You need spec coverage and native spec tests without QEMU. |
| `./scripts/zig.sh build prod-readiness` | You need production-readiness and secure-by-design release-gate checks without changing spec conformance status. |
| `./scripts/zig.sh build release-security-check` | You touched parser, ABI, diagnostics, release-security policy, unsafe Zig, or disclosure gate inputs and need the fast release-security gate. |
| `./scripts/zig.sh build release-security-gate` | You are preparing public-release evidence and need fuzzing, reproducible builds, SBOM/provenance, memory-safety audit, redaction, disclosure, and QEMU fault proofs together. |
| `./scripts/zig.sh build spec-conformance` | You need spec coverage, native spec tests, the two-boot native smoke path, and the recovery QEMU proof. |
| `./scripts/zig.sh build zigos-native-smoke-test` | You need the native cold-reboot smoke test across two QEMU boots. |
| `./scripts/zig.sh build driver-restart-qemu-test` | You touched userspace driver restart, broker rebinding, or crash recovery paths. |
| `./scripts/zig.sh build recovery-qemu-test` | You touched recovery-mode boot, repair, or break-glass flows. |
| `./scripts/zig.sh build uefi-qemu-test` | You touched ISO, GRUB, UEFI handoff, or first-hardware-target boot evidence. |
| `./scripts/zig.sh build benchmark` | You touched performance-sensitive kernel or native-service paths. |

## Build And Cleanup Commands

| Command | Use it when |
| --- | --- |
| `./scripts/zig.sh build userspace-images` | You need only the embedded userspace image artifacts. |
| `./scripts/zig.sh build release-sbom-provenance` | You need the release artifact digest, SPDX SBOM, in-toto/SLSA provenance, DSSE envelope, keyring/revocation metadata, customer verification policy, and disclosure dry-run bundle under `build/release-security/`. |
| `./scripts/zig.sh build reproducible-build-check` | You need a two-build digest comparison for release artifacts in isolated tracked-workspace copies. |
| `./scripts/zig.sh build native-store-image` | You need to build or preserve the native storage image used by run targets. |
| `./scripts/zig.sh build iso` | You need a bootable ISO at `build/os.iso`. |
| `./test_kernel.sh` | You want the release-fast smoke-test convenience wrapper. |
| `./scripts/zig.sh build clean` | You want to remove local build outputs and Zig caches. |
| `./scripts/zig.sh build -Dclean-dry-run=true clean` | You want to inspect what `clean` would remove. |

Keep the spec contract intact:

- Treat `spec/coverage.json` as the architecture and coverage contract.
- Treat `spec/production_readiness.json` as the separate manifest for prototype-to-production work; do not encode production readiness by weakening or overloading spec conformance status.
- Keep `first_hardware_target` pinned to one real machine until it is boringly reliable. The current target is `intel-nuc11tnki5`; QEMU can be preflight evidence, but production readiness requires a real hardware proof bundle checked by `scripts/check-nuc11tnki5-hardware-proof.sh build/hardware-proofs/nuc11tnki5`.
- Keep the secure-by-design release gate in `spec/production_readiness.json` complete, release-blocking, and backed by `./scripts/zig.sh build release-security-check`. Updates that touch parsing, boot, storage, sync, kernel/user ABI, drivers, diagnostics, crypto, or release tooling should consider fuzzing, fault injection, reproducible builds, DSSE SBOM/provenance, hardware-backed release keys, rotation/revocation, customer verifier metadata, threat-model tests, memory-safety audits, crash dump redaction, and the disclosure process in `SECURITY.md`.
- Keep requirement ids stable when editing manifest prose or mappings so coverage references do not churn.
- If you add, rename, or split spec tests, keep the test names and coverage references aligned.
- Prefer expanding tests and coverage before changing requirement anchors or architecture claims.

Respect the architectural boundaries from the spec:

- Keep the kernel typed and minimal.
- Keep drivers, networking, storage, sync, policy, and recovery logic in restartable user-space services.
- Preserve the first-class model concepts: principals, capabilities, objects, workspaces, and tasks.
- Do not reintroduce ambient authority, compatibility portal paths, direct host integration, or authoritative file-path APIs in place of object/workspace mediation.

Keep the repo tidy:

- Put generated artifacts under `build/`; keep tracked build logic under `build_support/`.
- Keep architecture assembly and linker files under `src/arch/`, and bootloader-facing files under `src/boot/`.
- Put host-only support utilities under `tools/`, and Zig helper binaries that share `src/` imports under `src/tools/`, rather than `src/native/`.
- Prefer small focused modules over growing import hubs and monolithic integration files.
