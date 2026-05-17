# Contributing

Use the pinned toolchain and repo entrypoints:

- Run Zig commands through `./scripts/zig.sh`.
- Run host coverage with `./scripts/zig.sh build host-tests`; this includes the root host suite, userspace runtime tests, and the test-root reachability check.
- Run spec coverage without QEMU with `./scripts/zig.sh build spec-tests`.
- Run production-readiness tracking checks with `./scripts/zig.sh build prod-readiness`.
- Run full spec conformance with `./scripts/zig.sh build spec-conformance`; this includes spec coverage, native spec tests, the two-boot native smoke path, and the recovery QEMU proof.
- Run driver-restart and recovery smoke proofs directly with `./scripts/zig.sh build driver-restart-qemu-test` and `./scripts/zig.sh build recovery-qemu-test` when touching those paths.
- Run native benchmarks with `./scripts/zig.sh build benchmark` when touching performance-sensitive kernel or native-service paths.
- Run lint with `./scripts/zig.sh build lint`; use `fmt-check`, `shell-lint`, `zig-lint`, or `action-lint` for focused checks.

Keep the spec contract intact:

- Treat `SPEC.md` as the architecture contract and `spec/coverage.json` as the coverage manifest.
- Treat `spec/production_readiness.json` as the separate manifest for prototype-to-production work; do not encode production readiness by weakening or overloading spec conformance status.
- Keep the hidden `<!-- REQ: ... -->` anchors in `SPEC.md` stable when editing prose so coverage mappings do not churn.
- If you add, rename, or split spec tests, keep the test names and coverage references aligned.
- Prefer expanding tests and coverage before changing requirement anchors or architecture claims.

Respect the architectural boundaries from the spec:

- Keep the kernel typed and minimal.
- Keep drivers, networking, storage, sync, policy, and recovery logic in restartable user-space services.
- Preserve the first-class model concepts: principals, capabilities, objects, workspaces, and tasks.
- Do not reintroduce ambient authority, direct host integration for compatibility environments, or authoritative file-path APIs in place of object/workspace mediation.

Keep the repo tidy:

- Put generated artifacts under `build/`; keep tracked build logic under `build_support/`.
- Keep architecture assembly and linker files under `src/arch/`, and bootloader-facing files under `src/boot/`.
- Put host-only support utilities under `tools/`, and Zig helper binaries that share `src/` imports under `src/tools/`, rather than `src/native/`.
- Prefer small focused modules over growing import hubs and monolithic integration files.
