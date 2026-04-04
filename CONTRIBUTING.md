# Contributing

Use the pinned toolchain and repo entrypoints:

- Run Zig commands through `./scripts/zig.sh`.
- Run host coverage with `./scripts/run-host-tests.sh`.
- Run spec coverage and spec conformance with `./scripts/run-spec-conformance.sh`.
- Run native benchmarks with `./scripts/zig.sh build benchmark` when touching performance-sensitive kernel or native-service paths.
- Run shell lint with `bash scripts/lint-shell.sh`.

Keep the spec contract intact:

- Treat `SPEC.md` as the architecture contract and `spec/coverage.json` as the coverage manifest.
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
- Put host-only support utilities under `tools/`, and Zig helper binaries that share `src/` imports under `src/tools/`, rather than `src/native/`.
- Prefer small focused modules over growing import hubs and monolithic integration files.
