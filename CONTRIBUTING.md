# Contributing

Use the pinned toolchain and repo entrypoints:

- Preinstall Zig 0.17.0 on `PATH` and run commands directly with `zig`.
- Use `zig build setup-deps` to install and verify the remaining host tools;
  `zig build setup-deps -- --check` only verifies them, and
  `zig build setup-deps -- --dry-run` shows installation commands.
- Use `debug`, `safe`, `fast`, or `small` for
  `-Doptimize`; array initialization uses `@splat` and reflection uses
  `@typeInfo` field names and values.
- Native and spec tests target x86-64 on the host OS because they exercise the
  cooperative worker assembly. Apple Silicon hosts need Rosetta to run them;
  `-Dhost-test-target=<triple>` selects another hosted x86-64 target.
  macOS test binaries receive Zig's ad-hoc signature with an empty entitlement
  dictionary, preventing an observed startup stall with unsigned executables.
- `zlint` and `actionlint` are optional for local focused runs, but CI requires
  both through `ZIGOS_REQUIRE_ZLINT=1` and `ZIGOS_REQUIRE_ACTIONLINT=1`.
- EFI ISO generation normalizes FAT identity and all media timestamps in UTC.
  `-Dsource-date-epoch=<seconds>` selects nonnegative decimal seconds through the
  end of 2107; the default is 1980-01-01, and earlier values are clamped to 1980
  for all media dates. Pass any `SOURCE_DATE_EPOCH` value explicitly through
  this option so epoch changes invalidate Zig's cached build configuration.
  Keep the same epoch for both builds when checking reproducibility.
- Every published kernel is the exact ELF embedded in its EFI payload: one
  whole-kernel LTO link with static symbols retained and debug sections removed.
  `zig build kernel-debug` adds a second link with full source-line and type
  information under `zig-out/kernel-debug/`; use those files with
  `llvm-addr2line` when diagnosing kernel return addresses.
- Host tests and build checkers default to Debug whatever `-Doptimize` selects
  for the kernel, keeping runtime safety checks; `-Dtest-optimize` overrides it.

## Verification Matrix

| Command | Use it when |
| --- | --- |
| `zig build verify` | You want the default local gate: lint, kernel build, host tests, spec tests, production-readiness checks and the QEMU architecture probes. |
| `zig build -Dverify-smoke=true -Dverify-benchmark=true verify` | You want `verify` plus the QEMU native smoke and benchmark gates. |
| `zig build lint` | You only need local lint checks: Zig formatting, optional zlint, and optional actionlint. |
| `zig build fmt-check` | You only need tracked Zig formatting checks. |
| `zig build zig-lint` | You only need optional zlint over Zig sources. |
| `zig build action-lint` | You only need optional actionlint over GitHub workflows. |
| `zig build test-roots` | You need to confirm every test-bearing Zig file under `src/` and `tools/` is reachable from a build test root. |
| `zig build hardware-proof-checker-test` | You changed the RNUC15CRSU7 proof-bundle checker or bundle contract. |
| `zig build kernel` | You need the production native kernel and embedded userspace archive. |
| `zig build kernel-zigos-native-verification` | You need the native kernel with synthetic proof workloads; negative smokes select its injected faults through the authenticated command line. |
| `zig build kernel-debug` | You need every kernel with complete DWARF in `zig-out/kernel-debug/`. |
| `zig build kernel-role-check` | You changed native boot composition and need to prove verification code and state are absent from production. |
| `zig build kernel-recovery` | You need the freestanding recovery kernel profile. |
| `zig build kernel-benchmark` | You need the benchmark kernel profile. |
| `zig build host-tests` | You need host coverage; this includes the root host suite, userspace runtime tests, native host-tool tests, authenticated release-tool fixtures, and test-root reachability. |
| `zig build -Doptimize=fast arch-probes` | You touched architecture entry, SMP, xstate or cache policy and need every isolated QEMU architecture probe: native crypto, upper-half entry, positive Mapping xstate, AP cache rejection and SMP cache match. |
| `zig build -Doptimize=fast native-crypto-check` | Execute AVX2 arithmetic, hardware AES, SHA-256, GHASH and storage XXH64 known answers plus firmware floating-point control reset and 128 x87/XMM/YMM owner roundtrips in QEMU. Requires exact ordered evidence for every primitive. This isolated standard-XSAVE proof runs on TCG; production XSAVES, PKRU, FRED and physical preemption still require their own hardware evidence. |
| `zig build host-tool-tests` | You changed native file/media, QEMU process/log/peer relay, release, or hardware utilities. |
| `zig build release-tool-fixture-test` | You changed release generation/publication or signer arguments and need the real independent verifier with disposable fixture keys. |
| `zig build tool -- COMMAND [ARGUMENTS]` | Run one of the native utilities; use `--help` to list commands. |
| `zig build spec-tests` | You need the spec coverage gate, its checker tests, and native spec tests without QEMU. |
| `zig build prod-readiness` | You need the production-readiness manifest, first-hardware-target, retired-source, security-control and secure-by-design release-gate checks without changing spec conformance status. |
| `zig build production-readiness-tests` | You want focused readiness checker tests; these also run with `host-tests` and `prod-readiness`. |
| `zig build release-security-check` | You touched parser, ABI, diagnostics, release-security policy, unsafe Zig, or disclosure gate inputs and need the fast release-security gate. |
| `zig build release-security-preflight` | You need every mutable public-release audit, fixture, build, smoke, fault, recovery, sync, and UEFI-QEMU gate before freezing a candidate. |
| `zig build -Dhardware-proof-dir=build/hardware-proofs/<fresh-name> -Drelease-trust-root=<absolute-path> -Drelease-trust-root-sha256=<lowercase-sha256> -Drelease-trust-state=<absolute-path> -Drelease-verifier=<absolute-path> -Drelease-verifier-sha256=<lowercase-sha256> release-security-gate` | You set the external hardware-proof environment and need to reverify and seal an already frozen candidate without regenerating or signing artifacts. |
| `zig build spec-conformance` | You need spec coverage, native spec tests, the two-boot native smoke path, and the recovery QEMU proof. |
| `zig build zigos-native-production-smoke-test` | You need production cold boots, persistence, and firmware framebuffer scanout. |
| `zig build zigos-native-smoke-test` | You need production boot coverage plus the verification cold-reboot and negative-smoke suite. |
| `zig build driver-restart-qemu-test` | You touched userspace driver restart, broker rebinding, or crash recovery paths and want only that single-boot subset of the full smoke. |
| `zig build recovery-qemu-test` | You touched recovery-mode boot, repair, or break-glass flows. |
| `zig build uefi-qemu-test` | You touched the production ISO or UEFI handoff and the host CPU passes hardware admission (FRED, CET, LASS and an architectural TSC rate); QEMU CPU models are rejected. |
| `zig build uefi-verification-qemu-test` | You touched the verification ISO or first-hardware-target proof media; it has the same hardware admission requirement. |
| `zig build high-half-entry-check` | You touched high entry, AP ownership, lease mailboxes, copied syscall brokerage, trap provisioning or remote TLB/cache maintenance. Requires 32 exact ordered records from the isolated 16-CPU CPL0 guest. |
| `zig build benchmark` | You touched performance-sensitive kernel or native-service paths. |
| `zig build frame-allocator-benchmark` | Measure physical-page allocator reuse, sparse-memory searches, contiguous runs, and bounded exhaustion on the host without QEMU. Uses `fast` and reports the median of five samples. |
| `zig build heap-allocator-benchmark` | Measure heap reuse, successful or failed allocation across 1024 separated free blocks, and 512 page-sized allocations freed in permuted order. Reports allocator array bytes and the median of five `fast` samples. |
| `zig build ipc-ring-benchmark` | Compare single/split receive, full-queue backpressure, and staged-record/direct-payload enqueue for 0, 1, 17, and 88-byte messages in the same `fast` build. Uses the hosted x86-64-v3+AES/PCLMUL/SHA native CPU floor and the median of five samples; Apple Silicon needs Rosetta. |
| `zig build response-preflight-benchmark` | Compare repeated and single declared-span response validation over one, four, or eight memory regions and a terminal stack. Uses the hosted native x86-64 floor; physical page preparation is excluded equally. Checks statuses and checksums in seven alternating-order samples. |
| `zig build text-scanout-benchmark` | Measure host text rasterization, single-cell edits, and Unicode pool reordering with framebuffer damage counters. Uses `fast` and reports the median of five samples. |
| `zig build id-index-benchmark` | Measure ID hits, misses, generation reuse, empty-table lookups after deletion, and steady churn. Reports table bytes and the median of five `fast` samples. |
| `zig build endpoint-readiness-benchmark` | Compare owner scans and maintained readiness counts for 1–63 endpoints, including send/drain accounting. Checks results in the same `fast` build. |
| `zig build text-layout-benchmark` | Compare repeated layout, one-pass visible windows, and iterator-based vertical navigation for ASCII and Unicode documents. Checks exact rows, caret offsets, wrap affinity, and preferred columns before timing. |
| `zig build workspace-index-benchmark` | Measure path/object hits, empty misses after churn, and steady directory mutation using 192 path and 96 object buckets. Checks lookup results and replacement consistency. |
| `zig build object-chunks-benchmark` | Compare scratch preparation for complete immutable hashes, then prefix scans and positioned cursors for forward, reverse, and retransmitted object ranges. Checks exact digests and reconstructed bytes; reports alternating hash samples and cursor page visits. |
| `zig build surface-text-benchmark` | Compare repeated and combined canonical text validation for 512-byte ASCII and Unicode documents, with collapsed and selected cursors. Checks acceptance parity. |
| `zig build scheduler-wake-benchmark` | Measure coalesced and reactivated wakes for one task and a full native task table. Checks queue, incarnation, budget, deadline, and wake accounting; reports the median of nine `fast` samples. Targets hosted x86-64; Apple Silicon needs Rosetta. |

## Build And Cleanup Commands

| Command | Use it when |
| --- | --- |
| `zig build userspace-production-images` | You need the eight shipped userspace images and production archive. |
| `zig build userspace-verification-images` | You need the production images plus the five proof and synthetic-journey images. |
| `zig build userspace-images` | You intentionally need both production and verification userspace sets. |
| `zig build -Doptimize=fast -Drelease-trust-root=<absolute-path> -Drelease-trust-root-sha256=<lowercase-sha256> -Drelease-trust-policy=<absolute-path> -Drelease-verifier=<absolute-path> -Drelease-verifier-sha256=<lowercase-sha256> release-sbom-provenance` | You set the signer environment and independently pinned verifier and need the generator-side eight-file portion of the exact 17-target release evidence. |
| `zig build -Doptimize=fast -Drelease-trust-root=<absolute-path> -Drelease-trust-root-sha256=<lowercase-sha256> -Drelease-trust-policy=<absolute-path> -Drelease-trust-state=<absolute-path> -Drelease-verifier=<absolute-path> -Drelease-verifier-sha256=<lowercase-sha256> release-manifest-finalize` | The eight generated files and two independent reproducibility files are complete, and you are ready to candidate-verify, atomically publish, and statefully verify the exact top-level manifest. |
| `zig build -Doptimize=fast -Drelease-trust-root=<absolute-path> -Drelease-trust-root-sha256=<lowercase-sha256> -Drelease-trust-policy=<absolute-path> -Drelease-trust-state=<absolute-path> -Drelease-verifier=<absolute-path> -Drelease-verifier-sha256=<lowercase-sha256> release-bundle-check` | You supplied the signer, independently pinned verifier, and persistent rollback state and need the full phase-A candidate ceremony after preflight. |
| `zig build -Drelease-trust-root=<absolute-path> -Drelease-trust-root-sha256=<lowercase-sha256> -Drelease-trust-state=<absolute-path> -Drelease-verifier=<absolute-path> -Drelease-verifier-sha256=<lowercase-sha256> release-bundle-verify-existing` | You need to verify an existing frozen bundle with an independently pinned verifier and no generation or signing step. |
| `zig build verify-release-cli` | You need a local development/test build of the verifier; public verification still requires an independently distributed binary and pin, and this host tool is not a signed OS target. |
| `zig build reproducible-build-check` | You need a two-build digest comparison for release artifacts in isolated tracked-workspace copies. |
| `zig build native-store-image` | You need to build or preserve the native storage image used by run targets. |
| `zig build iso` | You need a bootable ISO at `build/os.iso`. |
| `zig build iso-verification` | You need bootable proof media at `build/os-verification.iso`. |
| `zig build -Doptimize=fast zigos-native-smoke-test` | You want the optimized smoke-test convenience wrapper. |
| `zig build clean` | You want to remove local build outputs and Zig caches. |
| `zig build -Dclean-dry-run=true clean` | You want to inspect what `clean` would remove. |

Keep the spec contract intact:

- Treat `spec/coverage.json` as the architecture and coverage contract.
- Treat `spec/production_readiness.json` as the separate manifest for prototype-to-production work; do not encode production readiness by weakening or overloading spec conformance status.
- Keep `first_hardware_target` pinned to one real machine until it is boringly reliable. The current target is `asus-nuc15crsu7`; QEMU can be preflight evidence, but production readiness requires a real hardware proof bundle checked by `zig build tool -- check-nuc15crsu7-hardware-proof build/hardware-proofs/<fresh-name>`.
- Prepare the NUC proof bundle with `zig build tool -- prepare-nuc15crsu7-hardware-proof --build --nonce <fresh-64-hex> --output build/hardware-proofs/<fresh-name>` after provisioning the authenticated release signer, root, policy, sequence, expiry, rollback state, and independently pinned verifier. The output must be a fresh empty direct child of `build/hardware-proofs`; acceptance requires two single-boot logs, individually hashed cycle evidence, a canonical capture statement, two role quote/signature pairs, an independently pinned hardware verifier and nonce, and an independently pinned release verifier, root, and persistent state path.
- Keep the secure-by-design release gate in `spec/production_readiness.json` complete, release-blocking, and backed by `zig build release-security-check`. Updates that touch parsing, boot, storage, sync, kernel/user ABI, drivers, diagnostics, crypto, or release tooling should consider fuzzing, fault injection, reproducible builds, DSSE SBOM/provenance, hardware-backed TPM/secure-enclave/HSM/KMS release keys, rotation/revocation, `zigos-verify-release` customer verifier coverage, artifact measurements, threat-model tests, memory-safety audits, crash dump redaction, and the disclosure process in `SECURITY.md`.
- `tools/check_production_readiness.zig` pins source text only for bans on retired legacy surfaces (`RETIRED_SOURCES`, `RETIRED_PATHS`), a short list of security controls and their required order (`SECURITY_CONTROLS`; moving one into another file means retargeting its entry), the benchmark-environment gate (`tools/host/qemu.zig`, `tools/check_kernel_benchmarks.zig`, the KVM benchmark job in `.github/workflows/ci.yml` and `benchmarks/kernel-baseline.txt`), the native scheduler loop in `src/kernel/boot/profiles/zigos_native.zig`, and the model-only marker on `syntheticUserspaceImage(` calls in critical launch paths. It also enforces kernel TCB imports, production boot flags and manifest anchors. Express any other invariant as a test or comptime assertion next to the code it protects instead of pinning source text in the checker.
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
