# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current tree implements a capability-first kernel and service architecture with principal-bound, task-scoped authority, restartable native services, a content-addressed object store, local-first sync primitives, immutable-base state, measured-boot records, recovery-mode proof flows, and task-first UX scaffolding.

## Current Focus

This repository treats the Zigos v0.1 clean-slate OS spec as its explicit conformance target. The spec, architecture notes, and contribution guidance live here:

- [SPEC.md](SPEC.md): design goals, platform model, and conformance target
- [ARCHITECTURE.md](ARCHITECTURE.md): how the current code maps onto the spec
- [CONTRIBUTING.md](CONTRIBUTING.md): repo conventions and verification expectations

Requirement status lives in `spec/coverage.json`.
Production-readiness status lives in `spec/production_readiness.json`; keep production-readiness status there instead of overloading spec conformance evidence.

The native kernel surface is intentionally small:

- scheduling
- virtual memory
- IPC transport
- capability enforcement
- interrupts and timekeeping
- secure-boot handoff hooks
- IOMMU and DMA isolation hooks

Everything above that layer lives behind native service and embedded userspace boundaries: service and platform modules under `src/native/`, the freestanding component runtime under `src/userspace/`, and build-time image/archive wiring under `build_support/`.

## Authority Model

The current native tree treats capabilities as live kernel-backed authority, not as advisory metadata:

- the syscall boundary requires the calling task to possess the capability id, match the capability holder principal, and satisfy any task scope
- the session manager keeps the broad session and policy capabilities; launched services and clients receive only narrow derived or minted bootstrap capabilities for their own task
- service-facing helpers such as the storage file bridge and driver registration resolve capability ids through the capability table so revocation and lease checks still apply
- boot-time service launch failures are recorded through the supervisor as structured crashes instead of trapping through `unreachable`

## Requirements

Use the pinned Zig toolchain and repo entrypoints:

- Zig `0.16.0` exactly
- `nasm`
- `qemu-system-x86_64`
- Python 3 for spec coverage and production-readiness checks
- ShellCheck for `zig build lint` and `zig build verify`
- Optional: `zlint` and `actionlint`; local hooks run them when installed, or require them with `ZIGOS_REQUIRE_ZLINT=1` / `ZIGOS_REQUIRE_ACTIONLINT=1`

For ISO and disk-image workflows, install the full set verified by `scripts/setup-deps.sh`:

- GRUB `mkrescue`
- `xorriso`
- `mtools`
- `dosfstools`
- `e2fsprogs`

The repo includes both `.tool-versions` and `mise.toml` pins. `build.zig` rejects any Zig version other than `0.16.0`.

## Setup

The fastest path is the repo setup script:

```bash
bash scripts/setup-deps.sh
```

That script supports:

- macOS via Homebrew
- Linux via `apt`, `dnf`, or `pacman`

All repo Zig commands should go through `./scripts/zig.sh`. It resolves the pinned Zig version in this order:

1. `ZIG_BIN`
2. active `zig` if it is `0.16.0`
3. `mise`
4. repo-local fallback binaries if present

## Quick Start

```bash
# Build the native kernel and embedded userspace archive
./scripts/zig.sh build kernel

# Run the native kernel in QEMU
./scripts/zig.sh build run

# Shortcut for the same QEMU boot path
./run.sh
```

`./scripts/zig.sh build run` and `./scripts/zig.sh build run-zigos-native` attach `build/native-store.img` as the native storage image.

Targets that boot or package the system build the current userspace image archive from `src/native/task/userspace_registry.zig` before using the kernel artifact.

## Common Commands

```bash
# Run CI-aligned local lint, kernel build, host tests, spec tests, and readiness checks
./scripts/zig.sh build verify

# Run host-side native and userspace runtime tests
./scripts/zig.sh build host-tests

# Run the spec coverage gate and native spec unit tests without QEMU smoke
./scripts/zig.sh build spec-tests

# Run spec coverage, native spec tests, smoke verification, and recovery verification
./scripts/zig.sh build spec-conformance

# Remove local build outputs and Zig caches
./scripts/zig.sh build clean
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full verification matrix, QEMU smoke targets, benchmark gates, lint slices, and cleanup dry-run command.

## Verification Model

Repo-level conformance is checked through the thin root `src/zigos_spec_test.zig`, which delegates to the suites under `src/tests/spec/`; the section-to-test contract is enforced by `spec/coverage.json` and `tools/check_spec_coverage.py`, with stable `REQ-*` anchors in `SPEC.md` driving the manifest instead of line-by-line prose claims. `Enforced` requirements in the manifest must name implementation modules and adversarial or negative tests; modeled and scenario-only requirements stay explicitly marked until they earn that evidence. The full local verification matrix lives in [CONTRIBUTING.md](CONTRIBUTING.md).

Production readiness is tracked separately in `spec/production_readiness.json` and validated by `tools/check_production_readiness.py`. This keeps a requirement's repository conformance status separate from the work needed to remove synthetic hardware, harnessed transport, emulator roots, scale limits, and model-only proof gaps.

Host-side native tests enter through `src/native_host_test.zig` and delegate to `src/tests/host/`. Deeper subsystem coverage lives beside each native module under `src/native/`.

## Repository Map

- `src/main.zig`: thin kernel entry and export surface
- `src/arch/`: architecture-specific assembly, syscall trap glue, and linker scripts
- `src/boot/`: boot assembly and GRUB config used by kernel and ISO builds
- `src/kernel/boot/profiles/zigos_native.zig`: primary native boot profile
- `src/kernel/boot/profiles/recovery.zig`: freestanding recovery-mode profile
- `src/kernel/boot/profiles/benchmark.zig`: benchmark profile
- `src/native/`: native principals, capabilities, runtime, mediation, services, storage, sync, recovery, and UX
- `src/native/demo/`: seeded demo bundles and scenario-world flows used by explicit conformance demos
- `src/userspace/`: freestanding userspace runtime, entry points, and linker script for embedded component images
- `src/tests/`: organized host and spec test suites, with thin root entrypoints kept at `src/*.zig`
- `src/tools/`: Zig helper binaries that need to share the `src/` module root
- `src/kernel/net/`: low-level networking and device transport
- `src/native_smoke_markers.zig`: expected boot markers shared by smoke harnesses and kernel code
- `src/print_native_smoke_markers.zig`: host utility for inspecting smoke marker expectations
- `build.zig`: native-only build graph
- `build_support/`: build helpers for kernel artifacts, embedded userspace images, and shared build paths
- `benchmarks/`: benchmark baselines and threshold files used by the QEMU benchmark gate
- `spec/coverage.json`: executable mapping from `SPEC.md` requirements to implementation and test evidence
- `spec/production_readiness.json`: production-readiness tracks for enforced requirements that still need real-hardware, scale, fault, or operational proof
- `scripts/`: repo entrypoints for setup, build, run, and verification
- `tools/`: host-side support utilities such as spec coverage checks
- `.github/`: CI workflows and shared setup action

## Status

The repository no longer builds or ships the old POSIX-like shell, POSIX-style syscall ABI, or VFS-rooted userland pipeline. Legacy support is modeled as explicit compatibility environments rather than as part of the native platform.

For the current requirement status, use `spec/coverage.json`; it separates enforced behavior from modeled or scenario-only evidence. For prototype-to-production planning, use `spec/production_readiness.json`.

Storage-volume persistence remains covered by host-side native tests through `src/native/storage/storage_volume.zig`.
The remaining freestanding entry surface is the native typed syscall dispatcher plus the native-only verification targets documented in [CONTRIBUTING.md](CONTRIBUTING.md).
