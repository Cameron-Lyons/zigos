# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current tree implements a capability-first kernel and service architecture with principal-bound, task-scoped authority, restartable native services, a content-addressed object store, local-first sync primitives, immutable-base state, measured-boot records, and task-first UX scaffolding.

## Current Focus

This repository treats the Zigos v0.1 clean-slate OS spec as its explicit conformance target. The spec, architecture notes, and contribution guidance live here:

- [SPEC.md](SPEC.md): design goals, platform model, and conformance target
- [ARCHITECTURE.md](ARCHITECTURE.md): how the current code maps onto the spec
- [CONTRIBUTING.md](CONTRIBUTING.md): repo conventions and verification expectations

The native kernel surface is intentionally small:

- scheduling
- virtual memory
- IPC transport
- capability enforcement
- interrupts and timekeeping
- secure-boot handoff hooks
- IOMMU and DMA isolation hooks

Everything above that layer is modeled as a native service boundary under `src/native/`.

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
- Python 3 for spec coverage checks

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
# Build the native kernel
./scripts/zig.sh build kernel

# Run the native kernel in QEMU
./scripts/zig.sh build run

# Shortcut for the same QEMU boot path
./run.sh
```

`./scripts/zig.sh build run` and `./scripts/zig.sh build run-zigos-native` attach `build/native-store.img` as the native storage image.

## Common Commands

```bash
# Run host-side native tests
./scripts/zig.sh build host-tests

# Run local hygiene plus host/spec tests
./scripts/zig.sh build verify

# Include optional QEMU gates in the verify target
./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify

# Run the spec coverage gate, native spec tests, and freestanding smoke verification
./scripts/zig.sh build spec-conformance

# Run the native cold-reboot smoke test across two QEMU boots
./scripts/zig.sh build zigos-native-smoke-test

# Run the spec-aligned native benchmark suite in QEMU
./scripts/zig.sh build benchmark

# Release-fast convenience wrapper for the smoke test
./test_kernel.sh

# Build a bootable ISO at build/os.iso
./scripts/zig.sh build iso
```

The smoke test uses `build/native-store-smoke.img` and validates the expected native bootstrap markers across two boots.

## Verification Model

Repo-level conformance is checked through the thin root `src/zigos_spec_test.zig`, which delegates to the suites under `src/tests/spec/`; the section-to-test contract is enforced by `spec/coverage.json` and `tools/check_spec_coverage.py`, with stable `REQ-*` anchors in `SPEC.md` driving the manifest instead of line-by-line prose claims. `Enforced` requirements in the manifest must name implementation modules and adversarial or negative tests; modeled and scenario-only requirements stay explicitly marked until they earn that evidence. The `spec-conformance` target also runs the native two-boot QEMU smoke harness so the repo-level gate is not host-only.

The main verification entrypoints are:

- `./scripts/zig.sh build verify`
- `./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify`
- `./scripts/zig.sh build kernel`
- `./scripts/zig.sh build host-tests`
- `./scripts/zig.sh build spec-tests`
- `./scripts/zig.sh build spec-conformance`
- `./scripts/zig.sh build zigos-native-smoke-test`
- `./scripts/zig.sh build benchmark`

Host-side native tests enter through `src/native_host_test.zig` and delegate to `src/tests/host/`. Deeper subsystem coverage lives beside each native module under `src/native/`.

## Repository Map

- `src/main.zig`: thin kernel entry and export surface
- `src/kernel/boot/profiles/zigos_native.zig`: only supported boot profile
- `src/native/`: native principals, capabilities, runtime, mediation, services, storage, sync, recovery, and UX
- `src/native/demo/`: seeded demo bundles and scenario-world flows used by explicit conformance demos
- `src/tests/`: organized host and spec test suites, with thin root entrypoints kept at `src/*.zig`
- `src/tools/`: Zig helper binaries that need to share the `src/` module root
- `src/kernel/net/`: low-level networking and device transport
- `build.zig`: native-only build graph
- `scripts/`: repo entrypoints for setup, build, run, and verification
- `tools/`: host-side support utilities such as spec coverage checks

## Status

The repository no longer builds or ships the old POSIX-like shell, POSIX-style syscall ABI, or VFS-rooted userland pipeline. Legacy support is modeled as explicit compatibility environments rather than as part of the native platform.

- `./scripts/zig.sh build kernel`
- `./scripts/zig.sh build spec-conformance`
- `./scripts/zig.sh build host-tests`
- `./scripts/zig.sh build zigos-native-smoke-test`
- `./scripts/zig.sh build benchmark`

Storage-volume persistence remains covered by host-side native tests through `src/native/storage/storage_volume.zig`.
The remaining freestanding entry surface is the native typed syscall dispatcher plus the native-only verification targets above.
