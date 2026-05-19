# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current
tree builds a freestanding x86 kernel, embeds a catalog of native userspace
service and component images, boots under QEMU with a dedicated native storage
image, and verifies capability, service, storage, recovery, and production
readiness behavior through Zig tests plus QEMU proof runs.

The project is no longer organized around a POSIX shell, POSIX syscall ABI, or
VFS-rooted userland. Compatibility is modeled as an explicit native service
boundary, while the primary platform model is capability-first, task-scoped,
and service-driven.

## Current State

- `build.zig` exposes native kernel, userspace image, QEMU run, smoke,
  recovery, benchmark, ISO, lint, host-test, spec-test, and readiness gates.
- Kernel profiles are built from `src/main.zig` with boot profile options for
  the native bootstrap path, recovery mode, benchmark mode, and native smoke
  fault-injection variants.
- Embedded userspace images are generated from
  `src/native/task/userspace_registry.zig` and packed into a build-time archive
  plus a production artifact manifest.
- The native service layer under `src/native/` contains the current principal,
  capability, syscall, task runtime, session, driver, storage, sync, policy,
  platform, and demo proof code.
- The driver restart proof now checks that storage I/O works before restart,
  stale authority is rejected after a process-generation change, stale DMA port
  access is rejected, a replacement storage session rebinds with a new DMA
  domain, and storage I/O works after restart.
- `spec/coverage.json` currently records 60 required requirements and marks all
  60 as `enforced`.
- `spec/production_readiness.json` currently tracks six production-readiness
  workstreams: two `prod_candidate` tracks and four `prototype` tracks.

The spec contract is now the machine-readable manifest in
`spec/coverage.json`; this checkout does not require a separate prose spec
document or secondary checker runtime for local verification.

## Architecture

Zigos is split into a small freestanding kernel, a typed native kernel API, and
an embedded native userspace service graph. The boot path starts in the
architecture and kernel layers, selects a boot profile, initializes core kernel
runtime state, and then hands off to the native bootstrap path. Native services
and components are compiled as freestanding ELF images, packed into a generated
archive, measured against a production artifact manifest, and loaded by the
native task runtime.

The kernel owns low-level platform concerns: boot setup, interrupts, timers,
memory protection, basic devices, typed syscall dispatch, and data-plane
boundaries for drivers and networking. The native kernel API exposes those
facilities through explicit capabilities, endpoints, shared memory objects,
device broker calls, component ports, and operation descriptors rather than a
POSIX syscall table.

The native layer is organized around services. Session bootstrap constructs the
service graph, binds bootstrap capabilities, starts supervised userspace
services, and proves service-path behavior for storage, compositor, sync,
syscall, and driver-recovery flows. Policy, storage, sync, platform, package,
notification, indexing, media/print, and compatibility behavior live as native
services under `src/native/`. Userspace code under `src/userspace/` provides the
freestanding runtime and entry points for those embedded service images.

Verification is part of the architecture rather than a separate afterthought.
Host tests exercise native logic without QEMU, spec tests tie behavior back to
machine-readable requirement coverage, and QEMU proof profiles validate boot,
smoke, recovery, storage durability, driver restart, and benchmark paths against
observable boot markers.

## Design Decisions

- Native-only userspace is the primary platform model. POSIX compatibility is
  treated as an explicit service boundary, not as the organizing ABI for the
  system.
- Capabilities are the unit of authority. Tasks receive scoped capabilities and
  communicate through typed endpoints, component ports, shared memory, and
  service contracts instead of ambient global namespaces.
- Services are supervised and restart-aware. Driver and service paths include
  generation checks, authority rebinding, stale-port rejection, and recovery
  proofs so restart behavior is modeled as a first-class lifecycle.
- Userspace artifacts are build-time inputs to the kernel profile. The generated
  image archive and artifact manifest make boot contents explicit, measurable,
  and testable.
- Storage and update behavior prefer proofable recovery paths. The native store,
  checkpoint logic, rollback-slot checks, and QEMU durability tests are designed
  to make interrupted boots and bad roots visible in automation.
- Platform policy is data-driven where possible. Coverage and production
  readiness manifests record requirement evidence and track the gap between
  prototype enforcement and production confidence.
- The build graph is the public workflow surface. `build.zig` and the shell
  wrappers expose repeatable local and CI entrypoints instead of relying on
  ad hoc commands.

## Requirements

Use the pinned toolchain and repo entrypoints:

- Zig `0.16.0` exactly
- `nasm`
- `qemu-system-x86_64`
- ShellCheck for shell lint
- Optional: `zlint` and `actionlint`; CI installs both, and local lint uses
  them when available

For ISO and full disk-image workflows, install the tools verified by
`scripts/setup-deps.sh`:

- GRUB `mkrescue`
- `xorriso`
- `mtools`
- `dosfstools`
- `e2fsprogs`

The repo includes `.tool-versions` and `mise.toml` pins. `build.zig` rejects any
Zig version other than `0.16.0`. Run Zig through `./scripts/zig.sh` so the repo
can resolve `ZIG_BIN`, the active Zig, `mise`, or local fallback binaries in the
right order.

## Setup

```bash
bash scripts/setup-deps.sh
```

The setup script supports macOS through Homebrew and Linux through `apt`, `dnf`,
or `pacman`.

## Quick Start

```bash
# Confirm the pinned Zig version.
./scripts/zig.sh version

# Build the native kernel and embedded userspace archive.
./scripts/zig.sh build kernel

# Build or preserve the native storage image used by QEMU run targets.
./scripts/zig.sh build native-store-image

# Run the native bootstrap kernel in QEMU.
./scripts/zig.sh build run

# Equivalent convenience wrapper for the default run path.
./run.sh
```

`run` and `run-zigos-native` attach `build/native-store.img`. Build targets that
boot or package the system depend on the generated userspace archive from the
registry before they consume the kernel artifact.

## Build And Verification

Useful build targets:

| Command | What it does |
| --- | --- |
| `./scripts/zig.sh build userspace-images` | Builds freestanding userspace ELF images and the generated image archive. |
| `./scripts/zig.sh build kernel` | Builds the default native-only kernel profile. |
| `./scripts/zig.sh build kernel-zigos-native` | Builds the native bootstrap kernel profile. |
| `./scripts/zig.sh build kernel-recovery` | Builds the freestanding recovery-mode kernel profile. |
| `./scripts/zig.sh build kernel-benchmark` | Builds the benchmark kernel profile. |
| `./scripts/zig.sh build native-store-image` | Builds or preserves `build/native-store.img`. |
| `./scripts/zig.sh build iso` | Builds a bootable ISO at `build/os.iso`. |
| `./scripts/zig.sh build clean` | Removes generated build outputs and Zig caches. |
| `./scripts/zig.sh build -Dclean-dry-run=true clean` | Prints the cleanup set without deleting files. |

Useful verification targets:

| Command | What it does |
| --- | --- |
| `./scripts/zig.sh build lint` | Runs Zig formatting, optional zlint, ShellCheck, and optional actionlint. |
| `./scripts/zig.sh build host-tests` | Runs host-side native logic and userspace runtime tests. |
| `./scripts/zig.sh build test-roots` | Checks that Zig files with tests are reachable from the build roots. |
| `./scripts/zig.sh build prod-readiness` | Validates `spec/production_readiness.json` and production-readiness source markers. |
| `./scripts/zig.sh build spec-tests` | Runs the spec coverage gate and native spec tests. |
| `./scripts/zig.sh build zigos-native-smoke-test` | Runs native QEMU smoke proofs, including tampered manifest, direct artifact tamper, and rollback-slot failure variants. |
| `./scripts/zig.sh build driver-restart-qemu-test` | Proves userspace storage driver restart and rebinding without reboot. |
| `./scripts/zig.sh build storage-durability-qemu-test` | Reuses one native-store image across forced reboots and proves storage recovery after an interrupted boot and one bad root slot. |
| `./scripts/zig.sh build recovery-qemu-test` | Proves the recovery profile can perform break-glass repair operations. |
| `./scripts/zig.sh build benchmark` | Runs the native benchmark suite and checks thresholds. |
| `./scripts/zig.sh build verify` | Runs the CI-aligned local gate: lint, kernel build, host tests, spec tests, and production-readiness checks. |

Optional QEMU gates can be added to `verify`:

```bash
./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify
```

## Verification Model

Host-side native tests enter through `src/native_host_test.zig` and delegate to
`src/tests/host/`. Spec-oriented tests enter through `src/zigos_spec_test.zig`
and delegate to `src/tests/spec/`.

The coverage manifest in `spec/coverage.json` maps requirement IDs to
implementation anchors and test evidence. The production-readiness manifest in
`spec/production_readiness.json` tracks the separate work needed to move
enforced prototype behavior toward production proof, such as real hardware,
fault injection, scale, transport, and operational validation.

QEMU proof runs are script-backed:

- `scripts/run-zigos-native-smoke.sh`
- `scripts/run-storage-durability-qemu.sh`
- `scripts/run-kernel-recovery.sh`
- `scripts/run-kernel-benchmark.sh`
- `scripts/qemu-harness.sh`

Shared boot marker expectations live in `src/native_smoke_markers.zig` and
`src/kernel/boot/markers.zig`.

## Repository Map

- `src/main.zig`: kernel entry/export surface and typed syscall trap dispatch.
- `src/arch/`: architecture-specific assembly, syscall trap glue, and linker
  scripts.
- `src/boot/`: boot assembly and GRUB config used by kernel and ISO builds.
- `src/kernel/`: low-level boot, interrupt, timer, memory, driver, network, and
  utility code.
- `src/kernel/boot/profiles/`: native, recovery, and benchmark boot profiles.
- `src/native/core/`: shared native IDs, principals, ABI helpers, signing,
  hashing, cursors, and fixed-table utilities.
- `src/native/kernel_api/`: typed kernel API, component ports, capabilities,
  endpoints, shared memory, device broker, and syscall surface.
- `src/native/task/`: task runtime, userspace loading/execution, bootstrap
  mailboxes, service protocols, generated image fixtures, and boot image
  registry.
- `src/native/session/`: session manager, service graph construction,
  bootstrap paths, supervisor behavior, and service-path proofs.
- `src/native/drivers/`: userspace driver runtime, storage/network driver
  tasks, device inventory, and driver protocol code.
- `src/native/storage/`: object store, workspace/storage services, checkpoint
  logic, storage volume backend, file bridge, and IPC paths.
- `src/native/sync/`: device graph, sync service, sync state, adapters, network
  policy, and transport harnesses.
- `src/native/policy/`: policy objects, manifest fixtures, mediation,
  permission review, enterprise management, and denial explanations.
- `src/native/platform/`: measured boot, attestation, recovery, update health,
  event ledger, compositor/session UX, rendered shell, and platform signals.
- `src/native/services/`: service registry, service authority, package service,
  typed component ABI, notifications, indexing, media/print, and compatibility
  service models.
- `src/native/demo/`: seeded scenario-world flows and demo bootstrap packages.
- `src/userspace/`: freestanding service/component entry points, runtime, and
  linker script for embedded userspace images.
- `src/tests/`: host and spec test suites.
- `src/tools/`: Zig helper binaries that need the `src/` module root.
- `build_support/`: build graph helpers for kernels, QEMU, checks, userspace
  images, and shared build paths.
- `scripts/`: setup, lint, build, QEMU, benchmark, smoke, ISO, and cleanup
  entrypoints.
- `tools/`: host-side Zig utilities for coverage, readiness, test root checks,
  and userspace archive generation.
- `spec/`: machine-readable coverage and production-readiness manifests.
- `benchmarks/`: benchmark baselines and thresholds.
- `.github/`: CI workflows and shared setup action.

## CI

GitHub Actions run these primary jobs:

- lint
- kernel build
- spec conformance
- host tests
- native smoke
- native benchmarks
- ISO build

CI uses `./scripts/zig.sh` and the shared `.github/actions/setup-zigos-ci`
action to install or resolve the pinned toolchain and required dependencies.
