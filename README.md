# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig, currently
focused on proving one narrow daily-driver slice for notes and documents before
trying to become a general desktop OS. The current tree builds a freestanding
x86 kernel, embeds a catalog of native userspace service and component images,
boots under QEMU with a dedicated native storage image, and verifies capability,
service, storage, recovery, and production readiness behavior through Zig tests
plus QEMU proof runs.

The project is not organized around a POSIX shell, POSIX syscall ABI, or
VFS-rooted userland. The platform model is capability-first, task-scoped,
service-driven, and based on signed typed components with explicit capability
requests.

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
- The first daily-driver slice is Notes/docs: signed native package install,
  workspace and document open, local permission review, object-scoped sharing,
  local-first sync, update rollback, recovery, and package removal are exercised
  together by the rendered-shell production journey.
- Local-first sync is modeled as core OS behavior: trusted device graph,
  durable inbound/outbound frame queues, replay rejection, offline edits,
  explicit conflict review, object-scoped sharing, revocation enforcement, and
  two-node QEMU proof runs with separate native stores.
- The driver model treats storage, network, USB controllers, GPU/display,
  media/print, input, and compositor-facing device policy as restartable
  userspace claims behind capability-scoped IOMMU DMA domains or brokered DMA
  buffers. Kernel device code is limited to bootstrap inventory shims and the
  storage bootstrap broker needed to hand early block devices to userspace.
- The driver restart proof now checks that storage I/O works before restart,
  the storage driver has a programmed DMA domain and brokered DMA buffer, stale
  authority/DMA/port access is rejected after a process-generation change, a
  replacement storage session rebinds with a new DMA domain, and storage I/O
  works after restart.
- `spec/coverage.json` currently records 59 required requirements and marks all
  59 as `enforced`.
- `spec/production_readiness.json` currently pins one first hardware target
  (`intel-nuc11tnki5`) and tracks nine production-readiness workstreams: one
  `prod_ready` track, three `prod_candidate` tracks, four `prototype` tracks,
  and one blocked real hardware track.
- The secure-by-design release gate is `blocked` until the real NUC11TNKi5
  hardware proof bundle passes. Release artifacts are measured, DSSE
  in-toto/SLSA provenance is generated through a hardware-backed
  TPM/secure-enclave/HSM/KMS signing command, and customers get a native
  `zigos-verify-release` verifier for signatures, revocation, subjects,
  reproducible digests, measurements, and post-quantum rollout policy. The
  `ed25519+ml-dsa65` path remains a preview, not a production FIPS 204
  implementation; production PQC is represented by a separate ML-DSA-65
  provider boundary with FIPS validation metadata and fail-closed verifier
  requirements.

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
memory protection, bootstrap console/inventory shims, typed syscall dispatch,
and data-plane exclusion boundaries for devices and subsystems. Storage,
network, USB, GPU/display, media/print, input, and compositor-facing device
policy live as restartable userspace driver/service claims behind IOMMU DMA
domains, brokered DMA buffers, explicit capabilities, endpoints, shared memory
objects, device broker calls, component ports, and operation descriptors rather
than a POSIX syscall table or legacy kernel-driver surface.

The native layer is organized around services. Session bootstrap constructs the
service graph, binds bootstrap capabilities, starts supervised userspace
services, and proves service-path behavior for storage, compositor, sync,
syscall, and driver-recovery flows. Policy, storage, sync, platform, package,
notification, indexing, and media/print behavior live as native services under
`src/native/`. Userspace code under `src/userspace/` provides the
freestanding runtime and entry points for those embedded service images.

Verification is part of the architecture rather than a separate afterthought.
Host tests exercise native logic without QEMU, spec tests tie behavior back to
machine-readable requirement coverage, and QEMU proof profiles validate boot,
smoke, recovery, storage durability, driver restart, and benchmark paths against
observable boot markers.

## Design Decisions

- Native-only userspace is the platform model. Apps are signed typed components
  with explicit interfaces and capability requests, not compatibility-wrapped
  foreign binaries.
- The product path starts with one daily-driver Notes/docs slice. Storage, sync,
  sharing, recovery, updates, and package install must become excellent there
  before Zigos broadens into a general desktop environment.
- Capabilities are the unit of authority. Tasks receive scoped capabilities and
  communicate through typed endpoints, component ports, shared memory, and
  service contracts instead of ambient global namespaces.
- Identity is passwordless and device-bound. Zigos models
  [FIDO-style passkeys](https://fidoalliance.org/passkeys/), recovery keys,
  hardware roots, and threshold recovery; administration is delegated through
  scoped capability bundles rather than a root or superuser account.
- Objects, not files, are the primary user-data model. Every native user-data
  object is typed, versioned, signed, capability-scoped, sync-aware,
  history-bearing, and share-policy-aware; workspace entries and file bridges
  are import/export projections rather than raw path authority.
- Networking is modeled as data egress, not app-owned sockets. Apps request to
  sync an object with a principal, call a named service, or publish a declared
  event type; raw sockets and packet I/O stay behind privileged driver and
  service boundaries.
- Userspace drivers are the rule, not the exception. Kernel-side device code is
  limited to discovery, fail-closed bootstrap shims, and broker hooks; storage,
  network, USB, GPU/display, media/print, input, and compositor-facing policy
  must bind through signed restartable userspace services with explicit device
  authority and IOMMU/brokered DMA.
- Services are supervised and restart-aware. Driver and service paths include
  generation checks, authority rebinding, brokered DMA-buffer invalidation,
  stale-port rejection, and recovery proofs so restart behavior is modeled as a
  first-class lifecycle.
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
- OVMF or edk2-ovmf firmware for `uefi-qemu-test`
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

The most common local gate is:

```bash
./scripts/zig.sh build verify
```

The most common build artifacts are:

```bash
./scripts/zig.sh build userspace-images
./scripts/zig.sh build kernel
./scripts/zig.sh build native-store-image
./scripts/zig.sh build iso
```

The full target matrix lives in `CONTRIBUTING.md`, which is the source of truth
for when to use focused checks such as `host-tests`, `spec-tests`,
`release-security-check`, QEMU proofs, and release gates.

Optional QEMU gates can be added to `verify`:

```bash
./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify
```

The first real-machine gate is an Intel NUC11TNKi5 proof bundle. Prepare the
bundle skeleton and exact artifact digests with:

```bash
scripts/prepare-nuc11tnki5-hardware-proof.sh --build
```

After the NUC run fills `build/hardware-proofs/nuc11tnki5/serial.log`,
`proof-manifest.txt`, firmware settings, and power-cycle notes, validate it
with:

```bash
scripts/check-nuc11tnki5-hardware-proof.sh build/hardware-proofs/nuc11tnki5
```

The same check is exposed as `./scripts/zig.sh build hardware-proof` and is a
hard dependency of `./scripts/zig.sh build release-security-gate`.

## Verification Model

Host-side native tests enter through `src/native_host_test.zig` and delegate to
`src/tests/host/`. Spec-oriented tests enter through `src/zigos_spec_test.zig`
and delegate to `src/tests/spec/`.

The coverage manifest in `spec/coverage.json` maps requirement IDs to
implementation anchors and test evidence. The production-readiness manifest in
`spec/production_readiness.json` tracks the separate work needed to move
enforced prototype behavior toward production proof, such as real hardware,
fault injection, scale, transport, and operational validation.

The secure-by-design release gate is part of the production-readiness manifest
and is validated by `./scripts/zig.sh build prod-readiness`, which also runs the
fast `release-security-check` gate. Public security releases must pass
`./scripts/zig.sh build release-security-gate`, covering fuzzing, fault
injection, reproducible builds, DSSE-wrapped SBOM/provenance, threat-model
tests, memory-safety audits for unsafe Zig and kernel sections, crash dump
redaction, the vulnerability disclosure process in `SECURITY.md`, and the
completed NUC11TNKi5 real-hardware proof bundle. Public release provenance must
be signed per DSSE payload through
`ZIGOS_RELEASE_DSSE_SIGN_COMMAND` by a hardware-backed TPM, secure enclave,
HSM, or KMS key and verified with `zig-out/bin/zigos-verify-release
build/release-security .` before distribution.
The release keyring also carries the 2026 PQC transition policy: FIPS 203
ML-KEM is reserved for key establishment, FIPS 204 ML-DSA is the production
signature path once a validated provider is linked, and FIPS 205 SLH-DSA is the
hash-based diversity path for long-lived or recovery roots. `ZIGOS_RELEASE_PQC_MODE`
defaults to `shadow` and may move through `canary` to `required`; required mode
is rejected unless the verifier can validate production ML-DSA signatures from
the published keyring.

The first real hardware target is Intel NUC 11 Pro Kit `NUC11TNKi5`. QEMU proof
runs remain required preflight evidence, but they do not satisfy the hardware
target gate. Real-machine proof must cover UEFI boot, ACPI, APIC/timer, GOP
framebuffer, USB xHCI input, NVMe block I/O, Intel I225-LM networking,
suspend/resume, compositor framebuffer presentation, crash recovery,
crash-record persistence, and update rollback across power cycles. Required
serial markers live in
`spec/hardware/nuc11tnki5-required-markers.txt`, and captured logs can be
checked with `scripts/check-nuc11tnki5-hardware-proof.sh`. A complete proof is
a directory described by `spec/hardware/nuc11tnki5-proof-bundle.md`, with
`serial.log`, `firmware-settings.txt`, `power-cycle-notes.txt`, and
`artifact-digests.sha256`. The checker rejects emulator-sourced logs and
requires the real-hardware metadata markers, the current repo commit,
`repo_dirty_files=0`, and the target cycle counters. The
UEFI preflight entrypoint is `./scripts/zig.sh build uefi-qemu-test`; set
`OVMF_CODE` and optionally `OVMF_VARS` if the firmware is not installed in a
standard path.

QEMU proof runs are script-backed:

- `scripts/run-zigos-native-smoke.sh`
- `scripts/run-storage-durability-qemu.sh`
- `scripts/run-kernel-recovery.sh`
- `scripts/run-kernel-benchmark.sh`
- `scripts/run-uefi-boot-test.sh`
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
  typed component ABI, notifications, indexing, and media/print service models.
- `src/native/sdk/`: native app developer SDK with component ABI helpers,
  typed IDL/codegen, manifest linting, package signing, simulator APIs,
  UI/accessibility primitives, permission review harnesses, object-store/sync
  facades, and generated-image fixtures.
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
