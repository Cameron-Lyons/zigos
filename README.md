# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig, currently
focused on proving one narrow daily-driver slice for notes and documents before
trying to become a general desktop OS. The current tree builds a freestanding
x86-64 kernel, embeds a catalog of ELF64 native userspace service and component
images, boots under QEMU with a dedicated native storage image, and verifies
capability, service, storage, recovery, and production readiness behavior
through Zig tests plus QEMU proof runs.

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
  TPM/secure-enclave/HSM/KMS signing command. Customers obtain
  `zigos-verify-release` and its SHA-256 pin independently of the release;
  the host verifier is deliberately not one of the signed OS targets or a
  trust bootstrap for itself. It checks signatures, revocation, subjects,
  reproducible digests, measurements, and post-quantum rollout policy.
  Ed25519 is the classical signing baseline; production PQC is represented
  by a separate ML-DSA-65 provider boundary with FIPS validation metadata
  and fail-closed verifier requirements.

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
than a POSIX syscall table or monolithic kernel-driver surface.

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

- Zig (pinned in `.tool-versions` and `mise.toml`)
- Jujutsu `jj` (pinned in `.tool-versions` and `mise.toml`)
- `nasm`
- `qemu-system-x86_64`
- A CPU with CPUID, SSE2, long mode, NX, SMEP, SMAP, and UMIP. Zigos rejects
  older x86 CPUs instead of weakening its security contract. GRUB Multiboot2
  enters the bootstrap in 32-bit protected mode; the bootstrap immediately
  installs four-level paging and enters the x86-64 Zig kernel.
- Production hardware must expose a checksum-valid ACPI DMAR table with at
  least 39 DMA address bits, x2APIC interrupt remapping, no x2APIC or DMA-remapping
  firmware opt-out, and a segment-zero VT-d unit covering all remaining PCI
  devices. Boot revokes every discovered PCI bus master, masks INTx and disables
  MSI/MSI-X, installs coherent deny-by-default DMA and interrupt-remapping tables
  across every segment-zero unit, maps only six direction-scoped NVMe regions:
  four queue pages, an independent 32-page bounce window, and one PRP-list page.
  NVMe reads and writes batch up to 128 KiB per command, accept completions only
  when phase, queue, command identifier, and submission-head bounds agree, and
  use invariant-TSC elapsed-time deadlines derived from CRTO/CAP timeout fields
  instead of CPU-speed-dependent loop counts. Fatal, timed-out, failed, or
  ownership-indeterminate queues are contained. When present, the
  I225-LM TX/RX descriptor pages plus
  independent 32-page TX and RX buffer regions in an independent domain, and
  confirms translation on every unit. VT-d command transitions, queued
  invalidations, and blocked-DMA proofs use invariant-TSC elapsed deadlines
  rather than CPU-speed-dependent loop counts. The I225-LM path attaches to the
  firmware-negotiated PHY, publishes the permanent MAC, queues TX without
  completion spinning, contains a stalled oldest TX descriptor after one
  second, and activates only after its requester is confined and the x2APIC is
  ready. It installs one exact-requester VT-d interrupt-remapping entry, programs
  a single-vector MSI message, masks queue causes in the top half, and drains at
  most 63 TX completions or one RX frame per task-side service pass. Malformed
  causes and eight consecutive no-progress interrupts fail closed.
  Native payloads are carried in padded Ethernet frames under the local
  experimental EtherType; service and sync traffic resolves a fixed peer-device
  directory to directed unicast frames, while scoped discovery alone uses
  broadcast. Receive polling accepts only directed or broadcast frames for that
  EtherType. NVMe, PCIe ECAM, I225-LM, ACPI, and VT-d cache-disabled mappings are assigned by one
  page-aligned, capacity-checked kernel MMIO layout whose pairwise non-overlap is
  enforced at compile time. Before
  normal storage attach, the controller must trigger a primary VT-d
  record by attempting
  a write to a reserved but unmapped guard page; the requester, address, direction,
  and unchanged canary are verified before the controller is reset and reused.
  Every later synchronous command polls the same primary records; a DMA fault
  disables the controller and PCI bus mastering and withdraws the storage backend.
- OVMF or edk2-ovmf firmware for every QEMU boot
- ShellCheck for shell lint
- Optional: `zlint` and `actionlint`; CI installs both, and local lint uses
  them when available

For ISO and full disk-image workflows, install the tools verified by
`scripts/setup-deps.sh`:

- x86-64 EFI-capable GRUB `mkrescue` and modules
- `xorriso`
- `mtools`
- `dosfstools`

`build.zig` and `./scripts/zig.sh` reject any Zig version other than the repo
pin. Run Zig through `./scripts/zig.sh` so the repo can resolve `ZIG_BIN`, the
active Zig, `mise`, or local fallback binaries in the right order.
The build accepts only the `x86_64-freestanding-none` target; 32-bit kernels and
userspace images are not compatibility outputs.
All generated optical media are UEFI-only and are rejected unless they contain a
bootable x86-64 EFI El Torito image. The QEMU harness uses OVMF pflash firmware
and exposes boot media through virtio-SCSI instead of a legacy disk controller;
legacy BIOS boot is not a supported execution path.
The installed benchmark ELF retains symbols for diagnostics, while its boot
media contains a separately linked debug-stripped derivative so firmware never
parses the suite's large non-loadable debug sections.
Benchmark captures append a host-derived accelerator record after the guest
exits. Hosted performance CI pins QEMU to KVM and enforces the checked-in cycle
baselines and hard ceilings; local software-emulation runs still validate the
complete report, checksums, summaries, and quality gates, but report cycle
ceilings as not enforced because those measurements are not hardware-comparable.
Native storage boots attach the store through NVMe rather than an emulated
legacy IDE controller, matching the first hardware target and production policy.
After validating the required CPU baseline, the kernel enables EFER.NXE and
maps only its linker-bounded text executable; kernel rodata, embedded images,
mutable state, stacks, heap, physical aliases, and MMIO are NX. Kernel text is
read-only, immutable data is read-only/NX, and mutable memory is writable/NX.
The same pager maps user code read-only/executable while data, mailboxes, and
stacks are NX.
The verification image proves the boundary with a real user-mode instruction-
fetch protection fault before continuing its separate unmapped-memory proof.

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

# Build the production kernel and embedded userspace archive.
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
./scripts/zig.sh build -Doptimize=ReleaseFast userspace-production-images
./scripts/zig.sh build -Doptimize=ReleaseFast kernel
./scripts/zig.sh build native-store-image
./scripts/zig.sh build iso
```

`kernel-zigos-native.elf` and `build/os.iso` are production artifacts. Synthetic
driver crashes, negative isolation proofs, rollback fault matrices, and scripted
desktop journeys live only in `kernel-zigos-native-verification.elf` and
`build/os-verification.iso`. Production embeds 24 stripped userspace ELFs;
verification adds five proof or synthetic-journey images. Build and check that
boundary with:

```bash
./scripts/zig.sh build kernel-role-check
./scripts/zig.sh build iso-verification
```

The full target matrix lives in `CONTRIBUTING.md`, which is the source of truth
for when to use focused checks such as `host-tests`, `spec-tests`,
`release-security-check`, QEMU proofs, and release gates.

Optional QEMU gates can be added to `verify`:

```bash
./scripts/zig.sh build -Dverify-smoke=true -Dverify-benchmark=true verify
```

The first real-machine gate is an Intel NUC11TNKi5 proof bundle. First complete
the phase-A `release-bundle-check` ceremony described below. Once that command
returns, freeze the authenticated release bundle and the exact 33 signed target
files; do not run any generator again. Prepare a fresh proof skeleton bound to
that candidate:

```bash
scripts/prepare-nuc11tnki5-hardware-proof.sh \
  --nonce <fresh-verifier-issued-64-hex> \
  --output build/hardware-proofs/<fresh-name>
```

The proof output must be a fresh empty direct child of
`build/hardware-proofs`; populated directories are never reused across
ceremonies.

Capture one production boot in `production-serial.log`, one verification boot
in `verification-serial.log`, and each repeated hardware cycle in its own
hashed `cycles/*.log`. After filling the stable device identity, sidecars, and
two role-specific hardware quote/signature pairs, write the canonical capture
statement and validate it with an external trusted verifier:

```bash
scripts/write-nuc11tnki5-capture-statement.sh build/hardware-proofs/<fresh-name>
ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE=<fresh-verifier-issued-64-hex> \
ZIGOS_HARDWARE_PROOF_VERIFIER=/absolute/path/to/trusted-verifier \
ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256=<externally-pinned-64-hex> \
ZIGOS_RELEASE_VERIFIER=/absolute/path/to/independently-pinned-zigos-verify-release \
ZIGOS_RELEASE_VERIFIER_SHA256=<externally-pinned-verifier-64-hex> \
ZIGOS_RELEASE_TRUST_ROOT=/absolute/independent/root-metadata.json \
ZIGOS_RELEASE_TRUST_ROOT_SHA256=<pinned-lowercase-sha256> \
ZIGOS_RELEASE_TRUST_STATE=/absolute/persistent/zigos-release-state.json \
  scripts/check-nuc11tnki5-hardware-proof.sh build/hardware-proofs/<fresh-name>
```

The same check is exposed as `./scripts/zig.sh build
-Dhardware-proof-dir=build/hardware-proofs/<fresh-name> hardware-proof` and is
the only dependency of the final, verify-only `release-security-gate`. That
phase uses the five root, state, and independently pinned verifier build
options shown below plus the hardware-proof environment; it never regenerates
or signs release artifacts.

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
fast `release-security-check` gate. A public release has two ordered phases.
`release-security-preflight` runs every mutable audit, fixture, build, smoke,
fault, recovery, sync, and UEFI-QEMU check. `release-bundle-check` depends on
that preflight, creates the candidate, verifies it before publication, then
publishes and statefully verifies its manifest. After the candidate's exact 33
target files and release bundle are frozen, the verify-only
`release-security-gate` rechecks the existing bundle and seals it with the
completed NUC11TNKi5 proof; it has no generator or signer dependency. Public
release provenance must be signed per
DSSE payload through `ZIGOS_RELEASE_DSSE_SIGN_COMMAND` by a
hardware-backed TPM, secure enclave, HSM, or KMS key. The signer key must be
delegated by a root-threshold-signed trust policy whose root metadata and
lowercase SHA-256 digest were obtained independently of the release bundle. The
bundled root copy is consistency evidence, never a trust bootstrap.

Trust metadata is strict JSON: unknown or duplicate fields are rejected. Raw
root metadata has exactly `schemaVersion`, `namespace`, `channel`, `version`,
`minimumPolicyVersion`, `issuedAt`, `expiresAt`, `threshold`, and `keys`; each
root key has `keyId`, `algorithm`, and `publicKey`. The signed trust-policy
payload has exactly `rootVersion`, `policyVersion`, `minimumReleaseSequence`,
`issuedAt`, `expiresAt`, `releaseRole`, `releaseKeys`, `revocations`,
`artifactProfile`, and `pqcPolicy`. Release keys also declare generation,
status, custody, hardware backing, and validity window; revocations bind key ID
and generation. The artifact profile must equal the catalogs in
`src/tools/release_catalog.zig`.

Ed25519 public keys are lowercase hex encodings of the raw 32-byte public key,
and their key ID is the lowercase SHA-256 of those raw bytes. Root policy
thresholds may use multiple distinct signers. The current production generator
and finalizer emit one release signature, so `releaseRole.threshold` must be
exactly `1`. `ZIGOS_RELEASE_DSSE_SIGN_COMMAND` receives the complete DSSE v1
pre-authentication encoding on standard input and must emit only the standard
base64 Ed25519 signature.

The `release-bundle-check` target coordinates eight generator-side evidence
files and two independently rebuilt reproducibility files for exactly 33 OS
targets: nine fixed production artifacts and 24 userspace images. The
independently distributed host verifier is outside that catalog. After both
evidence paths succeed, `release-manifest-finalize` holds a sibling ceremony
lock, verifies a private candidate, atomically publishes the release-key-signed
`release-manifest.dsse.json`, and performs a full stateful verification. That
authenticated manifest is the sole digest authority. Digest projections,
measurements, provenance, and reproducibility evidence are checked for exact
consistency; the SBOM digest and `spdxVersion` are checked, but this verifier
does not claim full SPDX graph-semantic validation.

```sh
export ZIGOS_RELEASE_DSSE_SIGN_COMMAND='/absolute/path/to/hardware-signer'
export ZIGOS_RELEASE_SIGNING_KEY_ID='<derived-lowercase-sha256-key-id>'
export ZIGOS_RELEASE_HARDWARE_BACKED=true
export ZIGOS_RELEASE_SEQUENCE='<strictly-increasing-sequence-for-this-new-candidate>'
export ZIGOS_RELEASE_EXPIRES_AT='<future-unix-timestamp>'

./scripts/zig.sh build -Doptimize=ReleaseFast \
  -Drelease-trust-root=/absolute/independent/root-metadata.json \
  -Drelease-trust-root-sha256=<pinned-lowercase-sha256> \
  -Drelease-trust-policy=/absolute/independent/release-trust-policy.dsse.json \
  -Drelease-trust-state=/absolute/persistent/zigos-release-state.json \
  -Drelease-verifier=/absolute/path/to/independently-pinned-zigos-verify-release \
  -Drelease-verifier-sha256=<externally-pinned-verifier-64-hex> \
  release-bundle-check
```

Run `release-security-preflight` by itself for an early mutable-only check; the
candidate command above always depends on it and cannot bypass it.

From the start of candidate generation through final hardware sealing, the
exact 33 target files and `build/release-security` inputs must be private,
owner-controlled, and quiescent: no process outside the ceremony may replace
them while they are being hashed. Prefer read-only or immutable staging for
those inputs. The fresh hardware-proof sibling remains writable for capture;
it is not one of the verifier's 33 target paths. Verification does not claim
safety against a concurrent writer already authorized as the same host user.

With the completed proof directory and external hardware-proof variables set,
seal the frozen candidate without regenerating it:

```sh
export ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE=<fresh-verifier-issued-64-hex>
export ZIGOS_HARDWARE_PROOF_VERIFIER=/absolute/path/to/trusted-verifier
export ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256=<externally-pinned-64-hex>

./scripts/zig.sh build \
  -Dhardware-proof-dir=build/hardware-proofs/<fresh-name> \
  -Drelease-trust-root=/absolute/independent/root-metadata.json \
  -Drelease-trust-root-sha256=<pinned-lowercase-sha256> \
  -Drelease-trust-state=/absolute/persistent/zigos-release-state.json \
  -Drelease-verifier=/absolute/path/to/independently-pinned-zigos-verify-release \
  -Drelease-verifier-sha256=<externally-pinned-verifier-64-hex> \
  release-security-gate
```

The state directory must already exist, be owned by the effective user, and be
owner-controlled (for example, mode `0700`); an existing state file and adjacent
lock file must also be owner-only. On macOS, all three must have no extended
ACL. The verifier serializes the entire check-and-advance operation
with an adjacent owner-only OS lock file. Back up both state and independently
distributed checkpoints: deleting or replacing local state forgets observed
history, while root `minimumPolicyVersion` and policy
`minimumReleaseSequence` provide the first-use rollback floors. Use a separate
protected state file for each independently pinned release channel.

To verify an already downloaded bundle without regenerating it:

```sh
trusted_verifier=/absolute/path/to/independently-obtained-zigos-verify-release
expected_verifier_sha256=<externally-pinned-verifier-64-hex>
umask 077
verifier_stage="$(mktemp -d "${TMPDIR:-/tmp}/zigos-release-verifier.XXXXXX")"
trap 'rm -rf -- "$verifier_stage"' EXIT
cp "$trusted_verifier" "$verifier_stage/zigos-verify-release"
chmod 0500 "$verifier_stage/zigos-verify-release"
if command -v sha256sum >/dev/null 2>&1; then
  actual_verifier_sha256="$(sha256sum "$verifier_stage/zigos-verify-release" | awk '{print $1}')"
else
  actual_verifier_sha256="$(shasum -a 256 "$verifier_stage/zigos-verify-release" | awk '{print $1}')"
fi
[ "$actual_verifier_sha256" = "$expected_verifier_sha256" ] || exit 1

"$verifier_stage/zigos-verify-release" verify \
  --bundle build/release-security \
  --artifacts . \
  --trusted-root /absolute/independent/root-metadata.json \
  --trusted-root-sha256 <pinned-lowercase-root-sha256> \
  --trust-state /absolute/persistent/zigos-release-state.json
```

This hashes and executes the same private copy, avoiding a path replacement
between pin verification and execution. The repository
`scripts/verify-release-bundle.sh` wrapper automates that flow for maintainers,
but it is not a signed OS target or trust bootstrap; customers must obtain the
wrapper itself from a trusted, pinned source if they rely on it. The verifier
rejects policy or release rollback, authenticated-payload equivocation, clock
rollback, implicit root changes, unknown or repeated threshold signers, path
traversal, and verification-only artifacts. Automatic root rotation is not
claimed; changing the pinned root requires an explicit external migration.

The authenticated trust policy also carries the PQC transition state. FIPS 204
ML-DSA is the required production signature algorithm when the policy reaches
`required`; until a validated ML-DSA verifier is linked, that mode fails closed.

The first real hardware target is Intel NUC 11 Pro Kit `NUC11TNKi5`. QEMU proof
runs remain required preflight evidence, but they do not satisfy the hardware
target gate. Real-machine proof must cover UEFI boot, ACPI, APIC/timer, GOP
framebuffer, USB xHCI input, NVMe block I/O, Intel I225-LM networking,
suspend/resume, compositor framebuffer presentation, crash recovery,
crash-record persistence, and update rollback across power cycles. Required
serial markers live in the production and verification contracts under
`spec/hardware/`. A complete proof is a directory described by
`spec/hardware/nuc11tnki5-proof-bundle.md`, with distinct
`production-serial.log` and `verification-serial.log` single-boot captures,
individually hashed cycle logs, stable identity and lifecycle sidecars, two
role-specific quote/signature pairs, and a canonical capture statement. The
checker independently recomputes every bound SHA-256, derives counts from
unique cycle-manifest entries, rejects emulator-sourced logs, and requires an
external nonce plus a verifier executable matching an externally pinned
digest. The
UEFI preflight entrypoints are `./scripts/zig.sh build uefi-qemu-test` for the
production ISO and `./scripts/zig.sh build uefi-verification-qemu-test` for the
proof image; set `OVMF_CODE` and optionally `OVMF_VARS` if the firmware is not
installed in a standard path. Each QEMU process copies an available variables
template beside its serial log so concurrent boots do not share firmware state.

QEMU proof runs are script-backed:

- `scripts/run-zigos-native-smoke.sh`
- `scripts/run-storage-durability-qemu.sh`
- `scripts/run-kernel-recovery.sh`
- `scripts/capture-kernel-benchmark.sh` (capture helper; `zig build benchmark` runs the strict gate)
- `scripts/run-uefi-boot-test.sh`
- `scripts/qemu-harness.sh`

Shared boot marker expectations live in `src/native_smoke_markers.zig` and
`src/kernel/boot/markers.zig`.

## Repository Map

- `src/main.zig`: kernel entry/export surface and typed native syscall dispatch.
- `src/arch/`: architecture-specific assembly, syscall entry glue, and linker
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
