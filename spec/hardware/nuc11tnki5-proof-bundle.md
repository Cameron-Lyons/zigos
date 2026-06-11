# Intel NUC11TNKi5 Hardware Proof Bundle

This bundle is the release gate for the first real hardware target. QEMU,
OVMF, emulator, or virtual-machine logs are preflight evidence only and must
not be archived as NUC11TNKi5 hardware proof.

Archive a completed run under `build/hardware-proofs/nuc11tnki5/` with these
files:

- `proof-manifest.txt`: key/value manifest tying the bundle to
  `intel-nuc11tnki5`, `NUC11TNKi5`, `real_hardware`, `serial.log`, the sidecar
  files, the marker contract, the current repo commit, a clean
  `repo_dirty_files=0` state, capture time, and operator.
- `serial.log`: concatenated serial output, framebuffer transcription, or HDMI
  capture transcript from the Intel NUC 11 Pro Kit `NUC11TNKi5`, plus the
  finalized operator metadata marker lines after the sidecars are filled.
- `firmware-settings.txt`: BIOS/UEFI version, boot mode, Secure Boot state,
  storage mode, wake/suspend settings, and any changed firmware options.
- `power-cycle-notes.txt`: operator notes for the ten cold boots, ten warm
  reboots, twenty suspend/resume cycles, ten induced crash-recovery cycles,
  ten crash-record persistence checks, and ten update rollback power cycles.
- `artifact-digests.sha256`: SHA-256 digest lines for the exact ISO or USB
  image, kernel, userspace archive, production artifact manifest, policy, and
  driver-set artifacts used for the run.

`serial.log` must include every subsystem and booted production-evidence marker
from `nuc11tnki5-required-markers.txt` as exact lines. The booted evidence
section covers generated userspace startup, service IPC, permission review,
sync replication/restart, driver restart/rebind with programmed DMA-domain and
brokered-buffer evidence, compositor presentation, persisted crash diagnostics,
and update rollback health checks from the same real hardware run. The log must
also include these
metadata markers:

```text
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:EVIDENCE_SOURCE:REAL_HARDWARE
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:BOARD_SKU:NUC11TNKi5
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:PROOF_MANIFEST:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FIRMWARE_SETTINGS:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:POWER_CYCLE_NOTES:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ARTIFACT_DIGESTS:RECORDED
```

`serial.log` must also include numeric counters meeting the minimums encoded in
`src/native/platform/hardware_target.zig`:

```text
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:COLD_BOOTS:10
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:WARM_REBOOTS:10
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:STORAGE_WRITE_READ_CYCLES:100
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NETWORK_FRAME_CYCLES:100
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SUSPEND_RESUME_CYCLES:20
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECOVERY_CYCLES:10
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECORD_PERSISTENCE_CYCLES:10
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UPDATE_ROLLBACK_CYCLES:10
```

Prepare the bundle skeleton and exact artifact digests with:

```bash
scripts/prepare-nuc11tnki5-hardware-proof.sh --build
```

The preparation script writes TODO-bearing sidecar templates on purpose. The
checker rejects placeholders, stale or dirty repo metadata, missing
`proof-manifest.txt` fields, low sidecar counters, emulator/OVMF/QEMU text, and
artifact digest manifests that omit the boot ISO, native kernel, required
userspace service images, production readiness manifest, release artifact
manifest, or marker contract.

Validate the completed bundle with:

```bash
scripts/check-nuc11tnki5-hardware-proof.sh build/hardware-proofs/nuc11tnki5
```
