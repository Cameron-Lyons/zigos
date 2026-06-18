# Intel NUC11TNKi5 Hardware Proof Bundle

This bundle is the release gate for the first real hardware target. QEMU,
OVMF, emulator, or virtual-machine logs are preflight evidence only and must
not be archived as NUC11TNKi5 hardware proof.

Archive a completed run under `build/hardware-proofs/nuc11tnki5/` with these
files:

- `proof-manifest.txt`: key/value manifest tying the bundle to
  `intel-nuc11tnki5`, `NUC11TNKi5`, `real_hardware`, `serial.log`, the sidecar
  files, the marker contract, `repo_vcs=jj`, the current Jujutsu change ID and
  commit ID, a clean `repo_dirty_files=0` state, preparation/capture times, and
  operator.
- `serial.log`: concatenated serial output, framebuffer transcription, or HDMI
  capture transcript from the Intel NUC 11 Pro Kit `NUC11TNKi5`, plus the
  finalized operator metadata marker lines after the sidecars are filled.
- `firmware-settings.txt`: BIOS/UEFI version, `boot_mode=UEFI`, explicit
  Secure Boot state (`enabled`, `disabled`, or
  `disabled-for-local-proof-media`), `storage_mode=nvme`, wake/suspend
  settings, and any changed firmware options.
- `power-cycle-notes.txt`: operator notes for the ten cold boots, ten warm
  reboots, twenty suspend/resume cycles, ten induced crash-recovery cycles,
  ten crash-record persistence checks, and ten update rollback power cycles.
- `attestation-lifecycle.txt`: operator and verifier notes for the
  real-hardware attestation root rotation, active generation, revoked
  generation count, stale/revoked-generation rejection, stale-attestation
  verifier rejection, bound verifier metadata digest, and attestation request
  digest.
- `artifact-digests.sha256`: SHA-256 digest lines for the exact ISO or USB
  image, kernel, userspace archive, production artifact manifest, release
  policy artifacts, and driver image artifacts used for the run.

The sidecar timestamps are part of the same capture window as the proof
manifest: `power-cycle-notes.txt` cannot start before `prepared_at_utc` or
finish after `captured_at_utc`, and `attestation-lifecycle.txt` cannot report a
capture time outside that interval.

`serial.log` must include every subsystem, concrete hardware fact, and booted
production-evidence marker from `nuc11tnki5-required-markers.txt` as exact
lines. Concrete hardware fact markers must appear before the subsystem PASS
markers or booted production-evidence markers that depend on them. The hardware
fact section preserves the observations behind the PASS
markers: SMBIOS SKU match, Multiboot memory map, RSDP/MADT/FADT discovery,
APIC timer interrupt delivery, GOP scanout, xHCI boot-keyboard reports, NVMe
write/read completion, I225-LM frame interrupts, suspend/resume power cycles,
crash-record reboot persistence, update rollback power cycles, and attestation
root lifecycle proof from a real-target root rotation/revocation run whose
verifier rejects stale attestations with request-bound verifier metadata. The
booted evidence section covers generated userspace startup, service IPC,
permission review, sync replication/restart, driver restart/rebind with
programmed DMA-domain, brokered-buffer, broker-revocation, republish evidence,
and accelerator queue ownership plus completion-interrupt evidence, compositor
presentation, persisted crash diagnostics, update rollback health checks, and
the Notes daily-driver lifecycle plus typed editor edit/sync/recovery markers
from the same real hardware run. The log must also include these metadata
markers:

```text
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:EVIDENCE_SOURCE:REAL_HARDWARE
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:BOARD_SKU:NUC11TNKi5
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:PROOF_MANIFEST:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FIRMWARE_SETTINGS:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:POWER_CYCLE_NOTES:RECORDED
ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ARTIFACT_DIGESTS:RECORDED
```

`attestation-lifecycle.txt` must include exact key/value evidence that matches
the typed proof requirements: `target_id=intel-nuc11tnki5`,
`evidence_source=real_hardware`, nonempty `operator`, RFC3339-style
`captured_at_utc`, nonempty `provider` and `root_key_id`, positive
`initial_generation`, `active_generation` greater than `initial_generation`,
positive `revoked_generation_count`, `stale_generation_rejected=true`,
`revoked_generation_rejected=true`, `verifier_rejected_stale_attestation=true`,
`verifier_metadata_digest_bound=true`, 64-hex `verifier_metadata_digest`,
64-hex `attestation_request_digest`, and nonempty `notes`.

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
generated `operator-metadata-markers.txt` contains the exact real-hardware
source, board SKU, manifest, firmware, power-cycle, and artifact-digest marker
lines to append after the sidecars are completed. The checker rejects
placeholders, stale Jujutsu change IDs, stale commit IDs, dirty
repo metadata, missing `proof-manifest.txt` fields, missing or malformed
attestation lifecycle fields, low sidecar counters, sidecar counters that
disagree with `serial.log`, reversed manifest, attestation lifecycle, or
power-cycle timestamps, alternate serial log paths, marker contracts, or
sidecar paths, missing concrete hardware fact markers including attestation
root lifecycle evidence from the typed proof path, duplicate required
markers or cycle-counter lines, duplicate sidecar keys, invalid Secure Boot
values, non-NVMe storage mode, emulator/OVMF/QEMU text, artifact digest
manifests that omit the boot ISO, native kernel, required userspace service
images, release policy artifacts, production readiness manifest, release
artifact manifest, or marker contract, duplicate artifact digest entries for
required paths, and malformed artifact digest rows or digest values that do not
match the checked artifact root.

Validate the completed bundle with:

```bash
scripts/check-nuc11tnki5-hardware-proof.sh build/hardware-proofs/nuc11tnki5
```
