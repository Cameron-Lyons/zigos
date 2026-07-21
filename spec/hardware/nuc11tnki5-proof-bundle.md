# Intel NUC11TNKi5 Authenticated Hardware Proof Bundle

This bundle is the real-machine release proof for the first hardware target.
It is fail-closed: the normal checker rejects a bundle unless the caller
supplies a fresh external challenge and a separately installed trusted
verifier whose executable matches an externally pinned SHA-256 digest.

The proof uses two single-boot captures from the same stable device identity:

1. Boot shipped `build/os.iso`, containing
   `zig-out/bin/kernel-zigos-native.elf`, and capture only that boot in
   `production-serial.log`.
2. Boot `build/os-verification.iso`, containing
   `zig-out/bin/kernel-zigos-native-verification.elf`, and capture only that
   boot in `verification-serial.log`.

Never concatenate reboots or cycle output into either single-boot log. Each
repeated cold boot, warm reboot, device operation, suspend/resume, crash, or
rollback cycle has its own file under `cycles/` and its own digest in the
canonical cycle manifest. QEMU, OVMF, hypervisor, emulator, or virtual-machine
logs are preflight evidence only.

## Bundle contents

Archive the completed bundle under `build/hardware-proofs/nuc11tnki5/`:

- `proof-manifest.txt` uses `format=zigos-nuc11tnki5-proof-v2` and binds the
  fresh `capture_nonce`, stable `device_id`, fixed target/SKU, both log names,
  both ISO/kernel pairs, both marker contracts, every sidecar name, Jujutsu
  change/commit IDs, clean working-copy state, operator, and capture window.
- `device-identity.txt` records the stable device ID, SMBIOS system UUID,
  baseboard serial, and SHA-256 of the TPM endorsement public key.
- `production-serial.log` is one production boot and contains exactly one
  `BOOT:ROLE:production` plus every active production marker.
- `verification-serial.log` is one verification boot and contains exactly one
  `BOOT:ROLE:verification`, every active verification marker, and exactly one
  `ZIGOS:NATIVE:READY`. Its scalar cycle counters are summaries only.
- `cycle-manifest.txt` is the canonical index of individually hashed
  `cycles/*.log` evidence.
- `firmware-settings.txt`, `power-cycle-notes.txt`,
  `attestation-lifecycle.txt`, `artifact-digests.sha256`, and
  `operator-metadata-markers.txt` are bound sidecars.
- `production-attestation.quote` and `production-attestation.sig` are the
  production-role hardware quote and signature for the issued nonce.
- `verification-attestation.quote` and `verification-attestation.sig` are the
  separate verification-role hardware quote and signature for that nonce.
- `capture-statement.txt` is the canonical statement produced after every
  other bundle input is final.

Symlinks are rejected for authenticated inputs. Template placeholders,
emulator text, stale repository IDs, duplicate required keys, and alternate
bundle paths are rejected.

## Canonical cycle evidence

`cycle-manifest.txt` has no comments or blank lines. Its first line is:

```text
format=zigos-nuc11tnki5-cycle-manifest-v1
```

Every following line is:

```text
cycle=<type>|<six-digit-index>|<lowercase-sha256>|cycles/<type>-<six-digit-index>.log
```

Types occur in this fixed order, and indices for each type are contiguous from
`000001`: `cold_boot`, `warm_reboot`, `storage_write_read`, `network_frame`,
`suspend_resume`, `crash_recovery`, `crash_record_persistence`, and
`update_rollback`. Paths and digests must be unique. The `cycles/` directory
must contain exactly the listed log files.

Every cycle log contains exactly one value for this envelope:

```text
format=zigos-nuc11tnki5-cycle-log-v1
capture_nonce=<fresh-64-hex-challenge>
target_id=intel-nuc11tnki5
device_id=<stable-device-id>
cycle_type=<manifest-type>
cycle_index=<manifest-index>
result=pass
```

The checker hashes every cycle log independently and derives the accepted
counts only from valid, unique manifest entries. It requires at least ten cold
boots, ten warm reboots, one hundred storage read/write cycles, one hundred
network frame cycles, twenty suspend/resume cycles, ten crash-recovery cycles,
ten crash-record persistence cycles, and ten update rollback cycles. The
numeric summaries in `power-cycle-notes.txt` and `verification-serial.log`
must exactly equal those derived counts; changing the summaries cannot create
evidence.

## Canonical capture statement and verifier

After all inputs are final,
`scripts/write-nuc11tnki5-capture-statement.sh` writes a fixed-order v1
statement. The statement binds:

- the fresh nonce, fixed target/SKU, stable device ID, and Jujutsu IDs;
- SHA-256 of both single-boot logs and the canonical cycle manifest;
- SHA-256 of both production ISO/kernel and verification ISO/kernel pairs;
- SHA-256 of both active marker contracts;
- SHA-256 of the proof manifest, stable device identity, firmware settings,
  power-cycle notes, attestation lifecycle, artifact digest manifest, and
  operator metadata sidecars; and
- four distinct role inputs: production quote, production signature,
  verification quote, and verification signature.

The checker independently reconstructs this statement and every referenced
hash. It then invokes the configured verifier with the statement path and
digest, nonce, target/device identity, and both role-specific quote/signature
pairs. Successful exit status is insufficient. Standard output must exactly
equal this assertion for the current values, with no extra bytes:

```text
format=zigos-trusted-hardware-verifier-response-v1
result=verified
assertion=signed-response
statement_sha256=<recomputed-statement-sha256>
nonce=<fresh-externally-issued-nonce>
target_id=intel-nuc11tnki5
device_id=<stable-device-id>
production_role=verified
verification_role=verified
```

The verifier is responsible for cryptographically validating both hardware
quotes, signatures, nonce binding, device root, and role measurements before
returning the assertion. The checker requires an absolute, executable,
non-symlink verifier path outside the bundle. Its actual digest must equal
`ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256`; this expected digest is supplied by
release policy outside the proof bundle. The expected fresh nonce is likewise
supplied out of band through `ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE`.

## Production checkpoint and ordering

The production log contains one and only one structured line:

```text
ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=<number> error=none
```

The checker requires measured-boot verified root before that checkpoint, the
checkpoint before `ZIGOS:TASK:SESSION_READY`, and task readiness before
`ZIGOS:NATIVE:READY`. Production evidence must not contain verification-only
markers or images, including the Notes daily-journey fixture.

Hardware fact observations in the verification log must precede their PASS or
dependent markers. Active marker contracts are parsed line by line; commented
text never satisfies a requirement.

## Workflow

Obtain a fresh 32-byte challenge from the external verifier or release
orchestrator, then prepare the skeleton:

```bash
scripts/prepare-nuc11tnki5-hardware-proof.sh \
  --build \
  --nonce <64-lowercase-hex>
```

Fill the identity and sidecars, capture the two single boots, record and hash
the cycle logs, and collect the two role-specific quotes/signatures. Once the
manifest is final, write the statement:

```bash
scripts/write-nuc11tnki5-capture-statement.sh \
  build/hardware-proofs/nuc11tnki5
```

Validate using only external trust configuration:

```bash
ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE=<64-lowercase-hex> \
ZIGOS_HARDWARE_PROOF_VERIFIER=/absolute/path/to/trusted-verifier \
ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256=<externally-pinned-64-hex> \
scripts/check-nuc11tnki5-hardware-proof.sh \
  build/hardware-proofs/nuc11tnki5
```

Without all three external values, normal validation fails. The repository
self-test uses an explicitly configured local verifier solely to exercise pass
and adversarial paths; it is not accepted by the release workflow unless its
digest is deliberately supplied by that test invocation.
