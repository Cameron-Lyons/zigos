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
- Shared handle arenas retire slots at generation exhaustion instead of wrapping
  into stale authority. Arena resets and index rebuilds preserve retired slots;
  endpoint table reset also preserves generation history. Replacement keeps the
  last valid handle intact when it cannot advance, and callers skip exhausted
  slots or return capacity errors. Task restore checks destinations before any
  retirement or grant changes. The 64-bit handle layout and resident memory
  ceilings are unchanged. The pasteboard, capture, network session, personal context,
  backup, and media/print tables now use the same checked generation limit. They
  preserve exhausted records and skip them during reuse, returning capacity
  errors when no reusable slot remains. The media/print completion queue preserves order
  while skipping exhausted jobs. Pasteboard revocation checks both the source
  task and principal. These guarantees apply within each table or arena's lifetime.
- The first daily-driver slice is Notes/docs: signed native package install,
  workspace and document open, local permission review, object-scoped sharing,
  local-first sync, update rollback, recovery, and package removal are exercised
  together by the rendered-shell production journey.
- Document saves in that journey acknowledge success only after a device
  checkpoint completes. Write failures keep the editor's draft pending; retries
  reuse its version, and stale editors cannot replace a newer document version.
  A bounded document-scoped endpoint protocol now has a userspace save client
  and a native storage backend, with host tests for durable receipts, retry,
  backpressure, revocation, and object/path scope. The Notes event loop captures
  Ctrl+Enter snapshots, sends bounded batches, and waits for durable receipts.
  The same channel loads one immutable version in bounded chunks before Notes
  accepts queued input. Loads reject changed revisions, revoked access,
  oversized documents, and text the current renderer cannot represent, while
  preserving an existing draft. Session opening now validates existing scoped
  authority, owns the channel's metadata, and publishes the opening binding
  before the app's first instruction. Launch offers and document channels hold
  a storage-service vault lease and sealed-key fingerprint instead of a raw
  signing seed. Each new save checks current signing policy, lease expiry,
  revocation, service ownership, and key binding before publishing a version.
  The vault signs bounded canonical metadata without exporting its key.
  A lazy four-channel pool services at most
  two frames or replies per dispatch, preserves suspended sessions, and cancels
  queued saves when either endpoint or task is retired. Editors keep their text
  and save state on each task's stack, and prepared bindings survive sibling
  dispatches through the shared mailbox. Boot verification runs two Notes tasks
  with distinct documents through modeled keyboard input, independent durable
  saves, and continued editing after one task retires. Launch preparation keeps
  the task off the run queue while permission review provisions scoped grants.
  Session activation binds the document, creates its window, and provisions UI
  authority before scheduling; failure retires the task and its resources and
  restores focus. Retiring a task releases its demand-paged stack while sibling
  tasks keep their shared page tables. Boot verification repeats failed
  activation beyond the stack-slot limit and checks physical page reclamation.
  The compositor's Open and Cancel controls now consume a session-owned,
  one-use document offer over a bounded endpoint channel. The session rechecks
  permissions and document identity before activation, rejects replays, and
  retires cancelled preparations. The 256-byte mailbox uses a typed UI channel
  for either a launcher or an editor. Cold-boot and reboot verification exercise
  these controls through the compositor ELF with modeled keyboard input.
  Native ABI v17 copies canonical text snapshots from validated task memory;
  the compositor owns each accepted revision and rejects conflicting updates.
  The native boot path now maps the firmware framebuffer and draws document
  text, cursors, unsaved state, and selected Open/Cancel controls. Later frames
  write only changed cells. Notes shows save progress, confirmed durable saves,
  retryable write failures, denied access, conflicting document changes, and
  unavailable storage. Later edits invalidate the saved label; failed saves
  retain the draft, and only an explicit retry resubmits a failed barrier.
  Notes supports insertion, Backspace and Delete at the cursor, arrow movement
  between characters and visible wrapped rows. Home/End reach the current visual
  row, Ctrl+Home/End reach document boundaries, and Page Up/Down move by the
  visible viewport with one row of overlap. Vertical movement remembers its
  column across shorter rows. Shift extends selection
  with these navigation keys, and Ctrl+A selects the document. Typing replaces
  the highlighted range; Backspace and Delete remove it. Navigation and selection
  preserve saved state; edits remain staged until Ctrl+Enter. The compositor
  scrolls wrapped text to keep the cursor visible without retaining another
  editor buffer. Ctrl+Z undoes edits and Ctrl+Shift+Z redoes them, restoring the
  cursor and selection. Task-local history retains up to 32 edit groups and
  1 KiB of changed text within a 1,920-byte budget. Typing groups break at spaces,
  navigation, and saves; a new edit after undo discards the redo branch. Save
  receipts track content revisions, so a delayed save cannot mark another draft
  clean. Ctrl+C, Ctrl+X, and Ctrl+V transfer selected text between Notes editors
  through native endpoints when document policy permits clipboard access. Each
  transfer requires a newly delivered foreground keyboard gesture; focus changes,
  suspension, expiry, and revoked document authority cancel pending transfers.
  Cut removes text only after acknowledgement, and paste applies the complete
  payload as one undoable edit. Transfers accept up to 512 bytes; copied content
  expires after five minutes or when its source document authority is lost.
  The editor and compositor share allocation-free wrapping, including an explicit
  caret position at soft-wrap boundaries. Display geometry arrives with trusted
  input without enlarging its 56-byte descriptor, and caret metadata keeps the
  text snapshot at 528 bytes. Notes loads, edits, copies, saves, and reopens UTF-8
  within the existing 512-byte document bound. Unicode 18 extended grapheme
  clusters keep combining accents, emoji sequences, and CRLF together during
  movement, selection, deletion, and wrapping. Tabs use four-column stops;
  East Asian wide characters and emoji occupy two cells. Narrow and wide bitmap
  glyphs and combining accents render through a pinned, licensed font
  ([font notices](src/kernel/platform/fonts/README.md),
  [Unicode notices](src/native/core/unicode_data/README.md)); damage
  tracking compares complete cluster bytes. Complex-script shaping, bidi layout,
  color emoji, and international input methods remain open. Unsupported shaped
  clusters display a replacement glyph without changing their stored bytes.
  The native text event accepts one UTF-8 scalar; the hardware keyboard currently
  supplies the US ASCII layout. Selection,
  clipboard failure feedback, and save feedback fit within the
  unchanged 528-byte text snapshot. Boot verification reads back mapped device
  pixels for the launcher, edited Notes text, selection and undo/redo results, save
  progress, durable success, and a denied save after revocation. A production
  document picker,
  identity and permission provisioning, accelerated graphics, complete international text support,
  physical display verification, and moving storage into userspace remain open.
- Early boot seeds the kernel CSPRNG with 256 bits from RDSEED64. The kernel
  checks instruction availability and success, bounds retries, rejects a stuck
  source, erases temporary seed buffers, and stops boot if seeding fails. Runtime
  requests are capped at 4 KiB and require reseeding after 1 MiB of output.
  Each boot publishes a fresh public 128-bit instance identifier; seed material
  stays private. Production identity provisioning still needs an authorization
  lifecycle and durable bindings between principals and their keys.
- A TPM 2.0 CRB driver discovers one checksum-validated ACPI TPM2 table and
  probes the real device with family and manufacturer queries. It supports the
  direct CRB start method, locality 0, and command/response buffers contained in
  one device page. Bounds checks, monotonic deadlines, bounded cancellation,
  locality handoff, and a permanent failure latch constrain device faults.
  Unsupported start methods, RAM buffers, and FIFO devices remain unavailable.
  `./scripts/zig.sh build -Doptimize=ReleaseFast tpm2-qemu-test` requires swtpm
  (or `SWTPM_BIN`) and checks a CRB cold boot and emulator restart, plus FIFO and
  absent-device boots. It uses disposable emulator state and a separate test
  disk. A sealing client now wraps 32-byte keys under an ECC P-256 storage
  parent using salted HMAC-SHA256 sessions and AES-CFB parameter encryption.
  Secrets and their authorization values stay encrypted on the TPM command path;
  authenticated responses are checked before decryption. Objects require 256-bit
  authorization supplied by the caller and remain bound to their TPM and parent.
  The client erases temporary material, flushes transient objects and sessions,
  and returns zeroed key output on failure. Authenticated NV operations use the
  same encrypted sessions, accept only full records up to 256 bytes, validate the
  index public area and changing Name, and erase failed read output. Index reads
  and writes require a separate caller authorization; no owner read/write, index
  deletion, or implicit redefinition is exposed. It expects empty owner-hierarchy
  authorization and does not enforce a PCR policy.
  The secret store now retains authenticated encrypted blobs instead of digest-only
  placeholders. A TPM adapter wraps fresh data keys and protects up to 96 bytes
  per secret with XChaCha20-Poly1305, binding owner, label, and export policy.
  Hardware-backed secrets remain encrypted in the store, including exportable
  ones. The vault can also generate nonexportable Ed25519 keys: the TPM adapter
  obtains each seed from the kernel CSPRNG, seals it, and erases it before returning
  ciphertext. Policy denial, unavailable generation, and provider failures publish
  no secret; an audit failure rolls back the unpublished record. Immutable provider
  operation tables keep sealing and opening paired and reduce resident state.
  Explicit recovery buffers are erased on failure. The vault can sign a
  digest through a leased handle without granting raw export; signing checks the
  holder, task, current policy, expiry, and revocation. Ed25519 signing runs in
  software after an authorized unseal. Restoring a sealed record
  authenticates its metadata and creates no handles. Identity registration,
  assertions, and recovery now use private service-owned vault leases. Requests
  carry handles instead of credential seeds. Each vault operation checks current
  vault policy, and assertions also recheck credential policy. Import, generation,
  rotation, lending and revocation preserve prior vault state when their supplied
  audit backend fails. Unpublished material is erased without consuming a key ID;
  both lease tables are checked before audit acceptance, including slot reuse.
  Rotation prepares its replacement before revoking old leases. Export and signing
  withhold results on audit failure. These are serialized service guarantees;
  durable audit retention remains the audit backend and caller's responsibility.
  Assertion signatures bind counters and security claims, and recovery approvals bind the registered
  threshold, replacement key, and credential generation. Unlock signatures also
  bind the current boot ID and a fresh service-owned session nonce; locking or
  restarting the verifier invalidates old proofs even when relative clocks reset.
  Proofs carry only the fixed Ed25519 signature and use the enrolled device key
  for verification, keeping existing request-size limits intact. A trusted
  authenticator can issue proofs through a private sealed device-key lease;
  software-seed issuance is restricted to verification builds. A TPM PIN capsule
  now seals a random 256-bit vault authorization under a 6–32 digit PIN. Its
  domain-separated authorization binds the owner, device, and random salt; the
  capsule stores no software PIN verifier. Unlock requires an independently
  trusted capsule digest and checks its enrolled TPM parent Name before sending
  PIN authorization. Failed unlocks erase the output. Explicit lockout-administrator
  enrollment and rotation encrypt the new authorization and verify responses with
  the new value. Persistent guessing limits require nonzero recovery intervals;
  the default is eight attempts and one recovered attempt per powered hour.
  The recovery administrator has a separate 24-hour retry interval. Ordinary PIN
  attempts never reset these limits. QEMU verifies lockout across a VM/TPM restart,
  explicit administrator recovery, and a lost authorization-change response.
  The primitive requires trusted enrollment and separately retained administrator
  authorization; it does not supply the first-user UI or an input trust path.
  A bounded identity-session owner now connects PIN verification to authenticated
  NV recovery, catalog restoration, enrolled-device key checks, and a fresh replay
  nonce before activation. Lock synchronously invalidates both lease tables,
  detaches the hardware provider, erases authorization and loaded secrets, and
  clears credentials and device state without depending on TPM cleanup or disk
  writes. Handle generations survive lock/reopen, so copied signing leases stay
  invalid even when the same catalog is restored. Unlock proofs retain the PIN's
  original verification time. Session operations lock on expiry or a backwards
  service clock; the desktop owner must also check idle deadlines. QEMU covers
  rejected PINs, failed anchor/key/entropy checks,
  stale proofs and handles, and durable counter recovery after locking with a
  lost NV-write response. Coordination adds at most 4 KiB, borrows existing stores,
  and reuses private credential leases for repeated assertions.
  Origin validation
  accepts canonical HTTPS DNS origins
  and rejects URL paths, user-info, and malformed ports. A signed vault catalog
  now checkpoints up to 16 sealed records and 16 credentials together, preserves
  key IDs, export policy, assertion counters, recovery generations and revocations,
  and restores them atomically without leases or unlock proofs. The durable
  identity service returns assertions only after their counters reach disk and,
  when attached, its external freshness anchor. Failed checkpoints block further
  identity changes until an explicit flush succeeds; retries reuse the pending
  version. A 136-byte authenticated TPM NV record binds the owner, catalog ID,
  signing key, optional device-root pin, generation, and exact payload digest.
  Restore reads these pins independently of the native volume and rejects both
  older catalogs and different signed payloads at the same generation before
  unsealing. Disk commits precede NV updates. A lost NV-write reply retains the
  pending version; a fresh client can authenticate the committed record and finish
  the retry without another NV write. This uses ordinary protected NV storage,
  with serialized software enforcing generation advancement, not a hardware
  monotonic counter. Enrollment is explicit, and missing or redefined indexes
  never trigger automatic reprovisioning. Catalog v5 signs the preceding catalog's
  SHA-256 digest. After an interrupted disk/NV commit, recovery accepts exactly
  one signed successor whose predecessor digest matches the TPM pin, confirms
  disk durability, and advances NV before restoring secrets. Unrelated histories,
  skipped generations, unsigned version links, and older snapshots cannot authorize
  recovery. Normal saves still use one NV write, with unchanged 136-byte anchors
  and 112-byte checkpoint coordination state. First enrollment durably commits
  the catalog, then binds its exact initial anchor and NV index into the immutable
  SHA-256 `authPolicy` field at index definition. AUTHREAD/AUTHWRITE remain the
  only data-access paths. After interruption, bounded inspection reconstructs an
  untrusted candidate without unsealing keys. A successful HMAC operation using
  that committed NV Name authenticates the candidate before restore. Recovery
  writes only an unwritten index, checking WRITTEN in the same public-area snapshot
  used for the command HMAC. An already committed enrollment is compared exactly
  and never rewritten; a missing index requires explicit recovery. This closes
  the definition/first-write crash gap without another object or normal-checkpoint
  NV write. Production authorization provisioning and first-user enrollment UI,
  physical TPM persistence validation, trusted PIN input, biometric verification,
  desktop lock/unlock event integration, and userspace
  request dispatch remain open.
  `./scripts/zig.sh build -Doptimize=ReleaseFast tpm2-sealing-qemu-test` verifies
  interrupted initial enrollment, recovery from the native disk after restarting
  the VM and swtpm, lost first-write replies, altered enrollment commitments,
  a forged public WRITTEN status, missing-index refusal,
  repeated handle cleanup, bad authorization, private-blob tampering, response
  HMAC tampering, and refusal by a replacement TPM. The same guest test persists
  a vault-generated signing key, checks its public key after reboot, proves another
  generation with the same label yields a distinct key, rejects altered owner,
  label, and export policy, and verifies signing leases and 96-byte secret export.
  Cold and reboot cases also register an identity against that recovered key,
  verify a vault-backed assertion, and reject counter tampering, expired leases,
  wrong service tasks, and revoked handles. It also signs document metadata
  with the recovered sealed key and rejects signing after lease revocation.
  The reboot restores three generated keys and a 96-byte exportable secret through
  the primary catalog and the remote catalog signer plus current device key through
  a separate catalog. Two rotations retire the predecessors and reuse a secret
  slot with a new ID; reboot rejects the old IDs and restores no leases.
  It also resumes an assertion counter after reboot and refuses a credential
  revoked before shutdown. The cold boot saves an unlock proof; the reboot rejects
  replay at matching relative ticks and rejects replacing its signed context with
  the new session. Both catalog pins now live in authenticated NV records. The
  gate checks wrong NV authorization, duplicate definition, encrypted traffic,
  corrupt read/write response MACs, and reconciliation of an accepted write with
  a lost reply. It restores the cold disk snapshot while retaining the newer TPM
  state and requires rejection before vault restore. Another boot halts with
  interrupts disabled after the disk commit but before NV_Write is sent. Restarting
  both VM and TPM then completes that signed checkpoint, restores its credential
  counter, and resumes assertions. Catalog format v5 includes the authenticated
  device graph and predecessor digest and rejects older snapshots.
  Public test authorization exists only in verification kernels. Sealing follows the [TPM 2.0 Library specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/);
  hardware interfaces follow the [TCG PC Client TPM profile](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
  and [TCG ACPI specification](https://trustedcomputinggroup.org/resource/tcg-acpi-specification/).
- Task checkpoints restore execution metadata without restoring saved capability
  attachments. Matching live tasks retain their current grants; removed or
  replaced tasks retire their endpoints, queued capability moves, shared memory,
  and associated authority. Reset and restore preserve identity issuance cursors,
  including exhaustion, so old identifiers cannot be issued to new tasks.
- Diagnostic ledger format v4 writes its header once and reconstructs sequence
  numbers from retained events, avoiding a second immutable version per append.
  Older diagnostic ledger formats are rejected.
- The storage pool provides 640 payload chunk slots for its 640-blob limit,
  with payload bytes allocated on demand. Failed writes release newly allocated
  chunks before publishing an object or version. Storage still has an explicit
  finite quota; automatic history reclamation remains open.
- Text surfaces use compositor-owned snapshots and the firmware framebuffer in
  production, with writes limited to changed cells. The shared-buffer handle,
  revision, and readiness-fence path still records modeled display requests;
  accelerated scanout and modesetting remain open.
- Local-first sync is modeled as core OS behavior: trusted device graph,
  durable inbound/outbound frame queues, replay rejection, offline edits,
  explicit conflict review, object-scoped sharing, revocation enforcement, and
  two-node QEMU proof runs with separate native stores.
  Device graph mutations verify the stored user-root signature, require the
  matching root key, and check device ownership. A sync-service capability alone
  cannot enroll, rotate, or revoke another user's devices. Enrollment retries
  must match the current device key, label, and platform binding; key changes
  use explicit rotation. Exhausted generations and rejected mutations leave the
  graph unchanged. Sealed-key graph mutations checkpoint before publication.
  Public enrollment lets a device prove possession and consent to an independently
  pinned owner root while retaining its private key in its own vault. The authority
  approves the public record and publishes a signed graph; import checks the local
  key, preserves observed rotations and revocations, and checkpoints before use.
  Public rotation binds consent from the current key to proof of its successor.
  The device checkpoints both keys before sending the request; owner approval and
  local import then commit the new generation. Stale and competing requests fail,
  matching approval and import retries do not write again, and old channels retire
  when the graph changes. The root certificate binds the exact predecessor consent
  and successor proof. After durable import, retirement removes every old lease
  and the current sealed record, preserving a slot generation in catalog v5.
  Reused slots receive new IDs; catalog signers, credential keys, owner roots and
  active device keys remain protected. Host tests cover 20 rotations, exhausted
  generations and failures at both storage barriers without raising memory ceilings.
  Historical encrypted checkpoints are retained; secure erasure and lost-key
  recovery remain open.
  Host tests join and rotate separate vaults and disks; the TPM cold/reboot proof
  restores two device vaults and catalogs on the same guest TPM and rejects the
  retired device key. Production approval, enrollment transport, trusted root-pin and authorization provisioning, interrupted first-enrollment recovery, and physical TPM validation remain open.
  The two-node gate uses modern VirtIO PCI networking with bounded 32-entry
  queues, separate DMA permissions, VT-d isolation and remapped MSI-X.
  Both guests must transmit and receive encrypted native frames and observe
  hardware interrupts; the harness saves wire captures beside the serial logs.
  Physical I225-LM evidence and complete cross-node object replication remain
  separate release requirements.
  Native sync ABI v4 uses XChaCha20-Poly1305 with fresh random session keys
  and nonces, authenticates task routing and sequence fields, and clears
  plaintext on authentication failure. Independent verification nodes
  now establish Noise XX channels with fresh X25519 keys certified by pinned
  device identities. Both nodes decrypt confirmation traffic and reject packet
  tampering and replay. Production identity provisioning, peer discovery and
  authorization of inbound object operations still need integration.
- The driver model treats storage, network, USB controllers, GPU/display,
  media/print, input, and compositor-facing device policy as restartable
  userspace claims behind capability-scoped IOMMU DMA domains or brokered DMA
  buffers. The prototype retains bootstrap inventory shims, the storage
  bootstrap broker in the kernel; display presentation is a userspace claim.
- The driver restart proof now checks that storage I/O works before restart,
  the storage driver has a programmed DMA domain and brokered DMA buffer, stale
  authority/DMA/port access is rejected after a process-generation change, a
  replacement storage session rebinds with a new DMA domain, and storage I/O
  works after restart.
- `spec/coverage.json` currently records 59 required requirements and marks all
  59 as `enforced`.
- `spec/production_readiness.json` currently pins one first hardware target
  (`asus-nuc15crsu7`) and tracks nine production-readiness workstreams: one
  `prod_ready` track, three `prod_candidate` tracks, four `prototype` tracks,
  and one blocked real hardware track.
- The secure-by-design release gate is `blocked` until the real RNUC15CRSU7
  hardware proof bundle passes. Release artifacts are measured, DSSE
  in-toto/SLSA provenance is generated through a hardware-backed
  TPM/secure-enclave/HSM/KMS signing command. Customers obtain
  `zigos-verify-release` and its SHA-256 pin independently of the release;
  the host verifier is deliberately not one of the signed OS targets or a
  trust bootstrap for itself. It checks signatures, revocation, subjects,
  reproducible digests, measurements, and post-quantum rollout policy.
  Measured policy roots cover boot service, device, and policy authority while
  excluding live resource grants and runtime issuance timestamps, so identical
  cold boots remain reproducible regardless of user activity or timer phase.
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

Physical memory allocation uses a two-level availability index above its
ownership bitmap to skip fully reserved or allocated regions. The index adds
266,240 bytes for the 512 GiB managed aperture; total allocator metadata remains
below 17 MiB. Single-page reuse probes the allocation cursor directly, while
sparse page and contiguous-run searches skip empty regions. DMA address bounds,
immutable firmware reservations, and transactional release checks apply to both
paths. `./scripts/zig.sh build frame-allocator-benchmark` measures these paths on
the host, including failed allocations in an exhausted physical range. These
microbenchmarks supplement the QEMU kernel benchmarks and hardware proof runs.

The kernel heap uses per-CPU magazines for power-of-two size classes from
32 bytes through 4 KiB, with eight cached spans per class. A locked span table
handles cache misses, larger allocations, splitting, and adjacent-span
coalescing. Payloads have no in-band header; a bounded address index validates
allocation starts and rejects invalid or duplicate frees. Host tests exercise
this same allocator in a bounded arena, including payload preservation and
randomized fragmentation. `./scripts/zig.sh build heap-allocator-benchmark`
measures reuse and allocation under fragmentation, including exhaustion.

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
- Focused hardware input crosses the native ABI as bounded semantic events.
  The compositor routes each event to one task, the session grants a dedicated
  task-scoped receive capability, and UI processes drain a fixed event budget
  without sharing router memory or raw HID reports. Each decoded key receives a
  distinct, increasing event number, including keys from the same HID report.
  Source replacement resets report replay checks while preserving event ordering
  for surviving tasks; exhausted event numbers stop delivery without wrapping.
  The focused-input benchmark generates a new key transition on every iteration
  and verifies delivery before counting the operation.
  Once the queue is empty, the process yields with an event-wait disposition and
  stays off the ready queue until focused work wakes it. Each UI process keeps an
  allocation-free model for editable text, focus, activation, recovery, and
  commits; Notes, Viewer, Capture, Permission Review, and the compositor select
  distinct state roles while the bootstrap mailbox exposes a compact snapshot.
  Native ABI v10 uses 128-byte sealed-ring slots with 88-byte payloads and a
  56-byte receive header carrying the kernel-recorded sender endpoint. Services explicitly address
  replies to connected clients; stale or unrelated endpoint handles are
  rejected before publishing a reply or moving a capability. Receive buffers
  are validated before dequeue, and undersized outputs leave messages queued.
  A full endpoint queue returns a distinct `would_block` status so clients can
  retry backpressure without spinning on a disconnected peer.
  Ring storage is explicitly cache-line aligned within its heap allocation.
  Power-of-two capacities preserve FIFO order across sequence-counter rollover;
  malformed geometry, impossible queue depths, and invalid record lengths are
  rejected before access. Receive validates and copies one snapshot before
  releasing the slot, preserving messages and moved capabilities on short
  outputs. Ring replacement rejects overlapping live storage. The host
  `ipc-ring-benchmark` target compares this receive path with separate peek/pop
  calls and measures full-queue backpressure.
  The `endpoint_close` operation requires its own right, releases one channel
  and all authority to it, and wakes surviving peers. Clients drain queued
  replies before receiving `peer_closed`; closed connections cannot be rebound.
  Closing one client leaves a shared service available to its other clients.
  Successful sends wake only the destination owner after publishing the message
  and completing any capability move. Kernel initialization binds one synchronous
  runtime retirement hook, so lifecycle requests, direct termination, and user
  exceptions release task-scoped grants, owned endpoints, and shared-memory
  objects and mappings through the same path. Termination releases unread
  moved grants before freeing endpoint queues; failed receipt attachment also
  releases a consumed move while leaving copied grants with their sender.
  Endpoint and shared-memory creation unwind unpublished objects if ownership
  grants fail, restoring owner budgets and frame reservations. Failed single
  grants preserve capacity for future capability targets. Removing the last
  grant to a target also releases its metadata; revoked sibling grants retain
  their epoch until they are removed.
  Services retire both temporary endpoints after their startup IPC check,
  including cleanup when a later startup step fails.
  Idle services park instead of generating
  heartbeat work; a task with queued endpoint messages stays runnable. Production
  smoke tests require the scheduler to reach idle and stop its periodic tick.
  The ABI also defines a task-scoped, 32-byte surface descriptor carrying a
  shared-buffer handle and readiness fence, with monotonic revision checks.
  UI processes coalesce each bounded input drain into one revision submission,
  acknowledge only accepted revisions, and park when no more focused input is
  queued. Production boot proves that the descriptor crosses the syscall
  boundary and appears in the compositor's diagnostic view. The document proof
  compares the mailbox's text digest with the loaded and durably saved content;
  neither proof establishes physical display output.
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
- An x86-64 CPU with NX, SMEP, SMAP, UMIP, RDSEED, PGE, PCID/INVPCID,
  x2APIC, XSAVE/XSAVES, CET IBT and shadow-stack support, FRED, LASS, LKGS,
  1 GiB pages, and a calibrated invariant TSC with deadline timers. Production
  boots require the complete floor. QEMU media explicitly selects its software
  CPU fallback for features unavailable in the emulator; RDSEED remains required.
  The native UEFI loader enters the x86-64 kernel directly.
- Supported boots initialize the calibrated invariant-TSC clock before emitting
  their first marker. COM1 transmit readiness uses a 100 ms elapsed deadline,
  yields to sibling hardware threads while polling, and waits only before
  enqueueing each byte; unsupported-CPU diagnostics retain a bounded
  best-effort path because no trustworthy clock is available.
- Production hardware must expose a checksum-valid ACPI DMAR table with at
  least 39 DMA address bits, x2APIC interrupt remapping, no x2APIC or DMA-remapping
  firmware opt-out, and a segment-zero VT-d unit covering all remaining PCI
  devices. Boot revokes every discovered PCI bus master, masks INTx and disables
  MSI/MSI-X, installs coherent deny-by-default DMA and interrupt-remapping tables
  across every segment-zero unit, maps only six direction-scoped NVMe regions:
  four queue pages, one contiguous 64-page bounce region split into two
  independent slots, and one contiguous two-page PRP-list region. NVMe reads
  and writes keep up to two 128 KiB commands in flight, overlap host copies with
  device I/O, accept out-of-order completions only when each CID remains owned
  by an active slot, validate phase, queue, command identifier, and
  submission-head bounds on every completion, and
  use invariant-TSC elapsed-time deadlines derived from CRTO/CAP timeout fields
  instead of CPU-speed-dependent loop counts. Fatal, timed-out, failed, or
  ownership-indeterminate queues are contained. The I/O completion queue enables
  single-message vector-zero interrupts; after x2APIC and VT-d initialization,
  the controller receives an exact-requester remapped MSI route on vector 66.
  Runtime I/O waits in `hlt` with a scheduled timer deadline and restores the
  caller's interrupt mask after each wake, while boot-time administration
  retains the bounded polling path. When present, boot maps the I225-LM TX/RX
  descriptor pages plus independent 32-page TX and RX buffer regions in a
  separate domain and confirms translation on every unit. VT-d command transitions, queued
  invalidations, and blocked-DMA proofs use invariant-TSC elapsed deadlines
  rather than CPU-speed-dependent loop counts. The I225-LM path attaches to the
  firmware-negotiated PHY, publishes the permanent MAC, queues TX without
  completion spinning, contains a stalled oldest TX descriptor after one
  second, and activates only after its requester is confined and the x2APIC is
  ready. It installs one exact-requester VT-d interrupt-remapping entry, programs
  a single-vector MSI message, masks queue causes in the top half, and defers
  descriptor service to the native runtime. Each wake drains at most eight
  frames into a fixed 32-frame software queue, wakes the network task, and
  rechecks pending work with interrupts disabled before idle so receive events
  cannot be lost across the sleep boundary. Malformed
  causes and eight consecutive no-progress interrupts fail closed. Queue
  enable and disable transitions use invariant-TSC elapsed deadlines.
  The halted xHCI controller owns a third requester domain containing only its
  command, event/transfer/ERST, DCBAA, scratchpad, Device Context, and Input
  Context pages, with read-only or read/write permissions matching each page's
  controller access. NVMe bring-up installs all three requester domains in one
  deny-by-default VT-d transaction before any of them may gain bus mastering.
  Native payloads are carried in padded Ethernet frames under the local
  experimental EtherType; service and sync traffic resolves a fixed peer-device
  directory to directed unicast frames, while scoped discovery alone uses
  broadcast. Receive polling accepts only directed or broadcast frames for that
  EtherType. NVMe, PCIe ECAM, I225-LM, xHCI, ACPI, and VT-d cache-disabled mappings are assigned by one
  page-aligned, capacity-checked kernel MMIO layout whose pairwise non-overlap is
  enforced at compile time. Before
  normal storage attach, the controller must trigger a primary VT-d
  record by attempting
  a write to a reserved but unmapped guard page; the requester, address, direction,
  and unchanged canary are verified before the controller is reset and reused.
  Every later synchronous command polls the same primary records; a DMA fault
  disables the controller and PCI bus mastering and withdraws the storage backend.
  The xHCI input lifecycle assigns device slots in constant time, recycles them
  after disconnects, and clears queued keyboard reports before a reclaimed slot
  can be assigned to another port. PCI inventory accepts an xHCI controller only
  after a shared typed BAR decoder maps one dedicated read-only cache-disabled
  page and the live capability block reports xHCI 1.1+, nonzero slots, ports,
  and interrupters, plus aligned doorbell and runtime offsets. Capability parsing
  masks the architectural 11-bit interrupter field, requires 64-bit DMA addressing,
  decodes 32- or 64-byte contexts, and reconstructs the split 10-bit scratchpad
  count while rejecting restore-state claims without scratchpad storage. The typed
  DMA plan reserves a zeroed DCBAA page, page-aligned scratchpad pointer and buffer
  storage, one complete 32-entry Device Context and compact endpoint-zero transfer
  ring per enabled slot, one dedicated interrupt-IN ring and cache-line-separated
  report buffer per slot, one shared 64 KiB-aligned enumeration buffer, and one
  page-contained reusable 33-entry Input Context. VT-d exposes command and transfer
  rings read-only to the controller while report-buffer pages are write-only.
  Reservation sizing checks every possible page offset within the 64 KiB alignment
  boundary, and the realized physical plan must fit the reserved frame count before
  any DMA memory is cleared or published.
  Checked arithmetic and disjoint-range validation cover the command and event
  pages, ERST, and DMA arena. The
  same page is remapped as a bounded sliding window over the extended-capability chain, and
  ownership is requested with the architected 8-bit OS-semaphore write, and the
  firmware semaphore must clear within a one-second invariant-TSC deadline. The
  window is restored read-only immediately after that byte write, while bus
  mastering remains disabled. After ownership, attach waits for CNR to clear,
  clears Run/Stop and interrupt enables, requires HCHalted within the specified
  16 ms bound, asserts HCRST, and requires reset completion plus a ready,
  halted, error-free final state within bounded elapsed deadlines. The window is
  restored read-only between each operational write. While the controller remains
  halted, attach then programs CONFIG.MaxSlotsEn to the smaller of the hardware
  capacity and the kernel's 32-slot table, preserves unrelated CONFIG fields, and
  requires exact readback. It allocates and clears the exact contiguous DMA frame
  run, installs cycle-one self-link TRBs, builds the primary event-ring table and
  scratchpad pointer array, requires 4 KiB controller pages, and programs DCBAAP,
  CRCR, ERSTSZ, ERSTBA, ERDP, and 125 microsecond interrupt moderation with
  readback validation. Bus mastering and interrupts remain disabled while these
  structures are added to the VT-d policy. Deferred activation then installs an
  exact-requester remapped MSI route, enables bus mastering only inside that
  domain, enables the primary interrupter before Run/Stop, and requires HCHalted
  to clear within a one-second invariant-TSC deadline. Vector 67 only latches
  work and acknowledges x2APIC; the native idle loop drains at most one 64-entry
  event ring per pass, follows the consumer cycle bit across wrap, writes ERDP
  to the first unconsumed TRB with EHB acknowledgement, and rechecks the ring
  before sleeping. Supported Protocol ranges may be sparse but must not overlap;
  every capability must carry the USB name and a supported revision, and explicit
  PSI entries define the accepted speed identifiers. Every serviced port must
  resolve to its exact Protocol Slot Type and endpoint-zero packet size. Port-status changes
  preserve only architected sticky controls while acknowledging RW1CS bits;
  connected USB2/USB3 ports receive bounded normal/warm resets as appropriate.
  A single cycle-tracked TRB producer submits Enable Slot, Address Device, Evaluate
  Context, Configure Endpoint, and disconnect-time Disable Slot commands through doorbell zero. Address
  Device uses the shared serialized Input Context to publish only Slot and endpoint-zero
  state, with a slot-private control ring and the negotiated root-port speed. The same
  serialized lifecycle then rings the slot's endpoint-zero doorbell for an eight-byte
  device-descriptor read, accepts only the exact Status Stage Transfer Event, validates
  the descriptor header and speed-specific packet size, and issues Evaluate Context
  before another transfer when a full-speed device reports 16, 32, or 64 bytes. It then
  reads the complete 18-byte device descriptor, validates its BCD versions, class and
  subclass relationship, USB generation, evaluated packet size, and nonzero
  configuration count, and retains the parsed device identity for the port lifecycle.
  It next reads the first configuration's nine-byte header and its complete descriptor
  tree, using the reported total length up to the full 16-bit USB limit. Short-packet
  interrupts make every descriptor read exact. The streaming parser validates tree
  framing, reserved configuration attributes, interface and endpoint counts, endpoint
  addresses, and mandatory SuperSpeed endpoint companions without copying the 64 KiB
  DMA window onto the kernel stack; the validated configuration summary remains bound
  to the port until disconnect. Selection accepts only an alternate-setting-zero HID
  boot-keyboard interface with a valid interrupt-IN endpoint, translates USB polling
  intervals and burst limits into xHCI fields, and retains its exact configuration value,
  DCI, packet size, and ESIT payload. The lifecycle then completes an exact no-data
  `SET_CONFIGURATION` transfer before publishing a Configure Endpoint Input Context
  with only A0 and that DCI set. A matching Configure Endpoint completion is required
  before the port is marked configured; no interrupt TD is posted early.
  Completion pointers, endpoint ids, residual lengths, and slot identities are
  validated before state advances, and DCBAA entries are linked or cleared only at the
  specified completion boundary. Reset, command, and control-transfer waits keep the one-shot timer armed and
  contain the controller after one second without progress. DMA faults, invalid
  port, command, or transfer events, unsupported event types, ERDP rejection, or an
  unexpected halted/error state quiesce the controller and revoke MSI plus bus
  mastering. Input-device authority still requires an interface-scoped HID
  `SET_PROTOCOL(Boot)` transfer, a real interrupt-IN report TD, matching hardware
  event-ring completion, and validated report bytes.
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

The first real-machine gate is an Intel RNUC15CRSU7 proof bundle. First complete
the phase-A `release-bundle-check` ceremony described below. Once that command
returns, freeze the authenticated release bundle and the exact 17 signed target
files; do not run any generator again. Prepare a fresh proof skeleton bound to
that candidate:

```bash
scripts/prepare-nuc15crsu7-hardware-proof.sh \
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
scripts/write-nuc15crsu7-capture-statement.sh build/hardware-proofs/<fresh-name>
ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE=<fresh-verifier-issued-64-hex> \
ZIGOS_HARDWARE_PROOF_VERIFIER=/absolute/path/to/trusted-verifier \
ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256=<externally-pinned-64-hex> \
ZIGOS_RELEASE_VERIFIER=/absolute/path/to/independently-pinned-zigos-verify-release \
ZIGOS_RELEASE_VERIFIER_SHA256=<externally-pinned-verifier-64-hex> \
ZIGOS_RELEASE_TRUST_ROOT=/absolute/independent/root-metadata.json \
ZIGOS_RELEASE_TRUST_ROOT_SHA256=<pinned-lowercase-sha256> \
ZIGOS_RELEASE_TRUST_STATE=/absolute/persistent/zigos-release-state.json \
  scripts/check-nuc15crsu7-hardware-proof.sh build/hardware-proofs/<fresh-name>
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
publishes and statefully verifies its manifest. After the candidate's exact 17
target files and release bundle are frozen, the verify-only
`release-security-gate` rechecks the existing bundle and seals it with the
completed RNUC15CRSU7 proof; it has no generator or signer dependency. Public
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
files and two independently rebuilt reproducibility files for exactly 17 OS
targets: nine fixed production artifacts and 8 userspace images. The
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
exact 17 target files and `build/release-security` inputs must be private,
owner-controlled, and quiescent: no process outside the ceremony may replace
them while they are being hashed. Prefer read-only or immutable staging for
those inputs. The fresh hardware-proof sibling remains writable for capture;
it is not one of the verifier's 15 target paths. Verification does not claim
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

The first real hardware target is Intel NUC 15 Pro Mini PC `RNUC15CRSU7`. QEMU proof
runs remain required preflight evidence, but they do not satisfy the hardware
target gate. Real-machine proof must cover UEFI boot, ACPI, APIC/timer, GOP
framebuffer, USB xHCI input, NVMe block I/O, Intel I225-LM networking,
suspend/resume, compositor framebuffer presentation, crash recovery,
crash-record persistence, and update rollback across power cycles. Required
serial markers live in the production and verification contracts under
`spec/hardware/`. A complete proof is a directory described by
`spec/hardware/nuc15crsu7-proof-bundle.md`, with distinct
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
