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
  before the app's first instruction. Workspace pickers and document channels hold
  a storage-service vault lease and sealed-key fingerprint instead of a raw
  signing seed. Each new save checks current signing policy, lease expiry,
  revocation, service ownership, and key binding before publishing a version.
  The vault signs bounded canonical metadata without exporting its key.
  A hardware wait cannot preserve stale document authority: the backend checks
  current time, live tasks, held grants and scoped access again before mutation
  and after checkpoint completion. Changed workspace pointers or object heads
  reject the save. Backpressured saved receipts and read data are checked again
  before delivery. Closing a suspended operation detaches its endpoints while
  retaining borrowed bytes until it finishes; pool teardown refuses live work.
  Actual cooperative host regressions exercise these boundaries. The native
  identity owner now runs document operations on a lazy guarded worker under
  the shared TPM lease. Authentication, assertions and document work hold one
  exact session operation token through provider cleanup. Lock retires idle
  channels and cancels active work immediately, retaining borrowed buffers
  until completion. Worker readiness and future wakes join the native loop;
  detach and owner teardown drain work before releasing its backing. Production
  still needs the Notes launch gesture and approved document grants.
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
  The compositor provides a workspace document picker under supplied approved
  grants. It lists four authorized UTF-8 paths per page, supports arrow-key
  selection, Page Up/Down browsing, and Open/Cancel or Escape. The session pins
  each row's path, object and version, rechecks authority before each outgoing
  chunk and activation, and rejects old-page decisions. Complete pages publish
  atomically; queue pressure retains one frame. Empty pages offer cancellation.
  Native picker storage is lazy and capped at 2 KiB; client state stays within
  512 bytes. The 256-byte mailbox and 528-byte surface snapshot remain unchanged.
  Cold-boot and reboot verification browse pages through the compositor ELF,
  choose a non-default row, and check the resulting Notes object, text and pixels.
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
  preserve saved state; edits remain staged until Ctrl+Enter. Held document keys
  repeat after 400 ms, then every 40 ms, with one repeat per service visit and
  no burst after a stall. Release, focus changes, USB interruption, and lost task
  authority cancel repeat. Shortcuts, permission controls, and trusted PIN entry
  remain press-only. Repeat deadlines wake an otherwise idle desktop. The compositor
  scrolls wrapped text to keep the cursor visible without retaining another
  editor buffer. Ctrl+Z undoes edits and Ctrl+Shift+Z redoes them, restoring the
  cursor and selection. Task-local history retains up to 32 edit groups and
  1 KiB of changed text within a 1,920-byte budget. Typing groups break at spaces,
  navigation, and saves; a new edit after undo discards the redo branch. Save
  receipts track content revisions, so a delayed save cannot mark another draft
  clean. Ctrl+C, Ctrl+X, and Ctrl+V transfer selected text between Notes editors
  through native endpoints when document policy permits clipboard access. The
  document's signing lease must remain live, bound to
  the storage service, and permitted by current policy; a valid workspace grant
  cannot preserve clipboard access after that lease expires or is revoked.
  Each transfer requires a newly delivered foreground keyboard gesture; focus changes,
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
  launch flow with identity and permission provisioning, accelerated graphics,
  complete international text support, physical display verification, and moving
  storage into userspace remain open.
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
  `./scripts/zig.sh build -Doptimize=fast tpm2-qemu-test` requires swtpm
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
  deletion, or implicit redefinition is exposed. Explicit bootstrap creates a
  storage parent on an unowned TPM and persists it under caller-supplied owner
  authorization. Enrollment pins its persistent handle and Name independently.
  Normal identity unlock authenticates that parent through an encrypted salted
  session without owner authorization; missing or changed parents fail closed.
  Closing a client never flushes or evicts a persistent parent. Owner-authorization
  changes encrypt the new value and authenticate the reply with it; NV definition
  borrows explicit owner authorization only during provisioning. Administrator
  secrets require independent recovery custody. No PCR policy is enforced.
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
  withhold results on audit failure. After a yielding unseal, both operations
  reacquire the exact generational lease and recheck current policy before
  returning success. Revocation, retirement with slot reuse, unload, and a
  policy change withhold signatures and erase export output; audit identity
  is retained by value across the wait. These are serialized service guarantees;
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
  A canonical public enrollment record now binds the owner, device, PIN capsule,
  persistent parent, catalog, NV index and key IDs under an independent digest.
  Its 176-byte recovery package encrypts separate random owner, lockout and vault
  authorizations with XChaCha20-Poly1305 and authenticates the entire enrollment
  binding. It requires a separately retained random 256-bit recovery key, never
  a PIN or password. Provisioning must commit the package and retain that key
  before changing TPM authorization. Recovery authenticates the package before
  hardware access, confirms the enrolled TPM, explicitly resets PIN lockout, and
  follows the same authenticated catalog/device-key restoration as PIN unlock.
  Signed proofs identify recovery-key verification; lock erases that state and
  invalidates its leases and replay domain. The session retains no recovery key
  or owner/lockout authorization. This restores access on the original TPM; it
  cannot recover keys after that TPM is cleared or lost. Production boot binding
  and independent recovery-material custody remain open.
  A serialized provisioning service generates the three sealed catalog/root/device
  signing keys and the owner/lockout/vault authorizations, then stages a signed
  catalog and canonical recovery bundle. The caller must retain the bundle pin
  and random recovery key independently before committing. Commit verifies both
  objects and crosses one durable storage barrier before changing permanent TPM
  state. A salted audit session authenticates hierarchy flags, allowing explicit
  retries to select the retained new authorization after a lost successful reply
  without probing with an old value. Parent identity and initial NV commitment
  remain pinned; setup neither clears the TPM nor evicts existing parents.
  Native setup now confirms the PIN twice, prepares on a guarded cooperative
  worker, and makes the encrypted candidate durable before displaying its recovery
  record. Four lines encode the independent bundle pin and random recovery key
  in 128 base32 characters plus grouping. The user must save all four lines
  outside the device, hide the display and re-enter the exact record before any
  permanent TPM changes. Ctrl+R resumes interrupted setup using that record.
  Input stays exclusive through completion and cancellation; no application
  inbox, surface, clipboard or diagnostic receives the secret. The worker shares
  the TPM lease, drains borrowed commands before teardown, and erases its private
  state and 128 KiB stack. Cancelled preparation uses fresh object IDs on retry
  to preserve any independently retained candidate. In-place identity and device
  resets avoid a large temporary that exceeded the guarded worker stack in Debug.
  Setup now commits a separate 48-byte public enrollment pin in TPM NV. Its
  immutable definition binds the exact bundle and index before the first write;
  only owner authorization can write it, and a persistent write lock completes
  enrollment. Existing conflicting indexes fail preflight before other permanent
  mutations. Retries compare completed data without another write or lock command.
  Boot loading reads this TPM-held candidate, verifies the disk bundle, proves
  possession of the enrolled parent, then authenticates the locked index through
  a salted HMAC read before exposing enrollment to PIN entry. It rechecks disk
  publication after hardware waits. Missing, incomplete or changed anchors require
  explicit recovery with the externally retained record; ordinary boot never
  provisions them. The local TPM transport and verified boot remain trusted.
  Production boot now attaches one retained native identity owner after measured
  boot and before surface presentation. Discovery runs without keyboard input on
  the guarded worker. A missing anchor offers explicit setup; an incomplete one
  requests the saved record. Failed or cancelled discovery stays locked, with
  Enter to retry and Ctrl+R to resume from the independently retained record.
  Setup completion rechecks the bundle and configured user, parent and NV indexes,
  releases its worker stack and binds sign-in across a fresh neutral-input boundary.
  PIN or recovery then restores the catalog and private session; lock and expiry
  erase authority. Reset and failed boot drain workers before releasing storage.
  Catalog and recovery-bundle publication recheck storage after TPM signing
  yields, so another task's intervening write is preserved. Owner backing
  initializes in place and is erased on destruction. Provisioning bundle v3
  carries a compact policy signed by the sealed identity root. The TPM-pinned
  bundle authenticates its issuer and user before policy attachment and sign-in.
  The enrolled duration caps sessions, credential unlock age and private key
  leases; hardware custody, local unlock, phishing resistance and denial of raw
  export are mandatory. Boot configuration can shorten the enrolled duration.
  Excessive session requests and tampered policy fail before TPM access. This
  immutable enrollment baseline has no policy-update or legacy-format fallback.
  No fixture signer is installed in production. The QEMU export fixture models independent
  custody; physical persistence and user recovery-record custody remain unproven.
  Applications can request one assertion through a native-approved, short-lived
  endpoint channel. Trusted code selects the credential, canonical HTTPS origin,
  relying party and exact application process; the application supplies only its
  challenge. Four bounded channels share the existing guarded authentication
  worker, with one poll per tick and explicit wake deadlines. They recheck the
  live process, endpoint capabilities and current sign-in
  session before work and every reply. Lock, expiry, restart or revocation cancels
  pending work incrementally; teardown drains it before releasing backing stores.
  The counter must reach disk and TPM NV before any assertion bytes are sent.
  A userspace client reassembles bounded replies and exposes only a complete
  canonical assertion; the relying party must verify it against its independently
  registered key. Mailbox v11 retains the 256-byte layout and adds a tagged
  identity binding. The ownership reboot proof drives the client in Ring3,
  verifies its signed result and durable counter, and locks a second request
  during TPM work. A native approval screen now shows the launch-authenticated
  application ID, full relying party and origin, with Cancel selected initially.
  Approval requires successful complete scanout and separate released gestures;
  lock, timeout, input interruption and process replacement discard the decision.
  The native origin owner must still authenticate the website before requesting
  consent: signed application provenance does not prove website ownership.
  Authenticated-origin acquisition, credential registration and recovery IPC,
  and physical-hardware validation remain open.
  Deadline and calibrated QEMU timer modes both derive ticks from elapsed TSC
  time, so capability and worker deadlines advance with interrupts masked.
  A bounded identity-session owner now connects PIN verification to authenticated
  NV recovery, catalog restoration, enrolled-device key checks, and a fresh replay
  nonce before activation. Lock synchronously invalidates both lease tables,
  detaches the hardware provider, erases authorization and loaded secrets, and
  clears credentials and device state without depending on TPM cleanup or disk
  writes. Handle generations survive lock/reopen, so copied signing leases stay
  invalid even when the same catalog is restored. Unlock proofs retain the PIN's
  original verification time. Session operations lock on expiry or a backwards
  service clock; the production owner services idle deadlines before userspace
  dispatch. QEMU covers
  rejected PINs, failed anchor/key/entropy checks,
  stale proofs and handles, and durable counter recovery after locking with a
  lost NV-write response. Coordination adds at most 4 KiB, borrows existing stores,
  and reuses private credential leases for repeated assertions.
  Native trusted authentication entry now intercepts hardware reports before task switching
  or app inbox delivery. Entry and exit drain queued reports and wait for a fresh
  key release; each keyboard retains its own held-key suppression. Ctrl+Alt+Delete
  locks the attached identity session through this native path. The framebuffer
  renders a separate masked prompt above all app content, and compositor reset
  preserves its live attachment without checkpointing it. Ctrl+R switches between
  PIN and recovery when an authenticated recovery package is attached. Recovery
  accepts the full 128-character setup record when the owner attaches its
  independent bundle pin, or a 56-character key for a separately enrolled
  recovery package. Both use a domain-separated 24-bit typo checksum;
  lowercase and printed four-character groups are accepted at the input boundary.
  The checksum detects typing errors; package authentication verifies the key.
  Mode changes erase partial input, discard the rest of the current report and
  queued reports, and require a fresh key release. PINs remain bounded to 32
  digits; entry storage is bounded to 128 bytes and erased after submission,
  interruption, cancellation, or timeout.
  Paste and application shortcuts cannot reach the prompt. Authentication and
  secret-entry deadlines participate in the desktop wake schedule, with expiry
  checked before userspace dispatch. QEMU connects modeled HID reports through
  the normal router and framebuffer to the real TPM verifier, including rejected
  PINs, lock/reopen, and expiry. PIN, recovery and credential assertion work share a lazy 128 KiB guarded,
  supervisor-only NX stack. The worker yields at TPM command boundaries and device
  waits so the native loop can service input, display and userspace tasks. The
  transport's bounded begin/poll/cancel engine releases its lock on every entry;
  nonwrapping command tokens reject stale polls and cancellation. Worker
  cancellation finishes an active command so cleanup can identify created TPM
  handles, permits only handle flushes afterward, and prevents late activation.
  The prompt stays locked during cleanup. Actual time, current policy and the
  pinned catalog are rechecked before success; private input and the complete worker
  stack are erased on completion. Ordinary lock and Escape do not wait for TPM
  cleanup. Exclusive teardown drains pending work before releasing borrowed
  stores; owners can cancel and service it before detaching. Host tests cover
  suspended buffers, cancellation, late results and stack-switch state. Virtual
  TPM proofs check userspace dispatch while suspended, input and scanout between
  polls, protected stack pages,
  cancellation before and after catalog restore, resource cleanup, reopen and
  expiry. Recovery decodes into the same private 32-byte worker buffer; malformed
  codes, changed enrollment pins and unauthenticated packages issue no TPM commands. Ownership reboot
  proofs exercise real TPM recovery through modeled HID input, masking, userspace
  dispatch during device waits, cancellation, cleanup, reopen and expiry.
  A new scheduler activation now receives its configured CPU budget even when
  the previous interaction left partial credit. Duplicate wakes of a ready task
  do not add credit, and explicit refills retain their exact amount. This prevents
  a compositor from reading a new action and exhausting its leftover budget
  before it can send the decision. Physical input validation remains open.
  Origin validation
  accepts canonical HTTPS DNS origins
  and rejects URL paths, user-info, and malformed ports. A signed vault catalog
  now checkpoints up to 16 sealed records and 16 credentials together, preserves
  key IDs, export policy, assertion counters, recovery generations and revocations,
  and restores them atomically without leases or unlock proofs. The durable
  identity service returns assertions only after their counters reach disk and,
  when attached, its external freshness anchor. Failed checkpoints block further
  identity changes until an explicit flush succeeds; retries reuse the pending
  version. A stable native publication guard now rechecks cancellation, the exact
  unlock binding, current policy, signing leases, and the latest trusted service
  time after device waits. Checks precede proof publication, counter changes,
  catalog version creation, and session activation. A cancellation during an
  accepted disk/NV commit withholds the result while retaining its recoverable
  signed successor. Cooperative host regressions exercise these boundaries;
  physical TPM validation remains open. A 136-byte authenticated TPM NV record binds the owner, catalog ID,
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
  NV write. Production boot enrollment and recovery-material custody,
  physical TPM persistence and trusted input validation, biometric verification,
  production enrollment binding for desktop sign-in, and userspace
  request dispatch remain open.
  `./scripts/zig.sh build -Doptimize=fast tpm2-sealing-qemu-test` verifies
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
  `./scripts/zig.sh build -Doptimize=fast tpm2-ownership-qemu-test` runs thirteen
  disposable boots through native setup and the production provisioning service.
  The first boot types and confirms a PIN through modeled HID, checks mismatch
  and cancellation, reads the complete recovery record from native display cells,
  hides it and requires exact re-entry. Later setup boots re-enter the retained
  record to resume. The proof dispatches userspace during TPM waits and checks
  private input, worker erasure and exclusive rendering. It loses accepted
  responses for parent persistence, owner and lockout authorization, lockout
  parameters, catalog NV definition and first write, and boot-pin definition,
  first write and persistent locking, restarting the VM and TPM after each.
  Completion reads both anchors without another NV write or lock command.
  A forged hierarchy-state HMAC fails before administrator commands; empty owner
  authorization cannot create parents or define indexes. A verification-only
  custody key encrypts the generated recovery record and an independent compiled
  signer pins that recovery fixture; neither key is supplied to production.
  Ordinary reboot obtains enrollment from the locked TPM index and rejects
  incomplete public state, damaged disk metadata and a corrupt read HMAC before
  PIN entry. Both setup recovery and ordinary sign-in reject a replacement TPM.
  Boot loading issues no owner commands, NV writes, locks or lockout resets.
  After provisioning, a separate verification credential exercises PIN unlock,
  durable assertion counters and recovery. The reboot exhausts all eight PIN
  attempts, requires recovery-key authentication before administrator commands,
  rejects damaged packages and changed enrollment, and verifies anchor tampering,
  replay-entropy failure, replay rejection and expiry. Host crash tests withhold
  TPM access after a failed disk barrier and keep the staged catalog and companion
  record in one checkpoint. The ownership suite runs in release preflight.
  The same retained owner now drives these setup proofs and reboot discovery,
  sign-in, lock/reopen and cancellation during teardown. Production smoke without
  a TPM requires an exclusive unavailable outcome before idle. Userspace identity
  dispatch, policy updates and recovery-secret custody remain
  open, along with physical TPM and input validation. Linking the shipped account
  path adds about 240 KiB to the production payload; the ReleaseFast symbol budget
  is 3,500, with identity proof modules explicitly excluded.
  Public test authorization exists only in verification kernels. Sealing follows the [TPM 2.0 Library specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/);
  hardware interfaces follow the [TCG PC Client TPM profile](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
  and [TCG ACPI specification](https://trustedcomputinggroup.org/resource/tcg-acpi-specification/).
- Task checkpoints restore execution metadata without restoring saved capability
  attachments. Matching live tasks retain their current grants; removed or
  replaced tasks retire their endpoints, queued capability moves, shared memory,
  and associated authority. Reset and restore preserve identity issuance cursors,
  including exhaustion, so old identifiers cannot be issued to new tasks.
  When the 128-slot task table fills, it reclaims the oldest fully retired
  application record. Live and suspended tasks, service owners, session owners,
  and records borrowed by an active callback remain protected. Exact generational
  borrows cover dispatch, launch, retirement, and presentation callbacks;
  wholesale runtime replacement refuses an outstanding borrow. The scheduler
  prunes retired registrations and claims while preserving its active dispatch.
  Host tests exercise repeated launches and prepared-document cancellation beyond
  table capacity, including reentrant termination during callbacks.
- Diagnostic ledger format v4 writes its header once and reconstructs sequence
  numbers from retained events, avoiding a second immutable version per append.
  Older diagnostic ledger formats are rejected.
- The storage pool provides 640 payload chunk slots for its 640-blob limit,
  with payload bytes allocated on demand. Failed writes release newly allocated
  chunks before publishing an object or version. Storage still has an explicit
  finite quota; automatic history reclamation remains open.
  Trusted service owners can publish a complete workspace directory in one
  generation, including replacement of all 96 paths. Validation and allocation
  precede publication. Replacement retains snapshot history; insufficient history
  capacity rejects the change without moving any path. With no retained snapshot,
  it can compact the 192-entry mutation log to the new directory, preserving
  capacity for later ordinary transactions without enlarging resident tables.
  Volume operations retain exclusive replay and checkpoint scratch across
  device waits. Checkpoints serialize object, version, workspace, and root data
  before submission, then clear dirty state only if both monotonic mutation
  revisions still match that snapshot. An older completed snapshot withholds a
  current-state receipt even if another caller cleared the dirty lists; retry
  persists newer edits without duplicating a pending immutable version. Loads
  reject concurrent destination mutation, including staged transactions, and
  transport failure before replay. Every load restores disk state rather than
  trusting a cached root over mutable RAM. Reset, rebind, and teardown retain
  borrowed storage until the operation ends; teardown runs storage cleanup
  before releasing the controller's port, task, and grants.
  Each store and directory adds one eight-byte revision, with no per-record
  growth. Removing the load cache shrinks each volume by sixteen bytes.
  Cooperative host tests exercise the actual worker and storage service;
  physical latency and fault/recovery measurements remain pending.
- Text surfaces use compositor-owned snapshots and the firmware framebuffer in
  production, with writes limited to changed cells. The shared-buffer handle,
  revision, and readiness-fence path still records modeled display requests;
  accelerated scanout and modesetting remain open.
- Local-first sync is modeled as core OS behavior: trusted device graph,
  durable inbound/outbound frame queues, replay rejection, offline edits,
  explicit conflict review, object-scoped sharing, revocation enforcement, and
  two-node QEMU proof runs with separate native stores.
  A sync checkpoint publishes all managed workspace paths in one generation,
  preserving unrelated entries. Failed record allocation leaves the previous
  directory intact, and retries reconcile immutable object heads before reusing
  or writing a version. Abandoned versions still consume the finite history
  quota. An attached disk must complete its durability barrier
  before a successful result is returned. Resident retry state survives service
  reinitialization; a fresh resident loaded from unflushed RAM also retains the
  pending checkpoint. Duplicate and unchanged operations retry a failed checkpoint.
  Host regressions cover a full frame queue, late allocation failure, failed
  barriers, restart, and checkpoint deferral by an outer storage batch.
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
  tampering and replay on the managed channel used for durable object transfer.
  The two-node gate uses a bounded localhost relay to discard the first two final
  confirmations, then requires an identical retransmission and a durable receipt.
  The session manager exposes owned connection handles; unmanaged handshake
  attachment and handoff entry points have been removed. Production identity
  provisioning, peer discovery and authorization of inbound object operations
  still need integration.
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

Userspace dispatch and device interrupts share one explicit runtime owner on
the bootstrap CPU. Each resource class has one ready queue; background, media,
and batch work are serviced by the same dispatcher as interactive tasks. The
executor arms the timer at every user entry and bounds every resource class to
a two-tick quantum, at most 20 ms in the nominal clock, even when no priority
callback or other ready task exists. Latched network, NVMe and xHCI interrupts
also hand an interrupted user back to the runtime owner, so its deferred
network and input work can run before that quantum expires. Native storage
workers yield after a bounded NVMe completion inspection and resume through
the owner loop. Kernel-origin work remains uninterrupted. Both paths preserve the complete user context and keep
the finite watchdog. Each materialized mapping owns an aligned x87/SSE image and
PKRU state; allocation rollback, retirement, and reset erase and release it.
Assembly preserves the kernel continuation and captures user state before
entering compiled handlers. The current enabled state is XCR0=x87|SSE and
IA32_XSS=0. Hosted alignment and dispatch regressions pass; the full assembly
roundtrip explicitly skips hosts without OSXSAVE.
FRED uses the architectural eight-qword frame, preserves every general register
and augmented return field, and publishes handler edits back before ERETS or
ERETU. Entry geometry, STAR selectors, GS ownership, 64-byte stack alignment,
and AP initialization match that path; double faults retain the existing guarded
emergency stack. Unsupported user software events cannot impersonate physical
device interrupts. Oversized yield arguments and unknown yield dispositions
stop the offending task through ordinary exception containment. Unexpected #NM
exceptions follow the registered handler rather than the retired lazy-state
shortcut. Native hardware execution still needs validation.
Production clock frequency requires the complete architectural CPUID `0x15`
ratio and crystal frequency. Advertised processor MHz is not a timer rate;
Intel documents that distinction in its
[CPUID reference](https://cdrdv2-public.intel.com/825745/252046-sdm-change-document.pdf).
Normal boot defaults supply no modeled devices or fixed frequency, and missing
network hardware cannot opt into a model implicitly. The fixed emulator clock
and software controls require the complete explicit QEMU request. Actual feature
flags still control privileged enablement, and every mode requires XSAVE/XSAVES.
The service loop drains one atomic pending-work latch and rechecks it before idle.
Idle checks use the dispatcher's eligibility rules: policy-delayed work remains
queued while the CPU sleeps, and runnable work can pass a delayed queue head.
Service deadlines still arm a wake timer even when no task can run yet.
Outstanding I225 and VirtIO transmits contribute their earliest watchdog
deadline, so stalled sends receive service even without receive traffic or an
interrupt. Completed transmits are pending work; draining them cancels or advances
the deadline, and contained or inactive controllers contribute no wake.
Coalesced wakeups preserve the earliest queued deadline, so repeated events cannot
postpone background or batch work indefinitely. Aging uses the shared 100 Hz
timer frequency: emergency, foreground, media, background, and batch targets are
10, 50, 200, 500, and 1000 ms. Accounting charges stay separate from elapsed
time, and requeue slack is one actual two-tick quantum. New registrations age
from the current clock. Hosted load regressions advance by that quantum and
check initial and repeated service under continuing foreground work. The
benchmark foreground wait model now also allows due lower-class work before
the foreground deadline, with a six-tick ceiling after quantum rounding.
These selection targets do not establish measured hardware response latency.
Required accelerator tasks retain
a bounded wait when claim reservation fails or policy denies an online engine;
eligibility checks allow other work to pass and resume the waiter after telemetry
or request changes without an idle retry loop. Credential approval records the
actual event time through the same external-wake helper.
Application processors are online for TLB maintenance and otherwise sleep.
Concurrent userspace dispatch requires independent executor state and service
ownership before it can use those processors.

CPU identity comes from RDPID reading the kernel-owned IA32_TSC_AUX value.
Each processor publishes and verifies its bounded logical number before native
entry, paging, or heap allocation. Scheduler ownership checks, syscall state,
and allocator caches use this number without trusting userspace GS state or
reading a privileged MSR on each lookup. RDPID is required for every boot;
its architectural contract is documented in the
[Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

Interrupt nesting uses one cache-line-isolated counter per logical CPU, so an
application processor's TLB interrupt cannot change the runtime owner's context.
Range retirement clears all affected mappings, invalidates the address space
once, and only then returns private frames to the allocator. A missing remote
acknowledgement stops the kernel before those frames can be reused. Object-backed
private pages retain their first materialized snapshot; the first write promotes
that owned page without recopying over task changes. Read-only zero mappings and
hardware protection faults retain their access restrictions.
The 2 MiB image-page path requests physically aligned runs independently of the
ordinary frame cursor. Fragmentation that leaves only unaligned runs falls back
to 4 KiB leaves, preserving the mapping without encoding an invalid huge page.

Native ID indexes mix all 64 bits, including handle generations, and close
probe chains after deletion. Zero marks an empty bucket, removing tombstones,
membership bytes, and whole-table rebuilds. Endpoint readiness counts nonempty
queues per owner; successful enqueue, final receive, and retirement maintain
the count so sleep checks avoid scanning every owned endpoint.

Storage append logs reuse chunks already referenced by committed versions and
emit each new shared chunk and affected blob manifest once per batch. The
committed set is reconstructed from the selected root's version watermark;
failed barriers retain dirty state, and retries or cold replay require no
separate durability cache. Workspace-only and clean saves avoid reconstructing
that set.
Workspace path and object indexes close affected probe chains after deletion,
so repeated directory edits leave no tombstones. Object sync positions a
verified chunk cursor at each transport range rather than visiting every
preceding payload page; version and manifest validation still precede access.
Workspace commits and snapshot replay apply each generation's deletions before
additions, allowing a full directory to replace paths in any lexical order.
Restore records its delta against stable entries and publishes the prepared
target in one copy. Matched Zig 0.17 `fast` host measurements of a 64-entry
signed-package restore with its normal mutation history reduced the median from
85.56 to 78.97 microseconds (7.7%), with identical entries, indexes, roots, and
checksums. Timings include signature verification and exclude fixture preparation
and result checks.

Text scanout compares visible cell metadata and grapheme bytes independently
of pool offsets, so recomposing an unchanged Unicode frame causes no pixel
writes. Damaged cells resolve glyph scaling and cursor coverage into row masks
before writing the framebuffer. The `text-scanout-benchmark` target measures
full redraws, single-cell edits, and pool reordering on host memory.
The compositor locates the caret and retains visible rows in one layout pass
using a caller-owned row ring. Scrolling preserves grapheme boundaries and
wrap affinity without a persistent layout cache.
Canonical surface ingress validates UTF-8 and both selection boundaries in one
traversal at each trust boundary. Presentation revisions belong to individual
surfaces; switching surfaces can submit a lower revision, and the display
driver replaces its active record only after the hardware accepts the update.

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
coalescing. When free spans cannot satisfy a request or splitting needs a
recycled span ID, it reclaims bounded magazine snapshots from every CPU and
coalesces them before reporting exhaustion or consuming an oversized span.
CPU locks protect cached spans and recent allocation identities; the shared
allocator lock always precedes a CPU lock on the slow path. Payloads have no
in-band header; a bounded address index validates
allocation starts and rejects invalid or duplicate frees. Compact 16-bit span
links keep allocator arrays at 100,370 bytes. Free spans have doubly linked
class lists for constant-time removal during coalescing; the address index
hashes aligned span numbers across its full table and closes probe chains
with bounded backward shifts after deletion. Host tests exercise this same
allocator in a bounded arena, including all 4096 span slots, payload
preservation, arbitrary release orders, and randomized fragmentation.
`./scripts/zig.sh build heap-allocator-benchmark` measures reuse and allocation
under fragmentation, including exhaustion, page-sized allocation batches, and
whole-arena reuse after all pages have entered magazines. Host regressions cover
every cached size class, remote CPU caches, full span-table pressure, and
concurrent cached reuse while another CPU requests large spans.

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
  Native ABI 19 validates and prepares fixed request and result storage before
  resource creation, input consumption, or wait changes. Result validation
  covers the complete declared span; page preparation touches only copied
  bytes. Freestanding copies use private user pages through kernel physical
  aliases, including demand preparation for untouched stack pages. Endpoint
  payloads and attached capabilities pass through bounded kernel scratch;
  receive outputs must be disjoint before a queued message can be consumed.
  Syscall buffers require authorized image or stack regions. Shared-object
  apertures retain their separate object-mapping contract.
  Task termination acknowledges through syscall status without a result copy,
  so self-termination never writes through a retired address-space record.
  Shared-memory unmap, revocation, and task retirement unregister their exact
  demand regions before mapping identities can be reused; failed registration
  rolls back the unpublished mapping. A user mapping requires a materialized
  target address space; unavailable targets fail before publication.
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
- Python 3 for the two-node network fault relay and its tests
- An x86-64 CPU with NX, SMEP, SMAP, UMIP, RDSEED, RDPID, PGE, PCID/INVPCID,
  x2APIC, XSAVE/XSAVES, CET IBT and shadow-stack support, FRED, LASS, LKGS,
  1 GiB pages, and a calibrated invariant TSC with deadline timers. Production
  boots require the complete floor. QEMU media explicitly selects its software
  CPU fallback for features unavailable in the emulator; RDSEED and RDPID remain required.
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
  use five-second invariant-TSC command deadlines. Controller-ready deadlines
  derive from CRTO/CAP timeout fields instead of CPU-speed-dependent loop counts. Fatal, timed-out, failed, or
  ownership-indeterminate queues are contained. The I/O completion queue enables
  single-message vector-zero interrupts; after x2APIC and VT-d initialization,
  the controller receives an exact-requester remapped MSI route on vector 66.
  A native storage worker yields while its completion is pending, allowing
  input, network, and other ready work to run. One try-only operation lease
  retains the queue, bounce buffers, and PRP lists through completion or fault
  containment. Cancellation and revoked live task, capability, or broker
  authority stop refill and drain accepted commands before release. Admission
  binds one fresh token to the exact worker, device, task, and process; reset
  and backend replacement refuse active submissions. Administrative commands
  retain bounded polling; callers outside a worker retain interrupt-backed
  `hlt` waits with scheduled deadlines and restored interrupt masks. When present, boot maps the I225-LM TX/RX
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
  causes and eight consecutive no-progress interrupts fail closed. TX reclamation
  and completed RX descriptors reset the no-progress streak even when polled
  before their delayed MSI; dropped packets still prove descriptor progress. Queue
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
  Every later completion inspection checks the same primary records; a DMA fault
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
  Context, Configure Endpoint, Stop Endpoint, Reset Endpoint, and Disable Slot
  commands through doorbell zero. Address
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
  specified completion boundary. A disconnect notification clears published reports
  and hides the old device, while retaining its slot, endpoints, and transfer
  ownership. Retirement drains matching late completions without publishing input,
  stops running endpoints, and requires each forced stopped Transfer Event before
  its matching Stop Endpoint completion. An owned USB Transaction Error can
  authenticate detachment through live port status before its notification arrives;
  a halted endpoint then uses Reset Endpoint with transfer state preserved and
  must reach Stopped before its transfer ownership is released. Endpoint command
  choice follows validated events; stale context reads cannot trigger a reset.
  A combined unplug and replug notification also retires the old device lifetime.
  Only then may
  Disable Slot release the DCBAA entry and permit a replacement attachment to
  enumerate; a replacement that is not enabled receives a fresh port reset.
  Other ports retain their transfers and can use report capacity released by
  retirement. Reset, command, and control-transfer waits keep the one-shot timer
  armed and contain the controller after one second without progress.
  Retirement has a six-second
  deadline set when retirement begins, which repeated notifications and
  reconnects cannot extend. DMA faults, invalid
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

The current pin is Zig 0.17.0. The source uses array `@splat`, the current
`std.lang` reflection and optimization APIs, and typed ELF program headers.
Kernel and EFI byte helpers use logical `@bitCast` to preserve little-endian
wire bytes on every target. Archive generation locks borrowed array-list
elements while writing both archives. Build configuration remains cacheable
under Zig 0.17's separate configuration and execution processes.

The build accepts only the `x86_64-freestanding-none` target; 32-bit kernels and
userspace images are not compatibility outputs.
All generated optical media are UEFI-only and are rejected unless they contain a
bootable x86-64 EFI El Torito image. The QEMU harness uses OVMF pflash firmware
and exposes boot media through virtio-SCSI instead of a legacy disk controller;
legacy BIOS boot is not a supported execution path.
Each native EFI executable embeds its kernel ELF and command line. The loader
never reads a replacement kernel or options from the boot volume or firmware
load options. It validates the ELF layout, reserves every destination page,
and passes SHA-256 measurements of the exact embedded payload to the kernel.
The kernel loads at 32 MiB, above the low firmware allocations observed in OVMF.
EFI allocates the 32 MiB early heap separately below the identity-map limit;
the frame allocator preserves both exact ranges and keeps free gaps available.
It no longer assumes that memory following the kernel is safe to overwrite.
Recovery and benchmark VMs share the default 256 MiB QEMU memory setting so
firmware has room for the explicitly reserved heap.
Firmware authentication is recorded separately: SecureBoot must be one and
SetupMode must be zero; AuditMode, if present, must be zero. Missing required
state, malformed values, and read errors leave the boot unverified.
Unsigned QEMU boots cannot claim an authenticated root or
use it for runtime measured-state attestation. Runtime measurement snapshots and the embedded
fixture-signed manifests check consistency; they do not establish release
authority, prove TPM PCR values, or enforce rollback protection.

When firmware provides TCG2 with an active SHA-256 bank, the loader extends
PCR 11 with a versioned description of the exact kernel and command-line hashes
and the firmware authentication state. It copies the event-log prefix through
that event into reserved memory, capped at 256 KiB. After successful
`ExitBootServices`, it appends the firmware's final events without allocation or
firmware calls. Events already captured by an earlier log reader must match an
exact suffix of the prefix and are not copied twice. Both firmware sources are
bounded by their allocated memory descriptors; malformed counts, changed overlap,
truncation and capacity overflow stop boot.
The kernel replays PCR 11 and compares it with both the handoff and a live TPM
read after CRB initialization. It also requires digest-authenticated firmware
exit invocation and success events in the appended portion, retains failed-exit
retries, and compares the complete PCR 5 replay with a live read. Handoff version 2
rejects the former pre-exit scope without growing its 56-byte payload. QEMU gates
require `FINAL_EVENTS:VERIFIED` alongside the boot-measurement checkpoint.
Missing SHA-256 support, partial extensions, and mismatches stop that measured
boot. Absence of the firmware protocol permits an unmeasured boot; it cannot
produce either verified checkpoint.
This local consistency check uses the [TCG2 firmware protocol](https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/).
Only PCR 5 and PCR 11 are verified here. This does not establish a remote trust
policy, manufacturer identity, or physical-machine validation.

The TPM client can create a restricted ECDSA P-256 attestation key under an
independently enrolled storage parent. Its private scalar stays inside the TPM;
the stored blob is encrypted and bound to that parent. Creation protects the
caller authorization through the existing salted, encrypted HMAC session.
Quotes require the separately pinned public key and qualified Name, a fresh
32-byte challenge, and an expected SHA-256 PCR 11 value. The verifier checks the
exact selection, digest, attestation type, challenge, signature, and bounded
framing. Verifier-owned challenges expire within one minute, reject clock
rollback, and can succeed only once. Invalid quotes publish no accepted result;
client failures clear output and clean up known transient keys and sessions.
`./scripts/zig.sh build -Doptimize=fast tpm2-quote-qemu-test` exercises real
TPM commands, cold boot, recovered keys, replay, wrong authorization, substituted
keys, damaged blobs/responses, and TPM replacement using disposable swtpm state.
Its enrollment authority is a verification-only fixture. Operational attestation
key enrollment, manufacturer/EK certification, release-policy approval of PCR
values, and PCR-bound secret policies
remain open; a valid signature alone does not establish those trust decisions.

The attestation service now has a separate TPM response path. The verifier owns
the enrolled device/key/generation and approved PCR value, generates a fresh
32-byte nonce, and binds the complete request and PCR expectation into the
quote's signed extraData. Responses contain only bounded TPM evidence. Acceptance
is single-use, expires within one minute, and rejects clock rollback. Service
failures erase the response and leave the challenge available for retry.
Native driver and endpoint connection paths consume this evidence through egress
capabilities, with separate pins for the enrollment and PCR 11 profile. A quote
does not claim that arbitrary runtime measurement records are hardware measured.
The cold/reboot QEMU proof authorizes an encrypted session through this path and
rejects wrong policy context, PCR, peer, expiry and replay. Its approved PCR is a
test fixture; deployed verifier policy, enrollment distribution and
physical-machine validation remain open. Callers must cancel
outstanding verifier challenges when their enrollment or approval policy changes.

Managed peer connections can require TPM attestation before object transfer.
The challenge binds the full Noise session hash; canonical records are at most
402 bytes and use up to three encrypted datagrams. Cached ciphertext retries
handle loss and reordering without reusing a nonce for new plaintext. The local
owner supplies the trusted enrollment and PCR policy, retrieves quote work by
connection handle, and completes the TPM operation outside packet dispatch.
A completed challenge wakes that owner once. Stale, expired and revoked handles
cannot complete a quote. Handshake, attestation and object traffic share the
existing two-operation dispatch budget; packets allocate no connection state.
Host tests cover fragment failures and durable transfer. The swtpm cold/reboot
proof carries an actual quote between two Noise endpoints in one guest;
attestation across independently enrolled machines still needs validation.

A locally bound quote worker now retrieves pending challenges and publishes
responses through those connection handles. It owns its TPM client and a private
snapshot of the supplied credentials, executes on a guarded stack, yields at
hardware waits, and polls at most once per tick. It rechecks the credential
lease, enrollment, service policy and connection before delivery. Cancellation
retains borrowed command buffers until cleanup finishes; late or rejected
completion leaves visible-request and nonce history unchanged. PIN/recovery and
quote workers serialize complete TPM operations through a shared lease, so a
queued cancellation cannot disturb another worker's command or loaded objects.
Reset and boot failure drain the worker before releasing its dependencies.
The swtpm proof cancels before quoting and after evidence exists, rejects a
completed delivery, then retries successfully with the same challenge. Native
provisioning must supply the enrolled key, encrypted blob, parent pin and
revocable authorization; the worker installs no default credentials.

Remote attestation service signatures bind the complete verifier request and
the provider's actual metadata digest through a domain-separated context.
Changing policy, key restrictions, revocations, or metadata invalidates the
signature, and standalone statements cannot be repackaged as remote responses.
The response remains 616 bytes. Verification checks bounded lengths and canonical
unused fields before hashing, then checks the signature once against the trusted
root. Failed signing and provisioning leave committed service state unchanged.
Verified service-identity connections also require the signed device identity to
match the selected peer before opening a connection.

`./scripts/zig.sh build unified-efi-qemu-test` checks firmware authorization of
the complete EFI image, rejection of changes to either embedded payload, and
immunity to external kernel and command-line files. Successful boots must pass the
live TPM measurement check; a TPM without an active SHA-256 bank must be rejected
before kernel entry. This proof uses the production kernel with embedded QEMU
test options; release media retain the hardware CPU baseline. It needs `swtpm`
and `swtpm_setup`, Secure Boot capable OVMF, and the Python packages
`virt-firmware` (tested with 26.9) and `pefile`.
Set `OVMF_SECURE_BOOT_CODE` and matching `OVMF_SECURE_BOOT_VARS` (or `OVMF_VARS`);
`EFI_TEST_PYTHON` and `EFI_VARS_TOOL`
can select tools installed in an isolated virtual environment. The test enrolls
only disposable VM variables and never accesses host firmware. CI supplies the
isolated tools, and release-security-preflight includes this gate. The production
hardware proof requires Secure Boot enabled, a firmware-authenticated image,
and a verified live TPM boot measurement.
Release signing, signer enrollment, TPM measured-boot quotes, and anti-rollback
policy remain separate production work. The firmware state and whole-image
authentication rules follow the [UEFI boot manager](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)
and [image validation specification](https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html).

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
./scripts/zig.sh build -Doptimize=fast userspace-production-images
./scripts/zig.sh build -Doptimize=fast kernel
./scripts/zig.sh build native-store-image
./scripts/zig.sh build -Doptimize=fast iso
```

`kernel-zigos-native.elf` and `build/os.iso` are production artifacts. Synthetic
driver crashes, negative isolation proofs, rollback fault matrices, and scripted
desktop journeys live only in `kernel-zigos-native-verification.elf` and
`build/os-verification.iso`. Production embeds 8 stripped userspace ELFs;
verification adds five proof or synthetic-journey images. Build and check that
boundary with:

```bash
./scripts/zig.sh build kernel-role-check
./scripts/zig.sh build iso-verification
```

The published `zig-out/bin/kernel-zigos-native.elf` is the exact ELF embedded
in the production EFI image. It retains static symbols for the role gate while
omitting non-loadable debug sections. The full diagnostic ELF is installed at
`zig-out/kernel-debug/kernel-zigos-native.elf` under the same role gate; use it
with `llvm-addr2line` for source locations, or a debugger for type information.
Optimized EFI images
omit host-specific debugging metadata before packaging or signing.

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

./scripts/zig.sh build -Doptimize=fast \
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
- `scripts/run-sync-two-node-qemu.sh` (drops two final confirmations by default;
  `SYNC_TWO_NODE_DROP_CONFIRMATIONS=0` runs without injected loss)
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
