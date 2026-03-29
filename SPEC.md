# Zigos

Hypothetical clean-slate operating system spec, v0.1

## 1. Design goals

Zigos is designed for how computers are actually used in 2026:

- multiple personal devices per user
- constant network exposure
- untrusted apps and services
- heavy use of sync and collaboration
- heterogeneous hardware: CPU, GPU, NPU, secure enclave
- high expectation of reliability, rollback, and low-friction recovery

Primary goals

1. Secure by default
2. No ambient authority
3. Local-first, multi-device operation
4. Atomic, reversible system updates
5. Strong app isolation
6. Memory-safe implementation wherever possible
7. First-class support for modern accelerators
8. Data-centric permissions and sharing
9. Explainable behavior and recoverability
10. No backward-compatibility constraints in the native platform

Non-goals

- POSIX compatibility
- unrestricted root/admin execution
- global writable system state
- arbitrary kernel extension by third parties
- app installation via opaque scripts
- files and paths as the only user-facing storage model

## 2. Core architectural principles

### 2.1 Zero ambient authority

A process starts with no access to:

- filesystem data
- network
- camera/mic
- clipboard
- sensors
- contacts
- location
- other processes
- background execution

Every access must be granted explicitly.

### 2.2 Immutable base system

The OS base image is:

- signed
- verified at boot
- mounted read-only
- updated atomically
- rollback-capable

### 2.3 User-space services by default

Most subsystems outside scheduling, memory management, interrupt routing, and capability enforcement run outside the kernel:

- drivers
- network stack
- object store
- sync engine
- UI compositor
- package manager
- indexer
- print/media subsystems

### 2.4 Data is versioned

User data is versioned and recoverable by default:

- snapshots
- object history
- per-workspace undo/restore
- selective sync
- auditable sharing

### 2.5 Platform APIs over system internals

Applications use stable, typed platform APIs.

They do not:

- inspect arbitrary system state
- patch global system files
- inject into other processes
- assume directory layouts
- assume raw device access

## 3. System model

Zigos exposes five core primitives:

### 3.1 Principal

An identity that can hold authority:

- user
- device
- app
- service
- organization policy authority

Each principal has cryptographic identity.

### 3.2 Capability

An unforgeable token granting a limited right over an object or service.

Examples:

- read document X
- append to workspace Y
- send HTTPS requests to service Z
- use microphone while task T is foregrounded

### 3.3 Object

The base storage unit.

Object types include:

- blob
- document
- collection
- secret
- media asset
- event stream

Objects are content-addressed and versioned.

### 3.4 Workspace

A mutable container for related objects, policies, and sharing rules.

Examples:

- personal notes
- project repository
- tax documents
- video editing project
- team design workspace

### 3.5 Task

A transient execution context combining:

- UI state
- app components
- granted capabilities
- resource budget
- audit trail

The user experiences "tasks" more directly than "apps."

## 4. Kernel specification

### 4.1 Kernel type

Zigos uses a microkernel or microkernel-like architecture.

Kernel responsibilities

The kernel is limited to:

- CPU scheduling
- virtual memory management
- IPC transport
- capability table enforcement
- interrupt handling
- low-level timekeeping
- secure boot handoff
- IOMMU and DMA isolation primitives

Excluded from kernel

These must run outside the kernel:

- drivers
- full network stack
- filesystem/object store logic
- window server
- package management
- indexing/search
- sync/replication

### 4.2 Kernel requirements

The kernel MUST:

- be memory-safe where feasible
- isolate processes and services strongly
- support service restart without full-system reboot
- expose minimal, typed syscall surface
- support capability passing over IPC
- support per-process and per-task resource accounting

### 4.3 Privilege model

There is no traditional omnipotent "root" user in normal operation.

Instead:

- system authority is split into scoped administrative principals
- admin actions require explicit policy authorization
- emergency maintenance uses a break-glass recovery mode
- all privileged changes are logged

## 5. Boot, trust, and attestation

### 5.1 Boot chain

Boot sequence:

1. hardware root of trust verifies bootloader
2. bootloader verifies kernel and base image manifest
3. kernel verifies core service set
4. system launches into a measured, attestable state

### 5.2 Measured state

The system maintains a measurement of:

- kernel
- base image version
- critical service hashes
- policy set
- driver set

Remote attestation is optional and user-visible when used.

### 5.3 Recovery mode

A separate recovery environment must:

- verify and reinstall system images
- revoke compromised device trust
- restore from snapshots
- repair sync state
- rotate device keys

## 6. Process and application model

### 6.1 App packaging

Applications are shipped as signed bundles containing:

- manifest
- executable components
- interface definitions
- assets
- update channel metadata

Installers are not arbitrary scripts.

### 6.2 App execution

Each app instance runs in:

- its own sandbox
- its own namespace
- with only declared and granted capabilities

App instances are isolated from one another unless linked by explicit platform channels.

### 6.3 Component model

The default application ABI is a typed component ABI designed for:

- safe IPC
- language interoperability
- portability
- versioned interfaces

Native code is allowed, but only inside the same capability sandbox.

### 6.4 Background execution

Background work is not unrestricted.

Allowed background triggers:

- user-approved scheduled jobs
- push events
- local object changes
- device proximity or sensor rules
- sync completion
- media/export completion
- organization policy tasks

Every background task must declare:

- trigger
- expected duration
- resource budget
- network needs
- visibility level

The system may throttle, delay, or deny abusive workloads.

## 7. Security model

### 7.1 Capability-based access control

All protected resources are accessed through capabilities.

No app can discover or access resources just by naming them.

Examples:

- a path string does not grant file access
- an IP address does not imply permission to connect
- knowing another app exists does not allow IPC with it

### 7.2 Permission grants

Permissions are:

- object-level where possible
- time-bounded when appropriate
- task-scoped by default
- revocable
- inspectable by the user

Examples:

- "Allow this editor to modify Workspace Alpha"
- "Allow this scanner app to use the camera for 10 minutes"

### 7.3 Data egress control

Network access is split into:

- none
- local network only
- named service identities
- named domains
- unrestricted internet

Default is none.

### 7.4 Process isolation

Apps may not:

- inspect arbitrary memory
- inject code into other processes
- scrape other windows
- read the clipboard continuously
- register hidden global hooks

Such rights require special user-visible entitlements.

### 7.5 Secrets

Secrets are stored in hardware-backed secure storage when available.

Apps receive handles to secrets, not raw export, unless explicitly allowed.

## 8. Storage model

### 8.1 Object store

The native storage layer is a content-addressed object store.

Properties:

- immutable object versions
- deduplication
- integrity verification
- cheap snapshots
- efficient replication
- built-in history

### 8.2 Mutable state

Mutable user data is represented as:

- versioned documents
- append-only logs
- transactional workspace state
- CRDT-backed shared objects where suitable

### 8.3 File bridge

For compatibility with user expectations and simple tooling, Zigos provides a file view.

The file view is:

- derived from the object store
- permission-aware
- optional for apps
- not the system's primary source of truth

This means users can still drag, save, and export "files," but the OS internally tracks richer structure.

### 8.4 Snapshots and recovery

Every workspace supports:

- automatic snapshots
- timeline restore
- deleted-object recovery
- branch/merge where applicable
- export/import of signed snapshots

## 9. Sync and multi-device model

### 9.1 Device graph

A user account is a graph of trusted devices, not a cloud username/password pair.

Each device has:

- hardware-backed keys when available
- replication permissions
- per-workspace sync policy
- revocation status

### 9.2 Local-first replication

Sync is built into the OS.

Requirements:

- offline operation first
- E2EE for personal data
- selective sync by workspace
- device-to-device sync when available
- relay-assisted sync when needed
- conflict detection at object level

### 9.3 Sync semantics

Different data classes use different replication models:

- notes, docs, settings: CRDT or mergeable object model
- large media projects: snapshot plus chunk replication
- secrets: explicit secure transfer
- databases: application-declared transactional sync model

### 9.4 Sharing

Users share objects or workspaces with:

- other users
- teams
- apps
- devices

Sharing specifies:

- read/write/admin rights
- expiration
- network scope
- resharing policy
- audit visibility

## 10. Networking model

### 10.1 Identity-first networking

Services are addressed by identity as well as location.

The OS prefers:

- authenticated services
- encrypted transport by default
- service identity pinning
- explicit egress rules
- scoped local network discovery

### 10.2 Network permissions

Network permissions are granted as policy objects, for example:

- connect to notes.example
- connect to https://api.example.com
- join local subnet discovery for printers only
- accept inbound connections for collaborative session type X

### 10.3 Private overlay

Zigos includes a private user-device overlay network for:

- sync
- remote access
- private service publishing
- encrypted device relay

## 11. UI and interaction model

### 11.1 Task-first UX

The top-level UX is task-oriented rather than purely app-oriented.

Examples:

- "write report"
- "review contract"
- "edit media project"
- "coordinate trip"
- "pair devices"

Apps still exist, but the OS orchestrates the task.

### 11.2 Windows and views

The system supports multiple view types:

- document view
- project/workspace view
- app panel
- full-screen media/task view

### 11.3 Permission UX

Permissions are granted at meaningful moments, not as blanket startup prompts.

The system should say:

- what the app wants
- why it wants it
- for how long
- over which objects
- with what network path
- whether the operation stays local

### 11.4 Notifications

Notifications are structured objects with:

- reason
- urgency
- source principal
- task linkage
- expiry
- suppression policy

Apps cannot spam arbitrary notifications indefinitely.

## 12. Hardware and resource management

### 12.1 Unified resource scheduler

The OS scheduler manages:

- CPU
- GPU
- NPU
- media engines
- memory bandwidth
- thermals
- battery budget

### 12.2 Shared memory objects

The platform supports secure shared memory objects across compute units, with:

- access labels
- lifetime tracking
- zero-copy where possible
- explicit revocation

### 12.3 Thermal and power policy

Every task receives a resource class:

- foreground interactive
- background light
- media export
- batch compute
- emergency/system critical

The scheduler may degrade quality or delay work to preserve:

- responsiveness
- battery
- thermals
- privacy mode constraints

## 13. Driver model

### 13.1 User-space drivers

All possible drivers run in user space.

Requirements:

- isolated crash domain
- restartable
- least privilege
- DMA bounded by IOMMU policy
- signed distribution
- versioned interfaces

### 13.2 Driver permissions

A driver receives only the authority needed for its device class.

A compromised audio driver should not gain display or network authority.

### 13.3 Hot-swap and failure recovery

Driver failure should:

- restart the driver
- preserve unaffected services
- notify the user only if impact is visible
- emit a structured diagnostic event

## 14. Updates and system lifecycle

### 14.1 Base OS updates

Base OS updates are:

- image-based
- signed
- atomic
- staged
- rollback-capable

### 14.2 Health checks

After update activation, the system validates:

- boot success
- core service startup
- storage mount integrity
- networking service health
- UI service availability

Failure triggers automatic rollback.

### 14.3 App updates

App updates are independent of base OS updates and must:

- preserve capability semantics
- declare permission changes
- support rollback of prior app version
- retain data compatibility or provide migration manifest

## 15. Observability and diagnostics

### 15.1 Structured event ledger

The OS keeps a structured event ledger for:

- permission grants/denials
- process crashes
- driver restarts
- update history
- sync conflicts
- device trust changes

### 15.2 Explainable denials

When an action fails, the OS should explain:

- which policy blocked it
- which capability was missing
- whether user approval can resolve it
- whether retry is safe

### 15.3 Privacy-preserving diagnostics

Crash and telemetry reporting are:

- opt-in by default for personal devices
- data-minimized
- scrubbed of protected content where possible
- exportable by the user

## 16. Policy and administration

### 16.1 Policy objects

Policies are signed objects applied at:

- user scope
- device scope
- workspace scope
- organization scope

### 16.2 Policy examples

Policies can control:

- allowed app sources
- network egress
- removable storage rules
- screen capture rights
- sync destinations
- retention and audit requirements

### 16.3 Enterprise support

Enterprise management exists, but as additive policy, not as a separate fork of the OS design.

## 17. Compatibility strategy

### 17.1 Native platform

The native platform does not preserve legacy APIs for compatibility's sake.

### 17.2 Legacy support

Legacy apps run in explicit compatibility environments:

- VM
- container
- emulation layer
- remote application session

These environments are:

- isolated
- clearly labeled
- limited in host integration
- granted access through portals, not direct host control

## 18. Example application manifest

Here's what an app permission model might look like:

```yaml
app:
  id: com.example.writer
  version: 1.4.0
  publisher: Example Software

interfaces:
  provides:
    - writer.edit/v1
  consumes:
    - documents.open/v1
    - export.pdf/v1

permissions:
  workspace:
    - id: workspace://report-alpha
      access: read-write

  network:
    - service: sync.example.com
      access: outbound
      purpose: document-sync

  devices:
    microphone: none
    camera: none
    location: none

  background:
    - trigger: sync-complete
      max_duration_seconds: 30
```

That is a very different world from:

- "this installer has admin rights"
- "this app can read your whole Documents folder"
- "this process can open sockets anywhere"
- "this updater runs forever in the background"

## 19. What using Zigos would feel like

For users:

- apps install cleanly
- uninstall actually removes them
- updates are boring and reversible
- data sync is built in
- permissions make sense at the object/task level
- malware has much less room to move
- recovery is much easier

For developers:

- stricter rules
- fewer hidden assumptions
- better APIs
- less power to poke internals
- much better reliability and security guarantees

For administrators:

- policy is declarative
- auditing is built in
- device trust is manageable
- rollback and recovery are straightforward

## 20. One-sentence summary

Zigos is a capability-based, local-first, multi-device operating system with an immutable core, versioned object storage, strong sandboxing, explicit identity, and first-class support for modern accelerators.
