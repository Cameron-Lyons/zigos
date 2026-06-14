const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_ALLOW_LIST: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;
const POLICY_INDEX_CAPACITY: usize = MAX_POLICIES * 2;

pub const Scope = enum(u8) {
    user,
    device,
    workspace,
    organization,
};

pub const InstallSourceMode = enum(u8) {
    any_signed,
    trusted_sources,
    platform_store_only,
};

pub const NetworkEgressMode = enum(u8) {
    inherit,
    none,
    local_only,
    allow_list,
    unrestricted,
};

pub const SubjectSet = struct {
    user_id: ?u64 = null,
    device_id: ?u64 = null,
    workspace_id: ?u64 = null,
    organization_id: ?u64 = null,
};

pub const DecisionReason = enum(u8) {
    none,
    unsigned_policy,
    install_source_denied,
    network_egress_denied,
    sync_destination_denied,
    removable_storage_denied,
    screen_capture_denied,
    clipboard_denied,
    camera_denied,
    microphone_denied,
    location_denied,
    contacts_denied,
    sensor_denied,
    peer_ipc_denied,
    remote_ai_denied,
    ai_training_denied,
    ai_context_denied,
    ai_model_measurement_denied,
    ai_model_source_denied,
    ai_model_staleness_denied,
    session_hardware_denied,
    session_device_posture_denied,
    session_unlock_stale,
    session_primary_device_denied,
    package_sbom_denied,
    package_reproducibility_denied,
    package_builder_denied,
    package_vulnerability_scan_denied,
    private_egress_budget_denied,
    data_export_denied,
    data_deletion_denied,
    data_deletion_receipt_denied,
    permission_retention_denied,
    permission_lease_denied,
    retention_denied,
    audit_export_required,
};

pub const PolicyDecision = struct {
    allowed: bool,
    reason: DecisionReason = .none,
    blocking_scope: ?Scope = null,
    blocking_policy_id: u64 = 0,
    blocking_generation: u32 = 0,
};

pub const CreateRequest = struct {
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label: []const u8,
    install_source_mode: InstallSourceMode = .any_signed,
    allowed_install_sources: []const []const u8 = &.{},
    network_egress_mode: NetworkEgressMode = .inherit,
    allowed_network_destinations: []const []const u8 = &.{},
    allowed_sync_destinations: []const []const u8 = &.{},
    removable_storage_allowed: bool = false,
    screen_capture_allowed: bool = false,
    clipboard_allowed: bool = false,
    camera_allowed: bool = false,
    microphone_allowed: bool = false,
    location_allowed: bool = false,
    contacts_allowed: bool = false,
    sensors_allowed: bool = false,
    peer_ipc_allowed: bool = false,
    remote_ai_allowed: bool = false,
    ai_training_allowed: bool = false,
    max_ai_context_bytes: usize = 0,
    require_ai_model_measurement: bool = false,
    require_trusted_ai_model_source: bool = false,
    max_ai_model_age_days: u16 = 0,
    require_hardware_backed_session: bool = false,
    require_platform_backed_device_session: bool = false,
    require_primary_device_session: bool = false,
    max_session_unlock_age_ticks: u64 = 0,
    require_package_sbom: bool = false,
    require_reproducible_package_build: bool = false,
    require_trusted_package_builder: bool = false,
    require_vulnerability_scan: bool = false,
    max_remote_private_egress_bytes: usize = 0,
    data_export_allowed: bool = false,
    data_deletion_allowed: bool = false,
    require_data_deletion_receipt: bool = false,
    max_data_export_bytes: usize = 0,
    max_sensitive_retention_days: u16 = 0,
    max_permission_lease_ticks: u64 = 0,
    require_sensitive_permission_lease: bool = false,
    retention_days: u16 = 0,
    audit_export_required: bool = false,
};

pub const RetentionAuditRequest = struct {
    retention_days: u16,
    audit_export_present: bool = false,
};

pub const AiUseRequest = struct {
    remote_model: bool = false,
    training_user_content: bool = false,
    context_bytes: usize = 0,
    local_model_measured: bool = true,
    model_source_trusted: bool = true,
    model_age_days: u16 = 0,
};

pub const SessionTrustRequest = struct {
    hardware_backed_credential: bool = false,
    device_platform_backed: bool = false,
    primary_device_assertion: bool = false,
    unlock_age_ticks: u64 = 0,
};

pub const SensitiveEgressRequest = struct {
    sensitivity: manifest.DataSensitivity = .internal_data,
    remote_bytes: usize = 0,
};

pub const DataRightsOperation = enum(u8) {
    portable_export,
    delete,
};

pub const PackageProvenanceRequest = struct {
    sbom_present: bool = false,
    source_archive_present: bool = false,
    build_recipe_present: bool = false,
    reproducible_build: bool = false,
    trusted_builder: bool = false,
    vulnerability_scan_present: bool = false,
};

pub const DataRightsRequest = struct {
    operation: DataRightsOperation,
    sensitivity: manifest.DataSensitivity = .internal_data,
    bytes: usize = 0,
    deletion_receipt_present: bool = false,
};

pub const PermissionUseRequest = struct {
    kind: manifest.PermissionKind,
    sensitivity: manifest.DataSensitivity = .internal_data,
    retention_days: u16 = 0,
    lease_ticks: u64 = 0,
};

pub const PolicyObject = struct {
    id: u64,
    generation: u32,
    revoked: bool,
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    install_source_mode: InstallSourceMode,
    allowed_install_source_count: usize,
    allowed_install_sources: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_install_source_lens: [MAX_ALLOW_LIST]usize,
    network_egress_mode: NetworkEgressMode,
    allowed_network_destination_count: usize,
    allowed_network_destinations: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_network_destination_lens: [MAX_ALLOW_LIST]usize,
    allowed_sync_destination_count: usize,
    allowed_sync_destinations: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_sync_destination_lens: [MAX_ALLOW_LIST]usize,
    removable_storage_allowed: bool,
    screen_capture_allowed: bool,
    clipboard_allowed: bool,
    camera_allowed: bool,
    microphone_allowed: bool,
    location_allowed: bool,
    contacts_allowed: bool,
    sensors_allowed: bool,
    peer_ipc_allowed: bool,
    remote_ai_allowed: bool,
    ai_training_allowed: bool,
    max_ai_context_bytes: usize,
    require_ai_model_measurement: bool,
    require_trusted_ai_model_source: bool,
    max_ai_model_age_days: u16,
    require_hardware_backed_session: bool,
    require_platform_backed_device_session: bool,
    require_primary_device_session: bool,
    max_session_unlock_age_ticks: u64,
    require_package_sbom: bool,
    require_reproducible_package_build: bool,
    require_trusted_package_builder: bool,
    require_vulnerability_scan: bool,
    max_remote_private_egress_bytes: usize,
    data_export_allowed: bool,
    data_deletion_allowed: bool,
    require_data_deletion_receipt: bool,
    max_data_export_bytes: usize,
    max_sensitive_retention_days: u16,
    max_permission_lease_ticks: u64,
    require_sensitive_permission_lease: bool,
    retention_days: u16,
    audit_export_required: bool,
    signature: manifest.Signature,

    pub fn labelSlice(self: *const PolicyObject) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn allowsInstallSource(self: *const PolicyObject, source_identity: []const u8) bool {
        return switch (self.install_source_mode) {
            .any_signed => true,
            .trusted_sources => listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
            .platform_store_only => std.mem.startsWith(u8, source_identity, "store:") or listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
        };
    }

    pub fn packageProvenanceDenial(self: *const PolicyObject, request: PackageProvenanceRequest) ?DecisionReason {
        if (self.require_package_sbom and !request.sbom_present) return .package_sbom_denied;
        if (self.require_reproducible_package_build and
            (!request.reproducible_build or !request.source_archive_present or !request.build_recipe_present))
        {
            return .package_reproducibility_denied;
        }
        if (self.require_trusted_package_builder and !request.trusted_builder) return .package_builder_denied;
        if (self.require_vulnerability_scan and !request.vulnerability_scan_present) return .package_vulnerability_scan_denied;
        return null;
    }

    pub fn allowsPackageProvenance(self: *const PolicyObject, request: PackageProvenanceRequest) bool {
        return self.packageProvenanceDenial(request) == null;
    }

    pub fn allowsNetworkDestination(self: *const PolicyObject, destination: []const u8) bool {
        return switch (self.network_egress_mode) {
            .inherit, .unrestricted => true,
            .none => false,
            .local_only => isLocalDestination(destination),
            .allow_list => listContains(
                self.allowed_network_destinations[0..self.allowed_network_destination_count],
                self.allowed_network_destination_lens[0..self.allowed_network_destination_count],
                destination,
            ),
        };
    }

    pub fn allowsSyncDestination(self: *const PolicyObject, destination: []const u8) bool {
        if (self.allowed_sync_destination_count == 0) {
            return switch (self.network_egress_mode) {
                .inherit, .unrestricted => true,
                .local_only => isLocalDestination(destination),
                .none, .allow_list => false,
            };
        }
        return listContains(
            self.allowed_sync_destinations[0..self.allowed_sync_destination_count],
            self.allowed_sync_destination_lens[0..self.allowed_sync_destination_count],
            destination,
        );
    }
};

pub const Error = error{
    InstallSourceTooLong,
    LabelTooLong,
    NetworkDestinationTooLong,
    PolicyAlreadyRevoked,
    PolicyNotFound,
    PolicyTableFull,
    SyncDestinationTooLong,
    TooManyInstallSources,
    TooManyNetworkDestinations,
    TooManySyncDestinations,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyObject = zeroPolicy(),
};

const PolicyIdIndex = indexed_arena.UniqueIndex(POLICY_INDEX_CAPACITY);
const PolicyScopeIndex = indexed_arena.MultimapIndex(MAX_POLICIES, MAX_POLICIES, POLICY_INDEX_CAPACITY);

pub const Directory = struct {
    next_policy_id: u64 = 1,
    slots: [MAX_POLICIES]PolicySlot = [_]PolicySlot{PolicySlot{}} ** MAX_POLICIES,
    policy_id_index: PolicyIdIndex = PolicyIdIndex.init(),
    scope_index: PolicyScopeIndex = PolicyScopeIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn create(
        self: *Directory,
        request: CreateRequest,
        signer: signing.SignerIdentity,
    ) (Error || anyerror)!*PolicyObject {
        if (request.allowed_install_sources.len > MAX_ALLOW_LIST) return error.TooManyInstallSources;
        if (request.allowed_network_destinations.len > MAX_ALLOW_LIST) return error.TooManyNetworkDestinations;
        if (request.allowed_sync_destinations.len > MAX_ALLOW_LIST) return error.TooManySyncDestinations;

        const slot_index = self.firstFreeSlotIndex() orelse return error.PolicyTableFull;
        const slot = &self.slots[slot_index];
        slot.in_use = true;
        errdefer slot.* = .{};
        slot.policy = zeroPolicy();
        slot.policy.id = self.next_policy_id;
        self.next_policy_id += 1;
        slot.policy.generation = nextGeneration(self, request.scope, request.subject_id);
        slot.policy.scope = request.scope;
        slot.policy.subject_id = request.subject_id;
        slot.policy.issuer = request.issuer;
        slot.policy.label_len = native_util.copyTextExact(&slot.policy.label, request.label) catch return error.LabelTooLong;
        slot.policy.install_source_mode = request.install_source_mode;
        slot.policy.network_egress_mode = request.network_egress_mode;
        slot.policy.removable_storage_allowed = request.removable_storage_allowed;
        slot.policy.screen_capture_allowed = request.screen_capture_allowed;
        slot.policy.clipboard_allowed = request.clipboard_allowed;
        slot.policy.camera_allowed = request.camera_allowed;
        slot.policy.microphone_allowed = request.microphone_allowed;
        slot.policy.location_allowed = request.location_allowed;
        slot.policy.contacts_allowed = request.contacts_allowed;
        slot.policy.sensors_allowed = request.sensors_allowed;
        slot.policy.peer_ipc_allowed = request.peer_ipc_allowed;
        slot.policy.remote_ai_allowed = request.remote_ai_allowed;
        slot.policy.ai_training_allowed = request.ai_training_allowed;
        slot.policy.max_ai_context_bytes = request.max_ai_context_bytes;
        slot.policy.require_ai_model_measurement = request.require_ai_model_measurement;
        slot.policy.require_trusted_ai_model_source = request.require_trusted_ai_model_source;
        slot.policy.max_ai_model_age_days = request.max_ai_model_age_days;
        slot.policy.require_hardware_backed_session = request.require_hardware_backed_session;
        slot.policy.require_platform_backed_device_session = request.require_platform_backed_device_session;
        slot.policy.require_primary_device_session = request.require_primary_device_session;
        slot.policy.max_session_unlock_age_ticks = request.max_session_unlock_age_ticks;
        slot.policy.require_package_sbom = request.require_package_sbom;
        slot.policy.require_reproducible_package_build = request.require_reproducible_package_build;
        slot.policy.require_trusted_package_builder = request.require_trusted_package_builder;
        slot.policy.require_vulnerability_scan = request.require_vulnerability_scan;
        slot.policy.max_remote_private_egress_bytes = request.max_remote_private_egress_bytes;
        slot.policy.data_export_allowed = request.data_export_allowed;
        slot.policy.data_deletion_allowed = request.data_deletion_allowed;
        slot.policy.require_data_deletion_receipt = request.require_data_deletion_receipt;
        slot.policy.max_data_export_bytes = request.max_data_export_bytes;
        slot.policy.max_sensitive_retention_days = request.max_sensitive_retention_days;
        slot.policy.max_permission_lease_ticks = request.max_permission_lease_ticks;
        slot.policy.require_sensitive_permission_lease = request.require_sensitive_permission_lease;
        slot.policy.retention_days = request.retention_days;
        slot.policy.audit_export_required = request.audit_export_required;

        for (request.allowed_install_sources, 0..) |source_identity, index| {
            slot.policy.allowed_install_source_lens[index] = native_util.copyTextExact(&slot.policy.allowed_install_sources[index], source_identity) catch return error.InstallSourceTooLong;
            slot.policy.allowed_install_source_count += 1;
        }
        for (request.allowed_network_destinations, 0..) |destination, index| {
            slot.policy.allowed_network_destination_lens[index] = native_util.copyTextExact(&slot.policy.allowed_network_destinations[index], destination) catch return error.NetworkDestinationTooLong;
            slot.policy.allowed_network_destination_count += 1;
        }
        for (request.allowed_sync_destinations, 0..) |destination, index| {
            slot.policy.allowed_sync_destination_lens[index] = native_util.copyTextExact(&slot.policy.allowed_sync_destinations[index], destination) catch return error.SyncDestinationTooLong;
            slot.policy.allowed_sync_destination_count += 1;
        }

        const digest = policyDigest(&slot.policy);
        slot.policy.signature = try signing.sign(signer, &digest);
        self.indexPolicy(slot_index);
        return &slot.policy;
    }

    pub fn activeForScope(self: *Directory, scope: Scope, subject_id: u64) ?*PolicyObject {
        var candidate: ?*PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    pub fn verify(self: *const Directory, policy_id: u64) bool {
        const policy = self.findConst(policy_id) orelse return false;
        const digest = policyDigest(policy);
        return signing.verify(policy.signature, &digest);
    }

    pub fn revokePolicy(self: *Directory, policy_id: u64) Error!void {
        const slot_index = self.policy_id_index.lookup(policy_id) orelse return error.PolicyNotFound;
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy id index points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.policy.id != policy_id) native_util.impossibleByInvariant("policy id index points at the wrong policy");
        if (slot.policy.revoked) return error.PolicyAlreadyRevoked;
        slot.policy.revoked = true;
    }

    pub fn revokePoliciesForScope(self: *Directory, scope: Scope, subject_id: u64) usize {
        var revoked_count: usize = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            slot.policy.revoked = true;
            revoked_count += 1;
        }
        return revoked_count;
    }

    pub fn installSourceAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        source_identity: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsInstallSource(source_identity);
    }

    pub fn syncDestinationAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        destination: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsSyncDestination(destination);
    }

    pub fn installSourceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        source_identity: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsInstallSource(source_identity)) {
                return block(policy, .install_source_denied);
            }
        }
        return allow();
    }

    pub fn packageProvenanceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: PackageProvenanceRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.packageProvenanceDenial(request)) |reason| return block(policy, reason);
        }
        return allow();
    }

    pub fn syncDestinationDecision(
        self: *const Directory,
        subjects: SubjectSet,
        destination: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsSyncDestination(destination)) {
                return block(policy, .sync_destination_denied);
            }
        }
        return allow();
    }

    pub fn networkEgressDecision(
        self: *const Directory,
        subjects: SubjectSet,
        destination: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsNetworkDestination(destination)) {
                return block(policy, .network_egress_denied);
            }
        }
        return allow();
    }

    pub fn removableStorageDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.removable_storage_allowed) return block(policy, .removable_storage_denied);
        }
        return allow();
    }

    pub fn screenCaptureDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.screen_capture_allowed) return block(policy, .screen_capture_denied);
        }
        return allow();
    }

    pub fn permissionKindDecision(
        self: *const Directory,
        subjects: SubjectSet,
        kind: manifest.PermissionKind,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policyAllowsPermissionKind(policy, kind)) {
                return block(policy, permissionKindDenialReason(kind));
            }
        }
        return allow();
    }

    pub fn aiUseDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: AiUseRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (request.remote_model and !policy.remote_ai_allowed) return block(policy, .remote_ai_denied);
            if (request.training_user_content and !policy.ai_training_allowed) return block(policy, .ai_training_denied);
            if (policy.max_ai_context_bytes != 0 and request.context_bytes > policy.max_ai_context_bytes) {
                return block(policy, .ai_context_denied);
            }
            if (!request.remote_model and policy.require_ai_model_measurement and !request.local_model_measured) {
                return block(policy, .ai_model_measurement_denied);
            }
            if (!request.remote_model and policy.require_trusted_ai_model_source and !request.model_source_trusted) {
                return block(policy, .ai_model_source_denied);
            }
            if (!request.remote_model and policy.max_ai_model_age_days != 0 and request.model_age_days > policy.max_ai_model_age_days) {
                return block(policy, .ai_model_staleness_denied);
            }
        }
        return allow();
    }

    pub fn sessionTrustDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SessionTrustRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.require_hardware_backed_session and !request.hardware_backed_credential) {
                return block(policy, .session_hardware_denied);
            }
            if (policy.require_platform_backed_device_session and !request.device_platform_backed) {
                return block(policy, .session_device_posture_denied);
            }
            if (policy.require_primary_device_session and !request.primary_device_assertion) {
                return block(policy, .session_primary_device_denied);
            }
            if (policy.max_session_unlock_age_ticks != 0 and request.unlock_age_ticks > policy.max_session_unlock_age_ticks) {
                return block(policy, .session_unlock_stale);
            }
        }
        return allow();
    }

    pub fn sensitiveEgressDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SensitiveEgressRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.max_remote_private_egress_bytes != 0 and request.remote_bytes > policy.max_remote_private_egress_bytes) {
                return block(policy, .private_egress_budget_denied);
            }
        }
        return allow();
    }

    pub fn dataRightsDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: DataRightsRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            switch (request.operation) {
                .portable_export => {
                    if (!policy.data_export_allowed) return block(policy, .data_export_denied);
                    if (policy.max_data_export_bytes != 0 and request.bytes > policy.max_data_export_bytes) {
                        return block(policy, .data_export_denied);
                    }
                },
                .delete => {
                    if (!policy.data_deletion_allowed) return block(policy, .data_deletion_denied);
                    if (policy.require_data_deletion_receipt and !request.deletion_receipt_present) {
                        return block(policy, .data_deletion_receipt_denied);
                    }
                },
            }
        }
        return allow();
    }

    pub fn permissionUseDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: PermissionUseRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.max_sensitive_retention_days != 0 and request.retention_days > policy.max_sensitive_retention_days) {
                return block(policy, .permission_retention_denied);
            }
            if (manifest.dangerousPermissionKind(request.kind) and
                policy.require_sensitive_permission_lease and
                request.lease_ticks == 0)
            {
                return block(policy, .permission_lease_denied);
            }
            if (manifest.dangerousPermissionKind(request.kind) and
                policy.max_permission_lease_ticks != 0 and
                request.lease_ticks > policy.max_permission_lease_ticks)
            {
                return block(policy, .permission_lease_denied);
            }
        }
        return allow();
    }

    pub fn retentionAuditDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: RetentionAuditRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.retention_days != 0 and request.retention_days > policy.retention_days) {
                return block(policy, .retention_denied);
            }
            if (policy.audit_export_required and !request.audit_export_present) {
                return block(policy, .audit_export_required);
            }
        }
        return allow();
    }

    fn findConst(self: *const Directory, policy_id: u64) ?*const PolicyObject {
        if (policy_id == 0) return null;
        const slot_index = self.policy_id_index.lookup(policy_id) orelse return null;
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy id index points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.policy.id != policy_id) native_util.impossibleByInvariant("policy id index points at the wrong policy");
        return &slot.policy;
    }

    fn activeForScopeConst(self: *const Directory, scope: Scope, subject_id: u64) ?*const PolicyObject {
        var candidate: ?*const PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    fn activePolicyIterator(self: *const Directory, subjects: SubjectSet) ActivePolicyIterator {
        return .{
            .directory = self,
            .subjects = subjects,
        };
    }

    fn requireVerified(self: *const Directory, policy: *const PolicyObject) PolicyDecision {
        if (self.verify(policy.id)) return allow();
        return block(policy, .unsigned_policy);
    }

    fn firstFreeSlotIndex(self: *const Directory) ?usize {
        for (self.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) return slot_index;
        }
        return null;
    }

    fn indexPolicy(self: *Directory, slot_index: usize) void {
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy index update points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.policy.id == 0) native_util.impossibleByInvariant("policy index update requires a live policy");
        self.policy_id_index.insert(slot.policy.id, slot_index);
        if (!self.scope_index.append(policyScopeKey(slot.policy.scope, slot.policy.subject_id), slot_index)) {
            native_util.impossibleByInvariant("policy scope index capacity covers policy slots");
        }
    }
};

const ActivePolicyIterator = struct {
    directory: *const Directory,
    subjects: SubjectSet,
    index: usize = 0,

    fn next(self: *ActivePolicyIterator) ?*const PolicyObject {
        while (self.index < 4) {
            const index = self.index;
            self.index += 1;
            switch (index) {
                0 => if (self.subjects.organization_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.organization, subject_id)) |policy| return policy;
                },
                1 => if (self.subjects.user_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.user, subject_id)) |policy| return policy;
                },
                2 => if (self.subjects.device_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.device, subject_id)) |policy| return policy;
                },
                3 => if (self.subjects.workspace_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.workspace, subject_id)) |policy| return policy;
                },
                else => {},
            }
        }
        return null;
    }
};

fn allow() PolicyDecision {
    return .{ .allowed = true };
}

fn block(policy: *const PolicyObject, reason: DecisionReason) PolicyDecision {
    return .{
        .allowed = false,
        .reason = reason,
        .blocking_scope = policy.scope,
        .blocking_policy_id = policy.id,
        .blocking_generation = policy.generation,
    };
}

fn policyAllowsPermissionKind(policy: *const PolicyObject, kind: manifest.PermissionKind) bool {
    return switch (kind) {
        .clipboard => policy.clipboard_allowed,
        .camera => policy.camera_allowed,
        .mic => policy.microphone_allowed,
        .location => policy.location_allowed,
        .contacts => policy.contacts_allowed,
        .sensor => policy.sensors_allowed,
        .screen_capture => policy.screen_capture_allowed,
        .peer_ipc => policy.peer_ipc_allowed,
        else => true,
    };
}

fn permissionKindDenialReason(kind: manifest.PermissionKind) DecisionReason {
    return switch (kind) {
        .clipboard => .clipboard_denied,
        .camera => .camera_denied,
        .mic => .microphone_denied,
        .location => .location_denied,
        .contacts => .contacts_denied,
        .sensor => .sensor_denied,
        .screen_capture => .screen_capture_denied,
        .peer_ipc => .peer_ipc_denied,
        else => .none,
    };
}

fn zeroPolicy() PolicyObject {
    return .{
        .id = 0,
        .generation = 0,
        .revoked = false,
        .scope = .user,
        .subject_id = 0,
        .issuer = .{ .kind = .policy_authority, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .install_source_mode = .any_signed,
        .allowed_install_source_count = 0,
        .allowed_install_sources = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_install_source_lens = [_]usize{0} ** MAX_ALLOW_LIST,
        .network_egress_mode = .inherit,
        .allowed_network_destination_count = 0,
        .allowed_network_destinations = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_network_destination_lens = [_]usize{0} ** MAX_ALLOW_LIST,
        .allowed_sync_destination_count = 0,
        .allowed_sync_destinations = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_sync_destination_lens = [_]usize{0} ** MAX_ALLOW_LIST,
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .clipboard_allowed = false,
        .camera_allowed = false,
        .microphone_allowed = false,
        .location_allowed = false,
        .contacts_allowed = false,
        .sensors_allowed = false,
        .peer_ipc_allowed = false,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 0,
        .require_ai_model_measurement = false,
        .require_trusted_ai_model_source = false,
        .max_ai_model_age_days = 0,
        .require_hardware_backed_session = false,
        .require_platform_backed_device_session = false,
        .require_primary_device_session = false,
        .max_session_unlock_age_ticks = 0,
        .require_package_sbom = false,
        .require_reproducible_package_build = false,
        .require_trusted_package_builder = false,
        .require_vulnerability_scan = false,
        .max_remote_private_egress_bytes = 0,
        .data_export_allowed = false,
        .data_deletion_allowed = false,
        .require_data_deletion_receipt = false,
        .max_data_export_bytes = 0,
        .max_sensitive_retention_days = 0,
        .max_permission_lease_ticks = 0,
        .require_sensitive_permission_lease = false,
        .retention_days = 0,
        .audit_export_required = false,
        .signature = .{},
    };
}

fn nextGeneration(self: *const Directory, scope: Scope, subject_id: u64) u32 {
    return latestGenerationForScope(self, scope, subject_id) + 1;
}

fn latestGenerationForScope(self: *const Directory, scope: Scope, subject_id: u64) u32 {
    var best_generation: u32 = 0;
    var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
    while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
        if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
        const slot = &self.slots[cursor];
        if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
        if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
        if (slot.policy.generation > best_generation) best_generation = slot.policy.generation;
    }
    return best_generation;
}

fn policyScopeKey(scope: Scope, subject_id: u64) u64 {
    const subject_id_offset = @sizeOf(Scope);
    const policy_scope_key_bytes = subject_id_offset + @sizeOf(u64);
    var bytes: [policy_scope_key_bytes]u8 = undefined;
    bytes[0] = @intFromEnum(scope);
    std.mem.writeInt(u64, bytes[subject_id_offset..][0..@sizeOf(u64)], subject_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.policy_scope_key, &bytes));
}

fn policyDigest(policy: *const PolicyObject) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "scope", policy.scope);
    crypto_hash.updateEnum(&hasher, "issuer-kind", policy.issuer.kind);
    crypto_hash.updateInt(&hasher, "subject-id", policy.subject_id);
    crypto_hash.updateInt(&hasher, "issuer-serial", policy.issuer.serial);
    crypto_hash.updateBytes(&hasher, "label", policy.labelSlice());
    crypto_hash.updateEnum(&hasher, "install-source-mode", policy.install_source_mode);
    crypto_hash.updateEnum(&hasher, "network-egress-mode", policy.network_egress_mode);
    crypto_hash.updateBool(&hasher, "removable-storage-allowed", policy.removable_storage_allowed);
    crypto_hash.updateBool(&hasher, "screen-capture-allowed", policy.screen_capture_allowed);
    crypto_hash.updateBool(&hasher, "clipboard-allowed", policy.clipboard_allowed);
    crypto_hash.updateBool(&hasher, "camera-allowed", policy.camera_allowed);
    crypto_hash.updateBool(&hasher, "microphone-allowed", policy.microphone_allowed);
    crypto_hash.updateBool(&hasher, "location-allowed", policy.location_allowed);
    crypto_hash.updateBool(&hasher, "contacts-allowed", policy.contacts_allowed);
    crypto_hash.updateBool(&hasher, "sensors-allowed", policy.sensors_allowed);
    crypto_hash.updateBool(&hasher, "peer-ipc-allowed", policy.peer_ipc_allowed);
    crypto_hash.updateBool(&hasher, "remote-ai-allowed", policy.remote_ai_allowed);
    crypto_hash.updateBool(&hasher, "ai-training-allowed", policy.ai_training_allowed);
    crypto_hash.updateInt(&hasher, "max-ai-context-bytes", policy.max_ai_context_bytes);
    crypto_hash.updateBool(&hasher, "require-ai-model-measurement", policy.require_ai_model_measurement);
    crypto_hash.updateBool(&hasher, "require-trusted-ai-model-source", policy.require_trusted_ai_model_source);
    crypto_hash.updateInt(&hasher, "max-ai-model-age-days", policy.max_ai_model_age_days);
    crypto_hash.updateBool(&hasher, "require-hardware-backed-session", policy.require_hardware_backed_session);
    crypto_hash.updateBool(&hasher, "require-platform-backed-device-session", policy.require_platform_backed_device_session);
    crypto_hash.updateBool(&hasher, "require-primary-device-session", policy.require_primary_device_session);
    crypto_hash.updateInt(&hasher, "max-session-unlock-age-ticks", policy.max_session_unlock_age_ticks);
    crypto_hash.updateBool(&hasher, "require-package-sbom", policy.require_package_sbom);
    crypto_hash.updateBool(&hasher, "require-reproducible-package-build", policy.require_reproducible_package_build);
    crypto_hash.updateBool(&hasher, "require-trusted-package-builder", policy.require_trusted_package_builder);
    crypto_hash.updateBool(&hasher, "require-vulnerability-scan", policy.require_vulnerability_scan);
    crypto_hash.updateInt(&hasher, "max-remote-private-egress-bytes", policy.max_remote_private_egress_bytes);
    crypto_hash.updateBool(&hasher, "data-export-allowed", policy.data_export_allowed);
    crypto_hash.updateBool(&hasher, "data-deletion-allowed", policy.data_deletion_allowed);
    crypto_hash.updateBool(&hasher, "require-data-deletion-receipt", policy.require_data_deletion_receipt);
    crypto_hash.updateInt(&hasher, "max-data-export-bytes", policy.max_data_export_bytes);
    crypto_hash.updateInt(&hasher, "max-sensitive-retention-days", policy.max_sensitive_retention_days);
    crypto_hash.updateInt(&hasher, "max-permission-lease-ticks", policy.max_permission_lease_ticks);
    crypto_hash.updateBool(&hasher, "require-sensitive-permission-lease", policy.require_sensitive_permission_lease);
    crypto_hash.updateInt(&hasher, "retention-days", policy.retention_days);
    crypto_hash.updateBool(&hasher, "audit-export-required", policy.audit_export_required);

    var allow_index: usize = 0;
    while (allow_index < policy.allowed_install_source_count) : (allow_index += 1) {
        crypto_hash.updateInt(&hasher, "install-source-index", allow_index);
        crypto_hash.updateBytes(&hasher, "install-source", policy.allowed_install_sources[allow_index][0..policy.allowed_install_source_lens[allow_index]]);
    }
    var network_index: usize = 0;
    while (network_index < policy.allowed_network_destination_count) : (network_index += 1) {
        crypto_hash.updateInt(&hasher, "network-destination-index", network_index);
        crypto_hash.updateBytes(&hasher, "network-destination", policy.allowed_network_destinations[network_index][0..policy.allowed_network_destination_lens[network_index]]);
    }
    var sync_index: usize = 0;
    while (sync_index < policy.allowed_sync_destination_count) : (sync_index += 1) {
        crypto_hash.updateInt(&hasher, "sync-destination-index", sync_index);
        crypto_hash.updateBytes(&hasher, "sync-destination", policy.allowed_sync_destinations[sync_index][0..policy.allowed_sync_destination_lens[sync_index]]);
    }
    return crypto_hash.finalize(&hasher);
}

fn listContains(items: []const [MAX_LABEL_BYTES]u8, lens: []const usize, needle: []const u8) bool {
    for (items, 0..) |item, index| {
        if (std.mem.eql(u8, item[0..lens[index]], needle)) return true;
    }
    return false;
}

fn isLocalDestination(destination: []const u8) bool {
    return std.mem.startsWith(u8, destination, "local:") or
        std.mem.startsWith(u8, destination, "lan.") or
        std.mem.eql(u8, destination, "local-network");
}

test "policy objects remain signed scoped and enforce enterprise controls" {
    var directory = Directory.init();
    const policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp-apps" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.corp.example" },
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 4096,
        .retention_days = 365,
        .audit_export_required = true,
    }, .{
        .label = "corp-policy-key",
        .seed = signing.seedFromByte(0x81),
    });

    try std.testing.expectEqual(@as(u32, 1), policy.generation);
    try std.testing.expectEqualStrings("corp-defaults", policy.labelSlice());
    try std.testing.expect(directory.verify(policy.id));
    try std.testing.expect(directory.installSourceAllowed(.organization, 77, "store:zigos"));
    try std.testing.expect(!directory.installSourceAllowed(.organization, 77, "repo:unknown"));
    try std.testing.expect(directory.syncDestinationAllowed(.organization, 77, "relay.corp.example"));
    try std.testing.expect(!directory.syncDestinationAllowed(.organization, 77, "relay.personal.example"));
    try std.testing.expect(!policy.removable_storage_allowed);
    try std.testing.expect(policy.screen_capture_allowed);
    try std.testing.expect(!policy.remote_ai_allowed);
    try std.testing.expect(!policy.ai_training_allowed);
    try std.testing.expectEqual(@as(usize, 4096), policy.max_ai_context_bytes);
    try std.testing.expect(policy.audit_export_required);
    try std.testing.expectEqual(@as(u16, 365), policy.retention_days);

    _ = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-tightened",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "corp-policy-key",
        .seed = signing.seedFromByte(0x81),
    });
    const latest = directory.activeForScope(.organization, 77).?;
    try std.testing.expectEqual(@as(u32, 2), latest.generation);
    try std.testing.expect(latest.allowsInstallSource("store:zigos"));
    try std.testing.expect(!latest.allowsInstallSource("repo:corp-apps"));
}

test "policy directory composes active user device workspace and organization policy" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "policy-compose-key",
        .seed = signing.seedFromByte(0x83),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-baseline",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .screen_capture_allowed = false,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 4096,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 70,
        .issuer = .{ .kind = .policy_authority, .serial = 8 },
        .label = "user-preferences",
        .install_source_mode = .any_signed,
        .network_egress_mode = .inherit,
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 2048,
    }, signer);
    const device_policy = try directory.create(.{
        .scope = .device,
        .subject_id = 701,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "device-hardening",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = true,
    }, signer);
    _ = try directory.create(.{
        .scope = .workspace,
        .subject_id = 9_001,
        .issuer = .{ .kind = .policy_authority, .serial = 10 },
        .label = "workspace-sync",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.project.example" },
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = true,
        .max_ai_context_bytes = 1024,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 70,
        .device_id = 701,
        .workspace_id = 9_001,
        .organization_id = 7,
    };
    const store_decision = directory.installSourceDecision(subjects, "store:zigos");
    try std.testing.expect(store_decision.allowed);

    const corp_repo_decision = directory.installSourceDecision(subjects, "repo:corp");
    try std.testing.expect(!corp_repo_decision.allowed);
    try std.testing.expectEqual(DecisionReason.install_source_denied, corp_repo_decision.reason);
    try std.testing.expectEqual(Scope.device, corp_repo_decision.blocking_scope.?);
    try std.testing.expectEqual(device_policy.id, corp_repo_decision.blocking_policy_id);

    const relay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(relay_decision.allowed);
    const overlay_decision = directory.syncDestinationDecision(subjects, "overlay.project.example");
    try std.testing.expect(!overlay_decision.allowed);
    try std.testing.expectEqual(DecisionReason.sync_destination_denied, overlay_decision.reason);
    try std.testing.expectEqual(Scope.organization, overlay_decision.blocking_scope.?);

    const removable_decision = directory.removableStorageDecision(subjects);
    try std.testing.expect(!removable_decision.allowed);
    try std.testing.expectEqual(Scope.organization, removable_decision.blocking_scope.?);

    const screen_decision = directory.screenCaptureDecision(subjects);
    try std.testing.expect(!screen_decision.allowed);
    try std.testing.expectEqual(org_policy.id, screen_decision.blocking_policy_id);

    const remote_ai_decision = directory.aiUseDecision(subjects, .{
        .remote_model = true,
        .context_bytes = 512,
    });
    try std.testing.expect(!remote_ai_decision.allowed);
    try std.testing.expectEqual(DecisionReason.remote_ai_denied, remote_ai_decision.reason);
    try std.testing.expectEqual(Scope.organization, remote_ai_decision.blocking_scope.?);

    const training_decision = directory.aiUseDecision(subjects, .{
        .training_user_content = true,
        .context_bytes = 512,
    });
    try std.testing.expect(!training_decision.allowed);
    try std.testing.expectEqual(DecisionReason.ai_training_denied, training_decision.reason);
    try std.testing.expectEqual(Scope.organization, training_decision.blocking_scope.?);

    const context_decision = directory.aiUseDecision(subjects, .{
        .context_bytes = 2_048,
    });
    try std.testing.expect(!context_decision.allowed);
    try std.testing.expectEqual(DecisionReason.ai_context_denied, context_decision.reason);
    try std.testing.expectEqual(Scope.workspace, context_decision.blocking_scope.?);

    const local_small_ai_decision = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
    });
    try std.testing.expect(local_small_ai_decision.allowed);

    const tightened_org = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-store-only",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .none,
    }, signer);
    const next_overlay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(!next_overlay_decision.allowed);
    try std.testing.expectEqual(tightened_org.id, next_overlay_decision.blocking_policy_id);
    try std.testing.expectEqual(@as(u32, 2), next_overlay_decision.blocking_generation);
}

test "policy directory gates sensitive device permissions and private egress budgets" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "privacy-policy-key",
        .seed = signing.seedFromByte(0x84),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 88,
        .issuer = .{ .kind = .policy_authority, .serial = 88 },
        .label = "privacy-baseline",
        .camera_allowed = false,
        .microphone_allowed = false,
        .location_allowed = false,
        .contacts_allowed = false,
        .sensors_allowed = false,
        .clipboard_allowed = false,
        .peer_ipc_allowed = false,
        .max_remote_private_egress_bytes = 1024,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 880,
        .issuer = .{ .kind = .policy_authority, .serial = 89 },
        .label = "user-local-tools",
        .camera_allowed = true,
        .microphone_allowed = true,
        .location_allowed = true,
        .contacts_allowed = true,
        .sensors_allowed = true,
        .clipboard_allowed = true,
        .peer_ipc_allowed = true,
        .max_remote_private_egress_bytes = 4096,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 880,
        .organization_id = 88,
    };
    const camera_decision = directory.permissionKindDecision(subjects, .camera);
    try std.testing.expect(!camera_decision.allowed);
    try std.testing.expectEqual(DecisionReason.camera_denied, camera_decision.reason);
    try std.testing.expectEqual(org_policy.id, camera_decision.blocking_policy_id);

    const clipboard_decision = directory.permissionKindDecision(subjects, .clipboard);
    try std.testing.expect(!clipboard_decision.allowed);
    try std.testing.expectEqual(DecisionReason.clipboard_denied, clipboard_decision.reason);

    const object_decision = directory.permissionKindDecision(subjects, .object_access);
    try std.testing.expect(object_decision.allowed);

    const small_private = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .private_user_data,
        .remote_bytes = 512,
    });
    try std.testing.expect(small_private.allowed);

    const large_private = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .private_user_data,
        .remote_bytes = 2048,
    });
    try std.testing.expect(!large_private.allowed);
    try std.testing.expectEqual(DecisionReason.private_egress_budget_denied, large_private.reason);
    try std.testing.expectEqual(Scope.organization, large_private.blocking_scope.?);

    const large_internal = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .internal_data,
        .remote_bytes = 65_536,
    });
    try std.testing.expect(large_internal.allowed);
}

test "policy directory gates local AI model provenance" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "ai-model-policy-key",
        .seed = signing.seedFromByte(0x87),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 91,
        .issuer = .{ .kind = .policy_authority, .serial = 94 },
        .label = "ai-model-provenance",
        .remote_ai_allowed = false,
        .require_ai_model_measurement = true,
        .require_trusted_ai_model_source = true,
        .max_ai_model_age_days = 30,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 91,
    };
    const measured = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = true,
        .model_age_days = 7,
    });
    try std.testing.expect(measured.allowed);

    const unmeasured = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = false,
        .model_source_trusted = true,
        .model_age_days = 7,
    });
    try std.testing.expect(!unmeasured.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_measurement_denied, unmeasured.reason);
    try std.testing.expectEqual(org_policy.id, unmeasured.blocking_policy_id);

    const untrusted_source = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = false,
        .model_age_days = 7,
    });
    try std.testing.expect(!untrusted_source.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_source_denied, untrusted_source.reason);

    const stale = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = true,
        .model_age_days = 45,
    });
    try std.testing.expect(!stale.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_staleness_denied, stale.reason);

    const remote = directory.aiUseDecision(subjects, .{
        .remote_model = true,
        .context_bytes = 512,
        .local_model_measured = false,
        .model_source_trusted = false,
        .model_age_days = 365,
    });
    try std.testing.expect(!remote.allowed);
    try std.testing.expectEqual(DecisionReason.remote_ai_denied, remote.reason);
}

test "policy directory gates trusted session posture" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "session-trust-policy-key",
        .seed = signing.seedFromByte(0x88),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 92,
        .issuer = .{ .kind = .policy_authority, .serial = 95 },
        .label = "trusted-session",
        .require_hardware_backed_session = true,
        .require_platform_backed_device_session = true,
        .require_primary_device_session = true,
        .max_session_unlock_age_ticks = 5,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 92,
    };
    const trusted = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(trusted.allowed);

    const software_secret = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = false,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!software_secret.allowed);
    try std.testing.expectEqual(DecisionReason.session_hardware_denied, software_secret.reason);
    try std.testing.expectEqual(org_policy.id, software_secret.blocking_policy_id);

    const software_device = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = false,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!software_device.allowed);
    try std.testing.expectEqual(DecisionReason.session_device_posture_denied, software_device.reason);

    const stale_unlock = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 9,
    });
    try std.testing.expect(!stale_unlock.allowed);
    try std.testing.expectEqual(DecisionReason.session_unlock_stale, stale_unlock.reason);

    const secondary_device = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = false,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!secondary_device.allowed);
    try std.testing.expectEqual(DecisionReason.session_primary_device_denied, secondary_device.reason);
}

test "policy directory gates package supply chain posture" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "package-provenance-policy-key",
        .seed = signing.seedFromByte(0x89),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 93,
        .issuer = .{ .kind = .policy_authority, .serial = 96 },
        .label = "package-provenance",
        .require_package_sbom = true,
        .require_reproducible_package_build = true,
        .require_trusted_package_builder = true,
        .require_vulnerability_scan = true,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 93,
    };
    const trusted = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(trusted.allowed);

    const missing_sbom = directory.packageProvenanceDecision(subjects, .{
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!missing_sbom.allowed);
    try std.testing.expectEqual(DecisionReason.package_sbom_denied, missing_sbom.reason);
    try std.testing.expectEqual(org_policy.id, missing_sbom.blocking_policy_id);

    const missing_recipe = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!missing_recipe.allowed);
    try std.testing.expectEqual(DecisionReason.package_reproducibility_denied, missing_recipe.reason);

    const untrusted_builder = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!untrusted_builder.allowed);
    try std.testing.expectEqual(DecisionReason.package_builder_denied, untrusted_builder.reason);

    const missing_scan = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
    });
    try std.testing.expect(!missing_scan.allowed);
    try std.testing.expectEqual(DecisionReason.package_vulnerability_scan_denied, missing_scan.reason);
}

test "policy directory gates sensitive data export deletion and receipts" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "data-rights-policy-key",
        .seed = signing.seedFromByte(0x86),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 90,
        .issuer = .{ .kind = .policy_authority, .serial = 92 },
        .label = "data-rights-baseline",
        .data_export_allowed = true,
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = true,
        .max_data_export_bytes = 4096,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 901,
        .issuer = .{ .kind = .policy_authority, .serial = 93 },
        .label = "user-data-rights",
        .data_export_allowed = true,
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = false,
        .max_data_export_bytes = 8192,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 901,
        .organization_id = 90,
    };
    const small_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .private_user_data,
        .bytes = 2048,
    });
    try std.testing.expect(small_export.allowed);

    const large_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .private_user_data,
        .bytes = 8192,
    });
    try std.testing.expect(!large_export.allowed);
    try std.testing.expectEqual(DecisionReason.data_export_denied, large_export.reason);
    try std.testing.expectEqual(org_policy.id, large_export.blocking_policy_id);

    const delete_without_receipt = directory.dataRightsDecision(subjects, .{
        .operation = .delete,
        .sensitivity = .private_user_data,
    });
    try std.testing.expect(!delete_without_receipt.allowed);
    try std.testing.expectEqual(DecisionReason.data_deletion_receipt_denied, delete_without_receipt.reason);

    const delete_with_receipt = directory.dataRightsDecision(subjects, .{
        .operation = .delete,
        .sensitivity = .private_user_data,
        .deletion_receipt_present = true,
    });
    try std.testing.expect(delete_with_receipt.allowed);

    const public_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .public_data,
        .bytes = 1_000_000,
    });
    try std.testing.expect(public_export.allowed);
}

test "policy directory gates sensitive permission retention and leases" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "permission-lifecycle-key",
        .seed = signing.seedFromByte(0x85),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 89,
        .issuer = .{ .kind = .policy_authority, .serial = 90 },
        .label = "sensitive-lifecycle",
        .max_sensitive_retention_days = 30,
        .max_permission_lease_ticks = 600,
        .require_sensitive_permission_lease = true,
        .camera_allowed = true,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 891,
        .issuer = .{ .kind = .policy_authority, .serial = 91 },
        .label = "user-lifecycle",
        .max_sensitive_retention_days = 90,
        .max_permission_lease_ticks = 1200,
        .require_sensitive_permission_lease = false,
        .camera_allowed = true,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 891,
        .organization_id = 89,
    };
    const allowed = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
        .lease_ticks = 300,
    });
    try std.testing.expect(allowed.allowed);

    const retention_denied = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 45,
        .lease_ticks = 300,
    });
    try std.testing.expect(!retention_denied.allowed);
    try std.testing.expectEqual(DecisionReason.permission_retention_denied, retention_denied.reason);
    try std.testing.expectEqual(org_policy.id, retention_denied.blocking_policy_id);

    const missing_lease = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
    });
    try std.testing.expect(!missing_lease.allowed);
    try std.testing.expectEqual(DecisionReason.permission_lease_denied, missing_lease.reason);

    const long_lease = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
        .lease_ticks = 900,
    });
    try std.testing.expect(!long_lease.allowed);
    try std.testing.expectEqual(DecisionReason.permission_lease_denied, long_lease.reason);

    const public_unbounded = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .public_data,
        .retention_days = 365,
    });
    try std.testing.expect(public_unbounded.allowed);
}

test "policy objects reject oversized lists and refuse authorization after tampering" {
    var directory = Directory.init();
    const too_many = [_][]const u8{
        "a", "b", "c", "d", "e", "f", "g", "h", "i",
    };
    try std.testing.expectError(error.TooManyInstallSources, directory.create(.{
        .scope = .user,
        .subject_id = 5,
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .label = "overflow",
        .allowed_install_sources = &too_many,
    }, .{
        .label = "policy-key",
        .seed = signing.seedFromByte(0x52),
    }));

    const policy = try directory.create(.{
        .scope = .device,
        .subject_id = 8,
        .issuer = .{ .kind = .policy_authority, .serial = 3 },
        .label = "signed-device-policy",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "device-policy-key",
        .seed = signing.seedFromByte(0x53),
    });
    try std.testing.expect(directory.verify(policy.id));

    policy.signature.value[0] ^=
        0x5A;
    try std.testing.expect(!directory.verify(policy.id));
    try std.testing.expect(!directory.installSourceAllowed(.device, 8, "store:zigos"));
}
