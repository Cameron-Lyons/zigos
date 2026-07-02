const std = @import("std");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const capability = @import("../kernel_api/capability.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const units = @import("../core/units.zig");

pub const MAX_DRIVER_SERVICES: usize = 8;
pub const MAX_SIGNER_BYTES: usize = 32;
const DRIVER_INDEX_CAPACITY: usize = MAX_DRIVER_SERVICES * 2;

pub const DeviceClass = enum(u8) {
    network_adapter,
    storage_controller,
    usb_controller,
    graphics_adapter,
    audio_print_io,
    input_device,
    compositor_policy,
};

pub const BootstrapTransport = enum(u8) {
    none,
    kernel_bootstrap_broker,
};

pub const KernelDriverRole = enum(u8) {
    inventory_only,
    bootstrap_broker_only,
};

pub const MAX_DMA_RANGES: usize = 4;
const DEFAULT_NETWORK_DMA_WINDOW_BYTES: u64 = units.kibibytes(64);
const DEFAULT_STORAGE_DMA_WINDOW_BYTES: u64 = units.kibibytes(128);
const DEFAULT_USB_DMA_WINDOW_BYTES: u64 = units.mebibytes(2);
const DEFAULT_GRAPHICS_DMA_WINDOW_BYTES: u64 = units.mebibytes(16);
const DEFAULT_AUDIO_PRINT_DMA_WINDOW_BYTES: u64 = units.mebibytes(1);
const DEFAULT_INPUT_DMA_WINDOW_BYTES: u64 = units.kibibytes(256);
const DEFAULT_COMPOSITOR_DMA_WINDOW_BYTES: u64 = units.kibibytes(512);
const DMA_TEST_PAGE_BASE: u64 = 0x1000;
const DMA_TEST_PAGE_BYTES: u64 = 4096;

pub const DmaProtection = enum(u8) {
    iommu_enforced,
};

pub const DmaRange = struct {
    base: u64,
    length: u64,

    pub fn contains(self: DmaRange, address: u64, length: u64) bool {
        if (length == 0 or self.length == 0) return false;
        const end = std.math.add(u64, address, length - 1) catch return false;
        const range_end = std.math.add(u64, self.base, self.length - 1) catch return false;
        return address >= self.base and end <= range_end;
    }
};

pub const DriverRecord = struct {
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    authority_capability_id: u64,
    restart_generation: u32,
    bootstrap_transport: BootstrapTransport,
    dma_domain_id: u64,
    dma_protection: DmaProtection,
    dma_range_count: usize,
    dma_ranges: [MAX_DMA_RANGES]DmaRange,
    signer_len: usize,
    signer: [MAX_SIGNER_BYTES]u8,

    pub fn signerSlice(self: *const DriverRecord) []const u8 {
        return self.signer[0..self.signer_len];
    }

    pub fn allowsDma(self: *const DriverRecord, address: u64, length: u64) bool {
        var index: usize = 0;
        while (index < self.dma_range_count) : (index += 1) {
            if (self.dma_ranges[index].contains(address, length)) return true;
        }
        return false;
    }
};

pub const RegistrationRequest = struct {
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    authority_capability_id: u64,
    capability_table: *const capability.CapabilityTable,
    requester: principal.PrincipalId,
    now_ticks: u64,
    bundle: manifest.BundleManifest,
    bootstrap_transport: BootstrapTransport = .none,
    require_iommu: bool = true,
};

pub const SignedRegistrationRequest = struct {
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    authority_capability_id: u64,
    capability_table: *const capability.CapabilityTable,
    requester: principal.PrincipalId,
    now_ticks: u64,
    signer: []const u8,
    bootstrap_transport: BootstrapTransport = .none,
    require_iommu: bool = true,
};

pub const Error = error{
    CapabilityNotFound,
    CapabilityRevoked,
    DriverNotFound,
    DriverTableFull,
    DuplicateServiceId,
    DuplicateDeviceBinding,
    InvalidBundleSignature,
    InvalidAuthorityTarget,
    AuthorityRightsEscalation,
    AuthorityHolderMismatch,
    AuthorityScopeViolation,
    InvalidBootstrapTransport,
    InvalidHotSwapBinding,
    IommuRequired,
};

const DriverSlot = struct {
    in_use: bool = false,
    driver: DriverRecord = zeroDriver(),
};

const DriverServiceIndex = indexed_arena.MultimapIndex(MAX_DRIVER_SERVICES, MAX_DRIVER_SERVICES, DRIVER_INDEX_CAPACITY);
const DriverBindingIndex = indexed_arena.UniqueIndex(DRIVER_INDEX_CAPACITY);
const DriverClassIndex = indexed_arena.MultimapIndex(MAX_DRIVER_SERVICES, MAX_DRIVER_SERVICES, DRIVER_INDEX_CAPACITY);
const DriverArena = indexed_arena.IndexedArenaWithKey(u64, DriverSlot, MAX_DRIVER_SERVICES, DRIVER_INDEX_CAPACITY, driverSlotKey);

pub const Directory = struct {
    next_dma_domain_id: u64 = 1,
    slots: DriverArena = DriverArena.init(),
    service_index: DriverServiceIndex = DriverServiceIndex.init(),
    binding_index: DriverBindingIndex = DriverBindingIndex.init(),
    class_index: DriverClassIndex = DriverClassIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn register(self: *Directory, request: RegistrationRequest) Error!*DriverRecord {
        return self.registerSigned(.{
            .service_id = request.service_id,
            .owner_task_id = request.owner_task_id,
            .device_id = request.device_id,
            .device_class = request.device_class,
            .authority_capability_id = request.authority_capability_id,
            .capability_table = request.capability_table,
            .requester = request.requester,
            .now_ticks = request.now_ticks,
            .signer = request.bundle.signature.signer,
            .bootstrap_transport = request.bootstrap_transport,
            .require_iommu = request.require_iommu,
        });
    }

    pub fn registerSigned(self: *Directory, request: SignedRegistrationRequest) Error!*DriverRecord {
        const authority = try validateSignedRequest(request);

        if (self.findByServiceAndClass(request.service_id, request.device_class) != null) return error.DuplicateServiceId;
        if (self.findByBinding(request.device_class, request.device_id) != null) return error.DuplicateDeviceBinding;

        const dma_domain_id = self.nextReservableDmaDomainId() orelse return error.DriverTableFull;
        const slot_index = self.slots.reserveIndex(driverServiceClassKey(request.service_id, request.device_class)) orelse return error.DriverTableFull;
        const slot = &self.slots.slots[slot_index];
        slot.driver = self.recordFromRequest(request, authority, 1, dma_domain_id);
        self.indexDriver(slot_index);
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return &slot.driver;
    }

    pub fn hotSwapSigned(self: *Directory, request: SignedRegistrationRequest) Error!*DriverRecord {
        const slot = self.findSlotByServiceAndClass(request.service_id, request.device_class) orelse return error.DriverNotFound;
        if (slot.driver.device_id != request.device_id or slot.driver.device_class != request.device_class) {
            return error.InvalidHotSwapBinding;
        }
        const next_generation = slot.driver.restart_generation + 1;
        const previous_dma_domain_id = slot.driver.dma_domain_id;
        const authority = try validateSignedRequest(request);
        const dma_domain_id = self.nextReservableDmaDomainId() orelse return error.DriverTableFull;
        _ = device_broker.invalidateDmaIsolation(slot.driver.device_id, previous_dma_domain_id);
        slot.driver = self.recordFromRequest(request, authority, next_generation, dma_domain_id);
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return &slot.driver;
    }

    pub fn findByService(self: *Directory, service_id: u64) ?*DriverRecord {
        const slot = self.findSlotByService(service_id) orelse return null;
        return &slot.driver;
    }

    pub fn findByServiceAndClass(self: *Directory, service_id: u64, device_class: DeviceClass) ?*DriverRecord {
        const slot = self.findSlotByServiceAndClass(service_id, device_class) orelse return null;
        return &slot.driver;
    }

    pub fn findByClass(self: *Directory, device_class: DeviceClass) ?*DriverRecord {
        var cursor = self.class_index.head(driverClassKey(device_class));
        while (cursor != indexed_arena.no_index) : (cursor = self.class_index.next(cursor)) {
            if (cursor >= MAX_DRIVER_SERVICES) native_util.impossibleByInvariant("driver class index points outside slots");
            const slot = &self.slots.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("driver class index points at a free slot");
            if (slot.driver.device_class == device_class) return &slot.driver;
        }
        return null;
    }

    fn findByBinding(self: *Directory, device_class: DeviceClass, device_id: u64) ?*DriverRecord {
        const slot_index = self.binding_index.lookup(driverBindingKey(device_class, device_id)) orelse return null;
        if (slot_index >= MAX_DRIVER_SERVICES) native_util.impossibleByInvariant("driver binding index points outside slots");
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use or slot.driver.device_class != device_class or slot.driver.device_id != device_id) {
            native_util.impossibleByInvariant("driver binding index points at the wrong driver");
        }
        return &slot.driver;
    }

    pub fn markRestarted(self: *Directory, service_id: u64) bool {
        const driver = self.findByService(service_id) orelse return false;
        const dma_domain_id = self.nextReservableDmaDomainId() orelse return false;
        _ = device_broker.invalidateDmaIsolation(driver.device_id, driver.dma_domain_id);
        driver.restart_generation += 1;
        driver.dma_domain_id = dma_domain_id;
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return true;
    }

    fn nextReservableDmaDomainId(self: *const Directory) ?u64 {
        var dma_domain_id = normalizeDmaDomainId(self.next_dma_domain_id);
        var attempts: usize = 0;
        while (attempts <= MAX_DRIVER_SERVICES) : (attempts += 1) {
            if (!self.hasActiveDmaDomainId(dma_domain_id)) return dma_domain_id;
            dma_domain_id = nextDmaDomainIdAfter(dma_domain_id);
        }
        return null;
    }

    fn advanceNextDmaDomainIdFrom(self: *Directory, dma_domain_id: u64) void {
        self.next_dma_domain_id = nextDmaDomainIdAfter(dma_domain_id);
    }

    fn hasActiveDmaDomainId(self: *const Directory, dma_domain_id: u64) bool {
        if (dma_domain_id == 0) return false;
        for (&self.slots.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.driver.dma_domain_id == dma_domain_id) return true;
        }
        return false;
    }

    fn findSlotByService(self: *Directory, service_id: u64) ?*DriverSlot {
        if (service_id == 0) return null;
        var cursor = self.service_index.head(service_id);
        while (cursor != indexed_arena.no_index) : (cursor = self.service_index.next(cursor)) {
            if (cursor >= MAX_DRIVER_SERVICES) native_util.impossibleByInvariant("driver service index points outside slots");
            const slot = &self.slots.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("driver service index points at a free slot");
            if (slot.driver.service_id == service_id) return slot;
        }
        return null;
    }

    fn findSlotByServiceAndClass(self: *Directory, service_id: u64, device_class: DeviceClass) ?*DriverSlot {
        if (service_id == 0) return null;
        const slot = self.slots.get(driverServiceClassKey(service_id, device_class)) orelse return null;
        if (slot.driver.service_id != service_id or slot.driver.device_class != device_class) return null;
        return slot;
    }

    fn indexDriver(self: *Directory, slot_index: usize) void {
        if (slot_index >= MAX_DRIVER_SERVICES) native_util.impossibleByInvariant("driver index update points outside slots");
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use or slot.driver.service_id == 0) native_util.impossibleByInvariant("driver index update requires a live driver");
        if (!self.service_index.append(slot.driver.service_id, slot_index)) {
            native_util.impossibleByInvariant("driver service index capacity covers driver slots");
        }
        self.binding_index.insert(driverBindingKey(slot.driver.device_class, slot.driver.device_id), slot_index);
        if (!self.class_index.append(driverClassKey(slot.driver.device_class), slot_index)) {
            native_util.impossibleByInvariant("driver class index capacity covers driver slots");
        }
    }

    fn recordFromRequest(
        self: *Directory,
        request: SignedRegistrationRequest,
        authority: capability.Capability,
        restart_generation: u32,
        dma_domain_id: u64,
    ) DriverRecord {
        _ = self;
        var record = DriverRecord{
            .service_id = request.service_id,
            .owner_task_id = request.owner_task_id,
            .device_id = request.device_id,
            .device_class = request.device_class,
            .authority_capability_id = authority.id,
            .restart_generation = restart_generation,
            .bootstrap_transport = request.bootstrap_transport,
            .dma_domain_id = dma_domain_id,
            .dma_protection = .iommu_enforced,
            .dma_range_count = 0,
            .dma_ranges = [_]DmaRange{zeroDmaRange()} ** MAX_DMA_RANGES,
            .signer_len = 0,
            .signer = [_]u8{0} ** MAX_SIGNER_BYTES,
        };
        record.dma_range_count = defaultDmaRanges(record.dma_ranges[0..], request.device_class, request.device_id);
        writeSigner(&record, request.signer);
        return record;
    }
};

pub fn authorityTarget(device_id: u64) capability.CapabilityTarget {
    return .{ .kind = .device, .id = device_id };
}

fn driverServiceClassKey(service_id: u64, device_class: DeviceClass) u64 {
    const class_offset = @sizeOf(u64);
    const key_bytes = class_offset + @sizeOf(DeviceClass);
    var bytes: [key_bytes]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..@sizeOf(u64)], service_id, .little);
    bytes[class_offset] = @intFromEnum(device_class);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.driver_service_class_key, &bytes));
}

// Arena primary key: a driver slot is uniquely identified by (service_id,
// device_class) (registerSigned rejects a duplicate pair). Only in-use slots are
// keyed; findSlotByServiceAndClass re-checks both fields to stay correct under a
// (vanishingly rare) Wyhash collision.
fn driverSlotKey(slot: *const DriverSlot) u64 {
    return driverServiceClassKey(slot.driver.service_id, slot.driver.device_class);
}

fn driverBindingKey(device_class: DeviceClass, device_id: u64) u64 {
    const device_id_offset = @sizeOf(DeviceClass);
    const driver_binding_key_bytes = device_id_offset + @sizeOf(u64);
    var bytes: [driver_binding_key_bytes]u8 = undefined;
    bytes[0] = @intFromEnum(device_class);
    std.mem.writeInt(u64, bytes[device_id_offset..][0..@sizeOf(u64)], device_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.driver_binding_key, &bytes));
}

fn driverClassKey(device_class: DeviceClass) u64 {
    return @as(u64, @intFromEnum(device_class)) + 1;
}

pub fn allowedRightsFor(device_class: DeviceClass) capability.CapabilityRights {
    return switch (device_class) {
        .network_adapter => .{ .device = .{
            .device_use = true,
            .network_local = true,
        } },
        .storage_controller => .{ .device = .{
            .device_use = true,
            .object_read = true,
            .object_write = true,
        } },
        .usb_controller => .{ .device = .{
            .device_use = true,
        } },
        .graphics_adapter => .{ .device = .{
            .device_use = true,
        } },
        .audio_print_io => .{ .device = .{
            .device_use = true,
        } },
        .input_device => .{ .device = .{
            .device_use = true,
        } },
        .compositor_policy => .{ .device = .{
            .device_use = true,
        } },
    };
}

fn normalizeDmaDomainId(dma_domain_id: u64) u64 {
    return if (dma_domain_id == 0) 1 else dma_domain_id;
}

fn nextDmaDomainIdAfter(dma_domain_id: u64) u64 {
    const next = dma_domain_id +% 1;
    return normalizeDmaDomainId(next);
}

pub const DriverAuthorityRequest = struct {
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    issued_at_ticks: u64 = 0,
    expires_at_ticks: u64 = std.math.maxInt(u64),
    renewable: bool = true,
    local_only: bool = true,
    audit: capability.AuditMetadata = .{},
};

pub fn mintDriverAuthority(
    capability_table: *capability.CapabilityTable,
    request: DriverAuthorityRequest,
) capability.Error!capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = request.holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(request.device_id),
        .rights = allowedRightsFor(request.device_class),
        .scope = .{
            .task_id = request.task_id,
            .local_only = request.local_only,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = request.issued_at_ticks,
            .expires_at_ticks = request.expires_at_ticks,
            .renewable = request.renewable,
        },
        .audit = request.audit,
    });
}

pub fn supportsKernelBootstrapBroker(device_class: DeviceClass) bool {
    return switch (device_class) {
        .storage_controller => true,
        .network_adapter,
        .usb_controller,
        .graphics_adapter,
        .audio_print_io,
        .input_device,
        .compositor_policy,
        => false,
    };
}

pub fn kernelDriverRole(device_class: DeviceClass) KernelDriverRole {
    return switch (device_class) {
        .storage_controller => .bootstrap_broker_only,
        .network_adapter,
        .usb_controller,
        .graphics_adapter,
        .audio_print_io,
        .input_device,
        .compositor_policy,
        => .inventory_only,
    };
}

pub fn requiresUserspaceDataPlane(device_class: DeviceClass) bool {
    return switch (kernelDriverRole(device_class)) {
        .inventory_only, .bootstrap_broker_only => true,
    };
}

pub fn permitsKernelDataPlane(device_class: DeviceClass) bool {
    return switch (kernelDriverRole(device_class)) {
        .inventory_only, .bootstrap_broker_only => false,
    };
}

pub fn permitsKernelBootstrapBroker(device_class: DeviceClass) bool {
    return switch (kernelDriverRole(device_class)) {
        .bootstrap_broker_only => true,
        .inventory_only => false,
    };
}

fn rightsAreSubset(owned: capability.CapabilityRights, allowed: capability.CapabilityRights) bool {
    const owned_bits = owned.toBits();
    const allowed_bits = allowed.toBits();
    return (owned_bits & ~allowed_bits) == 0;
}

fn validateSignedRequest(request: SignedRegistrationRequest) Error!capability.Capability {
    const authority = request.capability_table.query(request.authority_capability_id) orelse return error.CapabilityNotFound;
    if (request.signer.len == 0) return error.InvalidBundleSignature;
    if (!request.require_iommu) return error.IommuRequired;
    if (!request.capability_table.isUsable(authority, request.now_ticks)) return error.CapabilityRevoked;
    if (!authority.holder.eql(request.requester)) return error.AuthorityHolderMismatch;
    if (authority.scope.task_id) |task_id| {
        if (task_id != request.owner_task_id) return error.AuthorityScopeViolation;
    }
    if (authority.target.kind != .device or authority.target.id != request.device_id) {
        return error.InvalidAuthorityTarget;
    }
    if (!rightsAreSubset(authority.rights, allowedRightsFor(request.device_class))) {
        return error.AuthorityRightsEscalation;
    }
    if (request.bootstrap_transport == .kernel_bootstrap_broker and
        !supportsKernelBootstrapBroker(request.device_class))
    {
        return error.InvalidBootstrapTransport;
    }
    return authority;
}

fn writeSigner(record: *DriverRecord, signer: []const u8) void {
    record.signer_len = @min(signer.len, record.signer.len);
    @memcpy(record.signer[0..record.signer_len], signer[0..record.signer_len]);
}

fn zeroDmaRange() DmaRange {
    return .{
        .base = 0,
        .length = 0,
    };
}

fn defaultDmaRanges(dest: []DmaRange, device_class: DeviceClass, device_id: u64) usize {
    if (dest.len == 0) return 0;
    const base = dmaWindowBase(device_id);
    dest[0] = .{
        .base = base,
        .length = switch (device_class) {
            .network_adapter => DEFAULT_NETWORK_DMA_WINDOW_BYTES,
            .storage_controller => DEFAULT_STORAGE_DMA_WINDOW_BYTES,
            .usb_controller => DEFAULT_USB_DMA_WINDOW_BYTES,
            .graphics_adapter => DEFAULT_GRAPHICS_DMA_WINDOW_BYTES,
            .audio_print_io => DEFAULT_AUDIO_PRINT_DMA_WINDOW_BYTES,
            .input_device => DEFAULT_INPUT_DMA_WINDOW_BYTES,
            .compositor_policy => DEFAULT_COMPOSITOR_DMA_WINDOW_BYTES,
        },
    };
    if (dest.len > 1 and (device_class == .network_adapter or device_class == .storage_controller)) {
        dest[1] = .{
            .base = base + dest[0].length,
            .length = dest[0].length,
        };
        return 2;
    }
    return 1;
}

fn dmaWindowBase(device_id: u64) u64 {
    return (device_id & 0x0000_FFFF_FFFF) << 12;
}

fn zeroDriver() DriverRecord {
    return .{
        .service_id = 0,
        .owner_task_id = 0,
        .device_id = 0,
        .device_class = .network_adapter,
        .authority_capability_id = 0,
        .restart_generation = 0,
        .bootstrap_transport = .none,
        .dma_domain_id = 0,
        .dma_protection = .iommu_enforced,
        .dma_range_count = 0,
        .dma_ranges = [_]DmaRange{zeroDmaRange()} ** MAX_DMA_RANGES,
        .signer_len = 0,
        .signer = [_]u8{0} ** MAX_SIGNER_BYTES,
    };
}

fn registerDriverForTest(
    directory: *Directory,
    capabilities: *capability.CapabilityTable,
    owner: principal.PrincipalId,
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    signer: []const u8,
) !*DriverRecord {
    const authority = try mintDriverAuthority(capabilities, .{
        .holder = owner,
        .task_id = owner_task_id,
        .device_id = device_id,
        .device_class = device_class,
    });
    return directory.registerSigned(.{
        .service_id = service_id,
        .owner_task_id = owner_task_id,
        .device_id = device_id,
        .device_class = device_class,
        .authority_capability_id = authority.id,
        .capability_table = capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = signer,
    });
}

test "driver services require signed least-privilege device authority" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.net.driver",
        .display_name = "Network Driver",
        .publisher = "zigos.dev",
        .signature = .{
            .format = manifest.SIGNATURE_FORMAT_ED25519,
            .signer = "zigos-driver-key",
        },
    };
    const authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 2 },
        .task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
    });

    const driver = try directory.register(.{
        .service_id = 44,
        .owner_task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });

    try std.testing.expectEqual(@as(u64, 44), driver.service_id);
    try std.testing.expectEqualStrings("zigos-driver-key", driver.signerSlice());
    try std.testing.expect(driver.dma_domain_id != 0);
    try std.testing.expectEqual(DmaProtection.iommu_enforced, driver.dma_protection);
    try std.testing.expect(driver.dma_range_count >= 1);
    try std.testing.expect(driver.allowsDma(driver.dma_ranges[0].base, DMA_TEST_PAGE_BYTES));
    try std.testing.expectEqual(BootstrapTransport.none, driver.bootstrap_transport);
    try std.testing.expect(directory.markRestarted(44));
    try std.testing.expectEqual(@as(u32, 2), driver.restart_generation);
    try std.testing.expect(driver.dma_domain_id != 1);
}

test "driver directory indexes service binding and class lookups" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 18 };
    const network_device_id: u64 = 0x8086_15F2_0018;
    const storage_device_id: u64 = 0x1F001;
    const network_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 18,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .renewable = false,
        .local_only = false,
    });
    const storage_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 19,
        .device_id = storage_device_id,
        .device_class = .storage_controller,
        .renewable = false,
        .local_only = false,
    });

    _ = try directory.registerSigned(.{
        .service_id = 18,
        .owner_task_id = 18,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = network_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = "net-driver",
    });
    _ = try directory.registerSigned(.{
        .service_id = 19,
        .owner_task_id = 19,
        .device_id = storage_device_id,
        .device_class = .storage_controller,
        .authority_capability_id = storage_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = "storage-driver",
    });

    try std.testing.expectEqual(@as(u64, 18), directory.findByService(18).?.service_id);
    try std.testing.expectEqual(@as(u64, 19), directory.findByClass(.storage_controller).?.service_id);
    try std.testing.expect(directory.findByServiceAndClass(18, .storage_controller) == null);
    try std.testing.expectError(error.DuplicateServiceId, directory.registerSigned(.{
        .service_id = 18,
        .owner_task_id = 18,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = network_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 2,
        .signer = "duplicate-service",
    }));
}

test "driver dma ranges reject overflowing spans" {
    const range = DmaRange{ .base = DMA_TEST_PAGE_BASE, .length = DMA_TEST_PAGE_BYTES };
    try std.testing.expect(range.contains(DMA_TEST_PAGE_BASE, DMA_TEST_PAGE_BYTES));
    try std.testing.expect(!range.contains(std.math.maxInt(u64) - 7, 16));
    try std.testing.expect(!(DmaRange{ .base = std.math.maxInt(u64) - 7, .length = 16 }).contains(std.math.maxInt(u64) - 7, 8));
}

test "driver dma domain ids wrap without zero and skip active drivers" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 70 };

    directory.next_dma_domain_id = std.math.maxInt(u64);
    const max_driver = try registerDriverForTest(&directory, &capabilities, owner, 70, 700, 0x7000, .network_adapter, "driver-max");
    try std.testing.expectEqual(std.math.maxInt(u64), max_driver.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 1), directory.next_dma_domain_id);

    const wrapped_driver = try registerDriverForTest(&directory, &capabilities, owner, 71, 701, 0x7001, .network_adapter, "driver-wrap");
    try std.testing.expectEqual(@as(u64, 1), wrapped_driver.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 2), directory.next_dma_domain_id);
    try std.testing.expect(max_driver.dma_domain_id != 0);
    try std.testing.expect(wrapped_driver.dma_domain_id != 0);

    directory.next_dma_domain_id = 1;
    const skipped_driver = try registerDriverForTest(&directory, &capabilities, owner, 72, 702, 0x7002, .network_adapter, "driver-skip");
    try std.testing.expectEqual(@as(u64, 2), skipped_driver.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 3), directory.next_dma_domain_id);
}

test "driver dma domain ids skip active drivers on restart and hot-swap" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 71 };
    const first_device_id: u64 = 0x7100;
    const second_device_id: u64 = 0x7101;
    const first = try registerDriverForTest(&directory, &capabilities, owner, 80, 800, first_device_id, .network_adapter, "first-v1");
    const second = try registerDriverForTest(&directory, &capabilities, owner, 81, 801, second_device_id, .network_adapter, "second-v1");
    try std.testing.expectEqual(@as(u64, 1), first.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 2), second.dma_domain_id);

    directory.next_dma_domain_id = 1;
    try std.testing.expect(directory.markRestarted(80));
    try std.testing.expectEqual(@as(u64, 3), first.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 4), directory.next_dma_domain_id);

    const second_authority_v2 = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 801,
        .device_id = second_device_id,
        .device_class = .network_adapter,
    });
    directory.next_dma_domain_id = 2;
    const swapped = try directory.hotSwapSigned(.{
        .service_id = 81,
        .owner_task_id = 801,
        .device_id = second_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = second_authority_v2.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 2,
        .signer = "second-v2",
    });
    try std.testing.expectEqual(@as(u64, 4), swapped.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 5), directory.next_dma_domain_id);
}

test "driver dma domain ids do not advance when registration fails" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 72 };

    const invalid_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 900,
        .device_id = 0x7200,
        .device_class = .network_adapter,
    });
    directory.next_dma_domain_id = 77;
    try std.testing.expectError(error.InvalidBundleSignature, directory.registerSigned(.{
        .service_id = 90,
        .owner_task_id = 900,
        .device_id = 0x7200,
        .device_class = .network_adapter,
        .authority_capability_id = invalid_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = "",
    }));
    try std.testing.expectEqual(@as(u64, 77), directory.next_dma_domain_id);

    for (0..MAX_DRIVER_SERVICES) |index| {
        const offset: u64 = @intCast(index);
        _ = try registerDriverForTest(&directory, &capabilities, owner, 100 + offset, 1_000 + offset, 0x7300 + offset, .network_adapter, "driver-fill");
    }

    const next_before_full = directory.next_dma_domain_id;
    const full_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 2_000,
        .device_id = 0x7400,
        .device_class = .network_adapter,
    });
    try std.testing.expectError(error.DriverTableFull, directory.registerSigned(.{
        .service_id = 200,
        .owner_task_id = 2_000,
        .device_id = 0x7400,
        .device_class = .network_adapter,
        .authority_capability_id = full_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 2,
        .signer = "driver-full",
    }));
    try std.testing.expectEqual(next_before_full, directory.next_dma_domain_id);
}

test "driver hot-swap rebinds authority signer and dma domain" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 12 };
    const device_id: u64 = 0x1234_1111_0044;
    const first_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 44,
        .device_id = device_id,
        .device_class = .graphics_adapter,
    });
    const second_authority = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 44,
        .device_id = device_id,
        .device_class = .graphics_adapter,
    });

    const first = try directory.registerSigned(.{
        .service_id = 44,
        .owner_task_id = 44,
        .device_id = device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = first_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = "driver-v1",
    });
    const first_dma_domain = first.dma_domain_id;

    const swapped = try directory.hotSwapSigned(.{
        .service_id = 44,
        .owner_task_id = 44,
        .device_id = device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = second_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 2,
        .signer = "driver-v2",
    });

    try std.testing.expectEqual(@as(u32, 2), swapped.restart_generation);
    try std.testing.expect(swapped.dma_domain_id != first_dma_domain);
    try std.testing.expectEqual(second_authority.id, swapped.authority_capability_id);
    try std.testing.expectEqualStrings("driver-v2", swapped.signerSlice());
    try std.testing.expectEqual(swapped.service_id, directory.findByClass(.graphics_adapter).?.service_id);
    try std.testing.expectError(error.InvalidHotSwapBinding, directory.hotSwapSigned(.{
        .service_id = 44,
        .owner_task_id = 44,
        .device_id = device_id + 1,
        .device_class = .graphics_adapter,
        .authority_capability_id = second_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 3,
        .signer = "driver-v3",
    }));
    try std.testing.expectError(error.DriverNotFound, directory.hotSwapSigned(.{
        .service_id = 45,
        .owner_task_id = 45,
        .device_id = device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = second_authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 3,
        .signer = "driver-v3",
    }));
}

test "kernel driver roles keep data planes out of kernel by default" {
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.network_adapter));
    try std.testing.expectEqual(KernelDriverRole.bootstrap_broker_only, kernelDriverRole(.storage_controller));
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.usb_controller));
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.graphics_adapter));
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.audio_print_io));
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.input_device));
    try std.testing.expectEqual(KernelDriverRole.inventory_only, kernelDriverRole(.compositor_policy));
    try std.testing.expect(requiresUserspaceDataPlane(.network_adapter));
    try std.testing.expect(requiresUserspaceDataPlane(.storage_controller));
    try std.testing.expect(requiresUserspaceDataPlane(.usb_controller));
    try std.testing.expect(requiresUserspaceDataPlane(.graphics_adapter));
    try std.testing.expect(requiresUserspaceDataPlane(.audio_print_io));
    try std.testing.expect(requiresUserspaceDataPlane(.input_device));
    try std.testing.expect(requiresUserspaceDataPlane(.compositor_policy));
    try std.testing.expect(!permitsKernelDataPlane(.network_adapter));
    try std.testing.expect(!permitsKernelDataPlane(.storage_controller));
    try std.testing.expect(!permitsKernelDataPlane(.usb_controller));
    try std.testing.expect(!permitsKernelDataPlane(.graphics_adapter));
    try std.testing.expect(!permitsKernelDataPlane(.audio_print_io));
    try std.testing.expect(!permitsKernelDataPlane(.input_device));
    try std.testing.expect(!permitsKernelDataPlane(.compositor_policy));
    try std.testing.expect(!supportsKernelBootstrapBroker(.network_adapter));
    try std.testing.expect(supportsKernelBootstrapBroker(.storage_controller));
    try std.testing.expect(!supportsKernelBootstrapBroker(.usb_controller));
    try std.testing.expect(!supportsKernelBootstrapBroker(.graphics_adapter));
    try std.testing.expect(!supportsKernelBootstrapBroker(.audio_print_io));
    try std.testing.expect(!supportsKernelBootstrapBroker(.input_device));
    try std.testing.expect(!supportsKernelBootstrapBroker(.compositor_policy));
    try std.testing.expect(!permitsKernelBootstrapBroker(.network_adapter));
    try std.testing.expect(permitsKernelBootstrapBroker(.storage_controller));
    try std.testing.expect(!permitsKernelBootstrapBroker(.usb_controller));
    try std.testing.expect(!permitsKernelBootstrapBroker(.graphics_adapter));
    try std.testing.expect(!permitsKernelBootstrapBroker(.audio_print_io));
    try std.testing.expect(!permitsKernelBootstrapBroker(.input_device));
    try std.testing.expect(!permitsKernelBootstrapBroker(.compositor_policy));
}

test "network drivers cannot request kernel bootstrap broker transports" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 91 },
        .task_id = 901,
        .device_id = 0x8086_15F2_0001,
        .device_class = .network_adapter,
    });

    try std.testing.expectError(error.InvalidBootstrapTransport, directory.registerSigned(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = 0x8086_15F2_0001,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1,
        .signer = "zigos-spec-driver",
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));
}

test "storage bootstrap broker remains available for userspace storage driver claims" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 92 },
        .task_id = 902,
        .device_id = 0x0000_1F00_0001,
        .device_class = .storage_controller,
    });

    const driver = try directory.registerSigned(.{
        .service_id = 92,
        .owner_task_id = 902,
        .device_id = 0x0000_1F00_0001,
        .device_class = .storage_controller,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1,
        .signer = "zigos-spec-driver",
        .bootstrap_transport = .kernel_bootstrap_broker,
    });

    try std.testing.expectEqual(BootstrapTransport.kernel_bootstrap_broker, driver.bootstrap_transport);
}

test "driver services reject unsigned bundles and escalated device rights" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const unsigned_bundle = manifest.BundleManifest{
        .bundle_id = "svc.storage.driver",
        .display_name = "Storage Driver",
        .publisher = "zigos.dev",
    };
    const escalated_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 3 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(200),
        .rights = .{ .device = .{
            .device_use = true,
            .object_read = true,
            .object_write = true,
            .sensor_read = true,
        } },
        .scope = .{
            .task_id = 9,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
        },
        .audit = .{},
    });

    try std.testing.expectError(error.InvalidBundleSignature, directory.register(.{
        .service_id = 50,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority_capability_id = escalated_authority.id,
        .capability_table = &capabilities,
        .requester = escalated_authority.holder,
        .now_ticks = 1,
        .bundle = unsigned_bundle,
    }));

    const signed_bundle = manifest.BundleManifest{
        .bundle_id = "svc.storage.driver",
        .display_name = "Storage Driver",
        .publisher = "zigos.dev",
        .signature = .{
            .format = manifest.SIGNATURE_FORMAT_ED25519,
            .signer = "zigos-driver-key",
        },
    };

    try std.testing.expectError(error.AuthorityRightsEscalation, directory.register(.{
        .service_id = 51,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority_capability_id = escalated_authority.id,
        .capability_table = &capabilities,
        .requester = escalated_authority.holder,
        .now_ticks = 1,
        .bundle = signed_bundle,
    }));

    const storage_authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 3 },
        .task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .renewable = false,
    });
    try std.testing.expectError(error.IommuRequired, directory.register(.{
        .service_id = 52,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority_capability_id = storage_authority.id,
        .capability_table = &capabilities,
        .requester = storage_authority.holder,
        .now_ticks = 1,
        .bundle = signed_bundle,
        .require_iommu = false,
    }));
}

test "kernel bootstrap transport is only granted to supported driver classes" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.graphics-runtime",
        .display_name = "Graphics Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = manifest.SIGNATURE_FORMAT_ED25519,
            .signer = "zigos-spec-driver",
        },
    };
    const graphics_authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 4 },
        .task_id = 12,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
    });

    try std.testing.expectError(error.InvalidBootstrapTransport, directory.register(.{
        .service_id = 60,
        .owner_task_id = 12,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = &capabilities,
        .requester = graphics_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));

    const input_authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 5 },
        .task_id = 13,
        .device_id = 0x8086_A0ED_0001,
        .device_class = .input_device,
    });
    try std.testing.expectError(error.InvalidBootstrapTransport, directory.register(.{
        .service_id = 61,
        .owner_task_id = 13,
        .device_id = 0x8086_A0ED_0001,
        .device_class = .input_device,
        .authority_capability_id = input_authority.id,
        .capability_table = &capabilities,
        .requester = input_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));
}
