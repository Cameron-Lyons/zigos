const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const capability = @import("../kernel_api/capability.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const principal = @import("../core/principal.zig");
const units = @import("../core/units.zig");

pub const MAX_DRIVER_SERVICES: usize = 8;
pub const SIGNER_FINGERPRINT_BYTES: usize = 16;
pub const SignerFingerprint = [SIGNER_FINGERPRINT_BYTES]u8;
pub const DRIVER_RECORD_SIZE_CEILING_BYTES: usize = 64;
pub const DIRECTORY_SIZE_CEILING_BYTES: usize = 584;

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

pub const MAX_DMA_RANGES: usize = 2;
const DEFAULT_NETWORK_DMA_WINDOW_BYTES: u64 = units.kibibytes(64);
const DEFAULT_STORAGE_DMA_WINDOW_BYTES: u64 = units.kibibytes(128);
const DEFAULT_USB_DMA_WINDOW_BYTES: u64 = units.mebibytes(2);
const DEFAULT_GRAPHICS_DMA_WINDOW_BYTES: u64 = units.mebibytes(16);
const DEFAULT_AUDIO_PRINT_DMA_WINDOW_BYTES: u64 = units.mebibytes(1);
const DEFAULT_INPUT_DMA_WINDOW_BYTES: u64 = units.kibibytes(256);
const DEFAULT_COMPOSITOR_DMA_WINDOW_BYTES: u64 = units.kibibytes(512);
const DMA_TEST_PAGE_BASE: u64 = 0x1000;
const DMA_TEST_PAGE_BYTES: u64 = 4096;

comptime {
    if (MAX_DMA_RANGES > std.math.maxInt(u8)) {
        @compileError("driver record capacities no longer fit compact metadata");
    }
}

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
    signer_fingerprint: SignerFingerprint,

    pub fn signerMatches(self: *const DriverRecord, signer: []const u8) bool {
        const fingerprint = fingerprintSigner(signer);
        return std.mem.eql(u8, &self.signer_fingerprint, &fingerprint);
    }

    pub fn allowsDma(self: *const DriverRecord, address: u64, length: u64) bool {
        var index: usize = 0;
        while (index < self.dmaRangeCount()) : (index += 1) {
            if (self.dmaRange(index).?.contains(address, length)) return true;
        }
        return false;
    }

    pub fn dmaRangeCount(self: *const DriverRecord) usize {
        return switch (self.device_class) {
            .network_adapter, .storage_controller => 2,
            .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => 1,
        };
    }

    pub fn dmaRange(self: *const DriverRecord, index: usize) ?DmaRange {
        if (index >= self.dmaRangeCount()) return null;
        const window_length = dmaWindowLength(self.device_class);
        const offset = std.math.mul(u64, @intCast(index), window_length) catch return null;
        const base = std.math.add(u64, dmaWindowBase(self.device_id), offset) catch return null;
        return .{ .base = base, .length = window_length };
    }

    comptime {
        if (@sizeOf(@This()) > DRIVER_RECORD_SIZE_CEILING_BYTES) {
            @compileError("driver record exceeds its compact size ceiling");
        }
    }
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
};

pub const Error = error{
    CapabilityNotFound,
    CapabilityRevoked,
    DriverNotFound,
    DriverTableFull,
    DuplicateServiceId,
    DuplicateDeviceBinding,
    DmaDomainExhausted,
    MissingSignerLabel,
    InvalidAuthorityTarget,
    AuthorityRightsEscalation,
    AuthorityHolderMismatch,
    AuthorityScopeViolation,
    InvalidBootstrapTransport,
    InvalidHotSwapBinding,
};

pub const Directory = struct {
    next_dma_domain_id: u64 = 1,
    // Registration fills the first free slot, so iteration order is
    // registration order and the measured driver-set digest is deterministic.
    slots: [MAX_DRIVER_SERVICES]?DriverRecord = @splat(null),

    pub fn init() Directory {
        return .{};
    }

    pub fn registerSigned(self: *Directory, request: SignedRegistrationRequest) Error!*DriverRecord {
        const authority_capability_id = try validateSignedRequest(request);

        if (self.findByServiceAndClass(request.service_id, request.device_class) != null) return error.DuplicateServiceId;
        if (self.findByBinding(request.device_class, request.device_id) != null) return error.DuplicateDeviceBinding;

        const dma_domain_id = self.nextReservableDmaDomainId() orelse return error.DmaDomainExhausted;
        const slot = self.freeSlot() orelse return error.DriverTableFull;
        slot.* = recordFromRequest(request, authority_capability_id, 1, dma_domain_id);
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return &slot.*.?;
    }

    pub fn hotSwapSigned(self: *Directory, request: SignedRegistrationRequest) Error!*DriverRecord {
        const driver = self.findByServiceAndClass(request.service_id, request.device_class) orelse return error.DriverNotFound;
        if (driver.device_id != request.device_id) return error.InvalidHotSwapBinding;
        const next_generation = driver.restart_generation + 1;
        const previous_dma_domain_id = driver.dma_domain_id;
        const authority_capability_id = try validateSignedRequest(request);
        const dma_domain_id = self.nextReservableDmaDomainId() orelse return error.DmaDomainExhausted;
        _ = device_broker.invalidateDmaIsolation(driver.device_id, previous_dma_domain_id);
        driver.* = recordFromRequest(request, authority_capability_id, next_generation, dma_domain_id);
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return driver;
    }

    pub fn findByService(self: *Directory, service_id: u64) ?*DriverRecord {
        if (service_id == 0) return null;
        for (&self.slots) |*slot| if (slot.*) |*driver| {
            if (driver.service_id == service_id) return driver;
        };
        return null;
    }

    pub fn findByServiceAndClass(self: *Directory, service_id: u64, device_class: DeviceClass) ?*DriverRecord {
        if (service_id == 0) return null;
        for (&self.slots) |*slot| if (slot.*) |*driver| {
            if (driver.service_id == service_id and driver.device_class == device_class) return driver;
        };
        return null;
    }

    pub fn findByClass(self: *Directory, device_class: DeviceClass) ?*DriverRecord {
        for (&self.slots) |*slot| if (slot.*) |*driver| {
            if (driver.device_class == device_class) return driver;
        };
        return null;
    }

    fn findByBinding(self: *Directory, device_class: DeviceClass, device_id: u64) ?*DriverRecord {
        for (&self.slots) |*slot| if (slot.*) |*driver| {
            if (driver.device_class == device_class and driver.device_id == device_id) return driver;
        };
        return null;
    }

    pub fn markRestarted(self: *Directory, driver: *DriverRecord) bool {
        const dma_domain_id = self.nextReservableDmaDomainId() orelse return false;
        _ = device_broker.invalidateDmaIsolation(driver.device_id, driver.dma_domain_id);
        driver.restart_generation += 1;
        driver.dma_domain_id = dma_domain_id;
        self.advanceNextDmaDomainIdFrom(dma_domain_id);
        return true;
    }

    fn freeSlot(self: *Directory) ?*?DriverRecord {
        for (&self.slots) |*slot| if (slot.* == null) return slot;
        return null;
    }

    fn nextReservableDmaDomainId(self: *const Directory) ?u64 {
        return if (self.next_dma_domain_id == 0) null else self.next_dma_domain_id;
    }

    fn advanceNextDmaDomainIdFrom(self: *Directory, dma_domain_id: u64) void {
        self.next_dma_domain_id = dma_domain_id +% 1;
    }

    comptime {
        if (@sizeOf(@This()) > DIRECTORY_SIZE_CEILING_BYTES) {
            @compileError("driver directory exceeds its compact size ceiling");
        }
    }
};

fn recordFromRequest(
    request: SignedRegistrationRequest,
    authority_capability_id: u64,
    restart_generation: u32,
    dma_domain_id: u64,
) DriverRecord {
    return .{
        .service_id = request.service_id,
        .owner_task_id = request.owner_task_id,
        .device_id = request.device_id,
        .device_class = request.device_class,
        .authority_capability_id = authority_capability_id,
        .restart_generation = restart_generation,
        .bootstrap_transport = request.bootstrap_transport,
        .dma_domain_id = dma_domain_id,
        .signer_fingerprint = fingerprintSigner(request.signer),
    };
}

pub fn authorityTarget(device_id: u64) capability.CapabilityTarget {
    return .{ .kind = .device, .id = device_id };
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

fn rightsAreSubset(owned: capability.CapabilityRights, allowed: capability.CapabilityRights) bool {
    const owned_bits = owned.toBits();
    const allowed_bits = allowed.toBits();
    return (owned_bits & ~allowed_bits) == 0;
}

fn validateSignedRequest(request: SignedRegistrationRequest) Error!u64 {
    const inspected = request.capability_table.inspect(request.authority_capability_id, request.now_ticks) orelse return error.CapabilityNotFound;
    if (request.signer.len == 0) return error.MissingSignerLabel;
    if (!inspected.usable) return error.CapabilityRevoked;
    const authority = inspected.capability;
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
    return authority.id;
}

pub fn fingerprintSigner(signer: []const u8) SignerFingerprint {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "driver-signer-v1", signer);
    const digest = crypto_hash.finalize(&hasher);
    return digest[0..SIGNER_FINGERPRINT_BYTES].*;
}

fn dmaWindowLength(device_class: DeviceClass) u64 {
    return switch (device_class) {
        .network_adapter => DEFAULT_NETWORK_DMA_WINDOW_BYTES,
        .storage_controller => DEFAULT_STORAGE_DMA_WINDOW_BYTES,
        .usb_controller => DEFAULT_USB_DMA_WINDOW_BYTES,
        .graphics_adapter => DEFAULT_GRAPHICS_DMA_WINDOW_BYTES,
        .audio_print_io => DEFAULT_AUDIO_PRINT_DMA_WINDOW_BYTES,
        .input_device => DEFAULT_INPUT_DMA_WINDOW_BYTES,
        .compositor_policy => DEFAULT_COMPOSITOR_DMA_WINDOW_BYTES,
    };
}

fn dmaWindowBase(device_id: u64) u64 {
    return (device_id & 0x0000_FFFF_FFFF) << 12;
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

test "driver directory uses compact bounded record metadata" {
    try std.testing.expectEqual(SignerFingerprint, @FieldType(DriverRecord, "signer_fingerprint"));
    try std.testing.expect(!@hasField(DriverRecord, "signer_len"));
    try std.testing.expect(!@hasField(DriverRecord, "signer"));
    try std.testing.expectEqual(@as(usize, DRIVER_RECORD_SIZE_CEILING_BYTES), @sizeOf(DriverRecord));
    try std.testing.expectEqual(@as(usize, DIRECTORY_SIZE_CEILING_BYTES), @sizeOf(Directory));
}

test "driver signer fingerprints bind identity beyond the former text limit" {
    const first_signer = "0123456789abcdef0123456789abcdef-v1";
    const second_signer = "0123456789abcdef0123456789abcdef-v2";
    try std.testing.expectEqualStrings(first_signer[0..32], second_signer[0..32]);
    const first = fingerprintSigner(first_signer);
    const second = fingerprintSigner(second_signer);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expectEqual(first, fingerprintSigner(first_signer));
}

test "driver services require signed least-privilege device authority" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 2 },
        .task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
    });

    const driver = try directory.registerSigned(.{
        .service_id = 44,
        .owner_task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1,
        .signer = "zigos-driver-key",
    });

    try std.testing.expectEqual(@as(u64, 44), driver.service_id);
    try std.testing.expect(driver.signerMatches("zigos-driver-key"));
    try std.testing.expect(!driver.signerMatches("other-driver-key"));
    try std.testing.expect(driver.dma_domain_id != 0);
    try std.testing.expectEqual(@as(usize, 2), driver.dmaRangeCount());
    const first_dma_range = driver.dmaRange(0).?;
    const second_dma_range = driver.dmaRange(1).?;
    try std.testing.expectEqual(first_dma_range.base + first_dma_range.length, second_dma_range.base);
    try std.testing.expect(driver.dmaRange(2) == null);
    try std.testing.expect(driver.allowsDma(first_dma_range.base, DMA_TEST_PAGE_BYTES));
    try std.testing.expectEqual(BootstrapTransport.none, driver.bootstrap_transport);
    try std.testing.expect(directory.markRestarted(driver));
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

test "driver dma domain ids stop at exhaustion" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 70 };

    directory.next_dma_domain_id = std.math.maxInt(u64);
    const max_driver = try registerDriverForTest(&directory, &capabilities, owner, 70, 700, 0x7000, .network_adapter, "driver-max");
    try std.testing.expectEqual(std.math.maxInt(u64), max_driver.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 0), directory.next_dma_domain_id);
    try std.testing.expect(max_driver.dma_domain_id != 0);
    try std.testing.expectError(
        error.DmaDomainExhausted,
        registerDriverForTest(&directory, &capabilities, owner, 71, 701, 0x7001, .network_adapter, "driver-exhausted"),
    );
}

test "driver restart and hot-swap stop when dma domains are exhausted" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 71 };
    const first_device_id: u64 = 0x7100;
    const second_device_id: u64 = 0x7101;
    const first = try registerDriverForTest(&directory, &capabilities, owner, 80, 800, first_device_id, .network_adapter, "first-v1");
    const second = try registerDriverForTest(&directory, &capabilities, owner, 81, 801, second_device_id, .network_adapter, "second-v1");
    try std.testing.expectEqual(@as(u64, 1), first.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 2), second.dma_domain_id);

    directory.next_dma_domain_id = std.math.maxInt(u64);
    try std.testing.expect(directory.markRestarted(first));
    try std.testing.expectEqual(std.math.maxInt(u64), first.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 0), directory.next_dma_domain_id);
    try std.testing.expect(!directory.markRestarted(second));

    const second_authority_v2 = try mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = 801,
        .device_id = second_device_id,
        .device_class = .network_adapter,
    });
    try std.testing.expectError(error.DmaDomainExhausted, directory.hotSwapSigned(.{
        .service_id = 81,
        .owner_task_id = 801,
        .device_id = second_device_id,
        .device_class = .network_adapter,
        .authority_capability_id = second_authority_v2.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 2,
        .signer = "second-v2",
    }));
    try std.testing.expectEqual(@as(u64, 2), second.dma_domain_id);
    try std.testing.expectEqual(@as(u64, 0), directory.next_dma_domain_id);
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
    try std.testing.expectError(error.MissingSignerLabel, directory.registerSigned(.{
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
    try std.testing.expect(swapped.signerMatches("driver-v2"));
    try std.testing.expect(!swapped.signerMatches("driver-v1"));
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

test "only storage drivers may use the kernel bootstrap broker" {
    for (std.meta.tags(DeviceClass)) |device_class| {
        try std.testing.expectEqual(device_class == .storage_controller, supportsKernelBootstrapBroker(device_class));
    }
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

    try std.testing.expectError(error.MissingSignerLabel, directory.registerSigned(.{
        .service_id = 50,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority_capability_id = escalated_authority.id,
        .capability_table = &capabilities,
        .requester = escalated_authority.holder,
        .now_ticks = 1,
        .signer = "",
    }));

    try std.testing.expectError(error.AuthorityRightsEscalation, directory.registerSigned(.{
        .service_id = 51,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority_capability_id = escalated_authority.id,
        .capability_table = &capabilities,
        .requester = escalated_authority.holder,
        .now_ticks = 1,
        .signer = "zigos-driver-key",
    }));
}

test "kernel bootstrap transport is only granted to supported driver classes" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const graphics_authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 4 },
        .task_id = 12,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
    });

    try std.testing.expectError(error.InvalidBootstrapTransport, directory.registerSigned(.{
        .service_id = 60,
        .owner_task_id = 12,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = &capabilities,
        .requester = graphics_authority.holder,
        .now_ticks = 1,
        .signer = "zigos-spec-driver",
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));

    const input_authority = try mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 5 },
        .task_id = 13,
        .device_id = 0x8086_A0ED_0001,
        .device_class = .input_device,
    });
    try std.testing.expectError(error.InvalidBootstrapTransport, directory.registerSigned(.{
        .service_id = 61,
        .owner_task_id = 13,
        .device_id = 0x8086_A0ED_0001,
        .device_class = .input_device,
        .authority_capability_id = input_authority.id,
        .capability_table = &capabilities,
        .requester = input_authority.holder,
        .now_ticks = 1,
        .signer = "zigos-spec-driver",
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));
}
