const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");

pub const MAX_DRIVER_SERVICES: usize = 8;

pub const DeviceClass = enum(u8) {
    network_adapter,
    storage_controller,
    graphics_adapter,
    audio_print_io,
};

pub const BootstrapTransport = enum(u8) {
    none,
    kernel_published_data_plane,
};

pub const MAX_DMA_RANGES: usize = 4;

pub const DmaProtection = enum(u8) {
    iommu_enforced,
};

pub const DmaRange = struct {
    base: u64,
    length: u64,

    pub fn contains(self: DmaRange, address: u64, length: u64) bool {
        if (length == 0) return false;
        const end = address + length - 1;
        const range_end = self.base + self.length - 1;
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
    signer: [32]u8,

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
    DriverTableFull,
    DuplicateServiceId,
    DuplicateDeviceBinding,
    InvalidBundleSignature,
    InvalidAuthorityTarget,
    AuthorityRightsEscalation,
    AuthorityHolderMismatch,
    AuthorityScopeViolation,
    InvalidBootstrapTransport,
    IommuRequired,
};

const DriverSlot = struct {
    in_use: bool = false,
    driver: DriverRecord = zeroDriver(),
};

pub const Directory = struct {
    next_dma_domain_id: u64 = 1,
    slots: [MAX_DRIVER_SERVICES]DriverSlot = [_]DriverSlot{DriverSlot{}} ** MAX_DRIVER_SERVICES,

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
        if (request.bootstrap_transport == .kernel_published_data_plane and
            !supportsKernelPublishedTransport(request.device_class))
        {
            return error.InvalidBootstrapTransport;
        }

        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.driver.service_id == request.service_id) return error.DuplicateServiceId;
            if (slot.driver.device_class == request.device_class and slot.driver.device_id == request.device_id) {
                return error.DuplicateDeviceBinding;
            }
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;

            slot.in_use = true;
            slot.driver = .{
                .service_id = request.service_id,
                .owner_task_id = request.owner_task_id,
                .device_id = request.device_id,
                .device_class = request.device_class,
                .authority_capability_id = authority.id,
                .restart_generation = 1,
                .bootstrap_transport = request.bootstrap_transport,
                .dma_domain_id = self.allocateDmaDomainId(),
                .dma_protection = .iommu_enforced,
                .dma_range_count = 0,
                .dma_ranges = [_]DmaRange{zeroDmaRange()} ** MAX_DMA_RANGES,
                .signer_len = 0,
                .signer = [_]u8{0} ** 32,
            };
            slot.driver.dma_range_count = defaultDmaRanges(slot.driver.dma_ranges[0..], request.device_class, request.device_id);
            writeSigner(&slot.driver, request.signer);
            return &slot.driver;
        }

        return error.DriverTableFull;
    }

    pub fn findByService(self: *Directory, service_id: u64) ?*DriverRecord {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.driver.service_id == service_id) return &slot.driver;
        }
        return null;
    }

    pub fn findByClass(self: *Directory, device_class: DeviceClass) ?*DriverRecord {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.driver.device_class == device_class) return &slot.driver;
        }
        return null;
    }

    pub fn markRestarted(self: *Directory, service_id: u64) bool {
        const driver = self.findByService(service_id) orelse return false;
        driver.restart_generation += 1;
        driver.dma_domain_id = self.allocateDmaDomainId();
        return true;
    }

    fn allocateDmaDomainId(self: *Directory) u64 {
        defer self.next_dma_domain_id += 1;
        return self.next_dma_domain_id;
    }
};

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
        .graphics_adapter => .{ .device = .{
            .device_use = true,
        } },
        .audio_print_io => .{ .device = .{
            .device_use = true,
        } },
    };
}

pub fn supportsKernelPublishedTransport(device_class: DeviceClass) bool {
    return switch (device_class) {
        .network_adapter, .storage_controller => true,
        .graphics_adapter, .audio_print_io => false,
    };
}

fn rightsAreSubset(owned: capability.CapabilityRights, allowed: capability.CapabilityRights) bool {
    const owned_bits = owned.toBits();
    const allowed_bits = allowed.toBits();
    return (owned_bits & ~allowed_bits) == 0;
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
            .network_adapter => 64 * 1024,
            .storage_controller => 128 * 1024,
            .graphics_adapter => 16 * 1024 * 1024,
            .audio_print_io => 1024 * 1024,
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
        .signer = [_]u8{0} ** 32,
    };
}

test "driver services require signed least-privilege device authority" {
    var directory = Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.net.driver",
        .display_name = "Network Driver",
        .publisher = "zigos.dev",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-driver-key",
        },
    };
    const authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 2 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(100),
        .rights = allowedRightsFor(.network_adapter),
        .scope = .{
            .task_id = 7,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
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
    try std.testing.expect(driver.allowsDma(driver.dma_ranges[0].base, 4096));
    try std.testing.expectEqual(BootstrapTransport.none, driver.bootstrap_transport);
    try std.testing.expect(directory.markRestarted(44));
    try std.testing.expectEqual(@as(u32, 2), driver.restart_generation);
    try std.testing.expect(driver.dma_domain_id != 1);
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
            .format = "ed25519",
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

    const storage_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 3 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(200),
        .rights = allowedRightsFor(.storage_controller),
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
            .format = "ed25519",
            .signer = "zigos-spec-driver",
        },
    };
    const graphics_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 4 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(0x1234_1111_0001),
        .rights = allowedRightsFor(.graphics_adapter),
        .scope = .{
            .task_id = 12,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
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
        .bootstrap_transport = .kernel_published_data_plane,
    }));
}
