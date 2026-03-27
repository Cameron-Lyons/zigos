const std = @import("std");
const capability = @import("capability.zig");
const manifest = @import("manifest.zig");

pub const MAX_DRIVER_SERVICES: usize = 8;

pub const DeviceClass = enum(u8) {
    network_adapter,
    storage_controller,
    graphics_adapter,
    audio_print_io,
};

pub const DriverRecord = struct {
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    authority_capability_id: u64,
    restart_generation: u32,
    signer_len: usize,
    signer: [32]u8,

    pub fn signerSlice(self: *const DriverRecord) []const u8 {
        return self.signer[0..self.signer_len];
    }
};

pub const RegistrationRequest = struct {
    service_id: u64,
    owner_task_id: u64,
    device_id: u64,
    device_class: DeviceClass,
    authority: capability.Capability,
    bundle: manifest.BundleManifest,
};

pub const Error = error{
    DriverTableFull,
    DuplicateServiceId,
    DuplicateDeviceBinding,
    InvalidBundleSignature,
    InvalidAuthorityTarget,
    AuthorityRightsEscalation,
};

const DriverSlot = struct {
    in_use: bool = false,
    driver: DriverRecord = zeroDriver(),
};

pub const Directory = struct {
    slots: [MAX_DRIVER_SERVICES]DriverSlot = [_]DriverSlot{DriverSlot{}} ** MAX_DRIVER_SERVICES,

    pub fn init() Directory {
        return .{};
    }

    pub fn register(self: *Directory, request: RegistrationRequest) Error!*DriverRecord {
        if (request.bundle.signature.signer.len == 0) return error.InvalidBundleSignature;
        if (request.authority.target.kind != .device or request.authority.target.id != request.device_id) {
            return error.InvalidAuthorityTarget;
        }
        if (!rightsAreSubset(request.authority.rights, allowedRightsFor(request.device_class))) {
            return error.AuthorityRightsEscalation;
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
                .authority_capability_id = request.authority.id,
                .restart_generation = 1,
                .signer_len = 0,
                .signer = [_]u8{0} ** 32,
            };
            writeSigner(&slot.driver, request.bundle.signature.signer);
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
        return true;
    }
};

pub fn authorityTarget(device_id: u64) capability.CapabilityTarget {
    return .{ .kind = .device, .id = device_id };
}

pub fn allowedRightsFor(device_class: DeviceClass) capability.CapabilityRights {
    return switch (device_class) {
        .network_adapter => .{
            .device_use = true,
            .network_local = true,
        },
        .storage_controller => .{
            .device_use = true,
            .object_read = true,
            .object_write = true,
        },
        .graphics_adapter => .{
            .device_use = true,
        },
        .audio_print_io => .{
            .device_use = true,
        },
    };
}

fn rightsAreSubset(owned: capability.CapabilityRights, allowed: capability.CapabilityRights) bool {
    const owned_bits: u32 = @bitCast(owned);
    const allowed_bits: u32 = @bitCast(allowed);
    return (owned_bits & ~allowed_bits) == 0;
}

fn writeSigner(record: *DriverRecord, signer: []const u8) void {
    record.signer_len = @min(signer.len, record.signer.len);
    @memcpy(record.signer[0..record.signer_len], signer[0..record.signer_len]);
}

fn zeroDriver() DriverRecord {
    return .{
        .service_id = 0,
        .owner_task_id = 0,
        .device_id = 0,
        .device_class = .network_adapter,
        .authority_capability_id = 0,
        .restart_generation = 0,
        .signer_len = 0,
        .signer = [_]u8{0} ** 32,
    };
}

test "driver services require signed least-privilege device authority" {
    var directory = Directory.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.net.driver",
        .display_name = "Network Driver",
        .publisher = "zigos.dev",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-driver-key",
        },
    };
    const authority = capability.Capability{
        .id = 11,
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
        .revocation_generation = 1,
        .audit = .{},
    };

    const driver = try directory.register(.{
        .service_id = 44,
        .owner_task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
        .authority = authority,
        .bundle = bundle,
    });

    try std.testing.expectEqual(@as(u64, 44), driver.service_id);
    try std.testing.expectEqualStrings("zigos-driver-key", driver.signerSlice());
    try std.testing.expect(directory.markRestarted(44));
    try std.testing.expectEqual(@as(u32, 2), driver.restart_generation);
}

test "driver services reject unsigned bundles and escalated device rights" {
    var directory = Directory.init();
    const unsigned_bundle = manifest.BundleManifest{
        .bundle_id = "svc.storage.driver",
        .display_name = "Storage Driver",
        .publisher = "zigos.dev",
    };
    const escalated_authority = capability.Capability{
        .id = 12,
        .holder = .{ .kind = .service, .serial = 3 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = authorityTarget(200),
        .rights = .{
            .device_use = true,
            .object_read = true,
            .object_write = true,
            .network_remote = true,
        },
        .scope = .{
            .task_id = 9,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
        },
        .revocation_generation = 1,
        .audit = .{},
    };

    try std.testing.expectError(error.InvalidBundleSignature, directory.register(.{
        .service_id = 50,
        .owner_task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .authority = escalated_authority,
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
        .authority = escalated_authority,
        .bundle = signed_bundle,
    }));
}
