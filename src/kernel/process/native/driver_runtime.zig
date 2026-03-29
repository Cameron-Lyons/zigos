const std = @import("std");
const bootstrap_driver_port = @import("bootstrap_driver_port.zig");
const driver_service = @import("driver_service.zig");
const storage_volume = @import("storage_volume.zig");
const native_util = @import("util.zig");
const copyText = native_util.copyText;

pub const MAX_ACTIVATIONS: usize = 8;

pub const ActivationMode = enum(u8) {
    control_only,
    published_data_plane,
};

pub const ActivationRecord = struct {
    service_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
    dma_domain_id: u64,
    iommu_enforced: bool,
    mode: ActivationMode,
    exclusive_claim: bool,
    activation_generation: u32,
    kernel_bootstrap: bool,
    publisher_len: usize,
    publisher: [32]u8,

    pub fn publisherSlice(self: *const ActivationRecord) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const Error = error{
    ActivationTableFull,
    MissingDmaDomain,
};

const ActivationSlot = struct {
    in_use: bool = false,
    activation: ActivationRecord = zeroActivation(),
};

pub const Runtime = struct {
    next_activation_generation: u32 = 1,
    slots: [MAX_ACTIVATIONS]ActivationSlot = [_]ActivationSlot{ActivationSlot{}} ** MAX_ACTIVATIONS,

    pub fn init() Runtime {
        return .{};
    }

    pub fn activate(self: *Runtime, driver: *const driver_service.DriverRecord) Error!ActivationRecord {
        var record = ActivationRecord{
            .service_id = driver.service_id,
            .device_id = driver.device_id,
            .device_class = driver.device_class,
            .dma_domain_id = driver.dma_domain_id,
            .iommu_enforced = driver.dma_protection == .iommu_enforced,
            .mode = .control_only,
            .exclusive_claim = false,
            .activation_generation = 0,
            .kernel_bootstrap = false,
            .publisher_len = 0,
            .publisher = [_]u8{0} ** 32,
        };
        if (record.dma_domain_id == 0 or !record.iommu_enforced) return error.MissingDmaDomain;

        switch (driver.device_class) {
            .network_adapter => {
                if (bootstrap_driver_port.networkPublication()) |publication| {
                    if (publication.device_id == driver.device_id and
                        bootstrap_driver_port.activateNetworkDevice(driver.device_id, driver.service_id))
                    {
                        record.mode = .published_data_plane;
                        record.exclusive_claim = true;
                        record.kernel_bootstrap = publication.kernel_bootstrap;
                        record.publisher_len = copyText(record.publisher[0..], publication.publisherSlice());
                    }
                }
            },
            .storage_controller => {
                if (bootstrap_driver_port.storagePublication()) |publication| {
                    if (publication.device_id == driver.device_id and
                        bootstrap_driver_port.activateStorageBackend(driver.device_id, driver.service_id))
                    {
                        record.mode = .published_data_plane;
                        record.exclusive_claim = true;
                        record.kernel_bootstrap = publication.kernel_bootstrap;
                        record.publisher_len = copyText(record.publisher[0..], publication.publisherSlice());
                    }
                }
            },
            else => {},
        }

        record.activation_generation = self.nextActivationGeneration();
        return self.upsert(record);
    }

    pub fn findByClass(self: *const Runtime, device_class: driver_service.DeviceClass) ?ActivationRecord {
        for (self.slots) |slot| {
            if (slot.in_use and slot.activation.device_class == device_class) return slot.activation;
        }
        return null;
    }

    pub fn deactivate(self: *Runtime, service_id: u64) bool {
        for (&self.slots) |*slot| {
            if (!slot.in_use or slot.activation.service_id != service_id) continue;
            if (slot.activation.mode == .published_data_plane and slot.activation.exclusive_claim) {
                const released = switch (slot.activation.device_class) {
                    .network_adapter => bootstrap_driver_port.deactivateNetworkDevice(service_id),
                    .storage_controller => bootstrap_driver_port.deactivateStorageBackend(service_id),
                    else => true,
                };
                if (!released) return false;
            }
            slot.activation.mode = .control_only;
            slot.activation.exclusive_claim = false;
            return true;
        }
        return false;
    }

    fn upsert(self: *Runtime, activation: ActivationRecord) Error!ActivationRecord {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.activation.service_id == activation.service_id) {
                slot.activation = activation;
                return slot.activation;
            }
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.activation = activation;
            return slot.activation;
        }

        return error.ActivationTableFull;
    }

    fn nextActivationGeneration(self: *Runtime) u32 {
        defer self.next_activation_generation += 1;
        return self.next_activation_generation;
    }
};

fn zeroActivation() ActivationRecord {
    return .{
        .service_id = 0,
        .device_id = 0,
        .device_class = .network_adapter,
        .dma_domain_id = 0,
        .iommu_enforced = false,
        .mode = .control_only,
        .exclusive_claim = false,
        .activation_generation = 0,
        .kernel_bootstrap = false,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** 32,
    };
}
