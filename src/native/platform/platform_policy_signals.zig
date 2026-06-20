const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const capability = @import("../kernel_api/capability.zig");
const fadt = @import("../../kernel/platform/fadt.zig");
const hardware_proof = @import("../../kernel/platform/hardware_proof.zig");
const hardware_target = @import("hardware_target.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const units = @import("../core/units.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Snapshot = struct {
    memory_capacity_bytes: usize = units.mebibytes(512),
    thermal_milli_celsius: u32 = 45_000,
    battery_percent: u8 = 100,
    battery_charging: bool = true,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = true,
    media_driver_online: bool = true,
};

pub const FirstTargetReaderSnapshot = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    thermal_sample_sequence: u64 = 0,
    battery_sample_sequence: u64 = 0,
    accelerator_sample_sequence: u64 = 0,
    grid_carbon_sample_sequence: u64 = 0,
    acpi_tables_observed: bool = false,
    thermal_reader_observed: bool = false,
    battery_reader_observed: bool = false,
    accelerator_reader_observed: bool = false,
    grid_carbon_reader_observed: bool = false,
    memory_capacity_bytes: usize = units.mebibytes(512),
    thermal_milli_celsius: u32 = 45_000,
    battery_percent: u8 = 100,
    battery_charging: bool = true,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = false,
    media_driver_online: bool = true,
    grid_carbon_intensity_grams_per_kwh: u16 = 0,

    pub fn verified(self: FirstTargetReaderSnapshot) bool {
        return std.mem.eql(u8, self.target_id, hardware_target.first_supported_target.id) and
            self.source == .real_hardware and
            self.reader_generation != 0 and
            self.acpi_tables_observed and
            self.thermal_reader_observed and
            self.battery_reader_observed and
            self.accelerator_reader_observed and
            self.grid_carbon_reader_observed and
            self.thermal_sample_sequence != 0 and
            self.battery_sample_sequence != 0 and
            self.accelerator_sample_sequence != 0 and
            self.grid_carbon_sample_sequence != 0 and
            self.memory_capacity_bytes != 0 and
            self.battery_percent <= 100;
    }

    pub fn freshAfter(self: FirstTargetReaderSnapshot, previous: FirstTargetReaderSnapshot) bool {
        if (!self.verified()) return false;
        if (previous.reader_generation == 0) return true;
        if (self.reader_generation < previous.reader_generation) return false;
        if (self.reader_generation > previous.reader_generation) return true;
        return self.thermal_sample_sequence > previous.thermal_sample_sequence and
            self.battery_sample_sequence > previous.battery_sample_sequence and
            self.accelerator_sample_sequence > previous.accelerator_sample_sequence and
            self.grid_carbon_sample_sequence > previous.grid_carbon_sample_sequence;
    }

    pub fn toSnapshot(self: FirstTargetReaderSnapshot) Snapshot {
        return .{
            .memory_capacity_bytes = self.memory_capacity_bytes,
            .thermal_milli_celsius = self.thermal_milli_celsius,
            .battery_percent = self.battery_percent,
            .battery_charging = self.battery_charging,
            .gpu_driver_online = self.gpu_driver_online,
            .npu_driver_online = self.npu_driver_online,
            .media_driver_online = self.media_driver_online,
        };
    }

    pub fn hardwareEvidence(self: FirstTargetReaderSnapshot) accelerator_scheduler.HardwareTelemetryEvidence {
        return .{
            .target_id = self.target_id,
            .reader_generation = self.reader_generation,
            .acpi_observed = self.acpi_tables_observed,
            .thermal_observed = self.thermal_reader_observed,
            .battery_observed = self.battery_reader_observed,
            .accelerator_observed = self.accelerator_reader_observed,
            .grid_carbon_observed = self.grid_carbon_reader_observed,
        };
    }
};

pub const PlatformTelemetryError = accelerator_scheduler.TelemetryError || error{
    FirstTargetTelemetryIncomplete,
    FirstTargetDriverCallbackMissing,
    FirstTargetReaderProviderRejected,
    FirstTargetReaderProviderTargetMismatch,
};

pub const FirstTargetReaderProviderRole = enum(u8) {
    production,
    test_only,
};

pub const FirstTargetReaderProviderDescriptor = struct {
    name: []const u8,
    role: FirstTargetReaderProviderRole,
    target_id: []const u8 = hardware_target.first_supported_target.id,
    reader_generation: u32 = 0,

    pub fn productionEligible(self: FirstTargetReaderProviderDescriptor) bool {
        return self.role == .production and
            self.name.len != 0 and
            std.mem.eql(u8, self.target_id, hardware_target.first_supported_target.id) and
            self.reader_generation != 0;
    }
};

pub const FirstTargetAcpiReaderProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    firmware: fadt.FixedAcpiDescription,
    thermal_zone_count: u16 = 0,
    battery_device_count: u16 = 0,

    pub fn verified(self: FirstTargetAcpiReaderProof) bool {
        return firstTargetReaderIdentityVerified(self.target_id, self.source, self.reader_generation) and
            self.thermal_zone_count != 0 and
            self.battery_device_count != 0 and
            self.firmware.sci_interrupt != 0 and
            (self.firmware.pm1a_event_block != 0 or self.firmware.pm1b_event_block != 0) and
            (self.firmware.pm1a_control_block != 0 or self.firmware.pm1b_control_block != 0) and
            self.firmware.pm1_control_length >= 2 and
            self.firmware.pm_timer_block != 0 and
            self.firmware.pm_timer_length != 0;
    }
};

pub const FirstTargetThermalReaderProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    acpi_reader_generation: u32 = 0,
    zone_count: u16 = 0,
    sample_sequence: u64 = 0,
    thermal_milli_celsius: u32 = 45_000,

    pub fn verified(self: FirstTargetThermalReaderProof) bool {
        return firstTargetReaderIdentityVerified(self.target_id, self.source, self.reader_generation) and
            self.acpi_reader_generation == self.reader_generation and
            self.zone_count != 0 and
            self.sample_sequence != 0 and
            self.thermal_milli_celsius <= 125_000;
    }
};

pub const FirstTargetBatteryReaderProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    acpi_reader_generation: u32 = 0,
    battery_device_count: u16 = 0,
    sample_sequence: u64 = 0,
    battery_percent: u8 = 100,
    charging: bool = true,

    pub fn verified(self: FirstTargetBatteryReaderProof) bool {
        return firstTargetReaderIdentityVerified(self.target_id, self.source, self.reader_generation) and
            self.acpi_reader_generation == self.reader_generation and
            self.battery_device_count != 0 and
            self.sample_sequence != 0 and
            self.battery_percent <= 100;
    }
};

pub const FirstTargetAcceleratorReaderProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    sample_sequence: u64 = 0,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = false,
    media_driver_online: bool = true,
    gpu_driver_generation: u32 = 0,
    npu_driver_generation: u32 = 0,
    media_driver_generation: u32 = 0,
    completion_interrupts_observed: u32 = 0,

    pub fn verified(self: FirstTargetAcceleratorReaderProof) bool {
        return firstTargetReaderIdentityVerified(self.target_id, self.source, self.reader_generation) and
            self.sample_sequence != 0 and
            self.completion_interrupts_observed != 0 and
            driverStateVerified(self.gpu_driver_online, self.gpu_driver_generation) and
            driverStateVerified(self.npu_driver_online, self.npu_driver_generation) and
            driverStateVerified(self.media_driver_online, self.media_driver_generation);
    }
};

pub const FirstTargetGridCarbonReaderProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    reader_generation: u32 = 0,
    sample_sequence: u64 = 0,
    grams_per_kwh: u16 = 0,

    pub fn verified(self: FirstTargetGridCarbonReaderProof) bool {
        return firstTargetReaderIdentityVerified(self.target_id, self.source, self.reader_generation) and
            self.sample_sequence != 0 and
            self.grams_per_kwh <= hardware_proof.MAX_GRID_CARBON_INTENSITY_GRAMS_PER_KWH;
    }
};

pub const FirstTargetReaderProofs = struct {
    reader_generation: u32,
    acpi: FirstTargetAcpiReaderProof,
    thermal: FirstTargetThermalReaderProof,
    battery: FirstTargetBatteryReaderProof,
    accelerators: FirstTargetAcceleratorReaderProof,
    grid_carbon: FirstTargetGridCarbonReaderProof,
    memory_capacity_bytes: usize = units.mebibytes(512),

    pub fn verified(self: FirstTargetReaderProofs) bool {
        return self.reader_generation != 0 and
            self.memory_capacity_bytes != 0 and
            self.acpi.reader_generation == self.reader_generation and
            self.thermal.reader_generation == self.reader_generation and
            self.battery.reader_generation == self.reader_generation and
            self.accelerators.reader_generation == self.reader_generation and
            self.grid_carbon.reader_generation == self.reader_generation and
            self.acpi.verified() and
            self.thermal.verified() and
            self.battery.verified() and
            self.accelerators.verified() and
            self.grid_carbon.verified();
    }

    pub fn toSnapshot(self: FirstTargetReaderProofs) PlatformTelemetryError!FirstTargetReaderSnapshot {
        if (!self.verified()) return error.FirstTargetTelemetryIncomplete;
        return .{
            .target_id = hardware_target.first_supported_target.id,
            .source = .real_hardware,
            .reader_generation = self.reader_generation,
            .thermal_sample_sequence = self.thermal.sample_sequence,
            .battery_sample_sequence = self.battery.sample_sequence,
            .accelerator_sample_sequence = self.accelerators.sample_sequence,
            .grid_carbon_sample_sequence = self.grid_carbon.sample_sequence,
            .acpi_tables_observed = true,
            .thermal_reader_observed = true,
            .battery_reader_observed = true,
            .accelerator_reader_observed = true,
            .grid_carbon_reader_observed = true,
            .memory_capacity_bytes = self.memory_capacity_bytes,
            .thermal_milli_celsius = self.thermal.thermal_milli_celsius,
            .battery_percent = self.battery.battery_percent,
            .battery_charging = self.battery.charging,
            .gpu_driver_online = self.accelerators.gpu_driver_online,
            .npu_driver_online = self.accelerators.npu_driver_online,
            .media_driver_online = self.accelerators.media_driver_online,
            .grid_carbon_intensity_grams_per_kwh = self.grid_carbon.grams_per_kwh,
        };
    }
};

pub const FirstTargetReaderProvider = struct {
    context: *anyopaque,
    descriptor: FirstTargetReaderProviderDescriptor,
    read_acpi_fn: *const fn (*anyopaque) PlatformTelemetryError!FirstTargetAcpiReaderProof,
    read_thermal_fn: *const fn (*anyopaque) PlatformTelemetryError!FirstTargetThermalReaderProof,
    read_battery_fn: *const fn (*anyopaque) PlatformTelemetryError!FirstTargetBatteryReaderProof,
    read_accelerators_fn: *const fn (*anyopaque) PlatformTelemetryError!FirstTargetAcceleratorReaderProof,
    memory_capacity_fn: *const fn (*anyopaque) usize,
    grid_carbon_fn: *const fn (*anyopaque) PlatformTelemetryError!FirstTargetGridCarbonReaderProof,

    pub fn init(
        comptime Provider: type,
        provider: *Provider,
        descriptor: FirstTargetReaderProviderDescriptor,
    ) FirstTargetReaderProvider {
        return .{
            .context = @ptrCast(provider),
            .descriptor = descriptor,
            .read_acpi_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetAcpiReaderProof {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.readAcpi();
                }
            }.read,
            .read_thermal_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetThermalReaderProof {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.readThermal();
                }
            }.read,
            .read_battery_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetBatteryReaderProof {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.readBattery();
                }
            }.read,
            .read_accelerators_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetAcceleratorReaderProof {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.readAccelerators();
                }
            }.read,
            .memory_capacity_fn = struct {
                fn read(context: *anyopaque) usize {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.memoryCapacityBytes();
                }
            }.read,
            .grid_carbon_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetGridCarbonReaderProof {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.readGridCarbon();
                }
            }.read,
        };
    }

    pub fn testOnly(self: FirstTargetReaderProvider) bool {
        return self.descriptor.role == .test_only;
    }

    pub fn readProofs(self: FirstTargetReaderProvider) PlatformTelemetryError!FirstTargetReaderProofs {
        if (!self.descriptor.productionEligible()) return error.FirstTargetReaderProviderRejected;
        const acpi = try self.read_acpi_fn(self.context);
        const thermal = try self.read_thermal_fn(self.context);
        const battery = try self.read_battery_fn(self.context);
        const accelerators = try self.read_accelerators_fn(self.context);
        const grid_carbon = try self.grid_carbon_fn(self.context);
        if (!std.mem.eql(u8, acpi.target_id, self.descriptor.target_id) or
            !std.mem.eql(u8, thermal.target_id, self.descriptor.target_id) or
            !std.mem.eql(u8, battery.target_id, self.descriptor.target_id) or
            !std.mem.eql(u8, accelerators.target_id, self.descriptor.target_id) or
            !std.mem.eql(u8, grid_carbon.target_id, self.descriptor.target_id))
        {
            return error.FirstTargetReaderProviderTargetMismatch;
        }
        return .{
            .reader_generation = self.descriptor.reader_generation,
            .acpi = acpi,
            .thermal = thermal,
            .battery = battery,
            .accelerators = accelerators,
            .grid_carbon = grid_carbon,
            .memory_capacity_bytes = self.memory_capacity_fn(self.context),
        };
    }
};

pub const FirstTargetAcpiDriverSample = struct {
    firmware: fadt.FixedAcpiDescription,
    thermal_zone_count: u16 = 0,
    battery_device_count: u16 = 0,
};

pub const FirstTargetThermalDriverSample = struct {
    zone_count: u16 = 0,
    sample_sequence: u64 = 0,
    thermal_milli_celsius: u32 = 45_000,
};

pub const FirstTargetBatteryDriverSample = struct {
    battery_device_count: u16 = 0,
    sample_sequence: u64 = 0,
    battery_percent: u8 = 100,
    charging: bool = true,
};

pub const FirstTargetAcceleratorDriverSample = struct {
    sample_sequence: u64 = 0,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = false,
    media_driver_online: bool = true,
    gpu_driver_generation: u32 = 0,
    npu_driver_generation: u32 = 0,
    media_driver_generation: u32 = 0,
    completion_interrupts_observed: u32 = 0,
};

pub const FirstTargetGridCarbonDriverSample = struct {
    sample_sequence: u64 = 0,
    grams_per_kwh: u16 = 0,
};

pub const FirstTargetDriverCallbacks = struct {
    context: *anyopaque,
    read_acpi_fn: ?*const fn (*anyopaque) PlatformTelemetryError!FirstTargetAcpiDriverSample = null,
    read_thermal_fn: ?*const fn (*anyopaque) PlatformTelemetryError!FirstTargetThermalDriverSample = null,
    read_battery_fn: ?*const fn (*anyopaque) PlatformTelemetryError!FirstTargetBatteryDriverSample = null,
    read_accelerators_fn: ?*const fn (*anyopaque) PlatformTelemetryError!FirstTargetAcceleratorDriverSample = null,
    memory_capacity_fn: ?*const fn (*anyopaque) usize = null,
    grid_carbon_fn: ?*const fn (*anyopaque) PlatformTelemetryError!FirstTargetGridCarbonDriverSample = null,

    pub fn init(comptime Driver: type, driver: *Driver) FirstTargetDriverCallbacks {
        return .{
            .context = @ptrCast(driver),
            .read_acpi_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetAcpiDriverSample {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.readAcpiSample();
                }
            }.read,
            .read_thermal_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetThermalDriverSample {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.readThermalSample();
                }
            }.read,
            .read_battery_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetBatteryDriverSample {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.readBatterySample();
                }
            }.read,
            .read_accelerators_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetAcceleratorDriverSample {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.readAcceleratorSample();
                }
            }.read,
            .memory_capacity_fn = struct {
                fn read(context: *anyopaque) usize {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.memoryCapacityBytes();
                }
            }.read,
            .grid_carbon_fn = struct {
                fn read(context: *anyopaque) PlatformTelemetryError!FirstTargetGridCarbonDriverSample {
                    const typed_driver: *Driver = @ptrCast(@alignCast(context));
                    return typed_driver.readGridCarbonSample();
                }
            }.read,
        };
    }

    pub fn readAcpi(self: FirstTargetDriverCallbacks) PlatformTelemetryError!FirstTargetAcpiDriverSample {
        const read_fn = self.read_acpi_fn orelse return error.FirstTargetDriverCallbackMissing;
        return read_fn(self.context);
    }

    pub fn readThermal(self: FirstTargetDriverCallbacks) PlatformTelemetryError!FirstTargetThermalDriverSample {
        const read_fn = self.read_thermal_fn orelse return error.FirstTargetDriverCallbackMissing;
        return read_fn(self.context);
    }

    pub fn readBattery(self: FirstTargetDriverCallbacks) PlatformTelemetryError!FirstTargetBatteryDriverSample {
        const read_fn = self.read_battery_fn orelse return error.FirstTargetDriverCallbackMissing;
        return read_fn(self.context);
    }

    pub fn readAccelerators(self: FirstTargetDriverCallbacks) PlatformTelemetryError!FirstTargetAcceleratorDriverSample {
        const read_fn = self.read_accelerators_fn orelse return error.FirstTargetDriverCallbackMissing;
        return read_fn(self.context);
    }

    pub fn memoryCapacityBytes(self: FirstTargetDriverCallbacks) usize {
        const read_fn = self.memory_capacity_fn orelse return 0;
        return read_fn(self.context);
    }

    pub fn readGridCarbon(self: FirstTargetDriverCallbacks) PlatformTelemetryError!FirstTargetGridCarbonDriverSample {
        const read_fn = self.grid_carbon_fn orelse return error.FirstTargetDriverCallbackMissing;
        return read_fn(self.context);
    }
};

pub const FirstTargetDriverCallbackProvider = struct {
    descriptor: FirstTargetReaderProviderDescriptor,
    callbacks: FirstTargetDriverCallbacks,

    pub fn init(
        descriptor: FirstTargetReaderProviderDescriptor,
        callbacks: FirstTargetDriverCallbacks,
    ) FirstTargetDriverCallbackProvider {
        return .{
            .descriptor = descriptor,
            .callbacks = callbacks,
        };
    }

    pub fn readerProvider(self: *FirstTargetDriverCallbackProvider) FirstTargetReaderProvider {
        return FirstTargetReaderProvider.init(FirstTargetDriverCallbackProvider, self, self.descriptor);
    }

    pub fn readAcpi(self: *FirstTargetDriverCallbackProvider) PlatformTelemetryError!FirstTargetAcpiReaderProof {
        const sample = try self.callbacks.readAcpi();
        const proof = FirstTargetAcpiReaderProof{
            .target_id = self.descriptor.target_id,
            .source = .real_hardware,
            .reader_generation = self.descriptor.reader_generation,
            .firmware = sample.firmware,
            .thermal_zone_count = sample.thermal_zone_count,
            .battery_device_count = sample.battery_device_count,
        };
        if (!proof.verified()) return error.FirstTargetTelemetryIncomplete;
        return proof;
    }

    pub fn readThermal(self: *FirstTargetDriverCallbackProvider) PlatformTelemetryError!FirstTargetThermalReaderProof {
        const sample = try self.callbacks.readThermal();
        const proof = FirstTargetThermalReaderProof{
            .target_id = self.descriptor.target_id,
            .source = .real_hardware,
            .reader_generation = self.descriptor.reader_generation,
            .acpi_reader_generation = self.descriptor.reader_generation,
            .zone_count = sample.zone_count,
            .sample_sequence = sample.sample_sequence,
            .thermal_milli_celsius = sample.thermal_milli_celsius,
        };
        if (!proof.verified()) return error.FirstTargetTelemetryIncomplete;
        return proof;
    }

    pub fn readBattery(self: *FirstTargetDriverCallbackProvider) PlatformTelemetryError!FirstTargetBatteryReaderProof {
        const sample = try self.callbacks.readBattery();
        const proof = FirstTargetBatteryReaderProof{
            .target_id = self.descriptor.target_id,
            .source = .real_hardware,
            .reader_generation = self.descriptor.reader_generation,
            .acpi_reader_generation = self.descriptor.reader_generation,
            .battery_device_count = sample.battery_device_count,
            .sample_sequence = sample.sample_sequence,
            .battery_percent = sample.battery_percent,
            .charging = sample.charging,
        };
        if (!proof.verified()) return error.FirstTargetTelemetryIncomplete;
        return proof;
    }

    pub fn readAccelerators(self: *FirstTargetDriverCallbackProvider) PlatformTelemetryError!FirstTargetAcceleratorReaderProof {
        const sample = try self.callbacks.readAccelerators();
        const proof = FirstTargetAcceleratorReaderProof{
            .target_id = self.descriptor.target_id,
            .source = .real_hardware,
            .reader_generation = self.descriptor.reader_generation,
            .sample_sequence = sample.sample_sequence,
            .gpu_driver_online = sample.gpu_driver_online,
            .npu_driver_online = sample.npu_driver_online,
            .media_driver_online = sample.media_driver_online,
            .gpu_driver_generation = sample.gpu_driver_generation,
            .npu_driver_generation = sample.npu_driver_generation,
            .media_driver_generation = sample.media_driver_generation,
            .completion_interrupts_observed = sample.completion_interrupts_observed,
        };
        if (!proof.verified()) return error.FirstTargetTelemetryIncomplete;
        return proof;
    }

    pub fn memoryCapacityBytes(self: *FirstTargetDriverCallbackProvider) usize {
        return self.callbacks.memoryCapacityBytes();
    }

    pub fn readGridCarbon(self: *FirstTargetDriverCallbackProvider) PlatformTelemetryError!FirstTargetGridCarbonReaderProof {
        const sample = try self.callbacks.readGridCarbon();
        const proof = FirstTargetGridCarbonReaderProof{
            .target_id = self.descriptor.target_id,
            .source = .real_hardware,
            .reader_generation = self.descriptor.reader_generation,
            .sample_sequence = sample.sample_sequence,
            .grams_per_kwh = sample.grams_per_kwh,
        };
        if (!proof.verified()) return error.FirstTargetTelemetryIncomplete;
        return proof;
    }
};

pub const FirstTargetHardwareProofDriverReadings = struct {
    facts: hardware_proof.ProbeFacts,

    pub fn init(facts: hardware_proof.ProbeFacts) FirstTargetHardwareProofDriverReadings {
        return .{ .facts = facts };
    }

    pub fn driverCallbackProvider(self: *FirstTargetHardwareProofDriverReadings) FirstTargetDriverCallbackProvider {
        return FirstTargetDriverCallbackProvider.init(
            .{
                .name = "nuc11tnki5-hardware-proof-driver-callbacks",
                .role = .production,
                .reader_generation = self.facts.telemetry_reader_generation,
            },
            FirstTargetDriverCallbacks.init(FirstTargetHardwareProofDriverReadings, self),
        );
    }

    pub fn readAcpiSample(self: *FirstTargetHardwareProofDriverReadings) PlatformTelemetryError!FirstTargetAcpiDriverSample {
        const acpi = self.facts.acpiTelemetryFacts() orelse return error.FirstTargetTelemetryIncomplete;
        return .{
            .firmware = acpi.firmware,
            .thermal_zone_count = acpi.thermal_zone_count,
            .battery_device_count = acpi.battery_device_count,
        };
    }

    pub fn readThermalSample(self: *FirstTargetHardwareProofDriverReadings) PlatformTelemetryError!FirstTargetThermalDriverSample {
        const thermal = self.facts.thermalTelemetryFacts() orelse return error.FirstTargetTelemetryIncomplete;
        return .{
            .zone_count = thermal.zone_count,
            .sample_sequence = thermal.sample_sequence,
            .thermal_milli_celsius = thermal.thermal_milli_celsius,
        };
    }

    pub fn readBatterySample(self: *FirstTargetHardwareProofDriverReadings) PlatformTelemetryError!FirstTargetBatteryDriverSample {
        const battery = self.facts.batteryTelemetryFacts() orelse return error.FirstTargetTelemetryIncomplete;
        return .{
            .battery_device_count = battery.battery_device_count,
            .sample_sequence = battery.sample_sequence,
            .battery_percent = battery.battery_percent,
            .charging = battery.charging,
        };
    }

    pub fn readAcceleratorSample(self: *FirstTargetHardwareProofDriverReadings) PlatformTelemetryError!FirstTargetAcceleratorDriverSample {
        const accelerators = self.facts.acceleratorTelemetryFacts() orelse return error.FirstTargetTelemetryIncomplete;
        return .{
            .sample_sequence = accelerators.sample_sequence,
            .gpu_driver_online = accelerators.gpu_driver_online,
            .npu_driver_online = accelerators.npu_driver_online,
            .media_driver_online = accelerators.media_driver_online,
            .gpu_driver_generation = accelerators.gpu_driver_generation,
            .npu_driver_generation = accelerators.npu_driver_generation,
            .media_driver_generation = accelerators.media_driver_generation,
            .completion_interrupts_observed = accelerators.completion_interrupts_observed,
        };
    }

    pub fn memoryCapacityBytes(self: *FirstTargetHardwareProofDriverReadings) usize {
        return self.facts.memory_capacity_bytes;
    }

    pub fn readGridCarbonSample(self: *FirstTargetHardwareProofDriverReadings) PlatformTelemetryError!FirstTargetGridCarbonDriverSample {
        const carbon = self.facts.gridCarbonTelemetryFacts() orelse return error.FirstTargetTelemetryIncomplete;
        return .{
            .sample_sequence = carbon.sample_sequence,
            .grams_per_kwh = carbon.grams_per_kwh,
        };
    }
};

pub const HostFakeTelemetryProvider = struct {
    current: accelerator_scheduler.TelemetrySample = .{ .source = .emulator },
    read_count: u32 = 0,

    pub const telemetry_descriptor = accelerator_scheduler.TelemetryProviderDescriptor{
        .name = "host-fake-platform-telemetry",
        .role = .test_only,
    };

    pub fn init(sample: accelerator_scheduler.TelemetrySample) HostFakeTelemetryProvider {
        var current = sample;
        current.source = .emulator;
        return .{ .current = current };
    }

    pub fn update(self: *HostFakeTelemetryProvider, sample: accelerator_scheduler.TelemetrySample) void {
        var current = sample;
        current.source = .emulator;
        self.current = current;
    }

    pub fn telemetryProvider(self: *HostFakeTelemetryProvider) accelerator_scheduler.TelemetryProvider {
        return accelerator_scheduler.TelemetryProvider.init(
            HostFakeTelemetryProvider,
            self,
            telemetry_descriptor,
        );
    }

    pub fn read(self: *HostFakeTelemetryProvider) accelerator_scheduler.TelemetrySample {
        self.read_count += 1;
        return self.current;
    }
};

pub const FirstTargetProofReaderBridge = struct {
    descriptor: FirstTargetReaderProviderDescriptor,
    proofs: FirstTargetReaderProofs,

    pub fn init(
        descriptor: FirstTargetReaderProviderDescriptor,
        proofs: FirstTargetReaderProofs,
    ) FirstTargetProofReaderBridge {
        return .{
            .descriptor = descriptor,
            .proofs = proofs,
        };
    }

    pub fn readerProvider(self: *FirstTargetProofReaderBridge) FirstTargetReaderProvider {
        return FirstTargetReaderProvider.init(FirstTargetProofReaderBridge, self, self.descriptor);
    }

    pub fn readAcpi(self: *FirstTargetProofReaderBridge) PlatformTelemetryError!FirstTargetAcpiReaderProof {
        return self.proofs.acpi;
    }

    pub fn readThermal(self: *FirstTargetProofReaderBridge) PlatformTelemetryError!FirstTargetThermalReaderProof {
        return self.proofs.thermal;
    }

    pub fn readBattery(self: *FirstTargetProofReaderBridge) PlatformTelemetryError!FirstTargetBatteryReaderProof {
        return self.proofs.battery;
    }

    pub fn readAccelerators(self: *FirstTargetProofReaderBridge) PlatformTelemetryError!FirstTargetAcceleratorReaderProof {
        return self.proofs.accelerators;
    }

    pub fn memoryCapacityBytes(self: *FirstTargetProofReaderBridge) usize {
        return self.proofs.memory_capacity_bytes;
    }

    pub fn readGridCarbon(self: *FirstTargetProofReaderBridge) PlatformTelemetryError!FirstTargetGridCarbonReaderProof {
        return self.proofs.grid_carbon;
    }
};

pub const FirstTargetPlatformTelemetryProvider = struct {
    booted: accelerator_scheduler.BootedPlatformTelemetryProvider,
    latest_readers: FirstTargetReaderSnapshot,

    pub const telemetry_descriptor = accelerator_scheduler.TelemetryProviderDescriptor{
        .name = "nuc11tnki5-platform-telemetry",
        .role = .production,
    };

    pub fn initForBootedService(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        readers: FirstTargetReaderSnapshot,
    ) PlatformTelemetryError!FirstTargetPlatformTelemetryProvider {
        const counters = try collectFirstTargetLiveCounters(runtime, scheduler, readers);
        return .{
            .booted = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(
                boot_id,
                task_id,
                observed_tick,
                counters,
            ),
            .latest_readers = readers,
        };
    }

    pub fn initFromReaderProofs(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        proofs: FirstTargetReaderProofs,
    ) PlatformTelemetryError!FirstTargetPlatformTelemetryProvider {
        return initForBootedService(
            boot_id,
            task_id,
            observed_tick,
            runtime,
            scheduler,
            try proofs.toSnapshot(),
        );
    }

    pub fn initFromReaderProvider(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        reader_provider: FirstTargetReaderProvider,
    ) PlatformTelemetryError!FirstTargetPlatformTelemetryProvider {
        return initFromReaderProofs(
            boot_id,
            task_id,
            observed_tick,
            runtime,
            scheduler,
            try reader_provider.readProofs(),
        );
    }

    pub fn observeFirstTarget(
        self: *FirstTargetPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        readers: FirstTargetReaderSnapshot,
    ) PlatformTelemetryError!void {
        if (self.booted.task_id == 0 or caller_task_id == 0 or caller_task_id != self.booted.task_id) {
            self.booted.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (!readers.freshAfter(self.latest_readers)) {
            self.booted.rejected_observation_count += 1;
            return error.TelemetryObservationStale;
        }
        const counters = try collectFirstTargetLiveCounters(runtime, scheduler, readers);
        try self.booted.observeLive(caller_task_id, observed_tick, counters);
        self.latest_readers = readers;
    }

    pub fn observeFirstTargetProofs(
        self: *FirstTargetPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        proofs: FirstTargetReaderProofs,
    ) PlatformTelemetryError!void {
        try self.observeFirstTarget(
            caller_task_id,
            observed_tick,
            runtime,
            scheduler,
            try proofs.toSnapshot(),
        );
    }

    pub fn observeFirstTargetProvider(
        self: *FirstTargetPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        runtime: *const task_runtime.Runtime,
        scheduler: *const userspace_scheduler.Scheduler,
        reader_provider: FirstTargetReaderProvider,
    ) PlatformTelemetryError!void {
        try self.observeFirstTargetProofs(
            caller_task_id,
            observed_tick,
            runtime,
            scheduler,
            try reader_provider.readProofs(),
        );
    }

    pub fn telemetryProvider(self: *FirstTargetPlatformTelemetryProvider) accelerator_scheduler.TelemetryProvider {
        return accelerator_scheduler.TelemetryProvider.init(
            FirstTargetPlatformTelemetryProvider,
            self,
            telemetry_descriptor,
        );
    }

    pub fn read(self: *FirstTargetPlatformTelemetryProvider) accelerator_scheduler.TelemetrySample {
        return self.booted.read();
    }

    pub fn liveObservationCount(self: *const FirstTargetPlatformTelemetryProvider) u32 {
        return self.booted.live_observation_count;
    }

    pub fn rejectedObservationCount(self: *const FirstTargetPlatformTelemetryProvider) u32 {
        return self.booted.rejected_observation_count;
    }

    pub fn readCount(self: *const FirstTargetPlatformTelemetryProvider) u32 {
        return self.booted.read_count;
    }
};

pub const FreestandingPlatformTelemetryProvider = struct {
    booted: accelerator_scheduler.BootedPlatformTelemetryProvider,

    pub const telemetry_descriptor = accelerator_scheduler.TelemetryProviderDescriptor{
        .name = "freestanding-platform-telemetry",
        .role = .production,
    };

    pub fn initForBootedService(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        counters: accelerator_scheduler.LivePlatformCounters,
    ) accelerator_scheduler.TelemetryError!FreestandingPlatformTelemetryProvider {
        return .{
            .booted = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(
                boot_id,
                task_id,
                observed_tick,
                counters,
            ),
        };
    }

    pub fn observeLive(
        self: *FreestandingPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        counters: accelerator_scheduler.LivePlatformCounters,
    ) accelerator_scheduler.TelemetryError!void {
        try self.booted.observeLive(caller_task_id, observed_tick, counters);
    }

    pub fn telemetryProvider(self: *FreestandingPlatformTelemetryProvider) accelerator_scheduler.TelemetryProvider {
        return accelerator_scheduler.TelemetryProvider.init(
            FreestandingPlatformTelemetryProvider,
            self,
            telemetry_descriptor,
        );
    }

    pub fn read(self: *FreestandingPlatformTelemetryProvider) accelerator_scheduler.TelemetrySample {
        return self.booted.read();
    }

    pub fn liveObservationCount(self: *const FreestandingPlatformTelemetryProvider) u32 {
        return self.booted.live_observation_count;
    }

    pub fn rejectedObservationCount(self: *const FreestandingPlatformTelemetryProvider) u32 {
        return self.booted.rejected_observation_count;
    }

    pub fn readCount(self: *const FreestandingPlatformTelemetryProvider) u32 {
        return self.booted.read_count;
    }
};

pub fn collectLiveCounters(
    runtime: *const task_runtime.Runtime,
    scheduler: *const userspace_scheduler.Scheduler,
    snapshot: Snapshot,
) accelerator_scheduler.LivePlatformCounters {
    var counters = accelerator_scheduler.LivePlatformCounters{
        .memory_capacity_bytes = snapshot.memory_capacity_bytes,
        .gpu_driver_online = snapshot.gpu_driver_online,
        .npu_driver_online = snapshot.npu_driver_online,
        .media_driver_online = snapshot.media_driver_online,
        .thermal_milli_celsius = snapshot.thermal_milli_celsius,
        .battery_percent = snapshot.battery_percent,
        .battery_charging = snapshot.battery_charging,
    };
    counters.total_cpu_budget_ticks = 0;

    var slot_index: usize = 0;
    while (slot_index < runtime.taskSlotCapacity()) : (slot_index += 1) {
        const slot = runtime.taskSlotAtConst(slot_index);
        if (!slot.in_use) continue;
        const task = &slot.task;
        counters.total_cpu_budget_ticks = saturatingAdd(u64, counters.total_cpu_budget_ticks, task.budget.cpu_time_ticks);
        counters.consumed_cpu_ticks = saturatingAdd(u64, counters.consumed_cpu_ticks, task.background_cpu_consumed_ticks);
        counters.reserved_memory_bytes = saturatingAdd(usize, counters.reserved_memory_bytes, task.budget.memory_bytes);
        counters.reserved_shared_memory_bytes = saturatingAdd(usize, counters.reserved_shared_memory_bytes, task.budget.shared_memory_bytes);

        if (scheduler.slots.getConst(task.id)) |scheduler_slot| {
            counters.consumed_cpu_ticks = saturatingAdd(u64, counters.consumed_cpu_ticks, scheduler_slot.cpu_ticks_consumed);
            if (scheduler_slot.dispatch_request.privacy_sensitive) {
                counters.privacy_sensitive_task_count += 1;
            }
        }
    }
    return counters;
}

pub fn collectFirstTargetLiveCounters(
    runtime: *const task_runtime.Runtime,
    scheduler: *const userspace_scheduler.Scheduler,
    readers: FirstTargetReaderSnapshot,
) PlatformTelemetryError!accelerator_scheduler.LivePlatformCounters {
    if (!readers.verified()) return error.FirstTargetTelemetryIncomplete;
    var counters = collectLiveCounters(runtime, scheduler, readers.toSnapshot());
    counters.grid_carbon_intensity_grams_per_kwh = readers.grid_carbon_intensity_grams_per_kwh;
    counters.hardware_evidence = readers.hardwareEvidence();
    return counters;
}

pub fn collectFirstTargetLiveCountersFromProofs(
    runtime: *const task_runtime.Runtime,
    scheduler: *const userspace_scheduler.Scheduler,
    proofs: FirstTargetReaderProofs,
) PlatformTelemetryError!accelerator_scheduler.LivePlatformCounters {
    return collectFirstTargetLiveCounters(runtime, scheduler, try proofs.toSnapshot());
}

pub fn collectFirstTargetLiveCountersFromReaderProvider(
    runtime: *const task_runtime.Runtime,
    scheduler: *const userspace_scheduler.Scheduler,
    reader_provider: FirstTargetReaderProvider,
) PlatformTelemetryError!accelerator_scheduler.LivePlatformCounters {
    return collectFirstTargetLiveCountersFromProofs(runtime, scheduler, try reader_provider.readProofs());
}

fn firstTargetReaderIdentityVerified(
    target_id: []const u8,
    source: hardware_target.EvidenceSource,
    reader_generation: u32,
) bool {
    return std.mem.eql(u8, target_id, hardware_target.first_supported_target.id) and
        source == .real_hardware and
        reader_generation != 0;
}

fn driverStateVerified(online: bool, generation: u32) bool {
    return !online or generation != 0;
}

fn saturatingAdd(comptime T: type, value: T, amount: T) T {
    return std.math.add(T, value, amount) catch std.math.maxInt(T);
}

fn testFadtFirmware() fadt.FixedAcpiDescription {
    return .{
        .revision = 6,
        .dsdt_address = 0x00AB_C000,
        .sci_interrupt = 9,
        .pm1a_event_block = 0x1800,
        .pm1b_event_block = 0,
        .pm1a_control_block = 0x1804,
        .pm1b_control_block = 0,
        .pm_timer_block = 0x1808,
        .pm1_event_length = 4,
        .pm1_control_length = 2,
        .pm_timer_length = 4,
        .reset_register = null,
        .reset_value = 0,
    };
}

fn testFirstTargetReaderProofs(reader_generation: u32) FirstTargetReaderProofs {
    return .{
        .reader_generation = reader_generation,
        .acpi = .{
            .source = .real_hardware,
            .reader_generation = reader_generation,
            .firmware = testFadtFirmware(),
            .thermal_zone_count = 1,
            .battery_device_count = 1,
        },
        .thermal = .{
            .source = .real_hardware,
            .reader_generation = reader_generation,
            .acpi_reader_generation = reader_generation,
            .zone_count = 1,
            .sample_sequence = 1,
            .thermal_milli_celsius = 76_000,
        },
        .battery = .{
            .source = .real_hardware,
            .reader_generation = reader_generation,
            .acpi_reader_generation = reader_generation,
            .battery_device_count = 1,
            .sample_sequence = 1,
            .battery_percent = 68,
            .charging = true,
        },
        .accelerators = .{
            .source = .real_hardware,
            .reader_generation = reader_generation,
            .sample_sequence = 1,
            .gpu_driver_online = true,
            .npu_driver_online = false,
            .media_driver_online = true,
            .gpu_driver_generation = reader_generation,
            .npu_driver_generation = 0,
            .media_driver_generation = reader_generation,
            .completion_interrupts_observed = 2,
        },
        .grid_carbon = .{
            .source = .real_hardware,
            .reader_generation = reader_generation,
            .sample_sequence = 2,
            .grams_per_kwh = 240,
        },
        .memory_capacity_bytes = units.mebibytes(2),
    };
}

const TestFirstTargetDriverReadings = struct {
    acpi: FirstTargetAcpiDriverSample,
    thermal: FirstTargetThermalDriverSample,
    battery: FirstTargetBatteryDriverSample,
    accelerators: FirstTargetAcceleratorDriverSample,
    memory_capacity_bytes: usize,
    grid_carbon: FirstTargetGridCarbonDriverSample,

    fn fromProofs(proofs: FirstTargetReaderProofs) TestFirstTargetDriverReadings {
        return .{
            .acpi = .{
                .firmware = proofs.acpi.firmware,
                .thermal_zone_count = proofs.acpi.thermal_zone_count,
                .battery_device_count = proofs.acpi.battery_device_count,
            },
            .thermal = .{
                .zone_count = proofs.thermal.zone_count,
                .sample_sequence = proofs.thermal.sample_sequence,
                .thermal_milli_celsius = proofs.thermal.thermal_milli_celsius,
            },
            .battery = .{
                .battery_device_count = proofs.battery.battery_device_count,
                .sample_sequence = proofs.battery.sample_sequence,
                .battery_percent = proofs.battery.battery_percent,
                .charging = proofs.battery.charging,
            },
            .accelerators = .{
                .sample_sequence = proofs.accelerators.sample_sequence,
                .gpu_driver_online = proofs.accelerators.gpu_driver_online,
                .npu_driver_online = proofs.accelerators.npu_driver_online,
                .media_driver_online = proofs.accelerators.media_driver_online,
                .gpu_driver_generation = proofs.accelerators.gpu_driver_generation,
                .npu_driver_generation = proofs.accelerators.npu_driver_generation,
                .media_driver_generation = proofs.accelerators.media_driver_generation,
                .completion_interrupts_observed = proofs.accelerators.completion_interrupts_observed,
            },
            .memory_capacity_bytes = proofs.memory_capacity_bytes,
            .grid_carbon = .{
                .sample_sequence = proofs.grid_carbon.sample_sequence,
                .grams_per_kwh = proofs.grid_carbon.grams_per_kwh,
            },
        };
    }

    pub fn readAcpiSample(self: *TestFirstTargetDriverReadings) PlatformTelemetryError!FirstTargetAcpiDriverSample {
        return self.acpi;
    }

    pub fn readThermalSample(self: *TestFirstTargetDriverReadings) PlatformTelemetryError!FirstTargetThermalDriverSample {
        return self.thermal;
    }

    pub fn readBatterySample(self: *TestFirstTargetDriverReadings) PlatformTelemetryError!FirstTargetBatteryDriverSample {
        return self.battery;
    }

    pub fn readAcceleratorSample(self: *TestFirstTargetDriverReadings) PlatformTelemetryError!FirstTargetAcceleratorDriverSample {
        return self.accelerators;
    }

    pub fn memoryCapacityBytes(self: *TestFirstTargetDriverReadings) usize {
        return self.memory_capacity_bytes;
    }

    pub fn readGridCarbonSample(self: *TestFirstTargetDriverReadings) PlatformTelemetryError!FirstTargetGridCarbonDriverSample {
        return self.grid_carbon;
    }
};

fn testFirstTargetDriverCallbackProvider(
    descriptor: FirstTargetReaderProviderDescriptor,
    readings: *TestFirstTargetDriverReadings,
) FirstTargetDriverCallbackProvider {
    return FirstTargetDriverCallbackProvider.init(
        descriptor,
        FirstTargetDriverCallbacks.init(TestFirstTargetDriverReadings, readings),
    );
}

fn testHardwareProofFacts(reader_generation: u32) hardware_proof.ProbeFacts {
    return .{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .memory_capacity_bytes = units.mebibytes(16),
        .acpi_rsdp = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .fadt_firmware = testFadtFirmware(),
        .telemetry_reader_generation = reader_generation,
        .thermal_zone_count = 2,
        .thermal_sample_sequence = 21,
        .thermal_milli_celsius = 64_000,
        .battery_device_count = 1,
        .battery_sample_sequence = 22,
        .battery_percent = 55,
        .battery_charging = true,
        .gpu_driver_online = true,
        .npu_driver_online = false,
        .media_driver_online = true,
        .gpu_driver_generation = reader_generation,
        .npu_driver_generation = 0,
        .media_driver_generation = reader_generation,
        .accelerator_sample_sequence = 23,
        .accelerator_completion_interrupts = 3,
        .grid_carbon_intensity_observed = true,
        .grid_carbon_sample_sequence = 24,
        .grid_carbon_intensity_grams_per_kwh = 215,
    };
}

test "platform policy signals derive hardware scheduler telemetry from booted runtime state" {
    const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");

    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const foreground_image = try generated_image_fixtures.appImage();
    const foreground = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .app, .serial = 91_001 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 1,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
            .resource_class = .foreground_interactive,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 91_001,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.viewer",
        },
        .userspace_image = &foreground_image,
    });
    foreground.background_cpu_consumed_ticks = 125;
    try std.testing.expect(scheduler.registerTask(foreground.id));

    const private_image = try generated_image_fixtures.appImage();
    const private_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .app, .serial = 91_002 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(128),
            .endpoint_slots = 1,
            .shared_memory_bytes = shared_memory.PAGE_SIZE * 2,
            .resource_class = .background_light,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 91_002,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.viewer",
        },
        .userspace_image = &private_image,
    });
    try std.testing.expect(scheduler.registerTask(private_task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(private_task.id, .{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    }, false));

    const counters = collectLiveCounters(&runtime, &scheduler, .{
        .memory_capacity_bytes = units.kibibytes(512),
        .thermal_milli_celsius = 91_000,
        .battery_percent = 12,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = false,
        .media_driver_online = true,
    });
    try std.testing.expectEqual(@as(u64, 3_000), counters.total_cpu_budget_ticks);
    try std.testing.expectEqual(@as(u64, 125), counters.consumed_cpu_ticks);
    try std.testing.expectEqual(@as(usize, units.kibibytes(512)), counters.memory_capacity_bytes);
    try std.testing.expectEqual(@as(usize, units.kibibytes(192)), counters.reserved_memory_bytes);
    try std.testing.expectEqual(@as(usize, shared_memory.PAGE_SIZE * 3), counters.reserved_shared_memory_bytes);
    try std.testing.expectEqual(@as(usize, 1), counters.privacy_sensitive_task_count);

    var provider = try FreestandingPlatformTelemetryProvider.initForBootedService(91, 91_000, 30, counters);
    const provider_interface = provider.telemetryProvider();
    try std.testing.expect(!provider_interface.testOnly());
    try std.testing.expectEqual(accelerator_scheduler.TelemetryProviderRole.production, provider_interface.descriptor.role);
    var controller = accelerator_scheduler.Controller.init();
    controller.configureFromProvider(provider_interface);
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, controller.last_telemetry_source);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.critical, controller.state.thermal_pressure);
    try std.testing.expect(controller.state.battery_saver);
    try std.testing.expect(controller.state.privacy_mode);
    try std.testing.expect(!controller.state.npu_available);
}

test "platform telemetry providers expose test-only host fake and production freestanding boundaries" {
    var host_fake = HostFakeTelemetryProvider.init(.{
        .source = .synthetic,
        .observed_tick = 5,
        .thermal_pressure = .critical,
        .battery_saver = true,
    });
    const host_provider = host_fake.telemetryProvider();
    try std.testing.expect(host_provider.testOnly());
    try std.testing.expectEqual(accelerator_scheduler.TelemetryProviderRole.test_only, host_provider.descriptor.role);
    const host_sample = host_provider.read();
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.emulator, host_sample.source);
    try std.testing.expectEqual(@as(u64, 5), host_sample.observed_tick);
    try std.testing.expectEqual(@as(u32, 1), host_fake.read_count);

    var freestanding = try FreestandingPlatformTelemetryProvider.initForBootedService(5, 50, 6, .{
        .total_cpu_budget_ticks = 2_000,
        .consumed_cpu_ticks = 500,
        .memory_capacity_bytes = units.kibibytes(128),
        .thermal_milli_celsius = 76_000,
        .battery_percent = 90,
        .battery_charging = true,
    });
    const freestanding_provider = freestanding.telemetryProvider();
    try std.testing.expect(!freestanding_provider.testOnly());
    try std.testing.expectEqual(accelerator_scheduler.TelemetryProviderRole.production, freestanding_provider.descriptor.role);
    const freestanding_sample = freestanding_provider.read();
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, freestanding_sample.source);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.elevated, freestanding_sample.thermal_pressure);
    try std.testing.expectEqual(@as(u64, 6), freestanding_sample.observed_tick);
    try std.testing.expectEqual(@as(u32, 1), freestanding.readCount());
    try std.testing.expectEqual(@as(u32, 1), freestanding.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 0), freestanding.rejectedObservationCount());
}

test "first target reader proofs compose fail closed into scheduler telemetry" {
    const proofs = testFirstTargetReaderProofs(8);
    try std.testing.expect(proofs.verified());
    const snapshot = try proofs.toSnapshot();
    try std.testing.expect(snapshot.verified());
    try std.testing.expectEqual(@as(u32, 8), snapshot.reader_generation);
    try std.testing.expectEqual(@as(u32, 76_000), snapshot.thermal_milli_celsius);
    try std.testing.expectEqual(@as(u8, 68), snapshot.battery_percent);
    try std.testing.expect(snapshot.gpu_driver_online);
    try std.testing.expect(!snapshot.npu_driver_online);
    try std.testing.expect(snapshot.media_driver_online);

    var qemu_acpi = proofs;
    qemu_acpi.acpi.source = .qemu;
    try std.testing.expect(!qemu_acpi.verified());
    try std.testing.expectError(error.FirstTargetTelemetryIncomplete, qemu_acpi.toSnapshot());

    var stale_thermal = proofs;
    stale_thermal.thermal.acpi_reader_generation = 7;
    try std.testing.expect(!stale_thermal.verified());
    try std.testing.expectError(error.FirstTargetTelemetryIncomplete, stale_thermal.toSnapshot());

    var missing_media_driver = proofs;
    missing_media_driver.accelerators.media_driver_generation = 0;
    try std.testing.expect(!missing_media_driver.verified());
    try std.testing.expectError(error.FirstTargetTelemetryIncomplete, missing_media_driver.toSnapshot());

    var overheated = proofs;
    overheated.thermal.thermal_milli_celsius = 126_000;
    try std.testing.expect(!overheated.verified());
    try std.testing.expectError(error.FirstTargetTelemetryIncomplete, overheated.toSnapshot());
}

test "first target reader provider rejects invalid bridges and validates driver callbacks" {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const proofs = testFirstTargetReaderProofs(9);
    var test_only_bridge = FirstTargetProofReaderBridge.init(.{
        .name = "host-fake-first-target-readers",
        .role = .test_only,
        .reader_generation = 9,
    }, proofs);
    const test_only_provider = test_only_bridge.readerProvider();
    try std.testing.expect(test_only_provider.testOnly());
    try std.testing.expectError(
        error.FirstTargetReaderProviderRejected,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, test_only_provider),
    );

    var stale_descriptor_bridge = FirstTargetProofReaderBridge.init(.{
        .name = "nuc11tnki5-driver-reader-bridge",
        .role = .production,
        .reader_generation = 10,
    }, proofs);
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, stale_descriptor_bridge.readerProvider()),
    );

    var target_mismatch_proofs = proofs;
    target_mismatch_proofs.thermal.target_id = "other-target";
    var target_mismatch_bridge = FirstTargetProofReaderBridge.init(.{
        .name = "nuc11tnki5-driver-reader-bridge",
        .role = .production,
        .reader_generation = 9,
    }, target_mismatch_proofs);
    try std.testing.expectError(
        error.FirstTargetReaderProviderTargetMismatch,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, target_mismatch_bridge.readerProvider()),
    );

    var driver_readings = TestFirstTargetDriverReadings.fromProofs(proofs);
    var missing_thermal_driver = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 9,
    }, &driver_readings);
    missing_thermal_driver.callbacks.read_thermal_fn = null;
    try std.testing.expectError(
        error.FirstTargetDriverCallbackMissing,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, missing_thermal_driver.readerProvider()),
    );

    var missing_grid_driver = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 9,
    }, &driver_readings);
    missing_grid_driver.callbacks.grid_carbon_fn = null;
    try std.testing.expectError(
        error.FirstTargetDriverCallbackMissing,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, missing_grid_driver.readerProvider()),
    );

    var stale_battery_readings = TestFirstTargetDriverReadings.fromProofs(proofs);
    stale_battery_readings.battery.sample_sequence = 0;
    var stale_battery_driver = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 9,
    }, &stale_battery_readings);
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, stale_battery_driver.readerProvider()),
    );

    var stale_grid_readings = TestFirstTargetDriverReadings.fromProofs(proofs);
    stale_grid_readings.grid_carbon.sample_sequence = 0;
    var stale_grid_driver = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 9,
    }, &stale_grid_readings);
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, stale_grid_driver.readerProvider()),
    );

    var driver_provider = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 9,
    }, &driver_readings);
    const counters = try collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, driver_provider.readerProvider());
    try std.testing.expect(counters.hardware_evidence.complete());
    try std.testing.expectEqual(@as(u32, 9), counters.hardware_evidence.reader_generation);
    try std.testing.expectEqual(@as(u32, 76_000), counters.thermal_milli_celsius);
    try std.testing.expectEqual(@as(u8, 68), counters.battery_percent);
    try std.testing.expectEqual(@as(u16, 240), counters.grid_carbon_intensity_grams_per_kwh);

    var telemetry_provider = try FirstTargetPlatformTelemetryProvider.initFromReaderProvider(
        93,
        93_000,
        20,
        &runtime,
        &scheduler,
        driver_provider.readerProvider(),
    );
    const sample = telemetry_provider.telemetryProvider().read();
    try std.testing.expect(sample.hardwareReaderEvidenceComplete());
    try std.testing.expectEqual(@as(u32, 9), sample.hardware_evidence.reader_generation);
    try std.testing.expectEqual(@as(u32, 1), telemetry_provider.readCount());
    try std.testing.expectEqual(@as(u32, 0), telemetry_provider.rejectedObservationCount());

    try std.testing.expectError(
        error.TelemetryObservationStale,
        telemetry_provider.observeFirstTargetProvider(
            93_000,
            21,
            &runtime,
            &scheduler,
            driver_provider.readerProvider(),
        ),
    );
    try std.testing.expectEqual(@as(u32, 1), telemetry_provider.rejectedObservationCount());

    driver_readings.thermal.sample_sequence = 2;
    driver_readings.battery.sample_sequence = 2;
    driver_readings.accelerators.sample_sequence = 2;
    driver_readings.grid_carbon.sample_sequence = 3;
    try telemetry_provider.observeFirstTargetProvider(
        93_000,
        22,
        &runtime,
        &scheduler,
        driver_provider.readerProvider(),
    );
    try std.testing.expectEqual(@as(u32, 2), telemetry_provider.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 1), telemetry_provider.rejectedObservationCount());
}

test "first target hardware proof facts feed production driver callback telemetry" {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    var missing_fadt_facts = testHardwareProofFacts(10);
    missing_fadt_facts.fadt_firmware = null;
    var missing_fadt_readings = FirstTargetHardwareProofDriverReadings.init(missing_fadt_facts);
    var missing_fadt_provider = missing_fadt_readings.driverCallbackProvider();
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, missing_fadt_provider.readerProvider()),
    );

    var missing_memory_facts = testHardwareProofFacts(10);
    missing_memory_facts.memory_capacity_bytes = 0;
    var missing_memory_readings = FirstTargetHardwareProofDriverReadings.init(missing_memory_facts);
    var missing_memory_provider = missing_memory_readings.driverCallbackProvider();
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, missing_memory_provider.readerProvider()),
    );

    var missing_grid_facts = testHardwareProofFacts(10);
    missing_grid_facts.grid_carbon_intensity_observed = false;
    var missing_grid_readings = FirstTargetHardwareProofDriverReadings.init(missing_grid_facts);
    var missing_grid_provider = missing_grid_readings.driverCallbackProvider();
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, missing_grid_provider.readerProvider()),
    );

    const facts = testHardwareProofFacts(10);
    var proof_readings = FirstTargetHardwareProofDriverReadings.init(facts);
    var proof_provider = proof_readings.driverCallbackProvider();
    const counters = try collectFirstTargetLiveCountersFromReaderProvider(&runtime, &scheduler, proof_provider.readerProvider());
    try std.testing.expect(counters.hardware_evidence.complete());
    try std.testing.expectEqual(@as(u32, 10), counters.hardware_evidence.reader_generation);
    try std.testing.expectEqual(@as(usize, units.mebibytes(16)), counters.memory_capacity_bytes);
    try std.testing.expectEqual(@as(u32, 64_000), counters.thermal_milli_celsius);
    try std.testing.expectEqual(@as(u8, 55), counters.battery_percent);
    try std.testing.expect(counters.gpu_driver_online);
    try std.testing.expect(!counters.npu_driver_online);
    try std.testing.expect(counters.media_driver_online);
    try std.testing.expectEqual(@as(u16, 215), counters.grid_carbon_intensity_grams_per_kwh);

    var telemetry_provider = try FirstTargetPlatformTelemetryProvider.initFromReaderProvider(
        94,
        94_000,
        31,
        &runtime,
        &scheduler,
        proof_provider.readerProvider(),
    );
    const sample = telemetry_provider.telemetryProvider().read();
    try std.testing.expect(sample.hardwareReaderEvidenceComplete());
    try std.testing.expectEqual(@as(u32, 10), sample.hardware_evidence.reader_generation);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.nominal, sample.thermal_pressure);
    try std.testing.expect(sample.gpu_available);
    try std.testing.expect(!sample.npu_available);
    try std.testing.expect(sample.media_available);
}

test "first target telemetry provider requires complete hardware reader evidence before accelerator scheduling" {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const incomplete_readers = FirstTargetReaderSnapshot{
        .source = .real_hardware,
        .reader_generation = 1,
        .acpi_tables_observed = true,
        .thermal_reader_observed = true,
        .battery_reader_observed = false,
        .accelerator_reader_observed = true,
    };
    try std.testing.expect(!incomplete_readers.verified());
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCounters(&runtime, &scheduler, incomplete_readers),
    );

    const qemu_readers = FirstTargetReaderSnapshot{
        .source = .qemu,
        .reader_generation = 1,
        .acpi_tables_observed = true,
        .thermal_reader_observed = true,
        .battery_reader_observed = true,
        .accelerator_reader_observed = true,
    };
    try std.testing.expectError(
        error.FirstTargetTelemetryIncomplete,
        collectFirstTargetLiveCounters(&runtime, &scheduler, qemu_readers),
    );

    const complete_readers = testFirstTargetReaderProofs(4);
    var complete_driver_readings = TestFirstTargetDriverReadings.fromProofs(complete_readers);
    var complete_driver = testFirstTargetDriverCallbackProvider(.{
        .name = "nuc11tnki5-driver-callbacks",
        .role = .production,
        .reader_generation = 4,
    }, &complete_driver_readings);
    var provider = try FirstTargetPlatformTelemetryProvider.initFromReaderProvider(
        92,
        92_000,
        20,
        &runtime,
        &scheduler,
        complete_driver.readerProvider(),
    );
    const provider_interface = provider.telemetryProvider();
    try std.testing.expect(!provider_interface.testOnly());
    try std.testing.expectEqual(accelerator_scheduler.TelemetryProviderRole.production, provider_interface.descriptor.role);
    const sample = provider_interface.read();
    try std.testing.expect(sample.hardwareReaderEvidenceComplete());
    try std.testing.expectEqualStrings(hardware_target.first_supported_target.id, sample.hardware_evidence.target_id);
    try std.testing.expectEqual(@as(u32, 4), sample.hardware_evidence.reader_generation);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.elevated, sample.thermal_pressure);
    try std.testing.expect(sample.gpu_available);
    try std.testing.expect(!sample.npu_available);
    try std.testing.expect(sample.media_available);
    try std.testing.expectEqual(@as(u16, 240), sample.grid_carbon_intensity_grams_per_kwh);

    var partial_controller = accelerator_scheduler.Controller.init();
    partial_controller.configureFromTelemetry(.{
        .source = .hardware,
        .observed_tick = 21,
        .gpu_available = true,
    });
    try std.testing.expect(partial_controller.observedTelemetry());
    try std.testing.expect(!partial_controller.last_hardware_evidence_complete);
    try std.testing.expectError(error.AcceleratorRequired, partial_controller.claim(.{
        .task_id = 77,
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
        },
        .require_accelerator = true,
    }));

    var controller = accelerator_scheduler.Controller.init();
    controller.configureFromProvider(provider.telemetryProvider());
    try std.testing.expect(controller.last_hardware_evidence_complete);
    const gpu_claim = try controller.claim(.{
        .task_id = 78,
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
        },
        .require_accelerator = true,
    });
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, gpu_claim.engine);
    try std.testing.expectEqual(@as(u32, 2), provider.readCount());
}
