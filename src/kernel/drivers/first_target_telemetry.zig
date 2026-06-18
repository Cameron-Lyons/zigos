const std = @import("std");
const fadt = @import("../platform/fadt.zig");
const hardware_proof = @import("../platform/hardware_proof.zig");

pub const kernel_boundary_role = "first_target_hardware_telemetry_recorder";
pub const publishes_scheduler_hardware_telemetry = true;
pub const requires_acpi_fadt_base = true;

pub const Error = error{
    HardwareTelemetryBaseMissing,
    TelemetrySourceRegistryEmpty,
    TelemetrySourceRegistryIncomplete,
    ThermalTelemetrySourceMissing,
    BatteryTelemetrySourceMissing,
    AcceleratorTelemetrySourceMissing,
    GridCarbonTelemetrySourceMissing,
    InvalidThermalZoneSample,
    InvalidBatteryStatusSample,
    InvalidAcceleratorDriverSample,
    InvalidGridCarbonTelemetrySample,
    TelemetrySampleSequenceStale,
    HardwareTelemetryRecorderRejected,
};

pub const ThermalZoneReading = struct {
    zone_count: u16,
    sample_sequence: u64,
    thermal_milli_celsius: u32,

    pub fn toSample(self: ThermalZoneReading, reader_generation: u32) hardware_proof.ThermalZoneSample {
        return .{
            .reader_generation = reader_generation,
            .zone_count = self.zone_count,
            .sample_sequence = self.sample_sequence,
            .thermal_milli_celsius = self.thermal_milli_celsius,
        };
    }
};

pub const BatteryStatusReading = struct {
    battery_device_count: u16,
    sample_sequence: u64,
    battery_percent: u8,
    charging: bool,

    pub fn toSample(self: BatteryStatusReading, reader_generation: u32) hardware_proof.BatteryStatusSample {
        return .{
            .reader_generation = reader_generation,
            .battery_device_count = self.battery_device_count,
            .sample_sequence = self.sample_sequence,
            .battery_percent = self.battery_percent,
            .charging = self.charging,
        };
    }
};

pub const AcceleratorEngineReading = struct {
    online: bool = false,
    driver_generation: u32 = 0,

    pub fn verified(self: AcceleratorEngineReading) bool {
        return !self.online or self.driver_generation != 0;
    }
};

pub const AcceleratorDriverReading = struct {
    sample_sequence: u64,
    gpu: AcceleratorEngineReading = .{},
    npu: AcceleratorEngineReading = .{},
    media: AcceleratorEngineReading = .{},
    completion_interrupts_observed: u32,

    pub fn toSample(self: AcceleratorDriverReading, reader_generation: u32) hardware_proof.AcceleratorDriverSample {
        return .{
            .reader_generation = reader_generation,
            .sample_sequence = self.sample_sequence,
            .gpu_driver_online = self.gpu.online,
            .npu_driver_online = self.npu.online,
            .media_driver_online = self.media.online,
            .gpu_driver_generation = self.gpu.driver_generation,
            .npu_driver_generation = self.npu.driver_generation,
            .media_driver_generation = self.media.driver_generation,
            .completion_interrupts_observed = self.completion_interrupts_observed,
        };
    }
};

pub const FirstTargetTelemetryReading = struct {
    reader_generation: u32,
    thermal: ThermalZoneReading,
    battery: BatteryStatusReading,
    accelerators: AcceleratorDriverReading,
    grid_carbon: GridCarbonReading,
};

pub const GridCarbonReading = struct {
    sample_sequence: u64,
    grams_per_kwh: u16,

    pub fn toSample(self: GridCarbonReading, reader_generation: u32) hardware_proof.GridCarbonIntensitySample {
        return .{
            .reader_generation = reader_generation,
            .sample_sequence = self.sample_sequence,
            .grams_per_kwh = self.grams_per_kwh,
        };
    }
};

pub const FirstTargetTelemetrySource = struct {
    context: ?*anyopaque = null,
    read_thermal_fn: ?*const fn (?*anyopaque) Error!ThermalZoneReading = null,
    read_battery_fn: ?*const fn (?*anyopaque) Error!BatteryStatusReading = null,
    read_accelerators_fn: ?*const fn (?*anyopaque) Error!AcceleratorDriverReading = null,
    read_grid_carbon_fn: ?*const fn (?*anyopaque) Error!GridCarbonReading = null,

    pub fn readThermal(self: FirstTargetTelemetrySource) Error!ThermalZoneReading {
        const read_fn = self.read_thermal_fn orelse return error.ThermalTelemetrySourceMissing;
        return read_fn(self.context);
    }

    pub fn readBattery(self: FirstTargetTelemetrySource) Error!BatteryStatusReading {
        const read_fn = self.read_battery_fn orelse return error.BatteryTelemetrySourceMissing;
        return read_fn(self.context);
    }

    pub fn readAccelerators(self: FirstTargetTelemetrySource) Error!AcceleratorDriverReading {
        const read_fn = self.read_accelerators_fn orelse return error.AcceleratorTelemetrySourceMissing;
        return read_fn(self.context);
    }

    pub fn readGridCarbonIntensity(self: FirstTargetTelemetrySource) Error!GridCarbonReading {
        const read_fn = self.read_grid_carbon_fn orelse return error.GridCarbonTelemetrySourceMissing;
        return read_fn(self.context);
    }

    pub fn completeForRegistry(self: FirstTargetTelemetrySource) bool {
        return self.read_thermal_fn != null and
            self.read_battery_fn != null and
            self.read_accelerators_fn != null and
            self.read_grid_carbon_fn != null;
    }

    pub fn thermalProvider(self: FirstTargetTelemetrySource) ThermalTelemetryProvider {
        return .{
            .context = self.context,
            .read_fn = self.read_thermal_fn,
        };
    }

    pub fn batteryProvider(self: FirstTargetTelemetrySource) BatteryTelemetryProvider {
        return .{
            .context = self.context,
            .read_fn = self.read_battery_fn,
        };
    }

    pub fn acceleratorProvider(self: FirstTargetTelemetrySource) AcceleratorTelemetryProvider {
        return .{
            .context = self.context,
            .read_fn = self.read_accelerators_fn,
        };
    }

    pub fn gridCarbonProvider(self: FirstTargetTelemetrySource) GridCarbonTelemetryProvider {
        return .{
            .context = self.context,
            .read_fn = self.read_grid_carbon_fn,
        };
    }
};

pub const ThermalTelemetryProvider = struct {
    context: ?*anyopaque = null,
    read_fn: ?*const fn (?*anyopaque) Error!ThermalZoneReading = null,

    pub fn complete(self: ThermalTelemetryProvider) bool {
        return self.read_fn != null;
    }

    pub fn read(self: ThermalTelemetryProvider) Error!ThermalZoneReading {
        const read_fn = self.read_fn orelse return error.ThermalTelemetrySourceMissing;
        return read_fn(self.context);
    }
};

pub const BatteryTelemetryProvider = struct {
    context: ?*anyopaque = null,
    read_fn: ?*const fn (?*anyopaque) Error!BatteryStatusReading = null,

    pub fn complete(self: BatteryTelemetryProvider) bool {
        return self.read_fn != null;
    }

    pub fn read(self: BatteryTelemetryProvider) Error!BatteryStatusReading {
        const read_fn = self.read_fn orelse return error.BatteryTelemetrySourceMissing;
        return read_fn(self.context);
    }
};

pub const AcceleratorTelemetryProvider = struct {
    context: ?*anyopaque = null,
    read_fn: ?*const fn (?*anyopaque) Error!AcceleratorDriverReading = null,

    pub fn complete(self: AcceleratorTelemetryProvider) bool {
        return self.read_fn != null;
    }

    pub fn read(self: AcceleratorTelemetryProvider) Error!AcceleratorDriverReading {
        const read_fn = self.read_fn orelse return error.AcceleratorTelemetrySourceMissing;
        return read_fn(self.context);
    }
};

pub const GridCarbonTelemetryProvider = struct {
    context: ?*anyopaque = null,
    read_fn: ?*const fn (?*anyopaque) Error!GridCarbonReading = null,

    pub fn complete(self: GridCarbonTelemetryProvider) bool {
        return self.read_fn != null;
    }

    pub fn read(self: GridCarbonTelemetryProvider) Error!GridCarbonReading {
        const read_fn = self.read_fn orelse return error.GridCarbonTelemetrySourceMissing;
        return read_fn(self.context);
    }
};

pub const FirstTargetTelemetrySourceRegistry = struct {
    thermal: ?ThermalTelemetryProvider = null,
    battery: ?BatteryTelemetryProvider = null,
    accelerators: ?AcceleratorTelemetryProvider = null,
    grid_carbon: ?GridCarbonTelemetryProvider = null,

    pub fn empty(self: FirstTargetTelemetrySourceRegistry) bool {
        return self.thermal == null and
            self.battery == null and
            self.accelerators == null and
            self.grid_carbon == null;
    }

    pub fn complete(self: FirstTargetTelemetrySourceRegistry) bool {
        return self.thermal != null and
            self.battery != null and
            self.accelerators != null and
            self.grid_carbon != null;
    }

    pub fn readThermal(self: FirstTargetTelemetrySourceRegistry) Error!ThermalZoneReading {
        const provider = self.thermal orelse return error.TelemetrySourceRegistryIncomplete;
        return provider.read();
    }

    pub fn readBattery(self: FirstTargetTelemetrySourceRegistry) Error!BatteryStatusReading {
        const provider = self.battery orelse return error.TelemetrySourceRegistryIncomplete;
        return provider.read();
    }

    pub fn readAccelerators(self: FirstTargetTelemetrySourceRegistry) Error!AcceleratorDriverReading {
        const provider = self.accelerators orelse return error.TelemetrySourceRegistryIncomplete;
        return provider.read();
    }

    pub fn readGridCarbonIntensity(self: FirstTargetTelemetrySourceRegistry) Error!GridCarbonReading {
        const provider = self.grid_carbon orelse return error.TelemetrySourceRegistryIncomplete;
        return provider.read();
    }
};

var installed_registry = FirstTargetTelemetrySourceRegistry{};
const RegistrySourceKind = enum(u8) {
    none,
    external,
    hardware_proof,
};
var installed_registry_source_kind: RegistrySourceKind = .none;

pub fn resetTelemetrySourceRegistry() void {
    installed_registry = .{};
    installed_registry_source_kind = .none;
}

pub fn installThermalTelemetryProvider(provider: ThermalTelemetryProvider) Error!void {
    if (!provider.complete()) return error.TelemetrySourceRegistryIncomplete;
    installed_registry.thermal = provider;
    installed_registry_source_kind = .external;
}

pub fn installBatteryTelemetryProvider(provider: BatteryTelemetryProvider) Error!void {
    if (!provider.complete()) return error.TelemetrySourceRegistryIncomplete;
    installed_registry.battery = provider;
    installed_registry_source_kind = .external;
}

pub fn installAcceleratorTelemetryProvider(provider: AcceleratorTelemetryProvider) Error!void {
    if (!provider.complete()) return error.TelemetrySourceRegistryIncomplete;
    installed_registry.accelerators = provider;
    installed_registry_source_kind = .external;
}

pub fn installGridCarbonTelemetryProvider(provider: GridCarbonTelemetryProvider) Error!void {
    if (!provider.complete()) return error.TelemetrySourceRegistryIncomplete;
    installed_registry.grid_carbon = provider;
    installed_registry_source_kind = .external;
}

pub fn installFirstTargetTelemetrySource(source: FirstTargetTelemetrySource) Error!void {
    if (!source.completeForRegistry()) return error.TelemetrySourceRegistryIncomplete;
    installed_registry = .{
        .thermal = source.thermalProvider(),
        .battery = source.batteryProvider(),
        .accelerators = source.acceleratorProvider(),
        .grid_carbon = source.gridCarbonProvider(),
    };
    installed_registry_source_kind = .external;
}

pub fn installHardwareProofTelemetryProviders() Error!void {
    try installFirstTargetTelemetrySource(hardwareProofTelemetrySource());
    installed_registry_source_kind = .hardware_proof;
}

pub fn hardwareProofTelemetrySource() FirstTargetTelemetrySource {
    return .{
        .read_thermal_fn = readHardwareProofThermal,
        .read_battery_fn = readHardwareProofBattery,
        .read_accelerators_fn = readHardwareProofAccelerators,
        .read_grid_carbon_fn = readHardwareProofGridCarbon,
    };
}

pub fn installedFirstTargetTelemetryRegistry() FirstTargetTelemetrySourceRegistry {
    return installed_registry;
}

pub fn installedFirstTargetTelemetrySource() ?FirstTargetTelemetrySource {
    if (!installed_registry.complete()) return null;
    return .{
        .read_thermal_fn = readInstalledThermal,
        .read_battery_fn = readInstalledBattery,
        .read_accelerators_fn = readInstalledAccelerators,
        .read_grid_carbon_fn = readInstalledGridCarbon,
    };
}

pub fn recordInstalledFirstTargetTelemetry(reader_generation: u32) Error!hardware_proof.ProbeFacts {
    if (installed_registry.empty()) return error.TelemetrySourceRegistryEmpty;
    if (!installed_registry.complete()) return error.TelemetrySourceRegistryIncomplete;

    const reading = FirstTargetTelemetryReading{
        .reader_generation = reader_generation,
        .thermal = try installed_registry.readThermal(),
        .battery = try installed_registry.readBattery(),
        .accelerators = try installed_registry.readAccelerators(),
        .grid_carbon = try installed_registry.readGridCarbonIntensity(),
    };
    if (installed_registry_source_kind == .hardware_proof) {
        const recorded = hardware_proof.factsSnapshot();
        if (recordedTelemetryMatches(recorded, reading)) return recorded;
    }
    return recordFirstTargetTelemetry(reading);
}

pub fn recordFirstTargetTelemetryFromSource(
    reader_generation: u32,
    source: FirstTargetTelemetrySource,
) Error!hardware_proof.ProbeFacts {
    return recordFirstTargetTelemetry(.{
        .reader_generation = reader_generation,
        .thermal = try source.readThermal(),
        .battery = try source.readBattery(),
        .accelerators = try source.readAccelerators(),
        .grid_carbon = try source.readGridCarbonIntensity(),
    });
}

fn readInstalledThermal(_: ?*anyopaque) Error!ThermalZoneReading {
    return installed_registry.readThermal();
}

fn readInstalledBattery(_: ?*anyopaque) Error!BatteryStatusReading {
    return installed_registry.readBattery();
}

fn readInstalledAccelerators(_: ?*anyopaque) Error!AcceleratorDriverReading {
    return installed_registry.readAccelerators();
}

fn readInstalledGridCarbon(_: ?*anyopaque) Error!GridCarbonReading {
    return installed_registry.readGridCarbonIntensity();
}

fn readHardwareProofThermal(_: ?*anyopaque) Error!ThermalZoneReading {
    const facts = hardware_proof.factsSnapshot();
    const thermal = facts.thermalTelemetryFacts() orelse return error.InvalidThermalZoneSample;
    return .{
        .zone_count = thermal.zone_count,
        .sample_sequence = thermal.sample_sequence,
        .thermal_milli_celsius = thermal.thermal_milli_celsius,
    };
}

fn readHardwareProofBattery(_: ?*anyopaque) Error!BatteryStatusReading {
    const facts = hardware_proof.factsSnapshot();
    const battery = facts.batteryTelemetryFacts() orelse return error.InvalidBatteryStatusSample;
    return .{
        .battery_device_count = battery.battery_device_count,
        .sample_sequence = battery.sample_sequence,
        .battery_percent = battery.battery_percent,
        .charging = battery.charging,
    };
}

fn readHardwareProofAccelerators(_: ?*anyopaque) Error!AcceleratorDriverReading {
    const facts = hardware_proof.factsSnapshot();
    const accelerators = facts.acceleratorTelemetryFacts() orelse return error.InvalidAcceleratorDriverSample;
    return .{
        .sample_sequence = accelerators.sample_sequence,
        .gpu = .{
            .online = accelerators.gpu_driver_online,
            .driver_generation = accelerators.gpu_driver_generation,
        },
        .npu = .{
            .online = accelerators.npu_driver_online,
            .driver_generation = accelerators.npu_driver_generation,
        },
        .media = .{
            .online = accelerators.media_driver_online,
            .driver_generation = accelerators.media_driver_generation,
        },
        .completion_interrupts_observed = accelerators.completion_interrupts_observed,
    };
}

fn readHardwareProofGridCarbon(_: ?*anyopaque) Error!GridCarbonReading {
    const facts = hardware_proof.factsSnapshot();
    const carbon = facts.gridCarbonTelemetryFacts() orelse return error.GridCarbonTelemetrySourceMissing;
    return .{
        .sample_sequence = carbon.sample_sequence,
        .grams_per_kwh = carbon.grams_per_kwh,
    };
}

pub fn recordFirstTargetTelemetry(reading: FirstTargetTelemetryReading) Error!hardware_proof.ProbeFacts {
    if (!hardware_proof.telemetryRecordingReady()) return error.HardwareTelemetryBaseMissing;

    const thermal = reading.thermal.toSample(reading.reader_generation);
    if (!thermal.verified()) return error.InvalidThermalZoneSample;
    const battery = reading.battery.toSample(reading.reader_generation);
    if (!battery.verified()) return error.InvalidBatteryStatusSample;
    const accelerators = reading.accelerators.toSample(reading.reader_generation);
    if (!accelerators.verified()) return error.InvalidAcceleratorDriverSample;
    const carbon = reading.grid_carbon.toSample(reading.reader_generation);
    if (!carbon.verified()) return error.InvalidGridCarbonTelemetrySample;
    if (telemetrySampleSequenceStale(hardware_proof.factsSnapshot(), reading)) return error.TelemetrySampleSequenceStale;

    hardware_proof.recordThermalZoneSample(thermal);
    hardware_proof.recordBatteryStatusSample(battery);
    hardware_proof.recordAcceleratorDriverSample(accelerators);
    hardware_proof.recordGridCarbonIntensitySample(carbon);

    const recorded = hardware_proof.factsSnapshot();
    if (!recordedTelemetryMatches(recorded, reading)) return error.HardwareTelemetryRecorderRejected;
    return recorded;
}

fn telemetrySampleSequenceStale(
    recorded: hardware_proof.ProbeFacts,
    reading: FirstTargetTelemetryReading,
) bool {
    if (recorded.telemetry_reader_generation == 0) return false;
    if (recorded.telemetry_reader_generation != reading.reader_generation) return false;
    if (recorded.thermal_sample_sequence != 0 and reading.thermal.sample_sequence <= recorded.thermal_sample_sequence) return true;
    if (recorded.battery_sample_sequence != 0 and reading.battery.sample_sequence <= recorded.battery_sample_sequence) return true;
    if (recorded.accelerator_sample_sequence != 0 and reading.accelerators.sample_sequence <= recorded.accelerator_sample_sequence) return true;
    if (recorded.grid_carbon_sample_sequence != 0 and reading.grid_carbon.sample_sequence <= recorded.grid_carbon_sample_sequence) return true;
    return false;
}

fn recordedTelemetryMatches(
    recorded: hardware_proof.ProbeFacts,
    reading: FirstTargetTelemetryReading,
) bool {
    const thermal = recorded.thermalTelemetryFacts() orelse return false;
    const battery = recorded.batteryTelemetryFacts() orelse return false;
    const accelerators = recorded.acceleratorTelemetryFacts() orelse return false;

    return recorded.telemetry_reader_generation == reading.reader_generation and
        thermal.zone_count == reading.thermal.zone_count and
        thermal.sample_sequence == reading.thermal.sample_sequence and
        thermal.thermal_milli_celsius == reading.thermal.thermal_milli_celsius and
        battery.battery_device_count == reading.battery.battery_device_count and
        battery.sample_sequence == reading.battery.sample_sequence and
        battery.battery_percent == reading.battery.battery_percent and
        battery.charging == reading.battery.charging and
        accelerators.sample_sequence == reading.accelerators.sample_sequence and
        accelerators.gpu_driver_online == reading.accelerators.gpu.online and
        accelerators.npu_driver_online == reading.accelerators.npu.online and
        accelerators.media_driver_online == reading.accelerators.media.online and
        accelerators.gpu_driver_generation == reading.accelerators.gpu.driver_generation and
        accelerators.npu_driver_generation == reading.accelerators.npu.driver_generation and
        accelerators.media_driver_generation == reading.accelerators.media.driver_generation and
        accelerators.completion_interrupts_observed == reading.accelerators.completion_interrupts_observed and
        recorded.gridCarbonTelemetryFacts() != null and
        recorded.gridCarbonTelemetryFacts().?.sample_sequence == reading.grid_carbon.sample_sequence and
        recorded.gridCarbonTelemetryFacts().?.grams_per_kwh == reading.grid_carbon.grams_per_kwh;
}

fn validReading(reader_generation: u32) FirstTargetTelemetryReading {
    return .{
        .reader_generation = reader_generation,
        .thermal = .{
            .zone_count = 2,
            .sample_sequence = 41,
            .thermal_milli_celsius = 57_000,
        },
        .battery = .{
            .battery_device_count = 1,
            .sample_sequence = 42,
            .battery_percent = 71,
            .charging = true,
        },
        .accelerators = .{
            .sample_sequence = 43,
            .gpu = .{
                .online = true,
                .driver_generation = reader_generation,
            },
            .npu = .{},
            .media = .{
                .online = true,
                .driver_generation = reader_generation,
            },
            .completion_interrupts_observed = 4,
        },
        .grid_carbon = .{
            .sample_sequence = 44,
            .grams_per_kwh = 180,
        },
    };
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

fn seedTelemetryBase() void {
    _ = hardware_proof.recordTelemetryBaseProof(.{
        .source = .real_hardware,
        .firmware = testFadtFirmware(),
        .memory_capacity_bytes = 16 * 1024 * 1024,
    });
}

const TestTelemetrySource = struct {
    thermal: ThermalZoneReading,
    battery: BatteryStatusReading,
    accelerators: AcceleratorDriverReading,
    grid_carbon: GridCarbonReading,

    fn fromReading(reading: FirstTargetTelemetryReading) TestTelemetrySource {
        return .{
            .thermal = reading.thermal,
            .battery = reading.battery,
            .accelerators = reading.accelerators,
            .grid_carbon = reading.grid_carbon,
        };
    }
};

var test_telemetry_source = TestTelemetrySource.fromReading(.{
    .reader_generation = 1,
    .thermal = .{
        .zone_count = 1,
        .sample_sequence = 1,
        .thermal_milli_celsius = 45_000,
    },
    .battery = .{
        .battery_device_count = 1,
        .sample_sequence = 1,
        .battery_percent = 100,
        .charging = true,
    },
    .accelerators = .{
        .sample_sequence = 1,
        .completion_interrupts_observed = 1,
    },
    .grid_carbon = .{
        .sample_sequence = 1,
        .grams_per_kwh = 180,
    },
});

fn testSource() FirstTargetTelemetrySource {
    return .{
        .read_thermal_fn = readTestThermal,
        .read_battery_fn = readTestBattery,
        .read_accelerators_fn = readTestAccelerators,
        .read_grid_carbon_fn = readTestGridCarbon,
    };
}

fn testThermalProvider() ThermalTelemetryProvider {
    return .{ .read_fn = readTestThermal };
}

fn testBatteryProvider() BatteryTelemetryProvider {
    return .{ .read_fn = readTestBattery };
}

fn testAcceleratorProvider() AcceleratorTelemetryProvider {
    return .{ .read_fn = readTestAccelerators };
}

fn testGridCarbonProvider() GridCarbonTelemetryProvider {
    return .{ .read_fn = readTestGridCarbon };
}

fn readTestThermal(_: ?*anyopaque) Error!ThermalZoneReading {
    return test_telemetry_source.thermal;
}

fn readTestBattery(_: ?*anyopaque) Error!BatteryStatusReading {
    return test_telemetry_source.battery;
}

fn readTestAccelerators(_: ?*anyopaque) Error!AcceleratorDriverReading {
    return test_telemetry_source.accelerators;
}

fn readTestGridCarbon(_: ?*anyopaque) Error!GridCarbonReading {
    return test_telemetry_source.grid_carbon;
}

test "first target telemetry driver rejects samples without ACPI base proof" {
    hardware_proof.resetForTest();

    try std.testing.expectError(
        error.HardwareTelemetryBaseMissing,
        recordFirstTargetTelemetry(validReading(12)),
    );
}

test "first target telemetry driver polls independent source callbacks" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(15));
    const recorded = try recordFirstTargetTelemetryFromSource(15, testSource());
    try std.testing.expectEqual(@as(u32, 15), recorded.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u64, 41), recorded.thermalTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u64, 42), recorded.batteryTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u64, 43), recorded.acceleratorTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u64, 44), recorded.gridCarbonTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u16, 180), recorded.gridCarbonTelemetryFacts().?.grams_per_kwh);
}

test "first target telemetry source callbacks fail closed when missing or malformed" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(16));
    var missing_battery = testSource();
    missing_battery.read_battery_fn = null;
    try std.testing.expectError(error.BatteryTelemetrySourceMissing, recordFirstTargetTelemetryFromSource(16, missing_battery));

    var missing_accelerator = testSource();
    missing_accelerator.read_accelerators_fn = null;
    try std.testing.expectError(error.AcceleratorTelemetrySourceMissing, recordFirstTargetTelemetryFromSource(16, missing_accelerator));

    var missing_grid = testSource();
    missing_grid.read_grid_carbon_fn = null;
    try std.testing.expectError(error.GridCarbonTelemetrySourceMissing, recordFirstTargetTelemetryFromSource(16, missing_grid));

    test_telemetry_source.thermal.sample_sequence = 0;
    try std.testing.expectError(error.InvalidThermalZoneSample, recordFirstTargetTelemetryFromSource(16, testSource()));

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(16));
    test_telemetry_source.grid_carbon.sample_sequence = 0;
    try std.testing.expectError(error.InvalidGridCarbonTelemetrySample, recordFirstTargetTelemetryFromSource(16, testSource()));

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(16));
    test_telemetry_source.grid_carbon.grams_per_kwh = hardware_proof.MAX_GRID_CARBON_INTENSITY_GRAMS_PER_KWH + 1;
    try std.testing.expectError(error.InvalidGridCarbonTelemetrySample, recordFirstTargetTelemetryFromSource(16, testSource()));
}

test "first target telemetry source registry requires complete installed sources" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    try std.testing.expectError(error.TelemetrySourceRegistryEmpty, recordInstalledFirstTargetTelemetry(17));

    var missing_grid = testSource();
    missing_grid.read_grid_carbon_fn = null;
    try std.testing.expectError(error.TelemetrySourceRegistryIncomplete, installFirstTargetTelemetrySource(missing_grid));
    try std.testing.expect(installedFirstTargetTelemetrySource() == null);

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(17));
    try installFirstTargetTelemetrySource(testSource());
    try std.testing.expect(installedFirstTargetTelemetrySource() != null);
    const recorded = try recordInstalledFirstTargetTelemetry(17);
    try std.testing.expectEqual(@as(u32, 17), recorded.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u16, 180), recorded.gridCarbonTelemetryFacts().?.grams_per_kwh);
}

test "first target telemetry source registry composes independent provider slots" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    test_telemetry_source = TestTelemetrySource.fromReading(validReading(18));
    try std.testing.expectError(error.TelemetrySourceRegistryIncomplete, installThermalTelemetryProvider(.{}));
    try installThermalTelemetryProvider(testThermalProvider());
    try installBatteryTelemetryProvider(testBatteryProvider());
    try installGridCarbonTelemetryProvider(testGridCarbonProvider());
    try std.testing.expect(!installedFirstTargetTelemetryRegistry().empty());
    try std.testing.expect(!installedFirstTargetTelemetryRegistry().complete());
    try std.testing.expect(installedFirstTargetTelemetrySource() == null);
    try std.testing.expectError(error.TelemetrySourceRegistryIncomplete, recordInstalledFirstTargetTelemetry(18));

    try installAcceleratorTelemetryProvider(testAcceleratorProvider());
    try std.testing.expect(installedFirstTargetTelemetryRegistry().complete());
    const source = installedFirstTargetTelemetrySource() orelse return error.TelemetrySourceRegistryIncomplete;
    const recorded_from_source = try recordFirstTargetTelemetryFromSource(18, source);
    try std.testing.expectEqual(@as(u32, 18), recorded_from_source.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u64, 43), recorded_from_source.acceleratorTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u16, 180), recorded_from_source.gridCarbonTelemetryFacts().?.grams_per_kwh);
}

test "first target telemetry registry installs hardware proof backed provider slots" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    try installHardwareProofTelemetryProviders();
    try std.testing.expect(installedFirstTargetTelemetryRegistry().complete());
    try std.testing.expectError(error.InvalidThermalZoneSample, recordInstalledFirstTargetTelemetry(19));

    hardware_proof.recordThermalZoneSample(.{
        .reader_generation = 19,
        .zone_count = 2,
        .sample_sequence = 51,
        .thermal_milli_celsius = 63_000,
    });
    hardware_proof.recordBatteryStatusSample(.{
        .reader_generation = 19,
        .battery_device_count = 1,
        .sample_sequence = 52,
        .battery_percent = 58,
        .charging = true,
    });
    hardware_proof.recordAcceleratorDriverSample(.{
        .reader_generation = 19,
        .sample_sequence = 53,
        .gpu_driver_online = true,
        .media_driver_online = true,
        .gpu_driver_generation = 19,
        .media_driver_generation = 19,
        .completion_interrupts_observed = 6,
    });
    try std.testing.expectError(error.GridCarbonTelemetrySourceMissing, recordInstalledFirstTargetTelemetry(19));

    hardware_proof.recordGridCarbonIntensitySample(.{
        .reader_generation = 19,
        .sample_sequence = 54,
        .grams_per_kwh = 205,
    });
    const recorded = try recordInstalledFirstTargetTelemetry(19);
    try std.testing.expectEqual(@as(u32, 19), recorded.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u32, 63_000), recorded.thermalTelemetryFacts().?.thermal_milli_celsius);
    try std.testing.expectEqual(@as(u8, 58), recorded.batteryTelemetryFacts().?.battery_percent);
    try std.testing.expect(recorded.acceleratorTelemetryFacts().?.gpu_driver_online);
    try std.testing.expect(recorded.acceleratorTelemetryFacts().?.media_driver_online);
    try std.testing.expectEqual(@as(u64, 54), recorded.gridCarbonTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u16, 205), recorded.gridCarbonTelemetryFacts().?.grams_per_kwh);
}

test "first target telemetry driver records thermal battery and accelerator proof facts" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    const recorded = try recordFirstTargetTelemetry(validReading(12));
    try std.testing.expect(recorded.thermalTelemetryFacts() != null);
    try std.testing.expect(recorded.batteryTelemetryFacts() != null);
    try std.testing.expect(recorded.acceleratorTelemetryFacts() != null);
    try std.testing.expectEqual(@as(u32, 12), recorded.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u32, 57_000), recorded.thermalTelemetryFacts().?.thermal_milli_celsius);
    try std.testing.expectEqual(@as(u8, 71), recorded.batteryTelemetryFacts().?.battery_percent);
    try std.testing.expect(recorded.acceleratorTelemetryFacts().?.gpu_driver_online);
    try std.testing.expect(!recorded.acceleratorTelemetryFacts().?.npu_driver_online);
    try std.testing.expect(recorded.acceleratorTelemetryFacts().?.media_driver_online);
}

test "first target telemetry driver fails closed on bad sensor and stale generation input" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    var overheated = validReading(13);
    overheated.thermal.thermal_milli_celsius = 126_000;
    try std.testing.expectError(error.InvalidThermalZoneSample, recordFirstTargetTelemetry(overheated));

    var missing_battery = validReading(13);
    missing_battery.battery.battery_device_count = 0;
    try std.testing.expectError(error.InvalidBatteryStatusSample, recordFirstTargetTelemetry(missing_battery));

    var missing_gpu_generation = validReading(13);
    missing_gpu_generation.accelerators.gpu.driver_generation = 0;
    try std.testing.expectError(error.InvalidAcceleratorDriverSample, recordFirstTargetTelemetry(missing_gpu_generation));

    _ = try recordFirstTargetTelemetry(validReading(13));
    try std.testing.expectError(error.HardwareTelemetryRecorderRejected, recordFirstTargetTelemetry(validReading(14)));
}

test "first target telemetry driver rejects replayed source sample sequences" {
    hardware_proof.resetForTest();
    resetTelemetrySourceRegistry();
    seedTelemetryBase();

    _ = try recordFirstTargetTelemetry(validReading(20));
    try std.testing.expectError(error.TelemetrySampleSequenceStale, recordFirstTargetTelemetry(validReading(20)));

    var partial_replay = validReading(20);
    partial_replay.thermal.sample_sequence = 45;
    partial_replay.battery.sample_sequence = 42;
    partial_replay.accelerators.sample_sequence = 46;
    partial_replay.grid_carbon.sample_sequence = 47;
    try std.testing.expectError(error.TelemetrySampleSequenceStale, recordFirstTargetTelemetry(partial_replay));

    var fresh = validReading(20);
    fresh.thermal.sample_sequence = 51;
    fresh.battery.sample_sequence = 52;
    fresh.accelerators.sample_sequence = 53;
    fresh.grid_carbon.sample_sequence = 54;
    const recorded = try recordFirstTargetTelemetry(fresh);
    try std.testing.expectEqual(@as(u64, 51), recorded.thermalTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u64, 54), recorded.gridCarbonTelemetryFacts().?.sample_sequence);
}
