const std = @import("std");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const units = @import("../core/units.zig");

pub const Engine = enum(u8) {
    cpu,
    gpu,
    npu,
    media,
};

pub const ResourceClass = enum(u8) {
    foreground_interactive,
    background_light,
    media_export,
    batch_compute,
    emergency_system_critical,
};

pub const ThermalPressure = enum(u8) {
    nominal,
    elevated,
    critical,
};

pub const DecisionReason = enum(u8) {
    normal,
    thermal_throttle,
    battery_preserve,
    privacy_mode,
    accelerator_unavailable,
    cpu_budget,
    memory_bandwidth,
    carbon_aware_delay,
};

pub const SystemState = struct {
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
};

pub const TelemetrySource = enum(u8) {
    synthetic,
    emulator,
    boot_provider,
    hardware,
};

pub const TelemetryProviderRole = enum(u8) {
    production,
    test_only,
};

pub const TelemetryProviderDescriptor = struct {
    name: []const u8,
    role: TelemetryProviderRole,
};

pub const TelemetryProvider = struct {
    context: *anyopaque,
    descriptor: TelemetryProviderDescriptor,
    read_fn: *const fn (*anyopaque) TelemetrySample,

    pub fn init(
        comptime Provider: type,
        provider: *Provider,
        descriptor: TelemetryProviderDescriptor,
    ) TelemetryProvider {
        return .{
            .context = @ptrCast(provider),
            .descriptor = descriptor,
            .read_fn = struct {
                fn read(context: *anyopaque) TelemetrySample {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.read();
                }
            }.read,
        };
    }

    pub fn read(self: TelemetryProvider) TelemetrySample {
        return self.read_fn(self.context);
    }

    pub fn testOnly(self: TelemetryProvider) bool {
        return self.descriptor.role == .test_only;
    }
};

pub const PlatformTelemetrySignals = struct {
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
};

pub const HardwareTelemetryObservationFlags = packed struct(u8) {
    acpi_observed: bool = false,
    thermal_observed: bool = false,
    battery_observed: bool = false,
    accelerator_observed: bool = false,
    grid_carbon_observed: bool = false,
    reserved: u3 = 0,
};

pub const HardwareTelemetryEvidence = struct {
    pub const SIZE_BYTES: usize = 24;

    target_id: []const u8 = "",
    reader_generation: u32 = 0,
    observations: HardwareTelemetryObservationFlags = .{},

    pub fn complete(self: HardwareTelemetryEvidence) bool {
        return self.target_id.len != 0 and
            self.reader_generation != 0 and
            self.observations.acpi_observed and
            self.observations.thermal_observed and
            self.observations.battery_observed and
            self.observations.accelerator_observed and
            self.observations.grid_carbon_observed;
    }

    comptime {
        if (@sizeOf(@This()) != SIZE_BYTES) {
            @compileError("hardware telemetry evidence no longer matches its compact layout");
        }
    }
};

pub const LivePlatformStatusFlags = packed struct(u8) {
    gpu_driver_online: bool = true,
    npu_driver_online: bool = true,
    media_driver_online: bool = true,
    battery_charging: bool = true,
    privacy_sensitive_task_present: bool = false,
    reserved: u3 = 0,
};

pub const LivePlatformCounters = struct {
    pub const SIZE_BYTES: usize = 72;

    total_cpu_budget_ticks: u64 = std.math.maxInt(u64),
    consumed_cpu_ticks: u64 = 0,
    memory_capacity_bytes: usize = std.math.maxInt(usize),
    reserved_memory_bytes: usize = 0,
    reserved_shared_memory_bytes: usize = 0,
    thermal_milli_celsius: u32 = 45_000,
    battery_percent: u8 = 100,
    status: LivePlatformStatusFlags = .{},
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
    hardware_evidence: HardwareTelemetryEvidence = .{},

    comptime {
        if (@sizeOf(@This()) != SIZE_BYTES) {
            @compileError("live platform counters no longer match their compact layout");
        }
    }
};

pub const TelemetrySample = struct {
    pub const SIZE_BYTES: usize = 64;

    source: TelemetrySource = .synthetic,
    observed_tick: u64 = 0,
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
    hardware_evidence: HardwareTelemetryEvidence = .{},

    pub fn toSystemState(self: TelemetrySample) SystemState {
        return .{
            .thermal_pressure = self.thermal_pressure,
            .battery_saver = self.battery_saver,
            .privacy_mode = self.privacy_mode,
            .gpu_available = self.gpu_available,
            .npu_available = self.npu_available,
            .media_available = self.media_available,
            .cpu_budget_ticks = self.cpu_budget_ticks,
            .memory_bandwidth_units = self.memory_bandwidth_units,
            .grid_carbon_intensity_grams_per_kwh = self.grid_carbon_intensity_grams_per_kwh,
        };
    }

    pub fn observed(self: TelemetrySample) bool {
        return self.source != .synthetic;
    }

    pub fn hardwareReaderEvidenceComplete(self: TelemetrySample) bool {
        return self.source != .hardware or self.hardware_evidence.complete();
    }

    comptime {
        if (@sizeOf(@This()) != SIZE_BYTES) {
            @compileError("telemetry sample no longer matches its compact layout");
        }
    }
};

pub const EmulatedTelemetryDevice = struct {
    current: TelemetrySample = .{ .source = .emulator },
    read_count: u32 = 0,

    pub const telemetry_descriptor = TelemetryProviderDescriptor{
        .name = "emulated-telemetry-device",
        .role = .test_only,
    };

    pub fn init(sample: TelemetrySample) EmulatedTelemetryDevice {
        var current = sample;
        current.source = .emulator;
        return .{ .current = current };
    }

    pub fn update(self: *EmulatedTelemetryDevice, sample: TelemetrySample) void {
        var current = sample;
        current.source = .emulator;
        self.current = current;
    }

    pub fn telemetryProvider(self: *EmulatedTelemetryDevice) TelemetryProvider {
        return TelemetryProvider.init(EmulatedTelemetryDevice, self, telemetry_descriptor);
    }

    pub fn read(self: *EmulatedTelemetryDevice) TelemetrySample {
        self.read_count += 1;
        return self.current;
    }
};

pub const BootedPlatformTelemetryProvider = struct {
    boot_id: u64,
    task_id: u64 = 0,
    current: TelemetrySample = .{ .source = .boot_provider },
    read_count: u32 = 0,
    live_observation_count: u32 = 0,
    rejected_observation_count: u32 = 0,

    pub const telemetry_descriptor = TelemetryProviderDescriptor{
        .name = "booted-platform-telemetry-provider",
        .role = .production,
    };

    pub fn init(boot_id: u64, observed_tick: u64, signals: PlatformTelemetrySignals) BootedPlatformTelemetryProvider {
        return .{
            .boot_id = boot_id,
            .current = sampleFromPlatformSignals(.boot_provider, observed_tick, signals),
        };
    }

    pub fn initForBootedService(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        counters: LivePlatformCounters,
    ) TelemetryError!BootedPlatformTelemetryProvider {
        if (boot_id == 0) return error.TelemetryProviderUnauthorized;
        if (task_id == 0) return error.TelemetryProviderUnauthorized;
        return .{
            .boot_id = boot_id,
            .task_id = task_id,
            .current = sampleFromLivePlatformCounters(observed_tick, counters),
            .live_observation_count = 1,
        };
    }

    pub fn observe(self: *BootedPlatformTelemetryProvider, observed_tick: u64, signals: PlatformTelemetrySignals) TelemetryError!void {
        if (self.task_id != 0) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (observed_tick < self.current.observed_tick) {
            self.rejected_observation_count += 1;
            return error.TelemetryObservationStale;
        }
        self.current = sampleFromPlatformSignals(.boot_provider, observed_tick, signals);
    }

    pub fn observeLive(
        self: *BootedPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        counters: LivePlatformCounters,
    ) TelemetryError!void {
        if (self.task_id == 0 or caller_task_id == 0) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (self.task_id != 0 and caller_task_id != self.task_id) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (observed_tick < self.current.observed_tick) {
            self.rejected_observation_count += 1;
            return error.TelemetryObservationStale;
        }
        self.current = sampleFromLivePlatformCounters(observed_tick, counters);
        self.live_observation_count += 1;
    }

    pub fn telemetryProvider(self: *BootedPlatformTelemetryProvider) TelemetryProvider {
        return TelemetryProvider.init(BootedPlatformTelemetryProvider, self, telemetry_descriptor);
    }

    pub fn read(self: *BootedPlatformTelemetryProvider) TelemetrySample {
        self.read_count += 1;
        return self.current;
    }
};

pub const TelemetryError = error{
    TelemetryObservationStale,
    TelemetryProviderUnauthorized,
};

pub const Request = struct {
    class: ResourceClass,
    wants_gpu: bool = false,
    wants_npu: bool = false,
    wants_media_engine: bool = false,
    privacy_sensitive: bool = false,
    shared_memory_bytes: usize = 0,
    expected_cpu_ticks: u64 = 0,
    memory_bandwidth_units: usize = 0,
    estimated_energy_milliwatt_hours: u32 = 0,
    defer_for_low_carbon_power: bool = false,
};

pub const Decision = struct {
    class: ResourceClass,
    engine: Engine,
    delayed: bool,
    degraded: bool,
    zero_copy_allowed: bool,
    reason: DecisionReason,
};

pub const EngineAvailability = struct {
    gpu: bool = true,
    npu: bool = true,
    media: bool = true,

    pub fn forEngine(self: EngineAvailability, engine: Engine) bool {
        return switch (engine) {
            .cpu => true,
            .gpu => self.gpu,
            .npu => self.npu,
            .media => self.media,
        };
    }
};

/// Planning view over the latest telemetry sample. Engine claims, queues and
/// zero-copy attachments are owned by the userspace scheduler and shared-memory
/// table; this only answers which engine a request would use.
pub const Controller = struct {
    state: SystemState = .{},
    last_telemetry_source: TelemetrySource = .synthetic,
    last_telemetry_observed_tick: u64 = 0,
    last_hardware_evidence_complete: bool = false,

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, state: SystemState) void {
        self.state = state;
        self.last_telemetry_source = .synthetic;
        self.last_telemetry_observed_tick = 0;
        self.last_hardware_evidence_complete = false;
    }

    pub fn configureFromTelemetry(self: *Controller, sample: TelemetrySample) void {
        if (!telemetrySampleIsFresh(self.last_telemetry_source, self.last_telemetry_observed_tick, sample)) return;
        self.state = sample.toSystemState();
        self.last_telemetry_source = sample.source;
        self.last_telemetry_observed_tick = sample.observed_tick;
        self.last_hardware_evidence_complete = sample.hardwareReaderEvidenceComplete();
    }

    pub fn configureFromProvider(self: *Controller, provider: TelemetryProvider) void {
        self.configureFromTelemetry(provider.read());
    }

    pub fn observedTelemetry(self: *const Controller) bool {
        return self.last_telemetry_source != .synthetic;
    }

    pub fn plan(self: *const Controller, request: Request) Decision {
        return planWithState(self.state, self.availableEngines(), request);
    }

    fn availableEngines(self: *const Controller) EngineAvailability {
        // Hardware samples publish accelerators only with complete reader evidence.
        const telemetry_ready = self.last_telemetry_source != .hardware or self.last_hardware_evidence_complete;
        return .{
            .gpu = telemetry_ready and self.state.gpu_available,
            .npu = telemetry_ready and self.state.npu_available,
            .media = telemetry_ready and self.state.media_available,
        };
    }
};

pub fn planWithState(state: SystemState, availability: EngineAvailability, request: Request) Decision {
    var decision = Decision{
        .class = request.class,
        .engine = .cpu,
        .delayed = false,
        .degraded = false,
        .zero_copy_allowed = false,
        .reason = .normal,
    };

    if (request.class != .emergency_system_critical) {
        if (request.expected_cpu_ticks != 0 and request.expected_cpu_ticks > state.cpu_budget_ticks) {
            decision.delayed = true;
            decision.degraded = true;
            decision.reason = .cpu_budget;
            return decision;
        }
        if (request.memory_bandwidth_units != 0 and request.memory_bandwidth_units > state.memory_bandwidth_units) {
            decision.degraded = true;
            if (request.class == .batch_compute or request.class == .background_light) {
                decision.delayed = true;
            }
            decision.reason = .memory_bandwidth;
            return decision;
        }
    }

    switch (request.class) {
        .emergency_system_critical => return decision,
        .foreground_interactive => {
            if (request.wants_gpu and availability.forEngine(.gpu)) {
                decision.engine = .gpu;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            }
            if (state.thermal_pressure == .critical) {
                decision.degraded = true;
                decision.reason = .thermal_throttle;
            }
            return decision;
        },
        .media_export => {
            if (request.wants_media_engine and availability.forEngine(.media) and state.thermal_pressure != .critical) {
                decision.engine = .media;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            } else if (request.wants_gpu and availability.forEngine(.gpu)) {
                decision.engine = .gpu;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                decision.degraded = state.thermal_pressure != .nominal;
                if (decision.degraded) decision.reason = .thermal_throttle;
            } else {
                decision.engine = .cpu;
                decision.degraded = true;
                decision.reason = .accelerator_unavailable;
            }
            if (state.battery_saver and decision.engine != .cpu) {
                decision.degraded = true;
                decision.reason = .battery_preserve;
            }
            return decision;
        },
        .batch_compute => {
            if (state.thermal_pressure == .critical) {
                decision.delayed = true;
                decision.degraded = true;
                decision.reason = .thermal_throttle;
                return decision;
            }
            if (state.battery_saver) {
                decision.delayed = true;
                decision.degraded = true;
                decision.reason = .battery_preserve;
                return decision;
            }
        },
        .background_light => {},
    }

    if (request.wants_npu) {
        if (state.privacy_mode and request.privacy_sensitive) {
            decision.degraded = true;
            decision.reason = .privacy_mode;
            return decision;
        }
        if (availability.forEngine(.npu) and !state.battery_saver and state.thermal_pressure == .nominal) {
            decision.engine = .npu;
            decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            return decision;
        }
        decision.degraded = true;
        decision.reason = .accelerator_unavailable;
    } else if (request.wants_gpu and availability.forEngine(.gpu)) {
        decision.engine = .gpu;
        decision.zero_copy_allowed = request.shared_memory_bytes != 0;
    }

    return decision;
}

fn sampleFromPlatformSignals(source: TelemetrySource, observed_tick: u64, signals: PlatformTelemetrySignals) TelemetrySample {
    return .{
        .source = source,
        .observed_tick = observed_tick,
        .thermal_pressure = signals.thermal_pressure,
        .battery_saver = signals.battery_saver,
        .privacy_mode = signals.privacy_mode,
        .gpu_available = signals.gpu_available,
        .npu_available = signals.npu_available,
        .media_available = signals.media_available,
        .cpu_budget_ticks = signals.cpu_budget_ticks,
        .memory_bandwidth_units = signals.memory_bandwidth_units,
        .grid_carbon_intensity_grams_per_kwh = signals.grid_carbon_intensity_grams_per_kwh,
    };
}

pub fn telemetrySampleIsFresh(
    current_source: TelemetrySource,
    current_observed_tick: u64,
    sample: TelemetrySample,
) bool {
    if (sample.source == .synthetic or current_source == .synthetic) return true;
    return sample.observed_tick >= current_observed_tick;
}

fn sampleFromLivePlatformCounters(observed_tick: u64, counters: LivePlatformCounters) TelemetrySample {
    const reserved_bytes = std.math.add(usize, counters.reserved_memory_bytes, counters.reserved_shared_memory_bytes) catch std.math.maxInt(usize);
    const available_memory_bytes = counters.memory_capacity_bytes -| reserved_bytes;
    return .{
        .source = .hardware,
        .observed_tick = observed_tick,
        .thermal_pressure = thermalPressureFromMilliCelsius(counters.thermal_milli_celsius),
        .battery_saver = !counters.status.battery_charging and counters.battery_percent <= 20,
        .privacy_mode = counters.status.privacy_sensitive_task_present,
        .gpu_available = counters.status.gpu_driver_online,
        .npu_available = counters.status.npu_driver_online,
        .media_available = counters.status.media_driver_online,
        .cpu_budget_ticks = counters.total_cpu_budget_ticks -| counters.consumed_cpu_ticks,
        .memory_bandwidth_units = available_memory_bytes / units.bytes_per_kib,
        .grid_carbon_intensity_grams_per_kwh = counters.grid_carbon_intensity_grams_per_kwh,
        .hardware_evidence = counters.hardware_evidence,
    };
}

fn thermalPressureFromMilliCelsius(value: u32) ThermalPressure {
    if (value >= 90_000) return .critical;
    if (value >= 75_000) return .elevated;
    return .nominal;
}

test "accelerator scheduler preserves responsiveness while degrading opportunistic work" {
    var controller = Controller.init();
    controller.configure(.{
        .thermal_pressure = .critical,
        .battery_saver = false,
        .privacy_mode = false,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const interactive = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expect(!interactive.delayed);
    try std.testing.expectEqual(Engine.gpu, interactive.engine);
    try std.testing.expect(interactive.degraded);

    const batch = controller.plan(.{
        .class = .batch_compute,
        .wants_gpu = true,
    });
    try std.testing.expect(batch.delayed);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, batch.reason);
}

test "accelerator scheduler uses media engines and privacy mode falls back from npu" {
    var controller = Controller.init();

    const media_export_plan = controller.plan(.{
        .class = .media_export,
        .wants_gpu = true,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(16),
    });
    try std.testing.expectEqual(Engine.media, media_export_plan.engine);
    try std.testing.expect(media_export_plan.zero_copy_allowed);

    controller.configure(.{
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    const inference = controller.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    try std.testing.expectEqual(Engine.cpu, inference.engine);
    try std.testing.expect(inference.degraded);
    try std.testing.expectEqual(DecisionReason.privacy_mode, inference.reason);
}

test "accelerator scheduler uses cpu and memory bandwidth accounting signals" {
    var controller = Controller.init();
    controller.configure(.{
        .cpu_budget_ticks = 1_000,
        .memory_bandwidth_units = 200,
    });

    const over_cpu_budget = controller.plan(.{
        .class = .background_light,
        .expected_cpu_ticks = 2_000,
    });
    try std.testing.expect(over_cpu_budget.delayed);
    try std.testing.expect(over_cpu_budget.degraded);
    try std.testing.expectEqual(DecisionReason.cpu_budget, over_cpu_budget.reason);

    const memory_limited = controller.plan(.{
        .class = .batch_compute,
        .memory_bandwidth_units = 512,
    });
    try std.testing.expect(memory_limited.delayed);
    try std.testing.expect(memory_limited.degraded);
    try std.testing.expectEqual(DecisionReason.memory_bandwidth, memory_limited.reason);

    const emergency = controller.plan(.{
        .class = .emergency_system_critical,
        .expected_cpu_ticks = 10_000,
        .memory_bandwidth_units = 10_000,
    });
    try std.testing.expect(!emergency.delayed);
    try std.testing.expect(!emergency.degraded);
}

test "accelerator scheduler does not delay CPU dispatch for carbon intensity" {
    var controller = Controller.init();
    controller.configure(.{
        .grid_carbon_intensity_grams_per_kwh = 620,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const deferrable_batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(!deferrable_batch.delayed);
    try std.testing.expectEqual(Engine.npu, deferrable_batch.engine);

    const foreground = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = units.kibibytes(4),
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(!foreground.delayed);
    try std.testing.expectEqual(Engine.gpu, foreground.engine);

    controller.configure(.{
        .grid_carbon_intensity_grams_per_kwh = 200,
        .npu_available = true,
    });
    const low_carbon_batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(!low_carbon_batch.delayed);
    try std.testing.expectEqual(Engine.npu, low_carbon_batch.engine);
}

test "accelerator scheduler consumes emulator telemetry samples" {
    var controller = Controller.init();
    var telemetry = EmulatedTelemetryDevice.init(.{
        .source = .synthetic,
        .observed_tick = 42,
        .thermal_pressure = .critical,
        .battery_saver = true,
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = 500,
        .memory_bandwidth_units = 128,
        .grid_carbon_intensity_grams_per_kwh = 610,
    });
    const telemetry_provider = telemetry.telemetryProvider();
    try std.testing.expect(telemetry_provider.testOnly());
    try std.testing.expectEqual(TelemetryProviderRole.test_only, telemetry_provider.descriptor.role);
    const sample = telemetry_provider.read();
    try std.testing.expect(sample.observed());
    controller.configureFromTelemetry(sample);
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.emulator, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 42), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u16, 610), controller.state.grid_carbon_intensity_grams_per_kwh);
    try std.testing.expectEqual(@as(u32, 1), telemetry.read_count);

    const interactive = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = shared_memory.PAGE_SIZE,
    });
    try std.testing.expect(!interactive.delayed);
    try std.testing.expectEqual(Engine.gpu, interactive.engine);
    try std.testing.expect(interactive.degraded);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, interactive.reason);

    const privacy_sensitive = controller.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    try std.testing.expectEqual(Engine.cpu, privacy_sensitive.engine);
    try std.testing.expect(privacy_sensitive.degraded);
    try std.testing.expectEqual(DecisionReason.privacy_mode, privacy_sensitive.reason);

    const memory_limited = controller.plan(.{
        .class = .batch_compute,
        .memory_bandwidth_units = 256,
    });
    try std.testing.expect(memory_limited.delayed);
    try std.testing.expectEqual(DecisionReason.memory_bandwidth, memory_limited.reason);

    telemetry.update(.{
        .observed_tick = 43,
        .thermal_pressure = .nominal,
        .battery_saver = true,
        .media_available = true,
    });
    controller.configureFromProvider(telemetry.telemetryProvider());
    const media_export = controller.plan(.{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expectEqual(Engine.media, media_export.engine);
    try std.testing.expect(media_export.degraded);
    try std.testing.expectEqual(DecisionReason.battery_preserve, media_export.reason);
    try std.testing.expectEqual(@as(u64, 43), controller.last_telemetry_observed_tick);
}

test "accelerator scheduler consumes booted platform provider samples" {
    var controller = Controller.init();
    var provider = BootedPlatformTelemetryProvider.init(7, 88, .{
        .thermal_pressure = .critical,
        .battery_saver = true,
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = 1_000,
        .memory_bandwidth_units = 32,
    });

    const provider_interface = provider.telemetryProvider();
    try std.testing.expect(!provider_interface.testOnly());
    try std.testing.expectEqual(TelemetryProviderRole.production, provider_interface.descriptor.role);
    controller.configureFromProvider(provider_interface);
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.boot_provider, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 88), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u32, 1), provider.read_count);

    const foreground = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = shared_memory.PAGE_SIZE,
    });
    try std.testing.expect(!foreground.delayed);
    try std.testing.expectEqual(Engine.gpu, foreground.engine);
    try std.testing.expect(foreground.degraded);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, foreground.reason);

    const batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
    });
    try std.testing.expect(batch.delayed);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, batch.reason);

    try provider.observe(89, .{
        .thermal_pressure = .nominal,
        .battery_saver = true,
        .media_available = true,
    });
    controller.configureFromProvider(provider.telemetryProvider());
    const media_export = controller.plan(.{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expectEqual(Engine.media, media_export.engine);
    try std.testing.expect(media_export.degraded);
    try std.testing.expectEqual(DecisionReason.battery_preserve, media_export.reason);
    try std.testing.expectEqual(@as(u64, 89), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u32, 2), provider.read_count);
}

test "accelerator scheduler rejects stale production telemetry observations" {
    var provider = try BootedPlatformTelemetryProvider.initForBootedService(8, 80, 10, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .status = .{ .npu_driver_online = false },
    });

    try std.testing.expectError(error.TelemetryObservationStale, provider.observeLive(80, 9, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .status = .{
            .gpu_driver_online = false,
            .media_driver_online = false,
        },
    }));
    try std.testing.expectEqual(@as(u32, 1), provider.rejected_observation_count);
    try std.testing.expectEqual(@as(u64, 10), provider.current.observed_tick);
    try std.testing.expect(provider.current.gpu_available);
    try std.testing.expect(!provider.current.npu_available);

    try provider.observeLive(80, 11, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .status = .{
            .gpu_driver_online = false,
            .media_driver_online = false,
        },
    });
    try std.testing.expectEqual(@as(u64, 11), provider.current.observed_tick);
    try std.testing.expect(!provider.current.gpu_available);
    try std.testing.expect(provider.current.npu_available);
}

test "accelerator live platform counters stay compact" {
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(HardwareTelemetryObservationFlags));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(HardwareTelemetryEvidence));
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(LivePlatformStatusFlags));
    try std.testing.expectEqual(LivePlatformStatusFlags, @FieldType(LivePlatformCounters, "status"));
    try std.testing.expectEqual(@as(usize, 72), @sizeOf(LivePlatformCounters));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(TelemetrySample));
}

test "accelerator scheduler derives hardware telemetry from booted live counters" {
    try std.testing.expectError(error.TelemetryProviderUnauthorized, BootedPlatformTelemetryProvider.initForBootedService(0, 70, 99, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(128),
    }));
    var provider = try BootedPlatformTelemetryProvider.initForBootedService(8, 70, 100, .{
        .total_cpu_budget_ticks = 10_000,
        .consumed_cpu_ticks = 3_000,
        .memory_capacity_bytes = units.kibibytes(128),
        .reserved_memory_bytes = units.kibibytes(64),
        .reserved_shared_memory_bytes = units.kibibytes(16),
        .thermal_milli_celsius = 82_000,
        .battery_percent = 15,
        .status = .{
            .npu_driver_online = false,
            .battery_charging = false,
            .privacy_sensitive_task_present = true,
        },
        .grid_carbon_intensity_grams_per_kwh = 590,
    });
    var controller = Controller.init();
    controller.configureFromProvider(provider.telemetryProvider());
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.hardware, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 100), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(ThermalPressure.elevated, controller.state.thermal_pressure);
    try std.testing.expect(controller.state.battery_saver);
    try std.testing.expect(controller.state.privacy_mode);
    try std.testing.expect(controller.state.gpu_available);
    try std.testing.expect(!controller.state.npu_available);
    try std.testing.expect(controller.state.media_available);
    try std.testing.expectEqual(@as(u64, 7_000), controller.state.cpu_budget_ticks);
    try std.testing.expectEqual(@as(usize, 48), controller.state.memory_bandwidth_units);
    try std.testing.expectEqual(@as(u16, 590), controller.state.grid_carbon_intensity_grams_per_kwh);
    try std.testing.expectEqual(@as(u32, 1), provider.live_observation_count);
    try std.testing.expectEqual(@as(u32, 1), provider.read_count);

    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observe(101, .{
        .thermal_pressure = .critical,
        .battery_saver = true,
    }));
    try std.testing.expectEqual(@as(u32, 1), provider.rejected_observation_count);

    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observeLive(71, 101, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(128),
    }));
    try std.testing.expectEqual(@as(u32, 2), provider.rejected_observation_count);

    try provider.observeLive(70, 102, .{
        .total_cpu_budget_ticks = 10_000,
        .consumed_cpu_ticks = 2_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .reserved_memory_bytes = units.kibibytes(64),
        .thermal_milli_celsius = 91_000,
        .battery_percent = 80,
        .status = .{ .media_driver_online = false },
    });
    controller.configureFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 102), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(ThermalPressure.critical, controller.state.thermal_pressure);
    try std.testing.expect(!controller.state.battery_saver);
    try std.testing.expect(controller.state.npu_available);
    try std.testing.expect(!controller.state.media_available);
    try std.testing.expectEqual(@as(u64, 8_000), controller.state.cpu_budget_ticks);
    try std.testing.expectEqual(@as(usize, 192), controller.state.memory_bandwidth_units);
    try std.testing.expectEqual(@as(u32, 2), provider.live_observation_count);
    try std.testing.expectEqual(@as(u32, 2), provider.read_count);
}
