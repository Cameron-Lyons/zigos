const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const capability = @import("../kernel_api/capability.zig");
const principal = @import("../core/principal.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Snapshot = struct {
    memory_capacity_bytes: usize = 512 * 1024 * 1024,
    thermal_milli_celsius: u32 = 45_000,
    battery_percent: u8 = 100,
    battery_charging: bool = true,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = true,
    media_driver_online: bool = true,
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

fn saturatingAdd(comptime T: type, value: T, amount: T) T {
    return std.math.add(T, value, amount) catch std.math.maxInt(T);
}

test "platform policy signals derive hardware scheduler telemetry from booted runtime state" {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const foreground_image = task_runtime.syntheticUserspaceImage("policy-signal-ui", "app.policy.signal-ui");
    const foreground = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .app, .serial = 91_001 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 4096,
            .resource_class = .foreground_interactive,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 91_001,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.policy.signal-ui",
        },
        .userspace_image = &foreground_image,
    });
    foreground.background_cpu_consumed_ticks = 125;
    try std.testing.expect(scheduler.registerTask(foreground.id));

    const private_image = task_runtime.syntheticUserspaceImage("policy-signal-private", "app.policy.signal-private");
    const private_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .app, .serial = 91_002 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 128 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 8192,
            .resource_class = .background_light,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 91_002,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.policy.signal-private",
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
        .memory_capacity_bytes = 512 * 1024,
        .thermal_milli_celsius = 91_000,
        .battery_percent = 12,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = false,
        .media_driver_online = true,
    });
    try std.testing.expectEqual(@as(u64, 3_000), counters.total_cpu_budget_ticks);
    try std.testing.expectEqual(@as(u64, 125), counters.consumed_cpu_ticks);
    try std.testing.expectEqual(@as(usize, 512 * 1024), counters.memory_capacity_bytes);
    try std.testing.expectEqual(@as(usize, 192 * 1024), counters.reserved_memory_bytes);
    try std.testing.expectEqual(@as(usize, 12 * 1024), counters.reserved_shared_memory_bytes);
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
        .memory_capacity_bytes = 128 * 1024,
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
