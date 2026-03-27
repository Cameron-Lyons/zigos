const std = @import("std");

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
};

pub const SystemState = struct {
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
};

pub const Request = struct {
    class: ResourceClass,
    wants_gpu: bool = false,
    wants_npu: bool = false,
    wants_media_engine: bool = false,
    privacy_sensitive: bool = false,
    shared_memory_bytes: usize = 0,
};

pub const Decision = struct {
    class: ResourceClass,
    engine: Engine,
    delayed: bool,
    degraded: bool,
    zero_copy_allowed: bool,
    reason: DecisionReason,
};

pub const Controller = struct {
    state: SystemState = .{},

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, state: SystemState) void {
        self.state = state;
    }

    pub fn plan(self: *const Controller, request: Request) Decision {
        var decision = Decision{
            .class = request.class,
            .engine = .cpu,
            .delayed = false,
            .degraded = false,
            .zero_copy_allowed = false,
            .reason = .normal,
        };

        switch (request.class) {
            .emergency_system_critical => return decision,
            .foreground_interactive => {
                if (request.wants_gpu and self.state.gpu_available) {
                    decision.engine = .gpu;
                    decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                }
                if (self.state.thermal_pressure == .critical) {
                    decision.degraded = true;
                    decision.reason = .thermal_throttle;
                }
                return decision;
            },
            .media_export => {
                if (request.wants_media_engine and self.state.media_available and self.state.thermal_pressure != .critical) {
                    decision.engine = .media;
                    decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                } else if (request.wants_gpu and self.state.gpu_available) {
                    decision.engine = .gpu;
                    decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                    decision.degraded = self.state.thermal_pressure != .nominal;
                    if (decision.degraded) decision.reason = .thermal_throttle;
                } else {
                    decision.engine = .cpu;
                    decision.degraded = true;
                    decision.reason = .accelerator_unavailable;
                }
                if (self.state.battery_saver and decision.engine != .cpu) {
                    decision.degraded = true;
                    decision.reason = .battery_preserve;
                }
                return decision;
            },
            .batch_compute => {
                if (self.state.thermal_pressure == .critical) {
                    decision.delayed = true;
                    decision.degraded = true;
                    decision.reason = .thermal_throttle;
                    return decision;
                }
                if (self.state.battery_saver) {
                    decision.delayed = true;
                    decision.degraded = true;
                    decision.reason = .battery_preserve;
                    return decision;
                }
            },
            .background_light => {},
        }

        if (request.wants_npu) {
            if (self.state.privacy_mode and request.privacy_sensitive) {
                decision.degraded = true;
                decision.reason = .privacy_mode;
                return decision;
            }
            if (self.state.npu_available and !self.state.battery_saver and self.state.thermal_pressure == .nominal) {
                decision.engine = .npu;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                return decision;
            }
            decision.degraded = true;
            decision.reason = .accelerator_unavailable;
        } else if (request.wants_gpu and self.state.gpu_available) {
            decision.engine = .gpu;
            decision.zero_copy_allowed = request.shared_memory_bytes != 0;
        }

        return decision;
    }
};

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
        .shared_memory_bytes = 8192,
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
        .shared_memory_bytes = 16 * 1024,
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
