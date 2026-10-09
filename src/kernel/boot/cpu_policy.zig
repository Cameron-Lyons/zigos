const std = @import("std");
const cpu_features = @import("../../arch/cpu_features.zig");
const baseline = cpu_features.baseline;

pub const QEMU_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;

// The fixed emulator clock belongs to the same explicit model request as its
// software CPU mode. Architectural frequency always takes precedence.
pub const ModelRequest = struct {
    model_inventory: bool = false,
    software_cpu_fallback: bool = false,
    tsc_frequency_hz: ?u64 = null,

    pub fn enabled(self: ModelRequest) bool {
        return self.model_inventory and self.software_cpu_fallback and
            self.tsc_frequency_hz == QEMU_TSC_FREQUENCY_HZ;
    }

    pub fn resolveTscFrequency(self: ModelRequest, architectural_frequency_hz: u64) u64 {
        if (architectural_frequency_hz != 0) return architectural_frequency_hz;
        if (self.enabled()) {
            return QEMU_TSC_FREQUENCY_HZ;
        }
        return 0;
    }
};

// Capture the BSP's authorization and selected controls once, before resolving
// its clock. Every AP is admitted against its own architectural features using
// this same value; neither a missing AP feature nor an AP clock authorizes a
// model fallback.
pub const AdmissionPolicy = struct {
    model_request: ModelRequest,
    process_context_mode: cpu_features.ProcessContextMode,
    cet_mode: cpu_features.CetMode,
    hardware_tsc_timer: bool,
    hardware_lass: bool,
    hardware_fred: bool,
    tsc_frequency_hz: u64,

    pub fn init(raw_features: baseline.Features, model_request: ModelRequest) AdmissionPolicy {
        const model_enabled = model_request.enabled();
        return .{
            .model_request = model_request,
            // Hardware admission keeps these modes mandatory even when the
            // BSP lacks a component, preserving the precise missing feature.
            .process_context_mode = if (!model_enabled or (raw_features.pcid and raw_features.invpcid)) .hardware_pcid else .software_flush,
            .cet_mode = if (!model_enabled or (raw_features.cet_ibt and raw_features.cet_ss)) .hardware else .deferred,
            .hardware_tsc_timer = raw_features.tsc_deadline and raw_features.invariant_tsc,
            .hardware_lass = raw_features.lass,
            .hardware_fred = raw_features.fred and raw_features.lkgs,
            .tsc_frequency_hz = model_request.resolveTscFrequency(raw_features.tsc_frequency_hz),
        };
    }

    pub fn featureMode(self: AdmissionPolicy) cpu_features.FeatureMode {
        return if (self.model_request.enabled()) .explicit_model else .hardware;
    }

    pub fn resolveFeatures(self: AdmissionPolicy, raw_features: baseline.Features) baseline.Features {
        var resolved = raw_features;
        resolved.tsc_frequency_hz = self.model_request.resolveTscFrequency(raw_features.tsc_frequency_hz);
        return resolved;
    }

    pub fn firstMissing(self: AdmissionPolicy, raw_features: baseline.Features) ?baseline.MissingFeature {
        const resolved = self.resolveFeatures(raw_features);
        if (cpu_features.firstMissingForEnablement(resolved, self.process_context_mode, self.cet_mode, self.featureMode())) |missing| {
            return missing;
        }
        // Explicit model authority may waive unavailable controls on the BSP,
        // but cannot downgrade controls the BSP selected for all CPUs.
        if (self.hardware_lass and !resolved.lass) return .lass;
        if (self.hardware_fred) {
            if (!resolved.fred) return .fred;
            if (!resolved.lkgs) return .lkgs;
        }
        if (self.hardware_tsc_timer and (!resolved.tsc_deadline or !resolved.invariant_tsc)) return .tsc;
        // Clock conversions and deadlines share one BSP-selected frequency.
        // Honor an AP's advertised frequency, then reject incompatible clocks.
        if (resolved.tsc_frequency_hz != self.tsc_frequency_hz) return .tsc;
        return null;
    }
};

test "fixed model clock requires the complete explicit software CPU request" {
    for (0..8) |flags| {
        const request = ModelRequest{
            .model_inventory = flags & 1 != 0,
            .software_cpu_fallback = flags & 2 != 0,
            .tsc_frequency_hz = if (flags & 4 != 0) QEMU_TSC_FREQUENCY_HZ else null,
        };
        try std.testing.expectEqual(flags == 7, request.enabled());
        try std.testing.expectEqual(
            @as(u64, if (flags == 7) QEMU_TSC_FREQUENCY_HZ else 0),
            request.resolveTscFrequency(0),
        );
    }
}

test "normal boot frequency override cannot authorize the model clock" {
    const request = ModelRequest{
        .model_inventory = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    };
    try std.testing.expect(!request.enabled());
    try std.testing.expectEqual(@as(u64, 0), request.resolveTscFrequency(0));
}

test "explicit model clock rejects missing and arbitrary frequencies" {
    for ([_]?u64{ null, 0, 1, QEMU_TSC_FREQUENCY_HZ - 1, QEMU_TSC_FREQUENCY_HZ + 1, std.math.maxInt(u64) }) |frequency| {
        const request = ModelRequest{
            .model_inventory = true,
            .software_cpu_fallback = true,
            .tsc_frequency_hz = frequency,
        };
        try std.testing.expect(!request.enabled());
        try std.testing.expectEqual(@as(u64, 0), request.resolveTscFrequency(0));
    }
}

test "architectural TSC frequency wins over every model clock request" {
    for (0..8) |flags| {
        const request = ModelRequest{
            .model_inventory = flags & 1 != 0,
            .software_cpu_fallback = flags & 2 != 0,
            .tsc_frequency_hz = if (flags & 4 != 0) QEMU_TSC_FREQUENCY_HZ else null,
        };
        try std.testing.expectEqual(@as(u64, 3_200_000_000), request.resolveTscFrequency(3_200_000_000));
    }
}

test "admission captures complete model authority before selecting software controls" {
    var features = baseline.completeFeatures();
    features.pcid = false;
    features.invpcid = false;
    features.cet_ibt = false;
    features.cet_ss = false;
    features.lass = false;
    features.fred = false;
    features.lkgs = false;
    features.tsc_deadline = false;
    features.invariant_tsc = false;
    features.tsc_frequency_hz = 0;
    for (0..8) |flags| {
        const request = ModelRequest{
            .model_inventory = flags & 1 != 0,
            .software_cpu_fallback = flags & 2 != 0,
            .tsc_frequency_hz = if (flags & 4 != 0) QEMU_TSC_FREQUENCY_HZ else null,
        };
        const policy = AdmissionPolicy.init(features, request);
        try std.testing.expectEqualDeep(request, policy.model_request);
        try std.testing.expectEqual(
            @as(cpu_features.FeatureMode, if (flags == 7) .explicit_model else .hardware),
            policy.featureMode(),
        );
        try std.testing.expectEqual(
            @as(cpu_features.ProcessContextMode, if (flags == 7) .software_flush else .hardware_pcid),
            policy.process_context_mode,
        );
        try std.testing.expectEqual(
            @as(cpu_features.CetMode, if (flags == 7) .deferred else .hardware),
            policy.cet_mode,
        );
        try std.testing.expectEqual(
            @as(?baseline.MissingFeature, if (flags == 7) null else .pcid),
            policy.firstMissing(features),
        );
        try std.testing.expectEqual(
            @as(u64, if (flags == 7) QEMU_TSC_FREQUENCY_HZ else 0),
            policy.tsc_frequency_hz,
        );
        try std.testing.expect(!policy.hardware_lass);
        try std.testing.expect(!policy.hardware_fred);
        try std.testing.expect(!policy.hardware_tsc_timer);
        var expected = features;
        expected.tsc_frequency_hz = policy.tsc_frequency_hz;
        try std.testing.expectEqualDeep(expected, policy.resolveFeatures(features));
    }
}

test "hardware BSP and AP admission share the complete mandatory feature floor" {
    const complete = baseline.completeFeatures();
    const policy = AdmissionPolicy.init(complete, .{});
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), policy.firstMissing(complete));
    inline for ([_]baseline.MissingFeature{ .cpuid, .sse2, .long_mode, .sse3, .ssse3, .sse4_1, .sse4_2, .popcnt, .cx16, .lahf_sahf, .avx, .avx2, .f16c, .fma, .movbe, .bmi1, .bmi2, .lzcnt, .aes, .pclmul, .sha, .ymm_state, .syscall, .nx, .smep, .smap, .umip, .pge, .pcid, .invpcid, .x2apic, .xsave, .xsaves, .cet_ibt, .cet_ss, .lass, .fred, .lkgs, .pages_1g, .rdseed, .rdpid }) |required| {
        var missing = complete;
        @field(missing, @tagName(required)) = false;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, required), policy.firstMissing(missing));
        const missing_bsp_policy = AdmissionPolicy.init(missing, .{});
        try std.testing.expectEqual(@as(?baseline.MissingFeature, required), missing_bsp_policy.firstMissing(missing));
    }
    inline for (.{ "tsc_deadline", "invariant_tsc", "tsc_frequency_hz" }) |field| {
        var missing = complete;
        @field(missing, field) = if (@TypeOf(@field(missing, field)) == bool) false else 0;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), policy.firstMissing(missing));
        const missing_bsp_policy = AdmissionPolicy.init(missing, .{});
        try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), missing_bsp_policy.firstMissing(missing));
    }
}

test "explicit model APs retain every real compiler and native instruction requirement" {
    const complete = baseline.completeFeatures();
    const policy = AdmissionPolicy.init(complete, .{
        .model_inventory = true,
        .software_cpu_fallback = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    });
    inline for ([_]baseline.MissingFeature{ .cpuid, .sse2, .long_mode, .sse3, .ssse3, .sse4_1, .sse4_2, .popcnt, .cx16, .lahf_sahf, .avx, .avx2, .f16c, .fma, .movbe, .bmi1, .bmi2, .lzcnt, .aes, .pclmul, .sha, .ymm_state, .syscall, .nx, .smep, .smap, .umip, .pge, .x2apic, .xsave, .xsaves, .pages_1g, .rdseed, .rdpid }) |required| {
        var missing = complete;
        @field(missing, @tagName(required)) = false;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, required), policy.firstMissing(missing));
    }
}

test "model authority cannot downgrade BSP selected AP hardware controls" {
    const complete = baseline.completeFeatures();
    const policy = AdmissionPolicy.init(complete, .{
        .model_inventory = true,
        .software_cpu_fallback = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    });
    try std.testing.expectEqual(cpu_features.ProcessContextMode.hardware_pcid, policy.process_context_mode);
    try std.testing.expectEqual(cpu_features.CetMode.hardware, policy.cet_mode);
    try std.testing.expect(policy.hardware_lass and policy.hardware_fred and policy.hardware_tsc_timer);
    inline for ([_]baseline.MissingFeature{ .pcid, .invpcid, .cet_ibt, .cet_ss, .lass, .fred, .lkgs }) |required| {
        var missing = complete;
        @field(missing, @tagName(required)) = false;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, required), policy.firstMissing(missing));
    }
    inline for (.{ "tsc_deadline", "invariant_tsc" }) |field| {
        var missing = complete;
        @field(missing, field) = false;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), policy.firstMissing(missing));
    }
}

test "model software process context does not waive BSP selected CET LASS FRED or timer" {
    var bsp = baseline.completeFeatures();
    bsp.invpcid = false;
    const policy = AdmissionPolicy.init(bsp, .{
        .model_inventory = true,
        .software_cpu_fallback = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    });
    try std.testing.expectEqual(cpu_features.ProcessContextMode.software_flush, policy.process_context_mode);
    try std.testing.expectEqual(cpu_features.CetMode.hardware, policy.cet_mode);
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), policy.firstMissing(bsp));
    inline for ([_]baseline.MissingFeature{ .cet_ibt, .cet_ss, .lass, .fred, .lkgs }) |required| {
        var ap = bsp;
        @field(ap, @tagName(required)) = false;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, required), policy.firstMissing(ap));
    }
    var ap = bsp;
    ap.tsc_deadline = false;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), policy.firstMissing(ap));
}

test "AP architectural TSC frequency is preserved and must match the BSP clock" {
    const request = ModelRequest{
        .model_inventory = true,
        .software_cpu_fallback = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    };
    var bsp = baseline.completeFeatures();
    bsp.tsc_frequency_hz = 3_200_000_000;
    const policy = AdmissionPolicy.init(bsp, request);
    try std.testing.expectEqual(@as(u64, 3_200_000_000), policy.tsc_frequency_hz);
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), policy.firstMissing(bsp));
    for ([_]u64{ 0, QEMU_TSC_FREQUENCY_HZ, 3_000_000_000 }) |frequency| {
        var ap = bsp;
        ap.tsc_frequency_hz = frequency;
        try std.testing.expectEqual(
            @as(u64, if (frequency == 0) QEMU_TSC_FREQUENCY_HZ else frequency),
            policy.resolveFeatures(ap).tsc_frequency_hz,
        );
        try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), policy.firstMissing(ap));
    }
    bsp.tsc_frequency_hz = 0;
    const model_clock_policy = AdmissionPolicy.init(bsp, request);
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), model_clock_policy.firstMissing(bsp));
    bsp.tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), model_clock_policy.firstMissing(bsp));
    bsp.tsc_frequency_hz = 3_200_000_000;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), model_clock_policy.firstMissing(bsp));
    const hardware_policy = AdmissionPolicy.init(bsp, .{});
    bsp.tsc_frequency_hz = 0;
    try std.testing.expectEqual(@as(u64, 0), hardware_policy.resolveFeatures(bsp).tsc_frequency_hz);
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), hardware_policy.firstMissing(bsp));
}

test "admission does not fabricate or require optional PKU" {
    var features = baseline.completeFeatures();
    features.pku = false;
    for ([_]ModelRequest{ .{}, .{
        .model_inventory = true,
        .software_cpu_fallback = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    } }) |request| {
        const policy = AdmissionPolicy.init(features, request);
        try std.testing.expectEqual(@as(?baseline.MissingFeature, null), policy.firstMissing(features));
        try std.testing.expect(!policy.resolveFeatures(features).pku);
    }
}
