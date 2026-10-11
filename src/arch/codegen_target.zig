const std = @import("std");

// Keep generated instructions within the state owned by xstate.zig. The fixed
// floor owns x87/SSE/YMM and selects the pinned compiler's hardware crypto.
pub const cpu_model = &std.Target.x86.cpu.x86_64_v3;
pub const cpu_features_string = "x86_64_v3+aes+pclmul+sha";
const crypto_features = std.Target.x86.featureSet(&.{ .aes, .pclmul, .sha });

pub fn query() std.Target.Query {
    return .{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_model = .{ .explicit = cpu_model },
        .cpu_features_add = crypto_features,
    };
}

pub fn features() std.Target.Cpu.Feature.Set {
    var result = cpu_model.features;
    result.addFeatureSet(crypto_features);
    result.populateDependencies(std.Target.x86.all_features[0..]);
    return result;
}

pub fn select(b: *std.Build) std.Build.ResolvedTarget {
    const triple = b.option([]const u8, "target", "Native target (x86_64-freestanding-none)") orelse "x86_64-freestanding-none";
    const cpu = b.option([]const u8, "cpu", "Native instruction floor (x86_64_v3+aes+pclmul+sha)") orelse cpu_features_string;
    const target_query = std.Build.parseTargetQuery(.{
        .arch_os_abi = triple,
        .cpu_features = cpu,
    }) catch @panic("invalid native target or CPU model");
    const target = b.resolveTargetQuery(target_query);
    if (!isSupported(target.result)) {
        @panic("Zigos requires x86_64-freestanding-none with -Dcpu=x86_64_v3+aes+pclmul+sha; custom CPU features need a matching extended-state contract");
    }
    return target;
}

pub fn isSupported(target: std.Target) bool {
    return target.cpu.arch == .x86_64 and target.os.tag == .freestanding and
        target.abi == .none and target.ofmt == .elf and target.cpu.model == cpu_model and
        target.cpu.features.eql(features());
}

test "native code generation uses the complete v3 crypto floor without unowned state" {
    const floor = features();
    inline for (.{ .cx16, .sahf, .popcnt, .sse3, .ssse3, .sse4_1, .sse4_2, .avx, .avx2, .fma, .f16c, .bmi, .bmi2, .movbe, .lzcnt, .xsave, .aes, .pclmul, .sha }) |feature| {
        try std.testing.expect(std.Target.x86.featureSetHas(floor, feature));
    }
    inline for (.{ .avx512f, .vaes, .vpclmulqdq, .amx_tile }) |feature| {
        try std.testing.expect(!std.Target.x86.featureSetHas(floor, feature));
    }
    try std.testing.expectEqual(@as(u64, 7), @import("xstate.zig").enabled_mask);
}

test "native target rejects weaker or independently extended CPU models" {
    var target = std.Target{
        .cpu = .{ .arch = .x86_64, .model = cpu_model, .features = features() },
        .os = .{ .tag = .freestanding, .version_range = .{ .none = {} } },
        .abi = .none,
        .ofmt = .elf,
    };
    try std.testing.expect(isSupported(target));
    target.cpu.features.addFeature(@backingInt(std.Target.x86.Feature.avx512f));
    try std.testing.expect(!isSupported(target));
    target.cpu.features = features();
    target.cpu.features.removeFeature(@backingInt(std.Target.x86.Feature.popcnt));
    try std.testing.expect(!isSupported(target));
    target.cpu.features = features();
    target.cpu.model = &std.Target.x86.cpu.x86_64;
    try std.testing.expect(!isSupported(target));
}
