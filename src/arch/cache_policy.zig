const std = @import("std");
const asm_abi = @import("asm_abi.zig");

// Native mappings have one immutable interpretation on every logical CPU.
// Admission requires the complete power-on table from firmware. Each CPU then
// programs NATIVE_PAT once, before the kernel builds any mapping that selects
// its only changed entry: an AP with paging off, the BSP through the SDM
// no-fill, WBINVD and TLB-flush sequence around its loader's live tables.
// Changing PAT after that needs an all-CPU rendezvous and stays outside this
// contract.
pub const PAT_MSR: u32 = 0x277;
pub const CPUID_PAT: u32 = 1 << 16;
pub const CR0_CD: usize = 1 << 30;
pub const CR0_NW: usize = 1 << 29;
pub const CR0_PG: usize = 1 << 31;
pub const CACHE_CONTROL_MASK = CR0_CD | CR0_NW;
pub const BOOTSTRAP_PAT: u64 = 0x0007_0406_0007_0406;
// PA4 becomes write-combining; every other entry keeps its power-on type.
pub const NATIVE_PAT: u64 = 0x0007_0401_0007_0406;

pub const CacheType = enum { write_back, uncacheable, write_combining };
pub const WRITE_BACK_SELECTOR: u64 = 0;
pub const UNCACHEABLE_SELECTOR: u64 = (1 << 4) | (1 << 3);
// A 4 KiB leaf selects PA4 with its PAT bit (bit 7) and PCD = PWT = 0.
pub const WRITE_COMBINING_SELECTOR: u64 = 1 << 7;

pub inline fn selector(cache_type: CacheType) u64 {
    return switch (cache_type) {
        .write_back => WRITE_BACK_SELECTOR,
        .uncacheable => UNCACHEABLE_SELECTOR,
        .write_combining => WRITE_COMBINING_SELECTOR,
    };
}

pub const BootstrapState = struct {
    pat_supported: bool,
    cr0: usize,
    pat: u64,
};

pub const AdmissionError = error{
    PatUnsupported,
    CacheDisabled,
    InvalidPatEncoding,
    UnsupportedPatLayout,
};

/// Firmware admission: the power-on table before this CPU programs its own.
pub inline fn validateBootstrap(state: BootstrapState) AdmissionError!void {
    return validateLayout(state, BOOTSTRAP_PAT);
}

/// Runtime admission after the entry assembly programmed the native table.
pub inline fn validateNative(state: BootstrapState) AdmissionError!void {
    return validateLayout(state, NATIVE_PAT);
}

inline fn validateLayout(state: BootstrapState, expected: u64) AdmissionError!void {
    if (!state.pat_supported) return error.PatUnsupported;
    if (state.cr0 & CACHE_CONTROL_MASK != 0) return error.CacheDisabled;
    inline for (0..8) |index| {
        const entry: u8 = @truncate(state.pat >> (index * 8));
        if (entry > 7 or entry == 2 or entry == 3) return error.InvalidPatEncoding;
    }
    if (state.pat != expected) return error.UnsupportedPatLayout;
}

pub const MAX_VARIABLE_MTRRS: usize = 32;
pub const FIXED_MTRR_MSRS = [_]u32{ 0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f };
pub const MTRR_VARIABLE_BASE_MSR: u32 = 0x200;
pub const MTRR_FIXED_SUPPORTED: u64 = 1 << 8;
pub const MTRR_WC_SUPPORTED: u64 = 1 << 10;
pub const MTRR_FIXED_ENABLED: u64 = 1 << 10;
pub const MTRR_ENABLED: u64 = 1 << 11;
pub const MTRR_VALID: u64 = 1 << 11;

pub const MemoryType = enum(u3) {
    uncacheable = 0,
    write_combining = 1,
    write_through = 4,
    write_protected = 5,
    write_back = 6,
};

pub const MtrrError = error{
    MtrrUnsupported,
    UnsupportedPhysicalAddressWidth,
    UnsupportedVariableMtrrCount,
    MtrrsDisabled,
    InvalidMtrrEncoding,
    InvalidMtrrRange,
    InvalidPhysicalRange,
    UndefinedMtrrOverlap,
    MixedMemoryTypes,
    MemoryNotWriteBack,
    UninitializedBspCachePolicy,
    ApplicationProcessorCacheMismatch,
    InvalidBootstrapMtrrSnapshot,
};

pub const VariableMtrr = extern struct { base: u64 = 0, mask: u64 = 0 };

// A read-only snapshot. All range queries validate it before interpreting any
// active entry; no caller may infer effective WB from a PAT or EFI WB bit alone.
pub const MtrrState = struct {
    physical_bits: u8 = 0,
    capabilities: u64 = 0,
    default_type: u64 = 0,
    fixed: [FIXED_MTRR_MSRS.len]u64 = @splat(0),
    variable: [MAX_VARIABLE_MTRRS]VariableMtrr = @splat(.{}),

    pub inline fn validate(self: *const MtrrState) MtrrError!void {
        if (self.physical_bits < 32 or self.physical_bits > 52) return error.UnsupportedPhysicalAddressWidth;
        if (self.variableCount() > MAX_VARIABLE_MTRRS) return error.UnsupportedVariableMtrrCount;
        if (self.default_type & ~@as(u64, 0xcff) != 0) return error.InvalidMtrrEncoding;
        _ = try self.decodeType(@truncate(self.default_type));
        if (self.default_type & MTRR_ENABLED == 0) return error.MtrrsDisabled;
        if (self.default_type & MTRR_FIXED_ENABLED != 0 and self.capabilities & MTRR_FIXED_SUPPORTED == 0)
            return error.InvalidMtrrEncoding;
        if (self.fixedEnabled()) {
            for (self.fixed) |value| {
                inline for (0..8) |byte| _ = try self.decodeType(@truncate(value >> (byte * 8)));
            }
        }
        for (self.variable[0..self.variableCount()]) |pair| {
            if (pair.mask & MTRR_VALID == 0) continue;
            var range: Range = undefined;
            try self.decodeVariableInto(pair, &range);
        }
        // Undefined overlap is unsafe even outside the particular range a
        // caller wants to map. Check the complete active union, respecting
        // fixed-range precedence and UC overrides, before admitting this CPU.
        for (self.variable[0..self.variableCount()]) |pair| {
            if (pair.mask & MTRR_VALID == 0) continue;
            var range: Range = undefined;
            try self.decodeVariableInto(pair, &range);
            var cursor = range.start;
            while (cursor < range.limit) {
                _ = try self.typeAt(cursor);
                cursor = self.boundaryAfter(cursor, range.limit);
            }
        }
    }

    // A readable disabled register is not necessarily a legal WRMSR operand.
    // AP bootstrap copies all implemented registers, so validate even operands
    // ignored by effective-type interpretation before publishing the snapshot.
    pub inline fn validateWritable(self: *const MtrrState) MtrrError!void {
        try self.validate();
        if (self.capabilities & MTRR_FIXED_SUPPORTED != 0) {
            for (self.fixed) |value| {
                inline for (0..8) |byte| _ = try self.decodeType(@truncate(value >> (byte * 8)));
            }
        }
        for (self.variable[0..self.variableCount()]) |pair| try self.validateVariableOperand(pair);
    }

    inline fn validateVariableOperand(self: *const MtrrState, pair: VariableMtrr) MtrrError!void {
        const address_mask = (self.physicalLimit() - 1) & ~@as(u64, 0xfff);
        if (pair.base & ~(address_mask | 0xff) != 0 or pair.mask & ~(address_mask | MTRR_VALID) != 0) return error.InvalidMtrrEncoding;
        _ = try self.decodeType(@truncate(pair.base));
    }

    pub inline fn variableCount(self: *const MtrrState) usize {
        return @as(u8, @truncate(self.capabilities));
    }

    pub inline fn sameConfiguration(self: *const MtrrState, other: *const MtrrState) bool {
        if (self.physical_bits != other.physical_bits or self.capabilities != other.capabilities or self.default_type != other.default_type) return false;
        if (self.variableCount() > MAX_VARIABLE_MTRRS) return false;
        if (self.capabilities & MTRR_FIXED_SUPPORTED != 0) {
            for (self.fixed, other.fixed) |left, right| if (left != right) return false;
        }
        for (self.variable[0..self.variableCount()], other.variable[0..other.variableCount()]) |left, right| {
            if (left.base != right.base or left.mask != right.mask) return false;
        }
        return true;
    }

    pub inline fn effectiveType(self: *const MtrrState, physical: u64) MtrrError!MemoryType {
        try self.validate();
        if (physical >= self.physicalLimit()) return error.InvalidPhysicalRange;
        return self.typeAt(physical);
    }

    // Returns the next possible type boundary, including fixed ranges below
    // 1MiB and every active variable start/end. Adjacent equal types may remain
    // separate; a huge-leaf builder can use uniformType for its whole candidate.
    pub inline fn nextBoundary(self: *const MtrrState, start: u64, limit: u64) MtrrError!u64 {
        try self.validate();
        if (start >= limit or limit > self.physicalLimit()) return error.InvalidPhysicalRange;
        return self.boundaryAfter(start, limit);
    }

    pub inline fn uniformType(self: *const MtrrState, start: u64, bytes: u64) MtrrError!MemoryType {
        try self.validate();
        return self.uniformTypeValidated(start, bytes);
    }

    // Only callers holding an immutable admitted state may skip whole-table
    // validation; public hostile-snapshot queries retain full validation.
    inline fn uniformTypeValidated(self: *const MtrrState, start: u64, bytes: u64) MtrrError!MemoryType {
        const limit = try self.rangeLimit(start, bytes);
        const first = try self.typeAt(start);
        var cursor = self.boundaryAfter(start, limit);
        while (cursor < limit) {
            if (try self.typeAt(cursor) != first) return error.MixedMemoryTypes;
            cursor = self.boundaryAfter(cursor, limit);
        }
        return first;
    }

    pub inline fn requireWriteBack(self: *const MtrrState, start: u64, bytes: u64) MtrrError!void {
        if (try self.uniformType(start, bytes) != .write_back) return error.MemoryNotWriteBack;
    }

    inline fn physicalLimit(self: *const MtrrState) u64 {
        return @as(u64, 1) << @as(u6, @intCast(self.physical_bits));
    }

    inline fn fixedEnabled(self: *const MtrrState) bool {
        return self.capabilities & MTRR_FIXED_SUPPORTED != 0 and self.default_type & MTRR_FIXED_ENABLED != 0;
    }

    inline fn rangeLimit(self: *const MtrrState, start: u64, bytes: u64) MtrrError!u64 {
        const limit = std.math.add(u64, start, bytes) catch return error.InvalidPhysicalRange;
        if (bytes == 0 or limit > self.physicalLimit()) return error.InvalidPhysicalRange;
        return limit;
    }

    inline fn decodeType(self: *const MtrrState, value: u8) MtrrError!MemoryType {
        const result: MemoryType = switch (value) {
            0 => .uncacheable,
            1 => .write_combining,
            4 => .write_through,
            5 => .write_protected,
            6 => .write_back,
            else => return error.InvalidMtrrEncoding,
        };
        if (result == .write_combining and self.capabilities & MTRR_WC_SUPPORTED == 0) return error.InvalidMtrrEncoding;
        return result;
    }

    const Range = struct { start: u64, limit: u64, memory_type: MemoryType };

    inline fn decodeVariableInto(self: *const MtrrState, pair: VariableMtrr, out: *Range) MtrrError!void {
        try self.validateVariableOperand(pair);
        const physical_mask = self.physicalLimit() - 1;
        const address_mask = physical_mask & ~@as(u64, 0xfff);
        const memory_type = try self.decodeType(@truncate(pair.base));
        const size = (~(pair.mask & address_mask) & physical_mask) + 1;
        const start = pair.base & address_mask;
        if (size < 4096 or !std.math.isPowerOfTwo(size) or start & (size - 1) != 0)
            return error.InvalidMtrrRange;
        out.* = .{ .start = start, .limit = start + size, .memory_type = memory_type };
    }

    inline fn fixedLocation(physical: u64) struct { register: usize, byte: u6, granule: u64 } {
        if (physical < 0x80000) return .{ .register = 0, .byte = @intCast(physical / 0x10000), .granule = 0x10000 };
        if (physical < 0xc0000) return .{ .register = 1 + @as(usize, @intCast((physical - 0x80000) / 0x20000)), .byte = @intCast((physical % 0x20000) / 0x4000), .granule = 0x4000 };
        return .{ .register = 3 + @as(usize, @intCast((physical - 0xc0000) / 0x8000)), .byte = @intCast((physical % 0x8000) / 0x1000), .granule = 0x1000 };
    }

    inline fn typeAt(self: *const MtrrState, physical: u64) MtrrError!MemoryType {
        if (self.fixedEnabled() and physical < 0x100000) {
            const location = fixedLocation(physical);
            return self.decodeType(@truncate(self.fixed[location.register] >> (location.byte * 8)));
        }
        var types: u8 = 0;
        for (self.variable[0..self.variableCount()]) |pair| {
            if (pair.mask & MTRR_VALID == 0) continue;
            var range: Range = undefined;
            try self.decodeVariableInto(pair, &range);
            if (physical >= range.start and physical < range.limit) types |= @as(u8, 1) << @backingInt(range.memory_type);
        }
        if (types == 0) return self.decodeType(@truncate(self.default_type));
        // Intel SDM12.11.4.1: UC dominates; the only other defined mixed
        // overlap is WT+WB. Evaluate the whole set so UC is order-independent.
        if (types & 1 != 0) return .uncacheable;
        if (types == (1 << 4 | 1 << 6)) return .write_through;
        if (!std.math.isPowerOfTwo(types)) return error.UndefinedMtrrOverlap;
        return self.decodeType(@intCast(@ctz(types)));
    }

    inline fn boundaryAfter(self: *const MtrrState, start: u64, limit: u64) u64 {
        var boundary = limit;
        if (self.fixedEnabled() and start < 0x100000) {
            const granule = fixedLocation(start).granule;
            boundary = @min(boundary, (start / granule + 1) * granule);
        }
        for (self.variable[0..self.variableCount()]) |pair| {
            if (pair.mask & MTRR_VALID == 0) continue;
            var range: Range = undefined;
            self.decodeVariableInto(pair, &range) catch unreachable;
            if (range.start > start) boundary = @min(boundary, range.start);
            if (range.limit > start) boundary = @min(boundary, range.limit);
        }
        return boundary;
    }
};

// A bounded query view over one validated snapshot. The owner must keep that
// snapshot alive and immutable for the lifetime of the view; initialization
// validates the complete active union once rather than once per mapped page.
pub const ValidatedMtrrView = struct {
    state: *const MtrrState,

    pub const Segment = struct { memory_type: MemoryType, next_boundary: u64 };

    pub inline fn init(state: *const MtrrState) MtrrError!ValidatedMtrrView {
        try state.validate();
        return .{ .state = state };
    }

    pub inline fn physicalLimit(self: ValidatedMtrrView) u64 {
        return self.state.physicalLimit();
    }

    pub inline fn queryInto(self: ValidatedMtrrView, start: u64, limit: u64, out: *Segment) MtrrError!void {
        if (start >= limit or limit > self.physicalLimit()) return error.InvalidPhysicalRange;
        const memory_type = try self.state.typeAt(start);
        out.* = .{ .memory_type = memory_type, .next_boundary = self.state.boundaryAfter(start, limit) };
    }

    pub inline fn effectiveType(self: ValidatedMtrrView, physical: u64) MtrrError!MemoryType {
        if (physical >= self.physicalLimit()) return error.InvalidPhysicalRange;
        return self.state.typeAt(physical);
    }

    pub inline fn nextBoundary(self: ValidatedMtrrView, start: u64, limit: u64) MtrrError!u64 {
        if (start >= limit or limit > self.physicalLimit()) return error.InvalidPhysicalRange;
        return self.state.boundaryAfter(start, limit);
    }

    pub inline fn uniformType(self: ValidatedMtrrView, start: u64, bytes: u64) MtrrError!MemoryType {
        return self.state.uniformTypeValidated(start, bytes);
    }

    pub inline fn requireWriteBack(self: ValidatedMtrrView, start: u64, bytes: u64) MtrrError!void {
        if (try self.uniformType(start, bytes) != .write_back) return error.MemoryNotWriteBack;
    }
};

// Written once by the BSP before INIT/SIPI; APs acquire it and compare every
// implemented MTRR (including disabled pairs). This is admission, not a live
// cache-policy update protocol and does not make broad huge aliases safe.
var bsp_cache_policy: struct { state: MtrrState = .{}, ready: bool = false } = .{};

pub inline fn initializeBsp(state: *const MtrrState) MtrrError!void {
    try state.validateWritable();
    if (@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) {
        if (!bsp_cache_policy.state.sameConfiguration(state)) return error.ApplicationProcessorCacheMismatch;
        return;
    }
    bsp_cache_policy.state = state.*;
    @atomicStore(bool, &bsp_cache_policy.ready, true, .release);
}

pub inline fn admitApplicationProcessor(state: *const MtrrState) MtrrError!void {
    try state.validate();
    if (!@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) return error.UninitializedBspCachePolicy;
    if (!bsp_cache_policy.state.sameConfiguration(state)) return error.ApplicationProcessorCacheMismatch;
}

// The BSP's validated width is immutable after publication. AP admission
// requires the same width; this cold authority check needs no repeated RDMSR.
pub inline fn admittedPhysicalAddressBits() ?u8 {
    if (!@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) return null;
    return bsp_cache_policy.state.physical_bits;
}

pub inline fn admittedMtrrView() MtrrError!ValidatedMtrrView {
    if (!@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) return error.UninitializedBspCachePolicy;
    return .{ .state = &bsp_cache_policy.state };
}

pub inline fn requireAdmittedWriteBack(start: u64, bytes: u64) MtrrError!void {
    if (!@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) return error.UninitializedBspCachePolicy;
    if (try bsp_cache_policy.state.uniformTypeValidated(start, bytes) != .write_back) return error.MemoryNotWriteBack;
}

// This bounded little-endian payload is appended to the existing SIPI CPU
// slot. It has no pointers and no additional assembly export. Its producer is
// the immutable, fully validated BSP policy, never a caller-provided snapshot.
pub const BOOTSTRAP_MTRR_VERSION: u32 = 1;
pub const BootstrapMtrrSnapshot = extern struct {
    version: u32,
    physical_bits: u32,
    capabilities: u64,
    default_type: u64,
    fixed: [FIXED_MTRR_MSRS.len]u64,
    variable: [MAX_VARIABLE_MTRRS]VariableMtrr,

    pub inline fn validate(self: *const BootstrapMtrrSnapshot) MtrrError!void {
        if (self.version != BOOTSTRAP_MTRR_VERSION or self.physical_bits > 255) return error.InvalidBootstrapMtrrSnapshot;
        var state: MtrrState = undefined;
        state.physical_bits = @intCast(self.physical_bits);
        state.capabilities = self.capabilities;
        state.default_type = self.default_type;
        state.fixed = self.fixed;
        state.variable = self.variable;
        try state.validateWritable();
    }
};

// cache_policy.inc and mtrr_bootstrap.inc are the assembly views of these
// controls and of the SIPI snapshot layout.
comptime {
    asm_abi.expectConstants("cache_policy.inc", @embedFile("x86_64/cache_policy.inc"), .{
        .{ "ZIGOS_CACHE_PAT_MSR", PAT_MSR },
        .{ "ZIGOS_CACHE_CPUID_PAT", CPUID_PAT },
        .{ "ZIGOS_CACHE_CONTROL_MASK", CACHE_CONTROL_MASK },
        .{ "ZIGOS_CACHE_CR0_CD", CR0_CD },
        .{ "ZIGOS_CACHE_CR0_NW", CR0_NW },
        .{ "ZIGOS_CACHE_CR0_PG", CR0_PG },
        .{ "ZIGOS_CACHE_CR4_PGE", 1 << 7 },
        .{ "ZIGOS_CACHE_PAT_LOW", @as(u32, @truncate(BOOTSTRAP_PAT)) },
        .{ "ZIGOS_CACHE_PAT_HIGH", @as(u32, @truncate(BOOTSTRAP_PAT >> 32)) },
        .{ "ZIGOS_CACHE_NATIVE_PAT_LOW", @as(u32, @truncate(NATIVE_PAT)) },
        .{ "ZIGOS_CACHE_NATIVE_PAT_HIGH", @as(u32, @truncate(NATIVE_PAT >> 32)) },
        .{ "ZIGOS_CACHE_WB_SELECTOR", WRITE_BACK_SELECTOR },
        .{ "ZIGOS_CACHE_UC_SELECTOR", UNCACHEABLE_SELECTOR },
    });
    asm_abi.expectConstants("mtrr_bootstrap.inc", @embedFile("x86_64/mtrr_bootstrap.inc"), .{
        .{ "ZIGOS_MTRR_SNAPSHOT_VERSION", BOOTSTRAP_MTRR_VERSION },
        .{ "ZIGOS_MTRR_SNAPSHOT_BYTES", @sizeOf(BootstrapMtrrSnapshot) },
        .{ "ZIGOS_MTRR_VERSION_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "version") },
        .{ "ZIGOS_MTRR_WIDTH_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "physical_bits") },
        .{ "ZIGOS_MTRR_CAP_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "capabilities") },
        .{ "ZIGOS_MTRR_DEFAULT_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "default_type") },
        .{ "ZIGOS_MTRR_FIXED_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "fixed") },
        .{ "ZIGOS_MTRR_VARIABLE_OFFSET", @offsetOf(BootstrapMtrrSnapshot, "variable") },
        .{ "ZIGOS_MTRR_MAX_VARIABLE", MAX_VARIABLE_MTRRS },
        .{ "ZIGOS_MTRR_CAP_MSR", 0xfe },
        .{ "ZIGOS_MTRR_DEFAULT_MSR", 0x2ff },
        .{ "ZIGOS_MTRR_VARIABLE_MSR", MTRR_VARIABLE_BASE_MSR },
        .{ "ZIGOS_MTRR_ENABLE", MTRR_ENABLED },
        .{ "ZIGOS_MTRR_FIXED_ENABLE", MTRR_FIXED_ENABLED },
        .{ "ZIGOS_MTRR_FIXED_SUPPORT", MTRR_FIXED_SUPPORTED },
        .{ "ZIGOS_MTRR_WC_SUPPORT", MTRR_WC_SUPPORTED },
        .{ "ZIGOS_MTRR_CPUID_SUPPORT", 1 << 12 },
    });
    if (@sizeOf(VariableMtrr) != 16 or @alignOf(BootstrapMtrrSnapshot) != 8)
        @compileError("the SIPI MTRR snapshot must keep its packed 8-byte-aligned wire layout");
}

pub inline fn copyBootstrapMtrrSnapshot(out: *BootstrapMtrrSnapshot) MtrrError!void {
    if (!@atomicLoad(bool, &bsp_cache_policy.ready, .acquire)) return error.UninitializedBspCachePolicy;
    out.version = BOOTSTRAP_MTRR_VERSION;
    out.physical_bits = bsp_cache_policy.state.physical_bits;
    out.capabilities = bsp_cache_policy.state.capabilities;
    out.default_type = bsp_cache_policy.state.default_type;
    out.fixed = bsp_cache_policy.state.fixed;
    out.variable = bsp_cache_policy.state.variable;
}

pub const CacheAdmissionError = AdmissionError || MtrrError;
const cache_errors = .{
    error.PatUnsupported,               error.CacheDisabled,                   error.InvalidPatEncoding,           error.UnsupportedPatLayout,
    error.MtrrUnsupported,              error.UnsupportedPhysicalAddressWidth, error.UnsupportedVariableMtrrCount, error.MtrrsDisabled,
    error.InvalidMtrrEncoding,          error.InvalidMtrrRange,                error.InvalidPhysicalRange,         error.UndefinedMtrrOverlap,
    error.MixedMemoryTypes,             error.MemoryNotWriteBack,              error.UninitializedBspCachePolicy,  error.ApplicationProcessorCacheMismatch,
    error.InvalidBootstrapMtrrSnapshot,
};

pub inline fn rejectionCode(err: CacheAdmissionError) u8 {
    inline for (cache_errors, 220..) |candidate, code| if (err == candidate) return code;
    unreachable;
}

pub inline fn rejectionName(code: u8) ?[]const u8 {
    inline for (cache_errors, 220..) |candidate, encoded| if (code == encoded) return @errorName(candidate);
    return null;
}

fn mtrrFixture() MtrrState {
    return .{ .physical_bits = 36, .capabilities = MTRR_WC_SUPPORTED, .default_type = MTRR_ENABLED | 6 };
}

fn variableFixture(start: u64, bytes: u64, memory_type: MemoryType) VariableMtrr {
    const physical_mask = (@as(u64, 1) << 36) - 1;
    return .{ .base = start | @backingInt(memory_type), .mask = physical_mask & ~(bytes - 1) | MTRR_VALID };
}

test "validated MTRR view retains bounded exact effective queries" {
    var state = mtrrFixture();
    state.capabilities |= 2;
    state.variable[0] = variableFixture(0x200000, 0x200000, .uncacheable);
    state.variable[1] = variableFixture(0x400000, 0x200000, .write_back);
    const view = try ValidatedMtrrView.init(&state);
    try std.testing.expectEqual(@as(u64, 1) << 36, view.physicalLimit());
    var segment: ValidatedMtrrView.Segment = undefined;
    try view.queryInto(0, 0x800000, &segment);
    try std.testing.expectEqual(ValidatedMtrrView.Segment{ .memory_type = .write_back, .next_boundary = 0x200000 }, segment);
    try view.queryInto(0x200000, 0x800000, &segment);
    try std.testing.expectEqual(ValidatedMtrrView.Segment{ .memory_type = .uncacheable, .next_boundary = 0x400000 }, segment);
    try std.testing.expectEqual(MemoryType.write_back, try view.uniformType(0x400000, 0x400000));
    try view.requireWriteBack(0x400000, 0x400000);
    try std.testing.expectError(error.MixedMemoryTypes, view.uniformType(0x100000, 0x400000));
    try std.testing.expectError(error.MemoryNotWriteBack, view.requireWriteBack(0x200000, 4096));
    const original = segment;
    try std.testing.expectError(error.InvalidPhysicalRange, view.queryInto(1, 1, &segment));
    try std.testing.expectError(error.InvalidPhysicalRange, view.queryInto(0, view.physicalLimit() + 1, &segment));
    try std.testing.expectEqual(original, segment);
    try std.testing.expectEqual(@as(u64, 0x200000), try view.nextBoundary(0, 0x800000));
    try std.testing.expectError(error.InvalidPhysicalRange, view.nextBoundary(1, 1));
    try std.testing.expectError(error.InvalidPhysicalRange, view.nextBoundary(0, view.physicalLimit() + 1));
    try std.testing.expectError(error.InvalidPhysicalRange, view.effectiveType(view.physicalLimit()));
}

test "admitted MTRR view requires publication and uses immutable BSP authority" {
    const saved = bsp_cache_policy;
    defer bsp_cache_policy = saved;
    bsp_cache_policy = .{};
    try std.testing.expectError(error.UninitializedBspCachePolicy, admittedMtrrView());
    var source = mtrrFixture();
    try initializeBsp(&source);
    const view = try admittedMtrrView();
    source.default_type = MTRR_ENABLED; // The admitted copy is independent.
    try std.testing.expectEqual(MemoryType.write_back, try view.uniformType(0, 4096));
    try std.testing.expectEqual(admittedPhysicalAddressBits().?, view.state.physical_bits);
}

test "cache rejection diagnostics retain exact bounded causes" {
    inline for (cache_errors) |err| {
        const code = rejectionCode(err);
        try std.testing.expect(code >= 220 and code < 255);
        try std.testing.expectEqualStrings(@errorName(err), rejectionName(code).?);
    }
    try std.testing.expectEqual(@as(?[]const u8, null), rejectionName(0));
    try std.testing.expectEqual(@as(?[]const u8, null), rejectionName(255));
}

test "MTRR admission rejects disabled controls and unsupported bounded state" {
    const valid = mtrrFixture();
    try valid.validate();
    var changed = valid;
    changed.default_type &= ~MTRR_ENABLED;
    try std.testing.expectError(error.MtrrsDisabled, changed.validate());
    for ([_]u8{ 0, 31, 53, 255 }) |bits| {
        changed = valid;
        changed.physical_bits = bits;
        try std.testing.expectError(error.UnsupportedPhysicalAddressWidth, changed.validate());
    }
    for ([_]u64{ 33, 255 }) |count| {
        changed = valid;
        changed.capabilities |= count;
        try std.testing.expectError(error.UnsupportedVariableMtrrCount, changed.validate());
    }
    changed = valid;
    changed.default_type |= MTRR_FIXED_ENABLED;
    try std.testing.expectError(error.InvalidMtrrEncoding, changed.validate());
    changed = valid;
    changed.default_type |= 1 << 9;
    try std.testing.expectError(error.InvalidMtrrEncoding, changed.validate());
    changed = valid;
    changed.capabilities &= ~MTRR_WC_SUPPORTED;
    changed.default_type = MTRR_ENABLED | 1;
    try std.testing.expectError(error.InvalidMtrrEncoding, changed.validate());
}

test "MTRR WB range queries reject wrapping empty and mixed spans" {
    @setEvalBranchQuota(20_000);
    var state = mtrrFixture();
    const physical_limit = @as(u64, 1) << 36;
    try state.requireWriteBack(0, physical_limit);
    try state.requireWriteBack(physical_limit - 1, 1);
    try std.testing.expectError(error.InvalidPhysicalRange, state.requireWriteBack(0, 0));
    try std.testing.expectError(error.InvalidPhysicalRange, state.requireWriteBack(physical_limit, 1));
    try std.testing.expectError(error.InvalidPhysicalRange, state.requireWriteBack(std.math.maxInt(u64) - 1, 4));
    try std.testing.expectError(error.InvalidPhysicalRange, state.nextBoundary(10, 10));
    state.capabilities |= 1;
    state.variable[0] = variableFixture(0x200000, 0x200000, .uncacheable);
    try std.testing.expectEqual(@as(u64, 0x200000), try state.nextBoundary(0x100000, 0x800000));
    try std.testing.expectEqual(@as(u64, 0x400000), try state.nextBoundary(0x200000, 0x800000));
    try state.requireWriteBack(0x400000, 0x400000);
    try std.testing.expectError(error.MemoryNotWriteBack, state.requireWriteBack(0x200000, 4096));
    try std.testing.expectError(error.MixedMemoryTypes, state.requireWriteBack(0, 0x400000));
    try std.testing.expectEqual(MemoryType.uncacheable, try state.uniformType(0x200000, 0x200000));
}

test "MTRR fixed granularities take precedence over variable ranges" {
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED | 1;
    state.default_type |= MTRR_FIXED_ENABLED;
    state.fixed = @splat(0x0606060606060606);
    state.variable[0] = variableFixture(0, 0x200000, .uncacheable);
    const examples = [_]struct { register: usize, byte: u6, start: u64, bytes: u64 }{
        .{ .register = 0, .byte = 7, .start = 0x70000, .bytes = 0x10000 },
        .{ .register = 1, .byte = 0, .start = 0x80000, .bytes = 0x4000 },
        .{ .register = 2, .byte = 7, .start = 0xbc000, .bytes = 0x4000 },
        .{ .register = 3, .byte = 0, .start = 0xc0000, .bytes = 0x1000 },
        .{ .register = 10, .byte = 7, .start = 0xff000, .bytes = 0x1000 },
    };
    for (examples) |example| {
        const original = state.fixed[example.register];
        state.fixed[example.register] = original & ~(@as(u64, 0xff) << (example.byte * 8));
        try std.testing.expectEqual(MemoryType.uncacheable, try state.effectiveType(example.start));
        try std.testing.expectEqual(example.start + example.bytes, try state.nextBoundary(example.start, 0x200000));
        state.fixed[example.register] = original;
        try state.requireWriteBack(example.start, example.bytes);
    }
    try std.testing.expectEqual(MemoryType.uncacheable, try state.effectiveType(0x100000));
    try std.testing.expectError(error.MixedMemoryTypes, state.uniformType(0, 0x200000));
}

test "MTRR every fixed byte bounds its exact granule and rejects bad encodings" {
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED;
    state.default_type |= MTRR_FIXED_ENABLED;
    state.fixed = @splat(0x0606060606060606);
    var physical: u64 = 0;
    for (0..FIXED_MTRR_MSRS.len) |register| {
        const granule: u64 = if (register == 0) 0x10000 else if (register < 3) 0x4000 else 0x1000;
        for (0..8) |byte| {
            const shift: u6 = @intCast(byte * 8);
            const original = state.fixed[register];
            state.fixed[register] = original & ~(@as(u64, 0xff) << shift);
            try std.testing.expectEqual(MemoryType.uncacheable, try state.uniformType(physical, granule));
            try std.testing.expectEqual(physical + granule, try state.nextBoundary(physical, 0x200000));
            state.fixed[register] = original & ~(@as(u64, 0xff) << shift) | @as(u64, 7) << shift;
            try std.testing.expectError(error.InvalidMtrrEncoding, state.validate());
            state.fixed[register] = original;
            physical += granule;
        }
    }
    try std.testing.expectEqual(@as(u64, 0x100000), physical);
}

test "MTRR variable decoding rejects active malformed masks and reserved fields" {
    const valid_pair = variableFixture(0x400000, 0x400000, .write_back);
    var state = mtrrFixture();
    state.capabilities |= 1;
    state.variable[0] = valid_pair;
    try state.requireWriteBack(0x400000, 0x400000);
    for ([_]VariableMtrr{
        .{ .base = valid_pair.base | 0x100, .mask = valid_pair.mask },
        .{ .base = valid_pair.base | (@as(u64, 1) << 36), .mask = valid_pair.mask },
        .{ .base = valid_pair.base, .mask = valid_pair.mask | 0x100 },
        .{ .base = valid_pair.base, .mask = valid_pair.mask | (@as(u64, 1) << 36) },
        .{ .base = valid_pair.base & ~@as(u64, 0xff) | 7, .mask = valid_pair.mask },
    }) |pair| {
        state.variable[0] = pair;
        try std.testing.expectError(error.InvalidMtrrEncoding, state.validate());
    }
    state.variable[0] = valid_pair;
    state.variable[0].mask ^= 1 << 24;
    try std.testing.expectError(error.InvalidMtrrRange, state.validate());
    state.variable[0] = valid_pair;
    state.variable[0].base ^= 1 << 12;
    try std.testing.expectError(error.InvalidMtrrRange, state.validate());
    // Disabled pairs can retain firmware/reset contents without defining a type.
    state.variable[0] = .{ .base = std.math.maxInt(u64), .mask = 0 };
    try state.requireWriteBack(0, 4096);
}

test "MTRR overlaps are evaluated as a complete order independent set" {
    var state = mtrrFixture();
    state.capabilities |= 3;
    state.variable[0] = variableFixture(0x400000, 0x400000, .write_back);
    state.variable[1] = variableFixture(0x400000, 0x400000, .write_through);
    try std.testing.expectEqual(MemoryType.write_through, try state.effectiveType(0x400000));
    state.variable[2] = variableFixture(0x400000, 0x400000, .write_combining);
    try std.testing.expectError(error.UndefinedMtrrOverlap, state.validate());
    try std.testing.expectError(error.UndefinedMtrrOverlap, state.requireWriteBack(0, 4096));
    try std.testing.expectError(error.UndefinedMtrrOverlap, state.effectiveType(0x400000));
    for (0..3) |uc_index| {
        const original = state.variable[uc_index];
        state.variable[uc_index] = variableFixture(0x400000, 0x400000, .uncacheable);
        try std.testing.expectEqual(MemoryType.uncacheable, try state.effectiveType(0x400000));
        state.variable[uc_index] = original;
    }
}

test "MTRR fixed precedence does not conceal undefined overlap beyond one MiB" {
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED | 2;
    state.default_type |= MTRR_FIXED_ENABLED;
    state.fixed = @splat(0x0606060606060606);
    state.variable[0] = variableFixture(0, 0x100000, .write_back);
    state.variable[1] = variableFixture(0, 0x100000, .write_combining);
    try state.requireWriteBack(0, 0x100000);
    state.variable[0] = variableFixture(0, 0x200000, .write_back);
    state.variable[1] = variableFixture(0, 0x200000, .write_combining);
    try std.testing.expectError(error.UndefinedMtrrOverlap, state.validate());
}

test "MTRR BSP snapshot admission compares implemented disabled pairs and fixed values" {
    const saved = bsp_cache_policy;
    defer bsp_cache_policy = saved;
    bsp_cache_policy = .{};
    try std.testing.expectEqual(@as(?u8, null), admittedPhysicalAddressBits());
    try std.testing.expectError(error.UninitializedBspCachePolicy, requireAdmittedWriteBack(0x2000000, 4096));
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED | 32;
    state.fixed = @splat(0x0606060606060606);
    try std.testing.expectError(error.UninitializedBspCachePolicy, admitApplicationProcessor(&state));
    try initializeBsp(&state);
    try std.testing.expectEqual(@as(?u8, 36), admittedPhysicalAddressBits());
    try requireAdmittedWriteBack(0x2000000, 4096);
    try std.testing.expectError(error.InvalidPhysicalRange, requireAdmittedWriteBack(@as(u64, 1) << 36, 4096));
    try admitApplicationProcessor(&state);
    for (0..MAX_VARIABLE_MTRRS) |index| {
        state.variable[index].base = 6;
        try std.testing.expectError(error.ApplicationProcessorCacheMismatch, admitApplicationProcessor(&state));
        state.variable[index].base = 0;
    }
    for (&state.fixed) |*value| {
        value.* = 0;
        try std.testing.expectError(error.ApplicationProcessorCacheMismatch, admitApplicationProcessor(&state));
        value.* = 0x0606060606060606;
    }
    state.physical_bits = 40;
    try std.testing.expectError(error.ApplicationProcessorCacheMismatch, admitApplicationProcessor(&state));
    try std.testing.expectError(error.ApplicationProcessorCacheMismatch, initializeBsp(&state));
    try std.testing.expectEqual(@as(?u8, 36), admittedPhysicalAddressBits());
}

test "cache selectors name the PAT entries the native table defines" {
    try std.testing.expectEqual(WRITE_BACK_SELECTOR, selector(.write_back));
    try std.testing.expectEqual(UNCACHEABLE_SELECTOR, selector(.uncacheable));
    try std.testing.expectEqual(WRITE_COMBINING_SELECTOR, selector(.write_combining));
    // The three leaf selector bits select entry zero, strict UC entry three and
    // write-combining entry four.
    for ([_]u64{ BOOTSTRAP_PAT, NATIVE_PAT }) |pat| {
        try std.testing.expectEqual(@as(u8, 6), @as(u8, @truncate(pat)));
        try std.testing.expectEqual(@as(u8, 0), @as(u8, @truncate(pat >> 24)));
    }
    try std.testing.expectEqual(@as(u8, 1), @as(u8, @truncate(NATIVE_PAT >> 32)));
    // Only PA4 changes, and no admitted mapping selects PA4 before programming.
    try std.testing.expectEqual(@as(u64, 0xff) << 32, BOOTSTRAP_PAT ^ NATIVE_PAT | @as(u64, 0xff) << 32);
    try std.testing.expectEqual(BOOTSTRAP_PAT & ~(@as(u64, 0xff) << 32), NATIVE_PAT & ~(@as(u64, 0xff) << 32));
}

fn expectOrderedMacro(source: []const u8, header: []const u8, ordered: []const []const u8) ![]const u8 {
    const start = std.mem.indexOf(u8, source, header) orelse return error.MissingNativePatMacro;
    const body = source[start..][0 .. std.mem.indexOf(u8, source[start..], ".endm") orelse return error.MissingNativePatMacro];
    var cursor: usize = 0;
    for (ordered) |instruction| {
        const position = std.mem.indexOf(u8, body[cursor..], instruction) orelse return error.MissingNativePatInstruction;
        cursor += position + instruction.len;
    }
    return body;
}

test "native PAT programming writes the native table and the BSP flushes caches and TLBs around it" {
    const source = @embedFile("x86_64/cache_policy.inc");
    const bare = try expectOrderedMacro(source, ".macro ZIGOS_PROGRAM_NATIVE_PAT\n", &.{ "movl $ZIGOS_CACHE_PAT_MSR, %ecx", "movl $ZIGOS_CACHE_NATIVE_PAT_LOW, %eax", "movl $ZIGOS_CACHE_NATIVE_PAT_HIGH, %edx", "wrmsr" });
    try std.testing.expect(std.mem.indexOf(u8, bare, "%cr0") == null);
    // SDM MTRR/PAT update: no-fill, WBINVD, TLB flush, write, WBINVD, TLB flush, caching.
    _ = try expectOrderedMacro(source, ".macro ZIGOS_PROGRAM_NATIVE_PAT_LIVE\n", &.{
        "movq %cr0, %r8",
        "orq $ZIGOS_CACHE_CR0_CD, %rax",
        "movq %rax, %cr0",
        "wbinvd",
        "movq %cr4, %r9",
        "xorq $ZIGOS_CACHE_CR4_PGE, %rax",
        "movq %rax, %cr4",
        "ZIGOS_PROGRAM_NATIVE_PAT\n",
        "wbinvd",
        "movq %r9, %cr4",
        "movq %r8, %cr0",
    });
    const entry = @embedFile("../boot/boot_x86_64.S");
    const admitted = std.mem.indexOf(u8, entry, "ZIGOS_REQUIRE_BOOTSTRAP_CACHE .Lcache_bsp_rejected, 64\n").?;
    try std.testing.expect(std.mem.indexOf(u8, entry[admitted..], "    ZIGOS_PROGRAM_NATIVE_PAT_LIVE\n    ZIGOS_REQUIRE_NATIVE ") != null);
    try validateNative(.{ .pat_supported = true, .cr0 = 0, .pat = NATIVE_PAT });
    try std.testing.expectError(error.UnsupportedPatLayout, validateNative(.{ .pat_supported = true, .cr0 = 0, .pat = BOOTSTRAP_PAT }));
    try std.testing.expectError(error.UnsupportedPatLayout, validateBootstrap(.{ .pat_supported = true, .cr0 = 0, .pat = NATIVE_PAT }));
    try std.testing.expectError(error.CacheDisabled, validateNative(.{ .pat_supported = true, .cr0 = CR0_CD, .pat = NATIVE_PAT }));
}

test "bootstrap cache admission rejects unsupported PAT and inherited cache controls" {
    const admitted = BootstrapState{ .pat_supported = true, .cr0 = 0x8001_0033, .pat = BOOTSTRAP_PAT };
    try validateBootstrap(admitted);
    var state = admitted;
    state.pat_supported = false;
    try std.testing.expectError(error.PatUnsupported, validateBootstrap(state));
    for ([_]usize{ CR0_CD, CR0_NW, CACHE_CONTROL_MASK }) |controls| {
        state = admitted;
        state.cr0 |= controls;
        try std.testing.expectError(error.CacheDisabled, validateBootstrap(state));
    }
}

test "bootstrap cache admission validates every PAT byte and rejects valid alternate layouts" {
    const admitted = BootstrapState{ .pat_supported = true, .cr0 = 0, .pat = BOOTSTRAP_PAT };
    for (0..8) |index| {
        const shift: u6 = @intCast(index * 8);
        const mask = @as(u64, 0xff) << shift;
        for (0..256) |encoding| {
            const entry: u8 = @intCast(encoding);
            var changed = admitted;
            changed.pat = admitted.pat & ~mask | @as(u64, entry) << shift;
            if (changed.pat == BOOTSTRAP_PAT) {
                try validateBootstrap(changed);
            } else if (entry > 7 or entry == 2 or entry == 3) {
                try std.testing.expectError(error.InvalidPatEncoding, validateBootstrap(changed));
            } else {
                try std.testing.expectError(error.UnsupportedPatLayout, validateBootstrap(changed));
            }
        }
    }
}

test "SIPI snapshot producer rejects every nonwritable disabled operand" {
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED | 1;
    // These values are ignored by effective MTRR interpretation, but writing
    // them during AP startup could fault. BSP publication rejects them first.
    for ([_]u64{ 1 << 8, 1 << 11, 1 << 36, 2, 3, 7, 255 }) |base| {
        state.variable[0].base = base;
        try state.validate();
        try std.testing.expectError(error.InvalidMtrrEncoding, state.validateWritable());
    }
    state.variable[0].base = 0;
    for ([_]u64{ 1, 1 << 10, 1 << 36, 1 << 63 }) |mask| {
        state.variable[0].mask = mask;
        try state.validate();
        try std.testing.expectError(error.InvalidMtrrEncoding, state.validateWritable());
    }
    state.variable[0].mask = 0;
    for (0..11) |index| {
        for (0..8) |byte| {
            state.fixed = @splat(0);
            state.fixed[index] = @as(u64, 2) << @as(u6, @intCast(byte * 8));
            try state.validate();
            try std.testing.expectError(error.InvalidMtrrEncoding, state.validateWritable());
        }
    }
}

test "SIPI snapshot publication requires admitted immutable policy and valid wire header" {
    const saved = bsp_cache_policy;
    defer bsp_cache_policy = saved;
    bsp_cache_policy = .{};
    var snapshot: BootstrapMtrrSnapshot = undefined;
    try std.testing.expectError(error.UninitializedBspCachePolicy, copyBootstrapMtrrSnapshot(&snapshot));
    var state = mtrrFixture();
    state.capabilities |= MTRR_FIXED_SUPPORTED | MAX_VARIABLE_MTRRS;
    state.fixed = @splat(0x0606060606060606);
    try initializeBsp(&state);
    try copyBootstrapMtrrSnapshot(&snapshot);
    try snapshot.validate();
    try std.testing.expectEqual(@as(u32, state.physical_bits), snapshot.physical_bits);
    try std.testing.expectEqual(state.capabilities, snapshot.capabilities);
    try std.testing.expectEqualSlices(u64, &state.fixed, &snapshot.fixed);
    snapshot.version = 0;
    try std.testing.expectError(error.InvalidBootstrapMtrrSnapshot, snapshot.validate());
    snapshot.version = BOOTSTRAP_MTRR_VERSION;
    snapshot.physical_bits = 256;
    try std.testing.expectError(error.InvalidBootstrapMtrrSnapshot, snapshot.validate());
    snapshot.physical_bits = state.physical_bits;
    snapshot.variable[31].base = 1 << 36;
    try std.testing.expectError(error.InvalidMtrrEncoding, snapshot.validate());
}
