//! Zero-filled heap storage for large kernel and service tables. Every target
//! uses the same path: kmalloc on freestanding, the page allocator on the host.
const builtin = @import("builtin");
const std = @import("std");

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("root").kernel_memory
else
    struct {};

pub fn alloc(comptime T: type) ?*T {
    const ptr: *T = if (comptime builtin.target.os.tag == .freestanding)
        @ptrCast(@alignCast(kernel_memory.kmalloc(@sizeOf(T)) orelse return null))
    else
        std.heap.page_allocator.create(T) catch return null;
    @memset(std.mem.asBytes(ptr), 0);
    return ptr;
}

pub fn free(comptime T: type, ptr: *T) void {
    @memset(std.mem.asBytes(ptr), 0);
    if (comptime builtin.target.os.tag == .freestanding) {
        kernel_memory.kfree(@ptrCast(ptr));
        return;
    }
    std.heap.page_allocator.destroy(ptr);
}

pub fn allocBytes(length: usize) ?[]u8 {
    if (length == 0) return &.{};
    const bytes = if (comptime builtin.target.os.tag == .freestanding)
        @as([*]u8, @ptrCast(kernel_memory.kmalloc(length) orelse return null))[0..length]
    else
        std.heap.page_allocator.alloc(u8, length) catch return null;
    @memset(bytes, 0);
    return bytes;
}

pub fn freeBytes(bytes: []u8) void {
    if (bytes.len == 0) return;
    std.crypto.secureZero(u8, bytes);
    if (comptime builtin.target.os.tag == .freestanding) {
        kernel_memory.kfree(bytes.ptr);
    } else std.heap.page_allocator.free(bytes);
}

/// One `T` allocated on first use. Its zero value is empty, so a Lazy field
/// may itself live in zero-filled storage. `initialize` runs once on the
/// zero-filled allocation for a `T` whose all-zero bytes are not empty.
pub fn Lazy(comptime T: type, comptime initialize: ?fn (*T) void) type {
    return struct {
        const Self = @This();
        pub const Target = T;
        pub const initialize_fn = initialize;

        ptr: ?*T = null,

        comptime {
            if (@sizeOf(Self) != @sizeOf(usize)) @compileError("lazy table backing must stay one pointer wide");
        }

        pub inline fn get(self: *const Self) ?*T {
            return self.ptr;
        }

        pub fn ensure(self: *Self) error{NoSpaceLeft}!*T {
            if (self.ptr) |ptr| return ptr;
            const ptr = alloc(T) orelse return error.NoSpaceLeft;
            if (initialize) |initializeFn| initializeFn(ptr);
            self.ptr = ptr;
            return ptr;
        }

        /// Scrubs and frees the storage. Owners tear down live state first.
        pub fn release(self: *Self) void {
            const ptr = self.ptr orelse return;
            self.ptr = null;
            free(T, ptr);
        }
    };
}

fn isLazy(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "Target") and @hasDecl(T, "initialize_fn") and
        T == Lazy(T.Target, T.initialize_fn);
}

fn ownsLazy(comptime T: type) bool {
    @setEvalBranchQuota(1_000_000);
    if (isLazy(T)) return true;
    return switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.field_types, info.field_attrs) |Field, attrs| {
            if (!attrs.@"comptime" and ownsLazy(Field)) break true;
        } else false,
        .@"union" => |info| inline for (info.field_types) |Field| {
            if (ownsLazy(Field)) break true;
        } else false,
        .array => |info| ownsLazy(info.child),
        .optional => |info| ownsLazy(info.child),
        else => false,
    };
}

/// Test support: the bytes of `value.*` followed by those of every table its
/// Lazy fields (and theirs, recursively) own. `std.mem.asBytes` alone covers
/// only the handles, so a failure-atomicity check must compare these instead.
pub fn deepBytes(allocator: std.mem.Allocator, value: anytype) error{OutOfMemory}![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try appendDeepBytes(allocator, &bytes, value);
    return bytes.toOwnedSlice(allocator);
}

/// Test support: fails unless `value` still has the `expected` deep bytes.
pub fn expectDeepBytes(expected: []const u8, value: anytype) !void {
    const actual = try deepBytes(std.testing.allocator, value);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

fn appendDeepBytes(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: anytype) error{OutOfMemory}!void {
    try bytes.appendSlice(allocator, std.mem.asBytes(value));
    try appendOwnedTables(allocator, bytes, @TypeOf(value.*), value);
}

fn appendOwnedTables(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), comptime T: type, value: *const T) error{OutOfMemory}!void {
    if (comptime !ownsLazy(T)) return;
    if (comptime isLazy(T)) {
        if (value.get()) |table| try appendDeepBytes(allocator, bytes, table);
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.field_names, info.field_types, info.field_attrs) |name, Field, attrs| {
            if (!attrs.@"comptime") try appendOwnedTables(allocator, bytes, Field, &@field(value.*, name));
        },
        .array => for (value) |*element| try appendOwnedTables(allocator, bytes, @TypeOf(element.*), element),
        .optional => |info| if (value.*) |*payload| try appendOwnedTables(allocator, bytes, info.child, payload),
        else => @compileError(@typeName(T) ++ " hides a lazy table where deep bytes cannot follow it"),
    }
}

test "table backing allocates and frees on the host" {
    const Slot = struct { value: u64 = 0 };
    const slot = alloc(Slot) orelse return error.OutOfMemory;
    defer free(Slot, slot);
    slot.value = 9;
    try std.testing.expectEqual(@as(u64, 9), slot.value);
}

test "lazy backing allocates once, initializes and releases" {
    const Counted = struct {
        value: u64,

        fn initialize(self: *@This()) void {
            self.value = 7;
        }
    };
    var lazy: Lazy(Counted, Counted.initialize) = .{};
    try std.testing.expect(lazy.get() == null);
    const first = try lazy.ensure();
    try std.testing.expectEqual(@as(u64, 7), first.value);
    first.value = 9;
    try std.testing.expect(try lazy.ensure() == first);
    try std.testing.expectEqual(@as(u64, 9), lazy.get().?.value);
    lazy.release();
    try std.testing.expect(lazy.get() == null);
    lazy.release();

    var records: Lazy([4]u32, null) = .{};
    defer records.release();
    try std.testing.expectEqual(@as(u32, 0), (try records.ensure())[3]);
}

test "deep bytes follow nested lazy tables" {
    const Inner = struct { value: u32 = 0 };
    const Outer = struct {
        resident: u32 = 0,
        tables: [2]?Lazy([2]Lazy(Inner, null), null) = .{ .{}, null },
    };
    var outer: Outer = .{};
    defer outer.tables[0].?.release();
    const nested = try outer.tables[0].?.ensure();
    defer for (nested) |*table| table.release();
    (try nested[1].ensure()).value = 3;

    const before = try deepBytes(std.testing.allocator, &outer);
    defer std.testing.allocator.free(before);
    try std.testing.expectEqual(@sizeOf(Outer) + @sizeOf([2]Lazy(Inner, null)) + @sizeOf(Inner), before.len);
    try expectDeepBytes(before, &outer);

    nested[1].get().?.value = 4;
    const after = try deepBytes(std.testing.allocator, &outer);
    defer std.testing.allocator.free(after);
    try std.testing.expect(!std.mem.eql(u8, before, after));
}
