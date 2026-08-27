const std = @import("std");

const cpu_baseline = @import("../../arch/cpu_baseline.zig");
const firmware_memory_map = @import("../../kernel/memory/firmware_memory_map.zig");
const frame_allocator = @import("../../kernel/memory/frame_allocator.zig");
const heap_geometry = @import("../../kernel/memory/heap_geometry.zig");
const page_table64 = @import("../../kernel/memory/page_table64.zig");
const virtual_layout = @import("../../kernel/memory/virtual_layout.zig");
const tsc_deadline = @import("../../kernel/timer/tsc_deadline.zig");
const abi = @import("../../native/core/abi.zig");
const crypto_hash = @import("../../native/core/crypto_hash.zig");
const ids = @import("../../native/core/ids.zig");
const indexed_arena = @import("../../native/core/indexed_arena.zig");
const native_smoke_markers = @import("../../native_smoke_markers.zig");
const native_util = @import("../../native/core/util.zig");
const principal = @import("../../native/core/principal.zig");
const request_header = @import("../../native/core/request_header.zig");
const signing = @import("../../native/core/signing.zig");

test "core host tests import native core modules" {
    std.testing.refAllDecls(cpu_baseline);
    std.testing.refAllDecls(firmware_memory_map);
    std.testing.refAllDecls(frame_allocator);
    std.testing.refAllDecls(heap_geometry);
    std.testing.refAllDecls(page_table64);
    std.testing.refAllDecls(virtual_layout);
    std.testing.refAllDecls(tsc_deadline);
    std.testing.refAllDecls(abi);
    std.testing.refAllDecls(crypto_hash);
    std.testing.refAllDecls(ids);
    std.testing.refAllDecls(indexed_arena);
    std.testing.refAllDecls(native_smoke_markers);
    std.testing.refAllDecls(native_util);
    std.testing.refAllDecls(principal);
    std.testing.refAllDecls(request_header);
    std.testing.refAllDecls(signing);
}
