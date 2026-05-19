const std = @import("std");

const abi = @import("../../native/core/abi.zig");
const crypto_hash = @import("../../native/core/crypto_hash.zig");
const fixed_table = @import("../../native/core/fixed_table.zig");
const ids = @import("../../native/core/ids.zig");
const indexed_arena = @import("../../native/core/indexed_arena.zig");
const native_smoke_markers = @import("../../native_smoke_markers.zig");
const native_util = @import("../../native/core/util.zig");
const principal = @import("../../native/core/principal.zig");
const request_header = @import("../../native/core/request_header.zig");
const signing = @import("../../native/core/signing.zig");

test "core host tests import native core modules" {
    std.testing.refAllDecls(abi);
    std.testing.refAllDecls(crypto_hash);
    std.testing.refAllDecls(fixed_table);
    std.testing.refAllDecls(ids);
    std.testing.refAllDecls(indexed_arena);
    std.testing.refAllDecls(native_smoke_markers);
    std.testing.refAllDecls(native_util);
    std.testing.refAllDecls(principal);
    std.testing.refAllDecls(request_header);
    std.testing.refAllDecls(signing);
}
