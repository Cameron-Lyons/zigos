const std = @import("std");
const manifest = @import("../../policy/manifest.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");

const DATABASE_CONTRACT_MESSAGE_BUFFER_BYTES: usize = 160;

pub fn signatureEql(a: manifest.Signature, b: manifest.Signature) bool {
    return std.mem.eql(u8, a.format, b.format) and
        std.mem.eql(u8, a.signer, b.signer) and
        a.public_key_len == b.public_key_len and
        std.mem.eql(u8, a.publicKeySlice(), b.publicKeySlice()) and
        a.value_len == b.value_len and
        std.mem.eql(u8, a.valueSlice(), b.valueSlice());
}

pub fn databaseBundleIdFromPath(path: []const u8) ?[]const u8 {
    const prefix = "databases/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const remainder = path[prefix.len..];
    const separator = std.mem.indexOfScalar(u8, remainder, '/') orelse return null;
    if (separator == 0) return null;
    return remainder[0..separator];
}

pub fn validateDatabaseContractSignature(contract: *const state_support.DatabaseContract) state_support.Error!void {
    var message_buffer: [DATABASE_CONTRACT_MESSAGE_BUFFER_BYTES]u8 = undefined;
    const message = state_support.databaseContractMessage(
        &message_buffer,
        contract.workspace_id,
        contract.bundleIdSlice(),
        contract.labelSlice(),
    ) catch return error.InvalidContractSignature;
    if (!signing.verify(contract.signature, message)) return error.InvalidContractSignature;
}
