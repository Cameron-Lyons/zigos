const std = @import("std");
const userspace_wire = @import("userspace_wire");

pub const MAGIC: u32 = 0x5A474F53;
pub const VERSION: u16 = 2;
pub const ELF_SECTION_NAME = ".zigos_userspace_descriptor";
pub const MAX_BUNDLE_ID_BYTES: usize = 64;
pub const MAX_DISPLAY_NAME_BYTES: usize = 48;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_ENTRY_BYTES: usize = 64;
pub const MAX_PUBLISHER_BYTES: usize = 48;

pub const Descriptor = extern struct {
    magic: u32,
    version: u16,
    component_class: u8,
    signed: u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
    bundle_id_len: u16,
    display_name_len: u16,
    label_len: u16,
    entry_len: u16,
    publisher_len: u16,
    typed_abi_major: u16,
    typed_abi_minor: u16,
    reserved: u16,
    bundle_id: [MAX_BUNDLE_ID_BYTES]u8,
    display_name: [MAX_DISPLAY_NAME_BYTES]u8,
    label: [MAX_LABEL_BYTES]u8,
    entry: [MAX_ENTRY_BYTES]u8,
    publisher: [MAX_PUBLISHER_BYTES]u8,

    pub fn bundleIdSlice(self: *const Descriptor) []const u8 {
        return self.bundle_id[0..@min(self.bundle_id_len, self.bundle_id.len)];
    }

    pub fn displayNameSlice(self: *const Descriptor) []const u8 {
        return self.display_name[0..@min(self.display_name_len, self.display_name.len)];
    }

    pub fn labelSlice(self: *const Descriptor) []const u8 {
        return self.label[0..@min(self.label_len, self.label.len)];
    }

    pub fn entrySlice(self: *const Descriptor) []const u8 {
        return self.entry[0..@min(self.entry_len, self.entry.len)];
    }

    pub fn publisherSlice(self: *const Descriptor) []const u8 {
        return self.publisher[0..@min(self.publisher_len, self.publisher.len)];
    }
};

pub const InitSpec = struct {
    component_class: u8,
    signed: bool,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
    bundle_id: []const u8,
    display_name: []const u8,
    label: []const u8,
    entry: []const u8,
    publisher: []const u8,
};

pub const ValidationError = error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidBundleIdLength,
    InvalidDisplayNameLength,
    InvalidLabelLength,
    InvalidEntryLength,
    InvalidPublisherLength,
    UnsupportedTypedAbiVersion,
};

pub const InitError = error{
    BundleIdTooLong,
    DisplayNameTooLong,
    LabelTooLong,
    EntryTooLong,
    PublisherTooLong,
};

pub fn init(spec: InitSpec) InitError!Descriptor {
    var descriptor = std.mem.zeroes(Descriptor);
    descriptor.magic = MAGIC;
    descriptor.version = VERSION;
    descriptor.component_class = spec.component_class;
    descriptor.signed = @intFromBool(spec.signed);
    descriptor.role_tag = spec.role_tag;
    descriptor.heartbeat_increment = spec.heartbeat_increment;
    descriptor.contract_flags = spec.contract_flags;
    descriptor.bundle_id_len = @intCast(userspace_wire.copyTextExact(descriptor.bundle_id[0..], spec.bundle_id) catch return error.BundleIdTooLong);
    descriptor.display_name_len = @intCast(userspace_wire.copyTextExact(descriptor.display_name[0..], spec.display_name) catch return error.DisplayNameTooLong);
    descriptor.label_len = @intCast(userspace_wire.copyTextExact(descriptor.label[0..], spec.label) catch return error.LabelTooLong);
    descriptor.entry_len = @intCast(userspace_wire.copyTextExact(descriptor.entry[0..], spec.entry) catch return error.EntryTooLong);
    descriptor.publisher_len = @intCast(userspace_wire.copyTextExact(descriptor.publisher[0..], spec.publisher) catch return error.PublisherTooLong);
    descriptor.typed_abi_major = 1;
    descriptor.typed_abi_minor = 0;
    return descriptor;
}

pub fn initComptime(comptime spec: InitSpec) Descriptor {
    return init(spec) catch |err| switch (err) {
        error.BundleIdTooLong => @compileError("userspace descriptor bundle id exceeds MAX_BUNDLE_ID_BYTES"),
        error.DisplayNameTooLong => @compileError("userspace descriptor display name exceeds MAX_DISPLAY_NAME_BYTES"),
        error.LabelTooLong => @compileError("userspace descriptor label exceeds MAX_LABEL_BYTES"),
        error.EntryTooLong => @compileError("userspace descriptor entry exceeds MAX_ENTRY_BYTES"),
        error.PublisherTooLong => @compileError("userspace descriptor publisher exceeds MAX_PUBLISHER_BYTES"),
    };
}

pub fn validate(descriptor: *const Descriptor) ValidationError!void {
    if (descriptor.magic != MAGIC) return error.InvalidMagic;
    if (descriptor.version != VERSION) return error.UnsupportedVersion;
    if (descriptor.bundle_id_len > descriptor.bundle_id.len) return error.InvalidBundleIdLength;
    if (descriptor.display_name_len > descriptor.display_name.len) return error.InvalidDisplayNameLength;
    if (descriptor.label_len > descriptor.label.len) return error.InvalidLabelLength;
    if (descriptor.entry_len > descriptor.entry.len) return error.InvalidEntryLength;
    if (descriptor.publisher_len > descriptor.publisher.len) return error.InvalidPublisherLength;
    if (descriptor.typed_abi_major != 1) return error.UnsupportedTypedAbiVersion;
}

test "descriptor init and validate preserve the embedded metadata" {
    const descriptor = try init(.{
        .component_class = 2,
        .signed = true,
        .role_tag = 0xA101,
        .heartbeat_increment = 1,
        .contract_flags = 0x3,
        .bundle_id = "zigos.system.session-manager",
        .display_name = "Session Manager",
        .label = "session-manager",
        .entry = "zigos.session.manager",
        .publisher = "zigos.system",
    });

    try validate(&descriptor);
    try std.testing.expectEqual(@as(u8, 2), descriptor.component_class);
    try std.testing.expectEqual(@as(u32, 0xA101), descriptor.role_tag);
    try std.testing.expectEqual(@as(u32, 1), descriptor.heartbeat_increment);
    try std.testing.expectEqual(@as(u32, 0x3), descriptor.contract_flags);
    try std.testing.expectEqual(@as(u16, 1), descriptor.typed_abi_major);
    try std.testing.expectEqual(@as(u16, 0), descriptor.typed_abi_minor);
    try std.testing.expectEqualStrings("zigos.system.session-manager", descriptor.bundleIdSlice());
    try std.testing.expectEqualStrings("Session Manager", descriptor.displayNameSlice());
    try std.testing.expectEqualStrings("session-manager", descriptor.labelSlice());
    try std.testing.expectEqualStrings("zigos.session.manager", descriptor.entrySlice());
    try std.testing.expectEqualStrings("zigos.system", descriptor.publisherSlice());
}

test "descriptor init rejects oversized identity strings instead of truncating" {
    const oversized_bundle_id = [_]u8{'b'} ** (MAX_BUNDLE_ID_BYTES + 1);
    const oversized_display_name = [_]u8{'d'} ** (MAX_DISPLAY_NAME_BYTES + 1);
    const oversized_label = [_]u8{'l'} ** (MAX_LABEL_BYTES + 1);
    const oversized_entry = [_]u8{'e'} ** (MAX_ENTRY_BYTES + 1);
    const oversized_publisher = [_]u8{'p'} ** (MAX_PUBLISHER_BYTES + 1);

    const base = InitSpec{
        .component_class = 2,
        .signed = true,
        .role_tag = 0xA101,
        .heartbeat_increment = 1,
        .contract_flags = 0x3,
        .bundle_id = "zigos.system.session-manager",
        .display_name = "Session Manager",
        .label = "session-manager",
        .entry = "zigos.session.manager",
        .publisher = "zigos.system",
    };

    var spec = base;
    spec.bundle_id = oversized_bundle_id[0..];
    try std.testing.expectError(error.BundleIdTooLong, init(spec));

    spec = base;
    spec.display_name = oversized_display_name[0..];
    try std.testing.expectError(error.DisplayNameTooLong, init(spec));

    spec = base;
    spec.label = oversized_label[0..];
    try std.testing.expectError(error.LabelTooLong, init(spec));

    spec = base;
    spec.entry = oversized_entry[0..];
    try std.testing.expectError(error.EntryTooLong, init(spec));

    spec = base;
    spec.publisher = oversized_publisher[0..];
    try std.testing.expectError(error.PublisherTooLong, init(spec));
}
