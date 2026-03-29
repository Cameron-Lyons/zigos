const std = @import("std");

pub const MAGIC: u32 = 0x5A474F53;
pub const VERSION: u16 = 1;
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
    bundle_id_len: u16,
    display_name_len: u16,
    label_len: u16,
    entry_len: u16,
    publisher_len: u16,
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
};

pub fn init(spec: InitSpec) Descriptor {
    var descriptor = std.mem.zeroes(Descriptor);
    descriptor.magic = MAGIC;
    descriptor.version = VERSION;
    descriptor.component_class = spec.component_class;
    descriptor.signed = @intFromBool(spec.signed);
    descriptor.bundle_id_len = copyTruncated(descriptor.bundle_id[0..], spec.bundle_id);
    descriptor.display_name_len = copyTruncated(descriptor.display_name[0..], spec.display_name);
    descriptor.label_len = copyTruncated(descriptor.label[0..], spec.label);
    descriptor.entry_len = copyTruncated(descriptor.entry[0..], spec.entry);
    descriptor.publisher_len = copyTruncated(descriptor.publisher[0..], spec.publisher);
    return descriptor;
}

pub fn validate(descriptor: *const Descriptor) ValidationError!void {
    if (descriptor.magic != MAGIC) return error.InvalidMagic;
    if (descriptor.version != VERSION) return error.UnsupportedVersion;
    if (descriptor.bundle_id_len > descriptor.bundle_id.len) return error.InvalidBundleIdLength;
    if (descriptor.display_name_len > descriptor.display_name.len) return error.InvalidDisplayNameLength;
    if (descriptor.label_len > descriptor.label.len) return error.InvalidLabelLength;
    if (descriptor.entry_len > descriptor.entry.len) return error.InvalidEntryLength;
    if (descriptor.publisher_len > descriptor.publisher.len) return error.InvalidPublisherLength;
}

fn copyTruncated(buffer: []u8, source: []const u8) u16 {
    const len = @min(buffer.len, source.len);
    @memcpy(buffer[0..len], source[0..len]);
    return @intCast(len);
}

test "descriptor init and validate preserve the embedded metadata" {
    const descriptor = init(.{
        .component_class = 2,
        .signed = true,
        .bundle_id = "zigos.system.session-manager",
        .display_name = "Session Manager",
        .label = "session-manager",
        .entry = "zigos.session.manager",
        .publisher = "zigos.system",
    });

    try validate(&descriptor);
    try std.testing.expectEqual(@as(u8, 2), descriptor.component_class);
    try std.testing.expectEqualStrings("zigos.system.session-manager", descriptor.bundleIdSlice());
    try std.testing.expectEqualStrings("Session Manager", descriptor.displayNameSlice());
    try std.testing.expectEqualStrings("session-manager", descriptor.labelSlice());
    try std.testing.expectEqualStrings("zigos.session.manager", descriptor.entrySlice());
    try std.testing.expectEqualStrings("zigos.system", descriptor.publisherSlice());
}
