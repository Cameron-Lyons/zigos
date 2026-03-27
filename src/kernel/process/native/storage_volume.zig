const std = @import("std");
const object_store = @import("object_store.zig");
const principal = @import("principal.zig");
const workspace = @import("workspace.zig");

pub const sector_size: usize = 512;
pub const slot_sectors: u32 = 384;
pub const slot_count: u32 = 2;
pub const header_sectors: u32 = 1;
pub const payload_sectors: u32 = slot_sectors - header_sectors;
pub const slot_bytes: usize = slot_sectors * sector_size;
pub const image_bytes: usize = slot_count * slot_bytes;
pub const max_payload_bytes: usize = payload_sectors * sector_size;
pub const required_device_sectors: u64 = slot_count * slot_sectors;
pub const max_signer_bytes: usize = 48;

const volume_magic = "ZG4VOL1";
const payload_magic = "ZG4STATE";
const format_version: u16 = 1;

pub const Error = error{
    ChecksumMismatch,
    CorruptImage,
    ImageTooSmall,
    InvalidSignatureEncoding,
    NoSpaceLeft,
    UnsupportedVersion,
};

pub const PersistResult = struct {
    generation: u64,
};

pub const Backend = struct {
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer: []u8) bool,
    write: *const fn (start_lba: u64, buffer: []const u8) bool,
};

var io_payload_buffer: [max_payload_bytes]u8 = undefined;
var sector_buffer: [sector_size]u8 = [_]u8{0} ** sector_size;
var attached_backend: ?Backend = null;
var version_signers: [object_store.MAX_VERSIONS][max_signer_bytes]u8 =
    [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** object_store.MAX_VERSIONS;
var snapshot_signers: [workspace.MAX_SNAPSHOTS][max_signer_bytes]u8 =
    [_][max_signer_bytes]u8{[_]u8{0} ** max_signer_bytes} ** workspace.MAX_SNAPSHOTS;

const CursorWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn writeByte(self: *CursorWriter, value: u8) Error!void {
        if (self.offset >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn writeBytes(self: *CursorWriter, bytes: []const u8) Error!void {
        if (self.offset + bytes.len > self.buffer.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeU16(self: *CursorWriter, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU32(self: *CursorWriter, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU64(self: *CursorWriter, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

const CursorReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn readByte(self: *CursorReader) Error!u8 {
        if (self.offset >= self.buffer.len) return error.CorruptImage;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    fn readBytes(self: *CursorReader, dest: []u8) Error!void {
        if (self.offset + dest.len > self.buffer.len) return error.CorruptImage;
        @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
        self.offset += dest.len;
    }

    fn readSlice(self: *CursorReader, len: usize) Error![]const u8 {
        if (self.offset + len > self.buffer.len) return error.CorruptImage;
        const slice = self.buffer[self.offset .. self.offset + len];
        self.offset += len;
        return slice;
    }

    fn readU16(self: *CursorReader) Error!u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u16, &bytes, .little);
    }

    fn readU32(self: *CursorReader) Error!u32 {
        var bytes: [4]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    fn readU64(self: *CursorReader) Error!u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};

const SlotHeader = struct {
    generation: u64,
    payload_len: u32,
    checksum: u64,
};

pub fn attachBackend(backend: Backend) void {
    attached_backend = backend;
}

pub fn clearAttachedBackend() void {
    attached_backend = null;
}

pub fn hasAttachedDevice() bool {
    return attached_backend != null;
}

pub fn clearAttachedVolume() void {
    if (!hasAttachedDevice()) return;
    const backend = attached_backend.?;
    if (backend.sector_count < required_device_sectors) return;
    @memset(sector_buffer[0..], 0);
    var slot_index: u32 = 0;
    while (slot_index < slot_count) : (slot_index += 1) {
        const header_lba = slotBaseLba(slot_index);
        if (!backend.write(header_lba, sector_buffer[0..])) return;
    }
}

pub fn loadFromVolume(store: *object_store.Store, workspaces: *workspace.Directory) bool {
    if (!hasAttachedDevice()) return false;
    const backend = attached_backend.?;
    if (backend.sector_count < required_device_sectors) return false;

    const candidate = (findLatestBackendSlot(backend) catch return false) orelse return false;
    const payload = readBackendPayload(backend, candidate.slot_index, candidate.header.payload_len) catch return false;
    deserializeState(store, workspaces, payload) catch return false;
    return true;
}

pub fn saveToVolume(store: *const object_store.Store, workspaces: *const workspace.Directory) !PersistResult {
    if (!hasAttachedDevice()) return .{ .generation = 0 };
    const backend = attached_backend.?;
    if (backend.sector_count < required_device_sectors) return error.ImageTooSmall;

    const current = findLatestBackendSlot(backend) catch null;
    const payload_len = try serializeState(store, workspaces, io_payload_buffer[0..]);
    const next_slot_index: u32 = if (current) |slot| (slot.slot_index + 1) % slot_count else 0;
    const generation: u64 = if (current) |slot| slot.header.generation + 1 else 1;
    const checksum = checksumBytes(io_payload_buffer[0..payload_len]);

    try writeBackendPayload(backend, next_slot_index, io_payload_buffer[0..payload_len]);
    try writeBackendHeader(backend, next_slot_index, .{
        .generation = generation,
        .payload_len = @intCast(payload_len),
        .checksum = checksum,
    });

    return .{ .generation = generation };
}

pub fn saveToImage(image: []u8, store: *const object_store.Store, workspaces: *const workspace.Directory) !PersistResult {
    if (image.len < image_bytes) return error.ImageTooSmall;
    const current = findLatestImageSlot(image) catch null;
    const payload_len = try serializeState(store, workspaces, io_payload_buffer[0..]);
    const next_slot_index: u32 = if (current) |slot| (slot.slot_index + 1) % slot_count else 0;
    const generation: u64 = if (current) |slot| slot.header.generation + 1 else 1;
    const checksum = checksumBytes(io_payload_buffer[0..payload_len]);

    try writeImagePayload(image, next_slot_index, io_payload_buffer[0..payload_len]);
    try writeImageHeader(image, next_slot_index, .{
        .generation = generation,
        .payload_len = @intCast(payload_len),
        .checksum = checksum,
    });

    return .{ .generation = generation };
}

pub fn loadFromImage(image: []const u8, store: *object_store.Store, workspaces: *workspace.Directory) !u64 {
    if (image.len < image_bytes) return error.ImageTooSmall;
    const candidate = (try findLatestImageSlot(image)) orelse return error.CorruptImage;
    const payload = try readImagePayload(image, candidate.slot_index, candidate.header.payload_len, io_payload_buffer[0..]);
    try deserializeState(store, workspaces, payload);
    return candidate.header.generation;
}

fn serializeState(store: *const object_store.Store, workspaces: *const workspace.Directory, buffer: []u8) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(payload_magic);
    try writer.writeU16(format_version);
    try writer.writeU64(store.next_object_id);
    try writer.writeU64(store.next_version_id);
    try writer.writeU16(@intCast(store.objectCount()));
    try writer.writeU16(@intCast(store.versionCount()));
    try writer.writeU64(workspaces.next_workspace_id);
    try writer.writeU64(workspaces.next_snapshot_id);
    try writer.writeU16(@intCast(workspaceCount(workspaces)));
    try writer.writeU16(@intCast(snapshotCount(workspaces)));

    for (store.objects) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.object.id);
        try writer.writeByte(@intFromEnum(slot.object.object_type));
        try writer.writeU64(slot.object.latest_version_id);
        try writer.writeU16(slot.object.version_count);
    }

    for (store.versions) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.version.id);
        try writer.writeU64(slot.version.object_id);
        try writer.writeU64(slot.version.previous_version_id);
        try writer.writeByte(@intFromEnum(slot.version.object_type));
        try writer.writeBytes(&slot.version.address);
        try writeMetadata(&writer, slot.version.metadata);
        try writer.writeU16(@intCast(slot.version.payload_len));
        try writer.writeBytes(slot.version.payloadSlice());
    }

    for (workspaces.workspaces) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.workspace.id);
        try writePrincipal(&writer, slot.workspace.owner);
        try writeText(&writer, slot.workspace.labelSlice());
        try writer.writeU32(slot.workspace.generation);
        try writer.writeU16(@intCast(slot.workspace.entry_count));
        for (slot.workspace.entries[0..slot.workspace.entry_count]) |entry| {
            try writeEntry(&writer, entry);
        }
        try writer.writeU16(@intCast(slot.workspace.share_grant_count));
        for (slot.workspace.share_grants[0..slot.workspace.share_grant_count]) |grant| {
            try writeShareGrant(&writer, grant);
        }
        try writer.writeU16(@intCast(slot.workspace.deleted_count));
        for (slot.workspace.deleted_entries[0..slot.workspace.deleted_count]) |entry| {
            try writeEntry(&writer, entry);
        }
    }

    for (workspaces.snapshots) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.snapshot.id);
        try writer.writeU64(slot.snapshot.workspace_id);
        try writer.writeU32(slot.snapshot.generation);
        try writeText(&writer, slot.snapshot.labelSlice());
        try writeSignature(&writer, slot.snapshot.signature);
        try writer.writeU16(@intCast(slot.snapshot.entry_count));
        for (slot.snapshot.entries[0..slot.snapshot.entry_count]) |entry| {
            try writeEntry(&writer, entry);
        }
    }

    return writer.offset;
}

fn deserializeState(store: *object_store.Store, workspaces: *workspace.Directory, payload: []const u8) Error!void {
    store.reset();
    workspaces.reset();

    var reader = CursorReader{ .buffer = payload };
    var payload_magic_bytes: [payload_magic.len]u8 = undefined;
    try reader.readBytes(&payload_magic_bytes);
    if (!std.mem.eql(u8, &payload_magic_bytes, payload_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != format_version) return error.UnsupportedVersion;

    store.next_object_id = try reader.readU64();
    store.next_version_id = try reader.readU64();
    const object_count = try reader.readU16();
    const version_count = try reader.readU16();
    workspaces.next_workspace_id = try reader.readU64();
    workspaces.next_snapshot_id = try reader.readU64();
    const workspace_count_value = try reader.readU16();
    const snapshot_count_value = try reader.readU16();

    if (object_count > object_store.MAX_OBJECTS or
        version_count > object_store.MAX_VERSIONS or
        workspace_count_value > workspace.MAX_WORKSPACES or
        snapshot_count_value > workspace.MAX_SNAPSHOTS)
    {
        return error.CorruptImage;
    }

    for (0..@as(usize, object_count)) |_| {
        const slot = nextObjectSlot(store) orelse return error.CorruptImage;
        slot.in_use = true;
        slot.object.id = try reader.readU64();
        slot.object.object_type = @enumFromInt(try reader.readByte());
        slot.object.latest_version_id = try reader.readU64();
        slot.object.version_count = try reader.readU16();
    }

    for (0..@as(usize, version_count)) |_| {
        const slot_index = nextVersionSlotIndex(store) orelse return error.CorruptImage;
        store.versions[slot_index].in_use = true;
        store.versions[slot_index].version.id = try reader.readU64();
        store.versions[slot_index].version.object_id = try reader.readU64();
        store.versions[slot_index].version.previous_version_id = try reader.readU64();
        store.versions[slot_index].version.object_type = @enumFromInt(try reader.readByte());
        try reader.readBytes(&store.versions[slot_index].version.address);
        store.versions[slot_index].version.metadata = try readMetadata(&reader, &version_signers[slot_index]);
        store.versions[slot_index].version.payload_len = @intCast(try reader.readU16());
        if (store.versions[slot_index].version.payload_len > object_store.MAX_PAYLOAD_BYTES) return error.CorruptImage;
        @memset(store.versions[slot_index].version.payload[0..], 0);
        try reader.readBytes(store.versions[slot_index].version.payload[0..store.versions[slot_index].version.payload_len]);
    }

    for (0..@as(usize, workspace_count_value)) |_| {
        const slot = nextWorkspaceSlot(workspaces) orelse return error.CorruptImage;
        slot.in_use = true;
        slot.workspace = zeroWorkspaceRecord();
        slot.workspace.id = try reader.readU64();
        slot.workspace.owner = try readPrincipal(&reader);
        readTextInto(&reader, &slot.workspace.label, &slot.workspace.label_len) catch return error.CorruptImage;
        slot.workspace.generation = try reader.readU32();
        slot.workspace.entry_count = @intCast(try reader.readU16());
        if (slot.workspace.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
        for (0..slot.workspace.entry_count) |entry_index| {
            slot.workspace.entries[entry_index] = try readEntry(&reader);
        }
        slot.workspace.share_grant_count = @intCast(try reader.readU16());
        if (slot.workspace.share_grant_count > workspace.MAX_SHARE_GRANTS) return error.CorruptImage;
        for (0..slot.workspace.share_grant_count) |grant_index| {
            slot.workspace.share_grants[grant_index] = try readShareGrant(&reader);
        }
        slot.workspace.deleted_count = @intCast(try reader.readU16());
        if (slot.workspace.deleted_count > workspace.MAX_RECOVERABLE_DELETES) return error.CorruptImage;
        for (0..slot.workspace.deleted_count) |entry_index| {
            slot.workspace.deleted_entries[entry_index] = try readEntry(&reader);
        }
    }

    for (0..@as(usize, snapshot_count_value)) |_| {
        const slot_index = nextSnapshotSlotIndex(workspaces) orelse return error.CorruptImage;
        workspaces.snapshots[slot_index].in_use = true;
        workspaces.snapshots[slot_index].snapshot = zeroSnapshotRecord();
        workspaces.snapshots[slot_index].snapshot.id = try reader.readU64();
        workspaces.snapshots[slot_index].snapshot.workspace_id = try reader.readU64();
        workspaces.snapshots[slot_index].snapshot.generation = try reader.readU32();
        readTextInto(&reader, &workspaces.snapshots[slot_index].snapshot.label, &workspaces.snapshots[slot_index].snapshot.label_len) catch return error.CorruptImage;
        workspaces.snapshots[slot_index].snapshot.signature = try readSignature(&reader, &snapshot_signers[slot_index]);
        workspaces.snapshots[slot_index].snapshot.entry_count = @intCast(try reader.readU16());
        if (workspaces.snapshots[slot_index].snapshot.entry_count > workspace.MAX_WORKSPACE_ENTRIES) return error.CorruptImage;
        for (0..workspaces.snapshots[slot_index].snapshot.entry_count) |entry_index| {
            workspaces.snapshots[slot_index].snapshot.entries[entry_index] = try readEntry(&reader);
        }
    }
}

fn writeMetadata(writer: *CursorWriter, metadata: object_store.SignedMetadata) Error!void {
    try writeText(writer, metadata.labelSlice());
    try writeText(writer, metadata.contentTypeSlice());
    try writer.writeU64(metadata.created_at_ticks);
    try writeSignature(writer, metadata.signature);
}

fn readMetadata(reader: *CursorReader, signer_storage: *[max_signer_bytes]u8) Error!object_store.SignedMetadata {
    var metadata = object_store.SignedMetadata{};
    readTextInto(reader, &metadata.label, &metadata.label_len) catch return error.CorruptImage;
    readTextInto(reader, &metadata.content_type, &metadata.content_type_len) catch return error.CorruptImage;
    metadata.created_at_ticks = try reader.readU64();
    metadata.signature = try readSignature(reader, signer_storage);
    return metadata;
}

fn writeSignature(writer: *CursorWriter, signature: anytype) Error!void {
    if (signature.isPresent()) {
        try writer.writeByte(1);
        try writeText(writer, signature.signer);
        try writer.writeU16(@intCast(signature.public_key_len));
        try writer.writeBytes(signature.publicKeySlice());
        try writer.writeU16(@intCast(signature.value_len));
        try writer.writeBytes(signature.valueSlice());
        return;
    }
    try writer.writeByte(0);
}

fn readSignature(reader: *CursorReader, signer_storage: *[max_signer_bytes]u8) Error!@import("manifest.zig").Signature {
    const manifest = @import("manifest.zig");
    const present = try reader.readByte();
    if (present == 0) return .{};

    const signer_len = try reader.readU16();
    if (signer_len > max_signer_bytes) return error.InvalidSignatureEncoding;
    @memset(signer_storage[0..], 0);
    try reader.readBytes(signer_storage[0..signer_len]);

    var signature = manifest.Signature{
        .format = "ed25519",
        .signer = signer_storage[0..signer_len],
    };
    signature.public_key_len = try reader.readU16();
    if (signature.public_key_len > signature.public_key.len) return error.InvalidSignatureEncoding;
    try reader.readBytes(signature.public_key[0..signature.public_key_len]);
    signature.value_len = try reader.readU16();
    if (signature.value_len > signature.value.len) return error.InvalidSignatureEncoding;
    try reader.readBytes(signature.value[0..signature.value_len]);
    return signature;
}

fn writeText(writer: *CursorWriter, text: []const u8) Error!void {
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readTextInto(reader: *CursorReader, buffer: []u8, out_len: *usize) Error!void {
    const len = try reader.readU16();
    if (len > buffer.len) return error.CorruptImage;
    @memset(buffer[0..], 0);
    try reader.readBytes(buffer[0..len]);
    out_len.* = len;
}

fn writePrincipal(writer: *CursorWriter, principal_id: principal.PrincipalId) Error!void {
    try writer.writeByte(@intFromEnum(principal_id.kind));
    try writer.writeU64(principal_id.serial);
}

fn readPrincipal(reader: *CursorReader) Error!principal.PrincipalId {
    return .{
        .kind = @enumFromInt(try reader.readByte()),
        .serial = try reader.readU64(),
    };
}

fn writeEntry(writer: *CursorWriter, entry: workspace.Entry) Error!void {
    try writeText(writer, entry.pathSlice());
    try writer.writeU64(entry.object_id);
    try writer.writeU64(entry.version_id);
    try writer.writeByte(@intFromEnum(entry.object_type));
}

fn readEntry(reader: *CursorReader) Error!workspace.Entry {
    var entry = workspace.Entry{};
    readTextInto(reader, &entry.path, &entry.path_len) catch return error.CorruptImage;
    entry.object_id = try reader.readU64();
    entry.version_id = try reader.readU64();
    entry.object_type = @enumFromInt(try reader.readByte());
    return entry;
}

fn writeShareGrant(writer: *CursorWriter, grant: workspace.ShareGrant) Error!void {
    try writePrincipal(writer, grant.principal_id);
    var flags: u8 = 0;
    if (grant.can_read) flags |= 1 << 0;
    if (grant.can_write) flags |= 1 << 1;
    if (grant.can_export) flags |= 1 << 2;
    if (grant.local_only) flags |= 1 << 3;
    try writer.writeByte(flags);
}

fn readShareGrant(reader: *CursorReader) Error!workspace.ShareGrant {
    const principal_id = try readPrincipal(reader);
    const flags = try reader.readByte();
    return .{
        .principal_id = principal_id,
        .can_read = (flags & (1 << 0)) != 0,
        .can_write = (flags & (1 << 1)) != 0,
        .can_export = (flags & (1 << 2)) != 0,
        .local_only = (flags & (1 << 3)) != 0,
    };
}

fn workspaceCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.workspaces) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn snapshotCount(workspaces: *const workspace.Directory) usize {
    var count: usize = 0;
    for (workspaces.snapshots) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn nextObjectSlot(store: *object_store.Store) ?*@TypeOf(store.objects[0]) {
    for (&store.objects) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn nextVersionSlotIndex(store: *object_store.Store) ?usize {
    for (store.versions, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn nextWorkspaceSlot(workspaces: *workspace.Directory) ?*@TypeOf(workspaces.workspaces[0]) {
    for (&workspaces.workspaces) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn nextSnapshotSlotIndex(workspaces: *workspace.Directory) ?usize {
    for (workspaces.snapshots, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn zeroWorkspaceRecord() workspace.WorkspaceRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .generation = 0,
        .entry_count = 0,
        .entries = [_]workspace.Entry{workspace.Entry{}} ** workspace.MAX_WORKSPACE_ENTRIES,
        .share_grant_count = 0,
        .share_grants = [_]workspace.ShareGrant{workspace.ShareGrant{
            .principal_id = .{ .kind = .service, .serial = 0 },
        }} ** workspace.MAX_SHARE_GRANTS,
        .transaction_open = false,
        .staged_entry_count = 0,
        .staged_entries = [_]workspace.Entry{workspace.Entry{}} ** workspace.MAX_WORKSPACE_ENTRIES,
        .deleted_count = 0,
        .deleted_entries = [_]workspace.Entry{workspace.Entry{}} ** workspace.MAX_RECOVERABLE_DELETES,
    };
}

fn zeroSnapshotRecord() workspace.SnapshotRecord {
    return .{
        .id = 0,
        .workspace_id = 0,
        .generation = 0,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .signature = .{},
        .entry_count = 0,
        .entries = [_]workspace.Entry{workspace.Entry{}} ** workspace.MAX_WORKSPACE_ENTRIES,
    };
}

fn checksumBytes(bytes: []const u8) u64 {
    var hash: u64 = 0xCBF29CE484222325;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
}

const SlotCandidate = struct {
    slot_index: u32,
    header: SlotHeader,
};

fn findLatestImageSlot(image: []const u8) Error!?SlotCandidate {
    var best: ?SlotCandidate = null;
    var slot_index: u32 = 0;
    while (slot_index < slot_count) : (slot_index += 1) {
        const header = readImageHeader(image, slot_index) catch continue;
        const payload = readImagePayload(image, slot_index, header.payload_len, io_payload_buffer[0..]) catch continue;
        if (checksumBytes(payload) != header.checksum) continue;
        if (best == null or header.generation > best.?.header.generation) {
            best = .{ .slot_index = slot_index, .header = header };
        }
    }
    return best;
}

fn findLatestBackendSlot(backend: Backend) Error!?SlotCandidate {
    var best: ?SlotCandidate = null;
    var slot_index: u32 = 0;
    while (slot_index < slot_count) : (slot_index += 1) {
        const header = readBackendHeader(backend, slot_index) catch continue;
        const payload = readBackendPayload(backend, slot_index, header.payload_len) catch continue;
        if (checksumBytes(payload) != header.checksum) continue;
        if (best == null or header.generation > best.?.header.generation) {
            best = .{ .slot_index = slot_index, .header = header };
        }
    }
    return best;
}

fn slotBaseLba(slot_index: u32) u64 {
    return @as(u64, slot_index) * slot_sectors;
}

fn readImageHeader(image: []const u8, slot_index: u32) Error!SlotHeader {
    const offset: usize = @as(usize, slot_index) * slot_bytes;
    return parseHeader(image[offset .. offset + sector_size]);
}

fn writeImageHeader(image: []u8, slot_index: u32, header: SlotHeader) Error!void {
    const offset: usize = @as(usize, slot_index) * slot_bytes;
    try encodeHeader(image[offset .. offset + sector_size], header);
}

fn writeImagePayload(image: []u8, slot_index: u32, payload: []const u8) Error!void {
    const offset: usize = @as(usize, slot_index) * slot_bytes + sector_size;
    if (payload.len > max_payload_bytes or offset + max_payload_bytes > image.len) return error.ImageTooSmall;
    @memset(image[offset .. offset + max_payload_bytes], 0);
    @memcpy(image[offset .. offset + payload.len], payload);
}

fn readImagePayload(image: []const u8, slot_index: u32, payload_len: u32, buffer: []u8) Error![]const u8 {
    if (payload_len == 0 or payload_len > max_payload_bytes) return error.CorruptImage;
    const offset: usize = @as(usize, slot_index) * slot_bytes + sector_size;
    const payload_len_usize: usize = @intCast(payload_len);
    if (offset + payload_len_usize > image.len or payload_len_usize > buffer.len) return error.ImageTooSmall;
    @memcpy(buffer[0..payload_len_usize], image[offset .. offset + payload_len_usize]);
    return buffer[0..payload_len_usize];
}

fn readBackendHeader(backend: Backend, slot_index: u32) Error!SlotHeader {
    @memset(sector_buffer[0..], 0);
    const lba = slotBaseLba(slot_index);
    if (!backend.read(lba, sector_buffer[0..])) return error.CorruptImage;
    return parseHeader(sector_buffer[0..]);
}

fn writeBackendHeader(backend: Backend, slot_index: u32, header: SlotHeader) Error!void {
    @memset(sector_buffer[0..], 0);
    try encodeHeader(sector_buffer[0..], header);
    const lba = slotBaseLba(slot_index);
    if (!backend.write(lba, sector_buffer[0..])) return error.CorruptImage;
}

fn writeBackendPayload(backend: Backend, slot_index: u32, payload: []const u8) Error!void {
    if (payload.len > max_payload_bytes) return error.NoSpaceLeft;
    const sectors = sectorCountForPayload(payload.len);
    @memset(io_payload_buffer[payload.len .. sectors * sector_size], 0);
    const lba = slotBaseLba(slot_index) + header_sectors;
    if (!backend.write(lba, io_payload_buffer[0 .. sectors * sector_size])) return error.CorruptImage;
}

fn readBackendPayload(backend: Backend, slot_index: u32, payload_len: u32) Error![]const u8 {
    if (payload_len == 0 or payload_len > max_payload_bytes) return error.CorruptImage;
    const sectors = sectorCountForPayload(payload_len);
    const lba = slotBaseLba(slot_index) + header_sectors;
    if (!backend.read(lba, io_payload_buffer[0 .. sectors * sector_size])) return error.CorruptImage;
    return io_payload_buffer[0..@as(usize, @intCast(payload_len))];
}

fn sectorCountForPayload(payload_len: usize) usize {
    return @max(1, (payload_len + sector_size - 1) / sector_size);
}

fn encodeHeader(buffer: []u8, header: SlotHeader) Error!void {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(volume_magic);
    try writer.writeU16(format_version);
    try writer.writeU64(header.generation);
    try writer.writeU32(header.payload_len);
    try writer.writeU64(header.checksum);
}

fn parseHeader(buffer: []const u8) Error!SlotHeader {
    var reader = CursorReader{ .buffer = buffer };
    var magic: [volume_magic.len]u8 = undefined;
    try reader.readBytes(&magic);
    if (!std.mem.eql(u8, &magic, volume_magic)) return error.CorruptImage;
    if ((try reader.readU16()) != format_version) return error.UnsupportedVersion;

    const header = SlotHeader{
        .generation = try reader.readU64(),
        .payload_len = try reader.readU32(),
        .checksum = try reader.readU64(),
    };
    if (header.payload_len == 0 or header.payload_len > max_payload_bytes) return error.CorruptImage;
    return header;
}

test "storage volume image reloads the latest persisted state across slot generations" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = @import("signing.zig").SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x71} ** 32,
    };
    const first = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", first.object_id, first.version_id, .document);
    _ = try workspaces.commit(notes.id, 11);
    const generation_one = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 1), generation_one.generation);

    const second = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello again",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello again", 12),
        .parent_version_id = first.version_id,
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", second.object_id, second.version_id, .document);
    _ = try workspaces.commit(notes.id, 13);
    const generation_two = try saveToImage(image, &store, &workspaces);
    try std.testing.expectEqual(@as(u64, 2), generation_two.generation);

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    const loaded_generation = try loadFromImage(image, &loaded_store, &loaded_workspaces);
    try std.testing.expectEqual(@as(u64, 2), loaded_generation);
    try std.testing.expectEqual(@as(usize, 1), loaded_store.objectCount());
    try std.testing.expectEqual(second.version_id, loaded_store.latestVersion(900).?.id);
    try std.testing.expectEqualStrings("zigos-storage-key", loaded_store.latestVersion(900).?.metadata.signature.signer);
    const loaded_notes = loaded_workspaces.findOwned(.{ .kind = .user, .serial = 1 }, "notes").?;
    try std.testing.expectEqual(second.version_id, (try loaded_workspaces.resolve(loaded_notes.id, "documents/notes.md")).version_id);
}

test "storage volume rejects corrupted slot payloads" {
    const image = try std.testing.allocator.alloc(u8, image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = @import("signing.zig").SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x72} ** 32,
    };
    _ = try store.putVersion(.{
        .preferred_object_id = 901,
        .object_type = .blob,
        .payload = "blob",
        .metadata = try object_store.signMetadata(signer, "blob", "application/octet-stream", .blob, "blob", 10),
    });
    _ = try saveToImage(image, &store, &workspaces);
    image[sector_size + 3] ^= 0xFF;

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, loadFromImage(image, &loaded_store, &loaded_workspaces));
}
