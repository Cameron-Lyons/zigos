const std = @import("std");
const wire = @import("tpm2_wire.zig");
const crypto = @import("tpm2_crypto.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Key = [32]u8;
pub const Name = [34]u8;
pub const MAX_BLOB_BYTES = 512;
const MAX_PACKET_BYTES = 1024;
const OWNER: u32 = 0x4000_0001;
const NULL: u32 = 0x4000_0007;
const PASSWORD: u32 = 0x4000_0009;
const CREATE_PRIMARY: u32 = 0x131;
const START_SESSION: u32 = 0x176;
const CREATE: u32 = 0x153;
const LOAD: u32 = 0x157;
const UNSEAL: u32 = 0x15e;
const FLUSH: u32 = 0x165;
const NV_DEFINE: u32 = 0x12a;
const NV_READ_PUBLIC: u32 = 0x169;
const NV_READ: u32 = 0x14e;
const NV_WRITE: u32 = 0x137;
const NV_ATTRIBUTES: u32 = 0x0004_1004; // AUTHREAD, AUTHWRITE, WRITEALL; dictionary attack protected
const NV_WRITTEN: u32 = 0x2000_0000;
pub const MAX_NV_BYTES = 256;

pub const NvBinding = union(enum) {
    none,
    // Read the immutable commitment from the public area. It is authenticated
    // only when the following HMAC command succeeds with this index Name.
    discover,
    pinned: Key,
};

// Caller allocates an application index. No undefine, clear, owner read/write,
// partial write, or implicit provisioning operation is exposed.
pub const NvSpace = struct {
    index: u32,
    size: u16,
    binding: NvBinding = .none,

    fn validate(self: NvSpace) !void {
        if (self.index < 0x0180_0000 or self.index > 0x0180_ffff or self.size == 0 or self.size > MAX_NV_BYTES)
            return error.InvalidNvSpace;
        if (self.binding == .pinned and std.mem.allEqual(u8, &self.binding.pinned, 0)) return error.InvalidNvSpace;
    }
};
const PRIMARY_PREFIX = [_]u8{
    0, 0x23, 0, 0x0b, 0, 3, 0, 0x72, 0, 0, // ECC, SHA256, restricted storage parent, no policy
    0, 6, 0, 0x80, 0, 0x43, 0, 0x10, 0, 3, 0, 0x10, // AES128 CFB, NULL scheme, P256, NULL KDF
};
const SEALED_PREFIX = [_]u8{
    0, 8, 0, 0x0b, 0, 0, 0, 0x52, 0, 0, 0, 0x10, // keyed hash, fixed TPM/parent, auth required, NULL scheme
};

pub const Error = wire.Error || error{
    TpmError,
    IntegrityFailure,
    InvalidAuthorization,
    InvalidBlob,
    WrongDevice,
    NotInitialized,
    AlreadyInitialized,
    Failed,
};

pub const Blob = struct {
    bytes: [MAX_BLOB_BYTES]u8 = @splat(0),
    len: u16 = 0,

    pub fn slice(self: *const Blob) []const u8 {
        std.debug.assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

const Session = struct {
    handle: u32 = 0,
    key: Key = @splat(0),
    nonce: Key = @splat(0),
};

const Reply = struct {
    handle: u32,
    parameters: []u8,
    authorization: []const u8,
};

// A caller owns each Client exclusively and supplies execute(command, response,
// timeout_ms) and random(out). The kernel adapter uses CRB and its seeded CSPRNG.
// No ownership changes, persistent TPM objects, index deletion, or hierarchy clears.
// The owner hierarchy must have empty authorization. Objects require a separate
// 256-bit caller authorization, are fixed to this TPM/parent, and use dictionary
// attack protection. PCR policy and user-auth provisioning belong to the caller.
pub const Client = struct {
    parent: u32 = 0,
    parent_name: Name = @splat(0),
    parent_x: Key = @splat(0),
    parent_y: Key = @splat(0),
    failed: bool = false,
    last_tpm_error: u32 = 0,
    command: [MAX_PACKET_BYTES]u8 = @splat(0),
    response: [MAX_PACKET_BYTES]u8 = @splat(0),

    pub fn initialize(self: *Client, io: anytype) !void {
        if (self.parent != 0) return error.AlreadyInitialized;
        if (self.failed) return error.Failed;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8002, CREATE_PRIMARY);
        try w.int(u32, OWNER);
        try w.int(u32, 9);
        try w.int(u32, PASSWORD);
        try w.sized("");
        try w.int(u8, 0);
        try w.sized("");
        try w.sized(&.{ 0, 0, 0, 0 }); // no parent auth or caller-supplied sensitive data
        try w.int(u16, PRIMARY_PREFIX.len + 4);
        try w.put(&PRIMARY_PREFIX);
        try w.sized("");
        try w.sized("");
        try w.sized("");
        try w.int(u32, 0); // no creation PCR selection
        const reply = try self.exchange(io, w.finish(), 0x8002, true, 120_000);
        try transient(reply.handle);
        self.parent = reply.handle;
        errdefer self.close(io) catch {};
        if (!std.mem.eql(u8, reply.authorization, &.{ 0, 0, 1, 0, 0 })) return error.InvalidResponse;
        var r = wire.Reader{ .bytes = reply.parameters };
        const public = try r.sized();
        if (public.len != PRIMARY_PREFIX.len + 68 or !std.mem.startsWith(u8, public, &PRIMARY_PREFIX))
            return error.InvalidResponse;
        var point = wire.Reader{ .bytes = public[PRIMARY_PREFIX.len..] };
        self.parent_x = try digest(try point.sized());
        self.parent_y = try digest(try point.sized());
        try point.end();
        _ = std.crypto.ecc.P256.fromSerializedAffineCoordinates(self.parent_x, self.parent_y, .big) catch return error.InvalidResponse;
        try skipCreation(&r);
        const name = try r.sized();
        self.parent_name = objectName(public);
        if (!std.mem.eql(u8, name, &self.parent_name)) return error.IntegrityFailure;
        try r.end();
    }

    pub fn close(self: *Client, io: anytype) !void {
        defer self.wipeBuffers();
        if (self.parent != 0) {
            self.flush(io, self.parent) catch |err| {
                self.failed = true;
                return err;
            };
            self.parent = 0;
        }
    }

    pub fn seal(self: *Client, io: anytype, key: *const Key, auth: *const Key, out: *Blob) !void {
        out.* = .{};
        errdefer out.* = .{};
        try self.ready(auth);
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [128]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.int(u16, 68);
        try w.sized(auth);
        try w.sized(key);
        try w.int(u16, SEALED_PREFIX.len + 2);
        try w.put(&SEALED_PREFIX);
        try w.sized("");
        try w.sized("");
        try w.int(u32, 0);
        const reply = try self.authorized(io, &session, CREATE, self.parent, &self.parent_name, "", parameters[0..w.pos], 0x21, false);
        var r = wire.Reader{ .bytes = reply.parameters };
        const private = try r.sized();
        const public = try r.sized();
        if (private.len == 0 or private.len > 256) return error.InvalidResponse;
        sealedPublic(public) catch return error.InvalidResponse;
        try skipCreation(&r);
        try r.end();
        var blob = wire.Writer{ .bytes = &out.bytes };
        try blob.put("ZSK1");
        try blob.put(&self.parent_name);
        try blob.sized(private);
        try blob.sized(public);
        out.len = @intCast(blob.pos);
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    pub fn unseal(self: *Client, io: anytype, blob: []const u8, auth: *const Key, out: *Key) !void {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        try self.ready(auth);
        defer self.wipeBuffers();
        const fields = parseBlob(blob, &self.parent_name) catch |err| {
            return if (err == error.WrongDevice) error.WrongDevice else error.InvalidBlob;
        };
        const private = fields.private;
        const public = fields.public;
        errdefer |err| self.rejectProtocolFailure(err);
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [MAX_BLOB_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.sized(private);
        try w.sized(public);
        const loaded = try self.authorized(io, &session, LOAD, self.parent, &self.parent_name, "", parameters[0..w.pos], 1, true);
        try transient(loaded.handle);
        var child = loaded.handle;
        defer if (child != 0) self.flush(io, child) catch {
            self.failed = true;
        };
        var r = wire.Reader{ .bytes = loaded.parameters };
        const name = objectName(public);
        if (!std.mem.eql(u8, try r.sized(), &name)) return error.IntegrityFailure;
        try r.end();
        const unsealed = try self.authorized(io, &session, UNSEAL, child, &name, auth, &.{}, 0x41, false);
        r = .{ .bytes = unsealed.parameters };
        var key = try digest(try r.sized());
        defer std.crypto.secureZero(u8, &key);
        try r.end();
        try self.flush(io, child);
        child = 0;
        try self.flush(io, session.handle);
        session.handle = 0;
        out.* = key;
    }

    // Explicit enrollment only. Existing indexes are never replaced. A failed
    // definition/write requires caller recovery, never an automatic redefinition.
    pub fn nvDefine(self: *Client, io: anytype, space: NvSpace, auth: *const Key) !void {
        try self.ready(auth);
        try space.validate();
        if (space.binding == .discover) return error.InvalidNvSpace;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [82]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.sized(auth);
        const commitment: []const u8 = if (space.binding == .pinned) &space.binding.pinned else "";
        try w.int(u16, @intCast(14 + commitment.len));
        try w.int(u32, space.index);
        try w.int(u16, 0x0b);
        try w.int(u32, NV_ATTRIBUTES);
        // AUTHREAD/AUTHWRITE remain the only access paths. The otherwise
        // unused policy digest commits enrollment metadata at NV_DefineSpace,
        // before the first data write. It is included in the authenticated Name.
        try w.sized(commitment);
        try w.int(u16, space.size);
        const reply = try self.authorizedHandles(io, &session, NV_DEFINE, &.{OWNER}, &.{&.{ 0x40, 0, 0, 1 }}, "", parameters[0..w.pos], 0x21, false);
        if (reply.parameters.len != 0) return error.InvalidResponse;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    pub fn nvRead(self: *Client, io: anytype, space: NvSpace, auth: *const Key, out: []u8) !void {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        try self.ready(auth);
        try space.validate();
        if (out.len != space.size) return error.InvalidNvSpace;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        const public = try self.nvPublic(io, space);
        if (!public.written) return error.NvUninitialized;
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [4]u8 = undefined;
        var w = wire.Writer{ .bytes = &parameters };
        try w.int(u16, space.size);
        try w.int(u16, 0);
        const reply = try self.authorizedHandles(io, &session, NV_READ, &.{ space.index, space.index }, &.{ &public.name, &public.name }, auth, &parameters, 0x41, false);
        var r = wire.Reader{ .bytes = reply.parameters };
        const data = try r.sized();
        if (data.len != out.len) return error.InvalidResponse;
        try r.end();
        @memcpy(out, data);
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    pub fn nvWrite(self: *Client, io: anytype, space: NvSpace, auth: *const Key, data: []const u8) !void {
        return self.writeNv(io, space, auth, data, false);
    }

    // The unwritten check and command HMAC use the SAME public-area snapshot.
    // A forged WRITTEN bit changes the Name and cannot authorize a rollback.
    pub fn nvInitialize(self: *Client, io: anytype, space: NvSpace, auth: *const Key, data: []const u8) !void {
        if (space.binding != .pinned) return error.InvalidNvSpace;
        return self.writeNv(io, space, auth, data, true);
    }

    fn writeNv(self: *Client, io: anytype, space: NvSpace, auth: *const Key, data: []const u8, initial_only: bool) !void {
        try self.ready(auth);
        try space.validate();
        if (data.len != space.size) return error.InvalidNvSpace;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        // WRITTEN changes the index Name on its first write. Never cache it.
        const public = try self.nvPublic(io, space);
        if (initial_only and public.written) return error.NvAlreadyInitialized;
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [MAX_NV_BYTES + 4]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.sized(data);
        try w.int(u16, 0);
        const reply = try self.authorizedHandles(io, &session, NV_WRITE, &.{ space.index, space.index }, &.{ &public.name, &public.name }, auth, parameters[0..w.pos], 0x21, false);
        if (reply.parameters.len != 0) return error.InvalidResponse;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    fn nvPublic(self: *Client, io: anytype, space: NvSpace) !NvPublic {
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8001, NV_READ_PUBLIC);
        try w.int(u32, space.index);
        const reply = self.exchange(io, w.finish(), 0x8001, false, 2000) catch |err| {
            // TPM_RC_HANDLE, handle 1. Other errors must not become absence.
            if (err == error.TpmError and self.last_tpm_error == 0x18b) return error.NvIndexMissing;
            return err;
        };
        return parseNvPublic(reply.parameters, space);
    }

    fn rejectProtocolFailure(self: *Client, err: anyerror) void {
        if (err == error.InvalidResponse or err == error.IntegrityFailure) self.failed = true;
    }

    fn ready(self: *Client, auth: *const Key) !void {
        self.last_tpm_error = 0;
        if (self.failed) return error.Failed;
        if (self.parent == 0) return error.NotInitialized;
        if (std.mem.allEqual(u8, auth, 0)) return error.InvalidAuthorization;
    }

    fn wipeBuffers(self: *Client) void {
        std.crypto.secureZero(u8, &self.command);
        std.crypto.secureZero(u8, &self.response);
    }

    fn retireSession(self: *Client, io: anytype, session: *Session) void {
        if (session.handle != 0) self.flush(io, session.handle) catch {
            self.failed = true;
        };
        std.crypto.secureZero(u8, std.mem.asBytes(session));
    }

    fn flush(self: *Client, io: anytype, handle: u32) !void {
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8001, FLUSH);
        try w.int(u32, handle);
        const reply = try self.exchange(io, w.finish(), 0x8001, false, 2000);
        if (reply.parameters.len != 0) return error.InvalidResponse;
    }

    fn exchange(self: *Client, io: anytype, command: []const u8, tag: u16, has_handle: bool, timeout_ms: u32) !Reply {
        const bytes = io.execute(command, &self.response, timeout_ms) catch |err| {
            self.failed = true;
            return err;
        };
        var r = wire.Reader{ .bytes = bytes };
        const response_tag = try r.int(u16);
        if (try r.int(u32) != bytes.len) return error.InvalidResponse;
        const response_code = try r.int(u32);
        if (response_code != 0) {
            self.last_tpm_error = response_code;
            if (response_tag != 0x8001 or bytes.len != 10) return error.InvalidResponse;
            return error.TpmError;
        }
        if (response_tag != tag) return error.InvalidResponse;
        const handle = if (has_handle) try r.int(u32) else 0;
        const length = if (tag == 0x8002) try r.int(u32) else bytes.len - r.pos;
        const offset = r.pos;
        _ = try r.take(length);
        return .{ .handle = handle, .parameters = bytes[offset..][0..length], .authorization = bytes[r.pos..] };
    }

    fn startSession(self: *Client, io: anytype) !Session {
        var salt = try crypto.makeSalt(io, self.parent_x, self.parent_y);
        defer salt.wipe();
        var nonce: Key = undefined;
        defer std.crypto.secureZero(u8, &nonce);
        try io.random(&nonce);
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8001, START_SESSION);
        try w.int(u32, self.parent);
        try w.int(u32, NULL);
        try w.sized(&nonce);
        try w.int(u16, 68);
        try w.sized(&salt.x);
        try w.sized(&salt.y);
        try w.int(u8, 0); // unbound HMAC session
        try w.put(&.{ 0, 6, 0, 0x80, 0, 0x43, 0, 0x0b }); // AES128 CFB, SHA256
        const reply = try self.exchange(io, w.finish(), 0x8001, true, 2000);
        if (reply.handle >> 24 != 2) return error.InvalidResponse;
        var session = Session{ .handle = reply.handle };
        errdefer self.retireSession(io, &session);
        var r = wire.Reader{ .bytes = reply.parameters };
        session.nonce = try digest(try r.sized());
        try r.end();
        session.key = crypto.kdfa(&salt.secret, "ATH", &session.nonce, &nonce);
        return session;
    }

    fn authorized(self: *Client, io: anytype, session: *Session, code: u32, handle: u32, name: *const Name, auth: []const u8, parameters: []u8, attributes: u8, has_handle: bool) !Reply {
        return self.authorizedHandles(io, session, code, &.{handle}, &.{name}, auth, parameters, attributes, has_handle);
    }

    fn authorizedHandles(self: *Client, io: anytype, session: *Session, code: u32, handles: []const u32, names: []const []const u8, auth: []const u8, parameters: []u8, attributes: u8, has_handle: bool) !Reply {
        std.debug.assert(handles.len == names.len and handles.len > 0 and handles.len <= 2 and auth.len <= 32);
        var value: [64]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &value);
        @memcpy(value[0..32], &session.key);
        @memcpy(value[32..][0..auth.len], auth);
        const session_value = value[0 .. 32 + auth.len];
        var nonce: Key = undefined;
        defer std.crypto.secureZero(u8, &nonce);
        try io.random(&nonce);
        if (attributes & 0x20 != 0) {
            var r = wire.Reader{ .bytes = parameters };
            const encrypted = try r.sized();
            var key_iv = crypto.kdfa(session_value, "CFB", &nonce, &session.nonce);
            defer std.crypto.secureZero(u8, &key_iv);
            crypto.cfb(parameters[2..][0..encrypted.len], &key_iv, .encrypt);
        }
        var cc: [4]u8 = undefined;
        std.mem.writeInt(u32, &cc, code, .big);
        var hash = Sha256.init(.{});
        hash.update(&cc);
        for (names) |name| hash.update(name);
        hash.update(parameters);
        const cp_hash = hash.finalResult();
        var mac = crypto.authHmac(session_value, &cp_hash, &nonce, &session.nonce, attributes);
        defer std.crypto.secureZero(u8, &mac);
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8002, code);
        for (handles) |handle| try w.int(u32, handle);
        try w.int(u32, 73);
        try w.int(u32, session.handle);
        try w.sized(&nonce);
        try w.int(u8, attributes);
        try w.sized(&mac);
        try w.put(parameters);
        const reply = try self.exchange(io, w.finish(), 0x8002, has_handle, 2000);
        var r = wire.Reader{ .bytes = reply.authorization };
        const next_nonce = try digest(try r.sized());
        const response_attributes = try r.int(u8);
        if (response_attributes != attributes) return error.InvalidResponse;
        const response_mac = try digest(try r.sized());
        try r.end();
        hash = Sha256.init(.{});
        hash.update(&.{ 0, 0, 0, 0 });
        hash.update(&cc);
        hash.update(reply.parameters);
        const rp_hash = hash.finalResult();
        var expected = crypto.authHmac(session_value, &rp_hash, &next_nonce, &nonce, response_attributes);
        defer std.crypto.secureZero(u8, &expected);
        if (!std.crypto.timing_safe.eql(Key, expected, response_mac)) {
            self.failed = true;
            return error.IntegrityFailure;
        }
        if (attributes & 0x40 != 0) {
            r = .{ .bytes = reply.parameters };
            const encrypted = try r.sized();
            var key_iv = crypto.kdfa(session_value, "CFB", &next_nonce, &nonce);
            defer std.crypto.secureZero(u8, &key_iv);
            crypto.cfb(reply.parameters[2..][0..encrypted.len], &key_iv, .decrypt);
        }
        session.nonce = next_nonce;
        return reply;
    }
};

const BlobFields = struct { private: []const u8, public: []const u8 };
const NvPublic = struct { name: Name, written: bool };

fn parseNvPublic(bytes: []const u8, space: NvSpace) !NvPublic {
    var r = wire.Reader{ .bytes = bytes };
    const public = try r.sized();
    var p = wire.Reader{ .bytes = public };
    if (try p.int(u32) != space.index or try p.int(u16) != 0x0b) return error.InvalidResponse;
    const attributes = try p.int(u32);
    if (attributes & ~NV_WRITTEN != NV_ATTRIBUTES) return error.InvalidResponse;
    const commitment = try p.sized();
    switch (space.binding) {
        .none => if (commitment.len != 0) return error.InvalidResponse,
        .discover => if (commitment.len != 32 or std.mem.allEqual(u8, commitment, 0)) return error.InvalidResponse,
        .pinned => |expected| if (!std.mem.eql(u8, commitment, &expected)) return error.NvBindingMismatch,
    }
    if (try p.int(u16) != space.size) return error.InvalidResponse;
    try p.end();
    const name = objectName(public);
    if (!std.mem.eql(u8, try r.sized(), &name)) return error.IntegrityFailure;
    try r.end();
    return .{ .name = name, .written = attributes & NV_WRITTEN != 0 };
}

fn parseBlob(blob: []const u8, parent_name: *const Name) Error!BlobFields {
    if (blob.len > MAX_BLOB_BYTES) return error.InvalidBlob;
    var r = wire.Reader{ .bytes = blob };
    if (!std.mem.eql(u8, try r.take(4), "ZSK1")) return error.InvalidBlob;
    if (!std.mem.eql(u8, try r.take(34), parent_name)) return error.WrongDevice;
    const private = try r.sized();
    const public = try r.sized();
    if (private.len == 0 or private.len > 256) return error.InvalidBlob;
    try sealedPublic(public);
    try r.end();
    return .{ .private = private, .public = public };
}

fn digest(bytes: []const u8) Error!Key {
    if (bytes.len != 32) return error.InvalidResponse;
    return bytes[0..32].*;
}

fn transient(handle: u32) Error!void {
    if (handle >> 24 != 0x80) return error.InvalidResponse;
}

fn objectName(public: []const u8) Name {
    var name: Name = undefined;
    name[0] = 0;
    name[1] = 0x0b;
    Sha256.hash(public, name[2..34], .{});
    return name;
}

fn sealedPublic(public: []const u8) Error!void {
    if (public.len != SEALED_PREFIX.len + 34 or !std.mem.startsWith(u8, public, &SEALED_PREFIX) or
        public[SEALED_PREFIX.len] != 0 or public[SEALED_PREFIX.len + 1] != 32) return error.InvalidBlob;
}

fn skipCreation(r: *wire.Reader) Error!void {
    _ = try r.sized(); // bounded creation data
    _ = try digest(try r.sized());
    if (try r.int(u16) != 0x8021 or try r.int(u32) != OWNER) return error.InvalidResponse;
    _ = try r.sized(); // creation ticket digest, opaque to this client
}

const RejectIo = struct {
    calls: usize = 0,
    pub fn random(self: *@This(), _: []u8) !void {
        self.calls += 1;
        return error.EntropyUnavailable;
    }
    pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
        self.calls += 1;
        return error.UnexpectedHardwareAccess;
    }
};

test "TPM unseal rejects invalid callers without exposing old output or touching hardware" {
    var client = Client{};
    var io = RejectIo{};
    const auth: Key = @splat(1);
    var out: Key = @splat(0xaa);
    try std.testing.expectError(error.NotInitialized, client.unseal(&io, "", &auth, &out));
    try std.testing.expectEqual(@as(Key, @splat(0)), out);
    client.parent = 0x8000_0000;
    try std.testing.expectError(error.InvalidAuthorization, client.unseal(&io, "", &(@as(Key, @splat(0))), &out));
    client.failed = true;
    try std.testing.expectError(error.Failed, client.unseal(&io, "", &auth, &out));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
}

test "TPM NV validates callers and full record bounds before touching hardware" {
    var client = Client{ .parent = 0x8000_0000 };
    var io = RejectIo{};
    const auth: Key = @splat(1);
    const space = NvSpace{ .index = 0x0180_1234, .size = 32 };
    var out: Key = @splat(0xaa);
    try std.testing.expectError(error.InvalidAuthorization, client.nvRead(&io, space, &(@as(Key, @splat(0))), &out));
    try std.testing.expectError(error.InvalidNvSpace, client.nvRead(&io, space, &auth, out[0..31]));
    try std.testing.expectEqual(@as(Key, @splat(0)), out);
    try std.testing.expectError(error.InvalidNvSpace, client.nvWrite(&io, space, &auth, "short"));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = 0x0100_0000, .size = 32 }, &auth));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = MAX_NV_BYTES + 1 }, &auth));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 0 }, &auth));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 32, .binding = .discover }, &auth));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 32, .binding = .{ .pinned = @splat(0) } }, &auth));
    try std.testing.expectError(error.InvalidNvSpace, client.nvInitialize(&io, space, &auth, &out));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
}

test "TPM NV enrollment binds the immutable policy and guards the first write with its Name" {
    const space = NvSpace{ .index = 0x0180_1234, .size = 136, .binding = .{ .pinned = @splat(7) } };
    var bytes: [85]u8 = @splat(0);
    var unwritten_name: Name = undefined;
    for ([_]u32{ NV_ATTRIBUTES, NV_ATTRIBUTES | NV_WRITTEN }) |attributes| {
        var w = wire.Writer{ .bytes = &bytes };
        try w.int(u16, 46);
        try w.int(u32, space.index);
        try w.int(u16, 0x0b);
        try w.int(u32, attributes);
        try w.sized(&space.binding.pinned);
        try w.int(u16, space.size);
        try w.sized(&objectName(bytes[2..48]));
        const public = try parseNvPublic(bytes[0..w.pos], space);
        if (public.written) {
            try std.testing.expect(!std.mem.eql(u8, &unwritten_name, &public.name));
        } else unwritten_name = public.name;
        var discovery = space;
        discovery.binding = .discover;
        try std.testing.expectEqualDeep(public, try parseNvPublic(bytes[0..w.pos], discovery));
        discovery.binding = .none;
        try std.testing.expectError(error.InvalidResponse, parseNvPublic(bytes[0..w.pos], discovery));
        for (0..w.pos) |len| try std.testing.expectError(error.InvalidResponse, parseNvPublic(bytes[0..len], space));
        try std.testing.expectError(error.InvalidResponse, parseNvPublic(&bytes, space));
        var wrong = space;
        wrong.binding.pinned[0] ^= 1;
        try std.testing.expectError(error.NvBindingMismatch, parseNvPublic(bytes[0..w.pos], wrong));
        var forged = bytes;
        forged[8] ^= 0x20; // Changing WRITTEN without changing Name is invalid.
        try std.testing.expectError(error.IntegrityFailure, parseNvPublic(forged[0..w.pos], space));
    }
    const PublicIo = struct {
        payload: []const u8,
        reads: usize = 0,
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedAuthorization;
        }
        pub fn execute(self: *@This(), command: []const u8, response: []u8, _: u32) ![]u8 {
            if (std.mem.readInt(u32, command[6..10], .big) != NV_READ_PUBLIC) return error.UnexpectedWrite;
            self.reads += 1;
            var w = wire.Writer{ .bytes = response };
            try w.begin(0x8001, 0);
            try w.put(self.payload);
            return response[0..w.finish().len];
        }
    };
    var io = PublicIo{ .payload = bytes[0..84] };
    var client = Client{ .parent = 0x8000_0000 };
    const data: [136]u8 = @splat(1);
    try std.testing.expectError(error.NvAlreadyInitialized, client.nvInitialize(&io, space, &(@as(Key, @splat(1))), &data));
    try std.testing.expectEqual(@as(usize, 1), io.reads);
    try std.testing.expect(!client.failed);
}

test "TPM NV public parsing rejects weaker access policy altered names and noncanonical framing" {
    const space = NvSpace{ .index = 0x0180_1234, .size = 136 };
    var bytes: [53]u8 = @splat(0);
    for ([_]u32{ NV_ATTRIBUTES, NV_ATTRIBUTES | NV_WRITTEN }) |attributes| {
        var w = wire.Writer{ .bytes = &bytes };
        try w.int(u16, 14);
        try w.int(u32, space.index);
        try w.int(u16, 0x0b);
        try w.int(u32, attributes);
        try w.sized("");
        try w.int(u16, space.size);
        try w.sized(&objectName(bytes[2..16]));
        const public = try parseNvPublic(bytes[0..w.pos], space);
        try std.testing.expectEqual(attributes & NV_WRITTEN != 0, public.written);
        for (0..w.pos) |len| try std.testing.expectError(error.InvalidResponse, parseNvPublic(bytes[0..len], space));
        try std.testing.expectError(error.InvalidResponse, parseNvPublic(&bytes, space));
        for ([_]usize{ 5, 7, 9, 10, 11, 13, 15, 18 }) |offset| {
            var changed = bytes;
            changed[offset] ^= 1;
            const result = parseNvPublic(changed[0..w.pos], space);
            if (offset == 18) try std.testing.expectError(error.IntegrityFailure, result) else try std.testing.expectError(error.InvalidResponse, result);
        }
    }
}

test "TPM sealed blob parser rejects truncation overflow trailing bytes and weakened object templates" {
    var client = Client{ .parent = 0x8000_0000 };
    const point = std.crypto.ecc.P256.basePoint.affineCoordinates();
    client.parent_x = point.x.toBytes(.big);
    client.parent_y = point.y.toBytes(.big);
    var blob = Blob{};
    var w = wire.Writer{ .bytes = &blob.bytes };
    try w.put("ZSK1");
    try w.put(&client.parent_name);
    try w.sized("private");
    try w.int(u16, SEALED_PREFIX.len + 34);
    const public_start = w.pos;
    try w.put(&SEALED_PREFIX);
    try w.sized(&(@as(Key, @splat(1))));
    blob.len = @intCast(w.pos);
    var io = RejectIo{};
    const auth: Key = @splat(1);
    var out: Key = undefined;
    for (0..blob.len) |length| {
        out = @splat(0xaa);
        try std.testing.expectError(error.InvalidBlob, client.unseal(&io, blob.bytes[0..length], &auth, &out));
        try std.testing.expectEqual(@as(Key, @splat(0)), out);
        try std.testing.expect(!client.failed);
    }
    var changed = blob;
    changed.bytes[38] = 0xff;
    changed.bytes[39] = 0xff;
    try std.testing.expectError(error.InvalidBlob, client.unseal(&io, changed.slice(), &auth, &out));
    changed = blob;
    changed.bytes[public_start + 7] ^= 0x40;
    try std.testing.expectError(error.InvalidBlob, client.unseal(&io, changed.slice(), &auth, &out));
    changed = blob;
    changed.bytes[4] ^= 1;
    try std.testing.expectError(error.WrongDevice, client.unseal(&io, changed.slice(), &auth, &out));
    changed = blob;
    changed.len += 1;
    try std.testing.expectError(error.InvalidBlob, client.unseal(&io, changed.slice(), &auth, &out));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
    try std.testing.expectError(error.EntropyUnavailable, client.unseal(&io, blob.slice(), &auth, &out));
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expectEqual(@as(Key, @splat(0)), out);
}
