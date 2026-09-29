const std = @import("std");
const wire = @import("tpm2_wire.zig");
const crypto = @import("tpm2_crypto.zig");
pub const quote = @import("tpm2_quote.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Key = [32]u8;
pub const Name = [34]u8;
pub const MAX_BLOB_BYTES = 512;
const MAX_PACKET_BYTES = 1024;
const OWNER: u32 = 0x4000_0001;
const LOCKOUT: u32 = 0x4000_000a;
const NULL: u32 = 0x4000_0007;
const PASSWORD: u32 = 0x4000_0009;
const CREATE_PRIMARY: u32 = 0x131;
const START_SESSION: u32 = 0x176;
const GET_CAPABILITY: u32 = 0x17a;
const CREATE: u32 = 0x153;
const LOAD: u32 = 0x157;
const UNSEAL: u32 = 0x15e;
const QUOTE: u32 = 0x158;
const FLUSH: u32 = 0x165;
const NV_DEFINE: u32 = 0x12a;
const READ_PUBLIC: u32 = 0x173;
const EVICT_CONTROL: u32 = 0x120;
const NV_READ_PUBLIC: u32 = 0x169;
const NV_READ: u32 = 0x14e;
const NV_WRITE: u32 = 0x137;
const HIERARCHY_CHANGE_AUTH: u32 = 0x129;
const DA_PARAMETERS: u32 = 0x13a;
const DA_RESET: u32 = 0x139;
const NV_ATTRIBUTES: u32 = 0x0004_1004; // AUTHREAD, AUTHWRITE, WRITEALL; dictionary attack protected
const NV_WRITTEN: u32 = 0x2000_0000;
pub const MAX_NV_BYTES = 256;

// TCG TPM 2.0 Part 2, TPMA_PERMANENT. These flags mean authorization has
// been changed since TPM2_Clear; they do not prove it is currently nonempty.
pub const HierarchyState = struct {
    owner_auth_set: bool,
    endorsement_auth_set: bool,
    lockout_auth_set: bool,
    in_lockout: bool,
};

pub const DictionaryAttackPolicy = struct {
    max_tries: u32,
    recovery_seconds: u32,
    lockout_recovery_seconds: u32,

    fn validate(self: DictionaryAttackPolicy) !void {
        // Zero recovery disables guessing protection or permits reboot-based
        // lockout-auth retries. Keep both recovery intervals persistent.
        if (self.max_tries == 0 or self.max_tries > 32 or self.recovery_seconds < 60 or self.lockout_recovery_seconds < 60)
            return error.InvalidDictionaryAttackPolicy;
    }
};

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
// Independently enrolled reference, never a Name discovered from untrusted
// storage. Owner persistent handles cannot name platform-owned objects.
pub const PersistentParent = struct {
    handle: u32,
    name: Name,

    pub fn validate(self: PersistentParent) !void {
        if (self.handle < 0x8100_0000 or self.handle >= 0x8180_0000 or
            self.name[0] != 0 or self.name[1] != 0x0b or std.mem.allEqual(u8, self.name[2..], 0))
            return error.InvalidPersistentParent;
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
// Persistent parent creation and hierarchy administration are explicit and
// require separately retained owner/lockout authorization. No persistent-object
// eviction, index deletion or hierarchy clear is exposed. Normal sessions open
// an independently pinned persistent parent without administrator secrets.
// Objects require a separate
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

    // Explicit bootstrap on an unowned TPM only. Never fall back here when an
    // enrolled persistent parent is missing or changed.
    pub fn createEnrollmentParent(self: *Client, io: anytype) !void {
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
        const key = try parseParentPublic(public);
        self.parent_x = key.x;
        self.parent_y = key.y;
        try skipCreation(&r);
        const name = try r.sized();
        self.parent_name = objectName(public);
        if (!std.mem.eql(u8, name, &self.parent_name)) return error.IntegrityFailure;
        try r.end();
    }

    pub fn close(self: *Client, io: anytype) !void {
        defer self.wipeBuffers();
        if (self.parent != 0) {
            if (self.parent >> 24 == 0x80) self.flush(io, self.parent) catch |err| {
                self.failed = true;
                return err;
            };
            self.parent = 0;
        }
    }

    // ReadPublic alone is unauthenticated. After checking the independently
    // pinned Name and exact storage template, prove possession of the private
    // parent through a salted-session ReadPublic HMAC before publishing success.
    pub fn openPersistent(self: *Client, io: anytype, enrolled: PersistentParent) !void {
        try enrolled.validate();
        if (self.parent != 0) return error.AlreadyInitialized;
        if (self.failed) return error.Failed;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        const public = try self.readParentPublic(io, enrolled.handle);
        if (!std.mem.eql(u8, &public.name, &enrolled.name)) return error.PersistentParentChanged;
        self.parent = enrolled.handle;
        self.parent_name = public.name;
        self.parent_x = public.x;
        self.parent_y = public.y;
        errdefer self.close(io) catch {};
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        // ReadPublic has no authorization role. Request response encryption so
        // its extra HMAC session is valid; verify the MAC before decrypting.
        const reply = try self.authorized(io, &session, READ_PUBLIC, self.parent, &self.parent_name, "", &.{}, 0x41, false);
        const confirmed = try parseParentReply(reply.parameters);
        if (!std.mem.eql(u8, &confirmed.name, &enrolled.name)) return error.PersistentParentChanged;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    // Persist only a live transient parent. Passing a persistent handle as the
    // object would evict it, so reject that case before any hardware operation.
    // A matching existing parent is authenticated without issuing EvictControl;
    // this reconciles a lost successful response without another NV mutation.
    pub fn persistParent(self: *Client, io: anytype, enrolled: PersistentParent, owner_auth: ?*const Key) !void {
        try enrolled.validate();
        try optionalAuthorization(owner_auth);
        if (self.failed) return error.Failed;
        if (self.parent >> 24 != 0x80) return error.TransientParentRequired;
        if (!std.mem.eql(u8, &self.parent_name, &enrolled.name)) return error.PersistentParentChanged;
        var existing = Client{};
        defer existing.close(io) catch {};
        existing.openPersistent(io, enrolled) catch |err| {
            if (err != error.PersistentParentMissing) return err;
            try self.makePersistent(io, enrolled.handle, owner_auth);
            try existing.openPersistent(io, enrolled);
        };
    }

    fn makePersistent(self: *Client, io: anytype, handle: u32, owner_auth: ?*const Key) !void {
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [4]u8 = undefined;
        std.mem.writeInt(u32, &parameters, handle, .big);
        const reply = try self.authorizedHandles(io, &session, EVICT_CONTROL, &.{ OWNER, self.parent }, &.{ &.{ 0x40, 0, 0, 1 }, &self.parent_name }, if (owner_auth) |auth| auth else "", &parameters, 1, false);
        if (reply.parameters.len != 0) return error.InvalidResponse;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    fn readParentPublic(self: *Client, io: anytype, handle: u32) !ParentPublic {
        var w = wire.Writer{ .bytes = &self.command };
        try w.begin(0x8001, READ_PUBLIC);
        try w.int(u32, handle);
        const reply = self.exchange(io, w.finish(), 0x8001, false, 2000) catch |err| {
            if (err == error.TpmError and self.last_tpm_error == 0x18b) return error.PersistentParentMissing;
            return err;
        };
        return parseParentReply(reply.parameters);
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

    // Explicit attestation-key enrollment. The TPM generates the private scalar
    // and encrypts it under this parent. Caller authorization is parameter-
    // encrypted; no private key or password session crosses the command path.
    // The returned public identity must be enrolled independently by a verifier.
    pub fn createAttestationKey(self: *Client, io: anytype, auth: *const Key, out: *Blob) !quote.Identity {
        out.* = .{};
        errdefer out.* = .{};
        try self.ready(auth);
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [96]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.int(u16, 36);
        try w.sized(auth);
        try w.sized(""); // sensitive scalar must be generated by the TPM
        try w.int(u16, quote.PUBLIC_PREFIX.len + 4);
        try w.put(&quote.PUBLIC_PREFIX);
        try w.sized("");
        try w.sized("");
        try w.sized(""); // outsideInfo
        try w.int(u32, 0); // no creation PCR policy
        const reply = try self.authorized(io, &session, CREATE, self.parent, &self.parent_name, "", parameters[0..w.pos], 0x21, false);
        var r = wire.Reader{ .bytes = reply.parameters };
        const private = try r.sized();
        const public = try r.sized();
        if (private.len == 0 or private.len > 256) return error.InvalidResponse;
        const identity = quote.Identity.fromPublic(public, &self.parent_name) catch return error.InvalidResponse;
        try skipCreation(&r);
        try r.end();
        var blob = wire.Writer{ .bytes = &out.bytes };
        try blob.put("ZAK1");
        try blob.put(&self.parent_name);
        try blob.sized(private);
        try blob.sized(public);
        out.len = @intCast(blob.pos);
        try self.flush(io, session.handle);
        session.handle = 0;
        return identity;
    }

    // Load a wrapped key only when it matches an independently enrolled public
    // identity. Publish only a fully authenticated, signature-verified quote of
    // the caller's challenge and expected PCR 11; retire known transient handles.
    pub fn quoteAttestation(self: *Client, io: anytype, blob: []const u8, auth: *const Key, enrolled: *const quote.Identity, nonce: *const Key, expected_pcr: *const Key, out: *quote.Evidence) !void {
        out.* = .{};
        errdefer out.* = .{};
        try self.ready(auth);
        try quote.validateChallenge(nonce);
        try enrolled.validate();
        defer self.wipeBuffers();
        const fields = parseAttestationBlob(blob, &self.parent_name) catch |err|
            return if (err == error.WrongDevice) error.WrongDevice else error.InvalidBlob;
        const identity = try quote.Identity.fromPublic(fields.public, &self.parent_name);
        if (!std.meta.eql(identity, enrolled.*)) return error.AttestationKeyChanged;
        errdefer |err| self.rejectProtocolFailure(err);
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [MAX_BLOB_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.sized(fields.private);
        try w.sized(fields.public);
        const loaded = try self.authorized(io, &session, LOAD, self.parent, &self.parent_name, "", parameters[0..w.pos], 1, true);
        try transient(loaded.handle);
        var child = loaded.handle;
        defer if (child != 0) self.flush(io, child) catch {
            self.failed = true;
        };
        var r = wire.Reader{ .bytes = loaded.parameters };
        const name = identity.name();
        if (!std.mem.eql(u8, try r.sized(), &name)) return error.IntegrityFailure;
        try r.end();
        w.pos = 0;
        try w.sized(nonce);
        try w.put(&.{ 0, 0x18, 0, 0x0b }); // ECDSA SHA256
        try w.put(&quote.SELECTION);
        const quoted = try self.authorized(io, &session, QUOTE, child, &name, auth, parameters[0..w.pos], 1, false);
        _ = try quote.verify(quoted.parameters, enrolled, nonce, expected_pcr);
        @memcpy(out.bytes[0..quoted.parameters.len], quoted.parameters);
        out.len = @intCast(quoted.parameters.len);
        try self.flush(io, child);
        child = 0;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    // Explicit enrollment only. Existing indexes are never replaced. A failed
    // definition/write requires caller recovery, never an automatic redefinition.
    pub fn nvDefine(self: *Client, io: anytype, space: NvSpace, auth: *const Key, owner_auth: ?*const Key) !void {
        try optionalAuthorization(owner_auth);
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
        const reply = try self.authorizedHandles(io, &session, NV_DEFINE, &.{OWNER}, &.{&.{ 0x40, 0, 0, 1 }}, if (owner_auth) |key| key else "", parameters[0..w.pos], 0x21, false);
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

    // Authenticate TPM_PT_PERMANENT through a salted audit session. A public
    // GetCapability response alone must never select an administrator secret.
    // No hierarchy authorization is attempted, so querying cannot consume a
    // dictionary-attack retry while reconciling an interrupted enrollment.
    pub fn hierarchyState(self: *Client, io: anytype) !HierarchyState {
        if (self.parent == 0) return error.NotInitialized;
        if (self.failed) return error.Failed;
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [12]u8 = undefined;
        var w = wire.Writer{ .bytes = &parameters };
        try w.int(u32, 6); // TPM_CAP_TPM_PROPERTIES
        try w.int(u32, 0x200); // TPM_PT_PERMANENT
        try w.int(u32, 1);
        const reply = try self.authorizedHandles(io, &session, GET_CAPABILITY, &.{}, &.{}, "", &parameters, 0x81, false);
        const state = try parseHierarchyState(reply.parameters);
        try self.flush(io, session.handle);
        session.handle = 0;
        return state;
    }

    // Explicit enrollment/rotation only. Null means the caller knows the
    // current lockout authorization is empty; never retry automatically with
    // empty auth after a failure. Retain the new authorization durably before
    // calling: a lost response can mean the TPM has already committed it.
    pub fn changeLockoutAuthorization(self: *Client, io: anytype, current: ?*const Key, next: *const Key) !void {
        return self.changeHierarchyAuthorization(io, LOCKOUT, current, next);
    }

    // Retain next durably outside the TPM before issuing this command. Owner
    // authorization protects parent persistence and NV definitions, but is never
    // needed by an ordinary session opening its enrolled persistent parent.
    pub fn changeOwnerAuthorization(self: *Client, io: anytype, current: ?*const Key, next: *const Key) !void {
        return self.changeHierarchyAuthorization(io, OWNER, current, next);
    }

    fn changeHierarchyAuthorization(self: *Client, io: anytype, hierarchy: u32, current: ?*const Key, next: *const Key) !void {
        try self.ready(next);
        try optionalAuthorization(current);
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        var parameters: [34]u8 = undefined;
        defer std.crypto.secureZero(u8, &parameters);
        var w = wire.Writer{ .bytes = &parameters };
        try w.sized(next);
        var name: [4]u8 = undefined;
        std.mem.writeInt(u32, &name, hierarchy, .big);
        const reply = try self.authorizedHandlesWithResponseAuth(io, &session, HIERARCHY_CHANGE_AUTH, &.{hierarchy}, &.{&name}, if (current) |auth| auth else "", next, &parameters, 0x21, false);
        if (reply.parameters.len != 0) return error.InvalidResponse;
        try self.flush(io, session.handle);
        session.handle = 0;
    }

    pub fn configureDictionaryAttack(self: *Client, io: anytype, auth: *const Key, policy: DictionaryAttackPolicy) !void {
        try policy.validate();
        var parameters: [12]u8 = undefined;
        var w = wire.Writer{ .bytes = &parameters };
        try w.int(u32, policy.max_tries);
        try w.int(u32, policy.recovery_seconds);
        try w.int(u32, policy.lockout_recovery_seconds);
        try self.lockoutCommand(io, auth, DA_PARAMETERS, &parameters);
    }

    // Recovery administrator operation; never part of an ordinary PIN retry.
    pub fn resetDictionaryAttack(self: *Client, io: anytype, auth: *const Key) !void {
        try self.lockoutCommand(io, auth, DA_RESET, &.{});
    }

    fn lockoutCommand(self: *Client, io: anytype, auth: *const Key, code: u32, parameters: []u8) !void {
        try self.ready(auth);
        errdefer |err| self.rejectProtocolFailure(err);
        defer self.wipeBuffers();
        var session = try self.startSession(io);
        defer self.retireSession(io, &session);
        const reply = try self.authorizedHandles(io, &session, code, &.{LOCKOUT}, &.{&.{ 0x40, 0, 0, 0x0a }}, auth, parameters, 1, false);
        if (reply.parameters.len != 0) return error.InvalidResponse;
        try self.flush(io, session.handle);
        session.handle = 0;
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
        if (err == error.InvalidResponse or err == error.IntegrityFailure or
            err == error.InvalidQuote or err == error.InvalidQuoteSignature) self.failed = true;
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
        return self.authorizedHandlesWithResponseAuth(io, session, code, handles, names, auth, auth, parameters, attributes, has_handle);
    }

    fn authorizedHandlesWithResponseAuth(self: *Client, io: anytype, session: *Session, code: u32, handles: []const u32, names: []const []const u8, auth: []const u8, response_auth: []const u8, parameters: []u8, attributes: u8, has_handle: bool) !Reply {
        std.debug.assert(handles.len == names.len and handles.len <= 2 and auth.len <= 32);
        std.debug.assert(response_auth.len <= 32);
        std.debug.assert(handles.len != 0 or (attributes == 0x81 and auth.len == 0 and response_auth.len == 0));
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
        // Audit exclusivity is reported by the TPM; every other requested
        // attribute must agree. The response HMAC below covers the actual bits.
        const variable: u8 = if (attributes & 0x80 != 0) 0x02 else 0;
        if (response_attributes & ~variable != attributes) return error.InvalidResponse;
        const response_mac = try digest(try r.sized());
        try r.end();
        hash = Sha256.init(.{});
        hash.update(&.{ 0, 0, 0, 0 });
        hash.update(&cc);
        hash.update(reply.parameters);
        const rp_hash = hash.finalResult();
        // HierarchyChangeAuth responses use the newly committed authValue.
        // Request encryption and its HMAC above always use the old value.
        std.crypto.secureZero(u8, value[32..]);
        @memcpy(value[32..][0..response_auth.len], response_auth);
        const response_value = value[0 .. 32 + response_auth.len];
        var expected = crypto.authHmac(response_value, &rp_hash, &next_nonce, &nonce, response_attributes);
        defer std.crypto.secureZero(u8, &expected);
        if (!std.crypto.timing_safe.eql(Key, expected, response_mac)) {
            self.failed = true;
            return error.IntegrityFailure;
        }
        if (attributes & 0x40 != 0) {
            r = .{ .bytes = reply.parameters };
            const encrypted = try r.sized();
            var key_iv = crypto.kdfa(response_value, "CFB", &next_nonce, &nonce);
            defer std.crypto.secureZero(u8, &key_iv);
            crypto.cfb(reply.parameters[2..][0..encrypted.len], &key_iv, .decrypt);
        }
        session.nonce = next_nonce;
        return reply;
    }
};

fn parseHierarchyState(bytes: []const u8) !HierarchyState {
    var r = wire.Reader{ .bytes = bytes };
    if (try r.int(u8) > 1 or try r.int(u32) != 6 or try r.int(u32) != 1 or try r.int(u32) != 0x200) return error.InvalidResponse;
    const flags = try r.int(u32);
    try r.end();
    if (flags & ~@as(u32, 0x707) != 0) return error.InvalidResponse;
    return .{ .owner_auth_set = flags & 1 != 0, .endorsement_auth_set = flags & 2 != 0, .lockout_auth_set = flags & 4 != 0, .in_lockout = flags & 0x200 != 0 };
}

fn optionalAuthorization(auth: ?*const Key) !void {
    if (auth) |value| if (std.mem.allEqual(u8, value, 0)) return error.InvalidAuthorization;
}

const ParentPublic = struct { name: Name, x: Key, y: Key };

fn parseParentPublic(public: []const u8) !ParentPublic {
    if (public.len != PRIMARY_PREFIX.len + 68 or !std.mem.startsWith(u8, public, &PRIMARY_PREFIX)) return error.InvalidResponse;
    var r = wire.Reader{ .bytes = public[PRIMARY_PREFIX.len..] };
    const x = try digest(try r.sized());
    const y = try digest(try r.sized());
    try r.end();
    _ = std.crypto.ecc.P256.fromSerializedAffineCoordinates(x, y, .big) catch return error.InvalidResponse;
    return .{ .name = objectName(public), .x = x, .y = y };
}

fn parseParentReply(bytes: []const u8) !ParentPublic {
    var r = wire.Reader{ .bytes = bytes };
    const public = try parseParentPublic(try r.sized());
    if (!std.mem.eql(u8, try r.sized(), &public.name)) return error.IntegrityFailure;
    var qualified: Name = .{ 0, 0x0b } ++ @as([32]u8, @splat(0));
    var hash = Sha256.init(.{});
    hash.update(&.{ 0x40, 0, 0, 1 }); // storage hierarchy Name
    hash.update(&public.name);
    hash.final(qualified[2..]);
    if (!std.mem.eql(u8, try r.sized(), &qualified)) return error.InvalidResponse;
    try r.end();
    return public;
}

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

fn parseAttestationBlob(blob: []const u8, parent_name: *const Name) !BlobFields {
    if (blob.len > MAX_BLOB_BYTES) return error.InvalidBlob;
    var r = wire.Reader{ .bytes = blob };
    if (!std.mem.eql(u8, try r.take(4), "ZAK1")) return error.InvalidBlob;
    if (!std.mem.eql(u8, try r.take(34), parent_name)) return error.WrongDevice;
    const private = try r.sized();
    const public = try r.sized();
    if (private.len == 0 or private.len > 256) return error.InvalidBlob;
    _ = try quote.Identity.fromPublic(public, parent_name);
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

test "TPM quote client validates pinned enrollment and clears failed outputs before hardware access" {
    const point = std.crypto.ecc.P256.basePoint.affineCoordinates();
    const parent = objectName("test storage parent");
    var public: [quote.PUBLIC_BYTES]u8 = undefined;
    var w = wire.Writer{ .bytes = &public };
    try w.put(&quote.PUBLIC_PREFIX);
    try w.sized(&point.x.toBytes(.big));
    try w.sized(&point.y.toBytes(.big));
    const enrolled = try quote.Identity.fromPublic(&public, &parent);
    var blob = Blob{};
    w = .{ .bytes = &blob.bytes };
    try w.put("ZAK1");
    try w.put(&parent);
    try w.sized("wrapped private area");
    try w.sized(&public);
    blob.len = @intCast(w.pos);
    var client = Client{ .parent = 0x8100_0001, .parent_name = parent, .parent_x = point.x.toBytes(.big), .parent_y = point.y.toBytes(.big) };
    var io = RejectIo{};
    const auth: Key = @splat(7);
    const nonce: Key = @splat(8);
    const pcr: Key = @splat(9);
    var evidence = quote.Evidence{ .bytes = @splat(0xaa), .len = 17 };
    for (0..blob.len) |length| {
        try std.testing.expectError(error.InvalidBlob, client.quoteAttestation(&io, blob.bytes[0..length], &auth, &enrolled, &nonce, &pcr, &evidence));
        try std.testing.expectEqualDeep(quote.Evidence{}, evidence);
        try std.testing.expect(!client.failed);
    }
    var changed = enrolled;
    changed.qualified_name[2] ^= 1;
    try std.testing.expectError(error.AttestationKeyChanged, client.quoteAttestation(&io, blob.slice(), &auth, &changed, &nonce, &pcr, &evidence));
    var damaged = blob;
    damaged.bytes[4] ^= 1;
    try std.testing.expectError(error.WrongDevice, client.quoteAttestation(&io, damaged.slice(), &auth, &enrolled, &nonce, &pcr, &evidence));
    try std.testing.expectError(error.InvalidChallenge, client.quoteAttestation(&io, blob.slice(), &auth, &enrolled, &(@as(Key, @splat(0))), &pcr, &evidence));
    try std.testing.expectError(error.InvalidAuthorization, client.quoteAttestation(&io, blob.slice(), &(@as(Key, @splat(0))), &enrolled, &nonce, &pcr, &evidence));
    var unpublished = blob;
    try std.testing.expectError(error.InvalidAuthorization, client.createAttestationKey(&io, &(@as(Key, @splat(0))), &unpublished));
    try std.testing.expectEqualDeep(Blob{}, unpublished);
    try std.testing.expectEqual(@as(usize, 0), io.calls);
    try std.testing.expectError(error.EntropyUnavailable, client.quoteAttestation(&io, blob.slice(), &auth, &enrolled, &nonce, &pcr, &evidence));
    try std.testing.expectEqualDeep(quote.Evidence{}, evidence);
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expectError(error.EntropyUnavailable, client.createAttestationKey(&io, &auth, &unpublished));
    try std.testing.expectEqualDeep(Blob{}, unpublished);
}

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
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = 0x0100_0000, .size = 32 }, &auth, null));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = MAX_NV_BYTES + 1 }, &auth, null));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 0 }, &auth, null));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 32, .binding = .discover }, &auth, null));
    try std.testing.expectError(error.InvalidNvSpace, client.nvDefine(&io, .{ .index = space.index, .size = 32, .binding = .{ .pinned = @splat(0) } }, &auth, null));
    try std.testing.expectError(error.InvalidNvSpace, client.nvInitialize(&io, space, &auth, &out));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
}

test "TPM lockout administration refuses empty secrets and disabled guessing limits" {
    var client = Client{ .parent = 0x8000_0000 };
    var io = RejectIo{};
    const key: Key = @splat(1);
    const empty: Key = @splat(0);
    try std.testing.expectError(error.InvalidAuthorization, client.changeLockoutAuthorization(&io, null, &empty));
    try std.testing.expectError(error.InvalidAuthorization, client.changeLockoutAuthorization(&io, &empty, &key));
    try std.testing.expectError(error.InvalidAuthorization, client.resetDictionaryAttack(&io, &empty));
    const valid = DictionaryAttackPolicy{ .max_tries = 8, .recovery_seconds = 3600, .lockout_recovery_seconds = 86400 };
    try std.testing.expectError(error.InvalidAuthorization, client.configureDictionaryAttack(&io, &empty, valid));
    for ([_]DictionaryAttackPolicy{
        .{ .max_tries = 0, .recovery_seconds = 60, .lockout_recovery_seconds = 60 },
        .{ .max_tries = 33, .recovery_seconds = 60, .lockout_recovery_seconds = 60 },
        .{ .max_tries = 8, .recovery_seconds = 0, .lockout_recovery_seconds = 60 },
        .{ .max_tries = 8, .recovery_seconds = 60, .lockout_recovery_seconds = 0 },
    }) |policy| try std.testing.expectError(error.InvalidDictionaryAttackPolicy, client.configureDictionaryAttack(&io, &key, policy));
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

test "TPM persistent parent rejects invalid enrollment and cannot evict on close or retry" {
    const name: Name = .{ 0, 0x0b } ++ @as(Key, @splat(3));
    const pin = PersistentParent{ .handle = 0x8100_1234, .name = name };
    var io = RejectIo{};
    var client = Client{};
    for ([_]u32{ 0, 0x8000_0000, 0x8180_0000, 0x81ff_ffff, 0x8200_0000 }) |handle| {
        try std.testing.expectError(error.InvalidPersistentParent, client.openPersistent(&io, .{ .handle = handle, .name = name }));
    }
    var invalid = pin;
    invalid.name[1] = 0x04;
    try std.testing.expectError(error.InvalidPersistentParent, client.openPersistent(&io, invalid));
    invalid = pin;
    @memset(invalid.name[2..], 0);
    try std.testing.expectError(error.InvalidPersistentParent, client.openPersistent(&io, invalid));
    client = .{ .parent = pin.handle, .parent_name = pin.name };
    try std.testing.expectError(error.TransientParentRequired, client.persistParent(&io, pin, null));
    const empty: Key = @splat(0);
    const next: Key = @splat(7);
    try std.testing.expectError(error.InvalidAuthorization, client.changeOwnerAuthorization(&io, null, &empty));
    try std.testing.expectError(error.InvalidAuthorization, client.changeOwnerAuthorization(&io, &empty, &next));
    try std.testing.expectError(error.InvalidAuthorization, client.nvDefine(&io, .{ .index = 0x0180_1234, .size = 32 }, &next, &empty));
    try client.close(&io);
    try std.testing.expectEqual(@as(u32, 0), client.parent);
    try std.testing.expectEqual(@as(usize, 0), io.calls);
}

test "TPM persistent parent public data cannot initialize a client without possession proof" {
    const Io = struct {
        bytes: []const u8,
        reads: usize = 0,
        entropy: usize = 0,
        pub fn execute(self: *@This(), command: []const u8, response: []u8, _: u32) ![]u8 {
            if (self.reads != 0 or command.len != 14 or std.mem.readInt(u32, command[6..10], .big) != READ_PUBLIC) return error.UnexpectedHardwareAccess;
            self.reads += 1;
            var w = wire.Writer{ .bytes = response };
            try w.begin(0x8001, 0);
            try w.put(self.bytes);
            return w.finish();
        }
        pub fn random(self: *@This(), _: []u8) !void {
            self.entropy += 1;
            return error.EntropyUnavailable;
        }
    };
    var bytes: [192]u8 = @splat(0);
    var w = wire.Writer{ .bytes = &bytes };
    const point = std.crypto.ecc.P256.basePoint.affineCoordinates();
    try w.int(u16, PRIMARY_PREFIX.len + 68);
    const offset = w.pos;
    try w.put(&PRIMARY_PREFIX);
    try w.sized(&point.x.toBytes(.big));
    try w.sized(&point.y.toBytes(.big));
    const name = objectName(bytes[offset..w.pos]);
    try w.sized(&name);
    var hash = Sha256.init(.{});
    hash.update(&.{ 0x40, 0, 0, 1 });
    hash.update(&name);
    const qualified: Name = .{ 0, 0x0b } ++ hash.finalResult();
    try w.sized(&qualified);
    const length = w.pos;
    const pin = PersistentParent{ .handle = 0x8100_1234, .name = name };
    var io = Io{ .bytes = bytes[0..length] };
    var client = Client{};
    try std.testing.expectError(error.EntropyUnavailable, client.openPersistent(&io, pin));
    try std.testing.expectEqual(@as(u32, 0), client.parent);
    try std.testing.expectEqual(@as(usize, 1), io.reads);
    try std.testing.expectEqual(@as(usize, 1), io.entropy);
    try std.testing.expect(std.mem.allEqual(u8, &client.command, 0));
    try std.testing.expect(std.mem.allEqual(u8, &client.response, 0));
    for (0..length) |len| try std.testing.expectError(error.InvalidResponse, parseParentReply(bytes[0..len]));
    try std.testing.expectError(error.InvalidResponse, parseParentReply(bytes[0 .. length + 1]));
    for ([_]usize{ 1, 5, 10, length - 1 }) |index| {
        var changed = bytes;
        changed[index] ^= 1;
        try std.testing.expectError(error.InvalidResponse, parseParentReply(changed[0..length]));
    }
    var changed_pin = pin;
    changed_pin.name[10] ^= 1;
    io = .{ .bytes = bytes[0..length] };
    client = .{};
    try std.testing.expectError(error.PersistentParentChanged, client.openPersistent(&io, changed_pin));
    try std.testing.expectEqual(@as(usize, 0), io.entropy);
    try std.testing.expectEqual(@as(u32, 0), client.parent);
}

test "TPM hierarchy state requires exactly one canonical permanent property" {
    var bytes: [17]u8 = undefined;
    var w = wire.Writer{ .bytes = &bytes };
    try w.int(u8, 1);
    try w.int(u32, 6);
    try w.int(u32, 1);
    try w.int(u32, 0x200);
    try w.int(u32, 0x707);
    const state = try parseHierarchyState(&bytes);
    try std.testing.expect(state.owner_auth_set and state.lockout_auth_set and state.endorsement_auth_set and state.in_lockout);
    for (0..bytes.len) |length| {
        if (parseHierarchyState(bytes[0..length])) |_| return error.AcceptedTruncatedHierarchyState else |_| {}
    }
    const oversized = bytes ++ [_]u8{0};
    if (parseHierarchyState(&oversized)) |_| return error.AcceptedOversizedHierarchyState else |_| {}
    for ([_]usize{ 0, 4, 8, 12, 13 }) |offset| {
        var changed = bytes;
        changed[offset] ^= 0x80;
        if (parseHierarchyState(&changed)) |_| return error.AcceptedMalformedHierarchyState else |_| {}
    }
    var client = Client{};
    var io = RejectIo{};
    try std.testing.expectError(error.NotInitialized, client.hierarchyState(&io));
    client.parent = 0x8100_1234;
    client.failed = true;
    try std.testing.expectError(error.Failed, client.hierarchyState(&io));
}
