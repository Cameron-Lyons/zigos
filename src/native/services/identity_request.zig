//! Trusted native credential grant. Application frames contain only a challenge;
//! credential selection, RP/origin, expiry and sign-in binding come from the owner.
const identity = @import("../platform/os_identity.zig");

pub const Grant = struct {
    credential_id: u64,
    relying_party_id: []const u8,
    origin: []const u8,
    session: identity.unlock_context.Binding,
    expires_at_ticks: u64,
};

pub const Request = struct { grant: Grant, challenge: []const u8 };

// Native-only lifetime interface. A single consumer owns an accepted operation
// until poll returns a result/error. Cancel is nonblocking and idempotent; the
// consumer must keep polling until terminal completion before releasing backing.
pub const Backend = struct {
    context: *anyopaque,
    authorized: *const fn (*anyopaque, Grant, u64) bool,
    start: *const fn (*anyopaque, Request, u64) anyerror!void,
    poll: *const fn (*anyopaque, u64) anyerror!?identity.Assertion,
    cancel: *const fn (*anyopaque) void,
};
