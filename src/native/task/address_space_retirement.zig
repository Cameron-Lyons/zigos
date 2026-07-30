pub const Reason = enum(u8) {
    rehost,
    terminate,
    runtime_reset,
    snapshot_restore,
};

pub const Event = struct {
    address_space_id: u64,
    reason: Reason,
};

pub const Sink = struct {
    context: *anyopaque,
    notify_fn: *const fn (*anyopaque, Event) void,

    pub fn init(comptime Context: type, context: *Context) Sink {
        return .{
            .context = @ptrCast(context),
            .notify_fn = struct {
                fn notify(raw_context: *anyopaque, event: Event) void {
                    const typed_context: *Context = @ptrCast(@alignCast(raw_context));
                    typed_context.retireAddressSpace(event);
                }
            }.notify,
        };
    }

    pub fn notify(self: Sink, event: Event) void {
        self.notify_fn(self.context, event);
    }

    pub fn eql(self: Sink, other: Sink) bool {
        return self.context == other.context and self.notify_fn == other.notify_fn;
    }
};
