const panic_handler = @import("panic.zig");

pub const Error = error{
    OutOfMemory,
    InvalidAddress,
    AccessViolation,
    InvalidParameter,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    DeviceError,
    Timeout,
    Interrupted,
    NotImplemented,
    SystemError,
};

pub const Result = union(enum) {
    ok: void,
    err: Error,
    
    pub fn isOk(self: Result) bool {
        return switch (self) {
            .ok => true,
            .err => false,
        };
    }
    
    pub fn isErr(self: Result) bool {
        return !self.isOk();
    }
    
    pub fn unwrap(self: Result) void {
        switch (self) {
            .ok => {},
            .err => |e| panic_handler.panic("Result unwrap failed: {}", .{e}),
        }
    }
    
    pub fn expect(self: Result, comptime message: []const u8) void {
        switch (self) {
            .ok => {},
            .err => |e| panic_handler.panic("{s}: {}", .{ message, e }),
        }
    }
};

pub fn ResultT(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: Error,
        
        pub fn isOk(self: @This()) bool {
            return switch (self) {
                .ok => true,
                .err => false,
            };
        }
        
        pub fn isErr(self: @This()) bool {
            return !self.isOk();
        }
        
        pub fn unwrap(self: @This()) T {
            return switch (self) {
                .ok => |val| val,
                .err => |e| panic_handler.panic("Result unwrap failed: {}", .{e}),
            };
        }
        
        pub fn unwrapOr(self: @This(), default: T) T {
            return switch (self) {
                .ok => |val| val,
                .err => default,
            };
        }
        
        pub fn expect(self: @This(), comptime message: []const u8) T {
            return switch (self) {
                .ok => |val| val,
                .err => |e| panic_handler.panic("{s}: {}", .{ message, e }),
            };
        }
    };
}

pub fn errorToString(err: Error) []const u8 {
    return switch (err) {
        Error.OutOfMemory => "Out of memory",
        Error.InvalidAddress => "Invalid address",
        Error.AccessViolation => "Access violation",
        Error.InvalidParameter => "Invalid parameter",
        Error.NotFound => "Not found",
        Error.AlreadyExists => "Already exists",
        Error.PermissionDenied => "Permission denied",
        Error.DeviceError => "Device error",
        Error.Timeout => "Timeout",
        Error.Interrupted => "Interrupted",
        Error.NotImplemented => "Not implemented",
        Error.SystemError => "System error",
    };
}

pub fn handleError(err: anyerror, message: []const u8) void {
    panic_handler.panic("{s}: {}", .{ message, err });
}