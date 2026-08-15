const std = @import("std");

pub const CapabilityTargetKind = enum(u8) {
    task,
    endpoint,
    service,
    shared_memory,
    object,
    workspace,
    device,
    policy,
    network_policy,
};

pub const CapabilityTarget = struct {
    kind: CapabilityTargetKind,
    id: u64,

    pub fn eql(self: CapabilityTarget, other: CapabilityTarget) bool {
        return self.kind == other.kind and self.id == other.id;
    }
};

pub const CapabilityRight = enum(u8) {
    task_create,
    task_terminate,
    endpoint_create,
    endpoint_connect,
    endpoint_send,
    endpoint_recv,
    input_recv,
    capability_mint,
    capability_derive,
    capability_pass,
    capability_revoke,
    capability_query,
    shared_memory_create,
    shared_memory_map,
    shared_memory_unmap,
    shared_memory_revoke,
    time_query,
    resource_query,
    accounting_query,
    object_read,
    object_write,
    device_use,
    clipboard_read,
    clipboard_write,
    sensor_read,
    background_run,
    network_local,
    network_remote,
    ipc_peer,
    location_read,
    contacts_read,
    screen_capture,
    notification_post,
    process_control,
    surface_present,
};

const RightsBits = packed struct(u64) {
    task_create: bool = false,
    task_terminate: bool = false,
    endpoint_create: bool = false,
    endpoint_connect: bool = false,
    endpoint_send: bool = false,
    endpoint_recv: bool = false,
    input_recv: bool = false,
    capability_mint: bool = false,
    capability_derive: bool = false,
    capability_pass: bool = false,
    capability_revoke: bool = false,
    capability_query: bool = false,
    shared_memory_create: bool = false,
    shared_memory_map: bool = false,
    shared_memory_unmap: bool = false,
    shared_memory_revoke: bool = false,
    time_query: bool = false,
    resource_query: bool = false,
    accounting_query: bool = false,
    object_read: bool = false,
    object_write: bool = false,
    device_use: bool = false,
    clipboard_read: bool = false,
    clipboard_write: bool = false,
    sensor_read: bool = false,
    background_run: bool = false,
    network_local: bool = false,
    network_remote: bool = false,
    ipc_peer: bool = false,
    location_read: bool = false,
    contacts_read: bool = false,
    screen_capture: bool = false,
    notification_post: bool = false,
    process_control: bool = false,
    surface_present: bool = false,
    _reserved: u29 = 0,
};

pub const CapabilityRights = union(CapabilityTargetKind) {
    task: TaskRights,
    endpoint: EndpointRights,
    service: SystemRights,
    shared_memory: SharedMemoryRights,
    object: ObjectRights,
    workspace: WorkspaceRights,
    device: DeviceRights,
    policy: SystemRights,
    network_policy: NetworkPolicyRights,

    pub const TaskRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        task_create: bool = false,
        task_terminate: bool = false,
        input_recv: bool = false,
        time_query: bool = false,
        resource_query: bool = false,
        accounting_query: bool = false,
        background_run: bool = false,
        notification_post: bool = false,
        process_control: bool = false,
        surface_present: bool = false,
    };

    pub const EndpointRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        endpoint_create: bool = false,
        endpoint_connect: bool = false,
        endpoint_send: bool = false,
        endpoint_recv: bool = false,
        ipc_peer: bool = false,
    };

    pub const SharedMemoryRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        shared_memory_create: bool = false,
        shared_memory_map: bool = false,
        shared_memory_unmap: bool = false,
        shared_memory_revoke: bool = false,
    };

    pub const ObjectRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        object_read: bool = false,
        object_write: bool = false,
        contacts_read: bool = false,
    };

    pub const DeviceRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        device_use: bool = false,
        object_read: bool = false,
        object_write: bool = false,
        sensor_read: bool = false,
        location_read: bool = false,
        screen_capture: bool = false,
        network_local: bool = false,
    };

    pub const NetworkPolicyRights = packed struct {
        capability_mint: bool = false,
        capability_derive: bool = false,
        capability_pass: bool = false,
        capability_revoke: bool = false,
        capability_query: bool = false,
        network_local: bool = false,
        network_remote: bool = false,
    };

    pub const WorkspaceRights = RightsBits;
    pub const SystemRights = RightsBits;

    pub fn emptyForTarget(kind: CapabilityTargetKind) CapabilityRights {
        return switch (kind) {
            .task => .{ .task = .{} },
            .endpoint => .{ .endpoint = .{} },
            .service => .{ .service = .{} },
            .shared_memory => .{ .shared_memory = .{} },
            .object => .{ .object = .{} },
            .workspace => .{ .workspace = .{} },
            .device => .{ .device = .{} },
            .policy => .{ .policy = .{} },
            .network_policy => .{ .network_policy = .{} },
        };
    }

    pub fn containsAll(self: CapabilityRights, requested: CapabilityRights) bool {
        if (std.meta.activeTag(self) != std.meta.activeTag(requested) and !self.isSystem() and !requested.isSystem()) return false;
        const owned = self.toBits();
        const needed = requested.toBits();
        return (owned & needed) == needed;
    }

    pub fn intersects(self: CapabilityRights, other: CapabilityRights) bool {
        if (std.meta.activeTag(self) != std.meta.activeTag(other) and !self.isSystem() and !other.isSystem()) return false;
        const left = self.toBits();
        const right = other.toBits();
        return (left & right) != 0;
    }

    pub fn unionWith(self: CapabilityRights, other: CapabilityRights) CapabilityRights {
        if (std.meta.activeTag(self) != std.meta.activeTag(other)) return self;
        return fromBits(std.meta.activeTag(self), self.toBits() | other.toBits());
    }

    pub fn isSystem(self: CapabilityRights) bool {
        return switch (self) {
            .service, .workspace, .policy => true,
            else => false,
        };
    }

    pub fn has(self: CapabilityRights, right: CapabilityRight) bool {
        const bits = self.toRightsBits();
        return switch (right) {
            inline else => |field| @field(bits, @tagName(field)),
        };
    }

    pub fn single(right: CapabilityRight) CapabilityRights {
        var bits = RightsBits{};
        switch (right) {
            inline else => |field| @field(bits, @tagName(field)) = true,
        }
        return .{ .policy = bits };
    }

    pub fn toBits(self: CapabilityRights) u64 {
        return @bitCast(self.toRightsBits());
    }

    pub fn retarget(self: CapabilityRights, kind: CapabilityTargetKind) CapabilityRights {
        return fromBits(kind, self.toBits());
    }

    fn toRightsBits(self: CapabilityRights) RightsBits {
        var bits = RightsBits{};
        switch (self) {
            inline else => |payload| {
                inline for (@typeInfo(@TypeOf(payload)).@"struct".fields) |field| {
                    @field(bits, field.name) = @field(payload, field.name);
                }
            },
        }
        return bits;
    }

    fn fromBits(kind: CapabilityTargetKind, raw_bits: u64) CapabilityRights {
        const bits: RightsBits = @bitCast(raw_bits);
        return switch (kind) {
            .task => .{ .task = projectRights(TaskRights, bits) },
            .endpoint => .{ .endpoint = projectRights(EndpointRights, bits) },
            .service => .{ .service = bits },
            .shared_memory => .{ .shared_memory = projectRights(SharedMemoryRights, bits) },
            .object => .{ .object = projectRights(ObjectRights, bits) },
            .workspace => .{ .workspace = bits },
            .device => .{ .device = projectRights(DeviceRights, bits) },
            .policy => .{ .policy = bits },
            .network_policy => .{ .network_policy = projectRights(NetworkPolicyRights, bits) },
        };
    }

    fn projectRights(comptime T: type, bits: RightsBits) T {
        var out = T{};
        inline for (@typeInfo(T).@"struct".fields) |field| {
            @field(out, field.name) = @field(bits, field.name);
        }
        return out;
    }
};
