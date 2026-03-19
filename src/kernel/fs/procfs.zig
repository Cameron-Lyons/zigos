const std = @import("std");
const process = @import("../process/process.zig");
const smp = @import("../smp/smp.zig");
const support = @import("../process/syscall/support.zig");
const system = @import("../process/syscall/system.zig");
const vfs = @import("vfs.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

const MAX_RENDER_SIZE = 2048;
const MAX_MOUNT_INFOS = 8;
const VERSION_TEXT = "ZigOS 0.1.0 (Zig 0.16.0-dev)\n";

const dir_mode = vfs.FileMode{
    .owner_read = true,
    .owner_exec = true,
    .group_read = true,
    .group_exec = true,
    .other_read = true,
    .other_exec = true,
};

const file_mode = vfs.FileMode{
    .owner_read = true,
    .group_read = true,
    .other_read = true,
};

const NodeKind = enum(u8) {
    root = 1,
    cpuinfo = 2,
    meminfo = 3,
    mounts = 4,
    uptime = 5,
    version = 6,
    hostname = 7,
    pid_dir = 8,
    pid_status = 9,
    pid_cwd = 10,
};

const EncodedNode = struct {
    kind: NodeKind,
    pid: u32,
};

const root_entries = [_]struct {
    name: []const u8,
    kind: NodeKind,
    file_type: vfs.FileType,
}{
    .{ .name = "cpuinfo", .kind = .cpuinfo, .file_type = .Regular },
    .{ .name = "hostname", .kind = .hostname, .file_type = .Regular },
    .{ .name = "meminfo", .kind = .meminfo, .file_type = .Regular },
    .{ .name = "mounts", .kind = .mounts, .file_type = .Regular },
    .{ .name = "uptime", .kind = .uptime, .file_type = .Regular },
    .{ .name = "version", .kind = .version, .file_type = .Regular },
};

const pid_entries = [_]struct {
    name: []const u8,
    kind: NodeKind,
}{
    .{ .name = "status", .kind = .pid_status },
    .{ .name = "cwd", .kind = .pid_cwd },
};

const TextBuilder = struct {
    buffer: []u8,
    len: usize = 0,

    fn append(self: *TextBuilder, text: []const u8) void {
        if (self.len >= self.buffer.len) return;
        const count = @min(text.len, self.buffer.len - self.len);
        @memcpy(self.buffer[self.len .. self.len + count], text[0..count]);
        self.len += count;
    }

    fn print(self: *TextBuilder, comptime format: []const u8, args: anytype) void {
        if (self.len >= self.buffer.len) return;
        const rendered = std.fmt.bufPrint(self.buffer[self.len..], format, args) catch return;
        self.len += rendered.len;
    }

    fn slice(self: *const TextBuilder) []const u8 {
        return self.buffer[0..self.len];
    }
};

fn encodeNode(kind: NodeKind, pid: u32) u64 {
    return (@as(u64, pid) << 8) | @as(u64, @intFromEnum(kind));
}

fn decodeNode(inode: u64) EncodedNode {
    return .{
        .kind = @enumFromInt(@as(u8, @truncate(inode & 0xFF))),
        .pid = @intCast(inode >> 8),
    };
}

fn createVNode(name: []const u8, file_type: vfs.FileType, mode: vfs.FileMode, inode: u64, mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const raw = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(raw));

    var vnode_name = [_]u8{0} ** 256;
    const name_len = @min(name.len, vnode_name.len - 1);
    @memcpy(vnode_name[0..name_len], name[0..name_len]);

    vnode.* = .{
        .name = vnode_name,
        .name_len = @intCast(name_len),
        .inode = inode,
        .file_type = file_type,
        .mode = mode,
        .size = 0,
        .uid = 0,
        .gid = 0,
        .ref_count = 1,
        .mount_point = mp,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &procfs_file_ops,
        .private_data = null,
    };

    return vnode;
}

fn parsePid(name: []const u8) ?u32 {
    if (name.len == 0) return null;

    var value: u32 = 0;
    for (name) |char| {
        if (char < '0' or char > '9') return null;
        value = value * 10 + (char - '0');
    }
    return value;
}

fn processName(proc: *const process.Process) []const u8 {
    var len: usize = 0;
    while (len < proc.name.len and proc.name[len] != 0) : (len += 1) {}
    return proc.name[0..len];
}

fn processCwd(proc: *const process.Process) []const u8 {
    if (proc.cwd_len == 0) return "/";
    return proc.cwd_path[0..proc.cwd_len];
}

fn liveProcess(pid: u32) ?*process.Process {
    const proc = process.getProcessByPid(pid) orelse return null;
    if (proc.state == .Terminated) return null;
    return proc;
}

fn nthLiveProcess(index: usize) ?*process.Process {
    var current = process.getProcessList();
    var seen: usize = 0;

    while (current) |proc| : (current = proc.next) {
        if (proc.pid == 0 or proc.state == .Terminated) continue;
        if (seen == index) return proc;
        seen += 1;
    }

    return null;
}

fn fillDirent(dirent: *vfs.DirEntry, name: []const u8, inode: u64, file_type: vfs.FileType) void {
    @memset(&dirent.name, 0);
    const len = @min(name.len, dirent.name.len);
    @memcpy(dirent.name[0..len], name[0..len]);
    dirent.name_len = @intCast(len);
    dirent.inode = inode;
    dirent.file_type = file_type;
}

fn stateName(state: process.ProcessState) []const u8 {
    return switch (state) {
        .Ready => "R (ready)",
        .Running => "R (running)",
        .Blocked => "S (blocked)",
        .Terminated => "X (terminated)",
        .Zombie => "Z (zombie)",
        .Stopped => "T (stopped)",
        .Waiting => "S (waiting)",
    };
}

fn readRendered(buffer: []u8, offset: u64, content: []const u8) usize {
    if (offset >= content.len) return 0;
    const start: usize = @intCast(offset);
    const count = @min(buffer.len, content.len - start);
    @memcpy(buffer[0..count], content[start .. start + count]);
    return count;
}

fn renderCpuInfo(buffer: []u8) []const u8 {
    var builder = TextBuilder{ .buffer = buffer };
    builder.append("processor\t: 0\n");
    builder.append("vendor_id\t: ZigOS\n");
    builder.append("model name\t: ZigOS virtual CPU\n");
    builder.print("cpu cores\t: {d}\n", .{smp.getActiveCPUCount()});
    return builder.slice();
}

fn renderMemInfo(buffer: []u8) []const u8 {
    const info = support.syntheticSysinfo();
    var builder = TextBuilder{ .buffer = buffer };
    builder.print("MemTotal: {d} kB\n", .{info.totalram / 1024});
    builder.print("MemFree: {d} kB\n", .{info.freeram / 1024});
    builder.print("SwapTotal: {d} kB\n", .{info.totalswap / 1024});
    builder.print("SwapFree: {d} kB\n", .{info.freeswap / 1024});
    return builder.slice();
}

fn renderMounts(buffer: []u8) []const u8 {
    var mounts: [MAX_MOUNT_INFOS]vfs.MountInfo = undefined;
    const count = vfs.snapshotMounts(mounts[0..]);

    var builder = TextBuilder{ .buffer = buffer };
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const mount = mounts[i];
        const device = if (mount.device_len == 0) "none" else mount.device[0..mount.device_len];
        builder.print("{s} {s} {s} {d}\n", .{
            device,
            mount.mount_path[0..mount.mount_path_len],
            mount.fs_name[0..mount.fs_name_len],
            mount.flags,
        });
    }

    return builder.slice();
}

fn renderUptime(buffer: []u8) []const u8 {
    const info = support.syntheticSysinfo();
    return std.fmt.bufPrint(buffer, "{d}\n", .{info.uptime}) catch buffer[0..0];
}

fn renderPidStatus(proc: *const process.Process, buffer: []u8) []const u8 {
    var builder = TextBuilder{ .buffer = buffer };
    builder.print("Name:\t{s}\n", .{processName(proc)});
    builder.print("Pid:\t{d}\n", .{proc.pid});
    builder.print("PPid:\t{d}\n", .{proc.parent_pid});
    builder.print("State:\t{s}\n", .{stateName(proc.state)});
    builder.print("Uid:\t{d}\t{d}\t{d}\t{d}\n", .{ proc.creds.uid, proc.creds.euid, proc.creds.uid, proc.creds.euid });
    builder.print("Gid:\t{d}\t{d}\t{d}\t{d}\n", .{ proc.creds.gid, proc.creds.egid, proc.creds.gid, proc.creds.egid });
    builder.print("Cwd:\t{s}\n", .{processCwd(proc)});
    builder.append("Threads:\t1\n");
    return builder.slice();
}

fn renderPidCwd(proc: *const process.Process, buffer: []u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}\n", .{processCwd(proc)}) catch buffer[0..0];
}

fn renderNode(node: EncodedNode, buffer: []u8) vfs.VFSError![]const u8 {
    return switch (node.kind) {
        .cpuinfo => renderCpuInfo(buffer),
        .meminfo => renderMemInfo(buffer),
        .mounts => renderMounts(buffer),
        .uptime => renderUptime(buffer),
        .version => VERSION_TEXT[0..VERSION_TEXT.len],
        .hostname => std.fmt.bufPrint(buffer, "{s}\n", .{system.getHostname()}) catch buffer[0..0],
        .pid_status => blk: {
            const proc = liveProcess(node.pid) orelse return vfs.VFSError.NotFound;
            break :blk renderPidStatus(proc, buffer);
        },
        .pid_cwd => blk: {
            const proc = liveProcess(node.pid) orelse return vfs.VFSError.NotFound;
            break :blk renderPidCwd(proc, buffer);
        },
        else => return vfs.VFSError.InvalidOperation,
    };
}

fn procfsRead(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    if (vnode.file_type == .Directory) return vfs.VFSError.IsDirectory;

    const node = decodeNode(vnode.inode);
    var render_buffer: [MAX_RENDER_SIZE]u8 = undefined;
    const content = try renderNode(node, &render_buffer);
    return readRendered(buffer, offset, content);
}

fn procfsWrite(_: *vfs.VNode, _: []const u8, _: u64) vfs.VFSError!usize {
    return vfs.VFSError.ReadOnly;
}

fn procfsOpen(_: *vfs.VNode, _: u32) vfs.VFSError!void {}

fn procfsClose(_: *vfs.VNode) vfs.VFSError!void {}

fn procfsSeek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const size: i64 = @intCast(vnode.size);
    const absolute = switch (whence) {
        vfs.SEEK_SET => offset,
        vfs.SEEK_END => size + offset,
        else => return vfs.VFSError.InvalidOperation,
    };
    if (absolute < 0) return vfs.VFSError.InvalidOperation;
    return @intCast(absolute);
}

fn procfsIoctl(_: *vfs.VNode, _: u32, _: usize) vfs.VFSError!i32 {
    return vfs.VFSError.InvalidOperation;
}

fn procfsStat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    var size: u64 = 0;
    if (vnode.file_type == .Regular) {
        var render_buffer: [MAX_RENDER_SIZE]u8 = undefined;
        const content = try renderNode(decodeNode(vnode.inode), &render_buffer);
        size = content.len;
        vnode.size = size;
    }

    stat_buf.* = .{
        .inode = vnode.inode,
        .mode = vnode.mode,
        .file_type = vnode.file_type,
        .size = size,
        .blocks = (size + 511) / 512,
        .block_size = 512,
        .uid = 0,
        .gid = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn procfsReaddir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    const node = decodeNode(vnode.inode);
    switch (node.kind) {
        .root => {
            if (index < root_entries.len) {
                const entry = root_entries[@intCast(index)];
                fillDirent(dirent, entry.name, encodeNode(entry.kind, 0), entry.file_type);
                return true;
            }

            const proc = nthLiveProcess(@intCast(index - root_entries.len)) orelse return false;
            var name_buffer: [16]u8 = undefined;
            const rendered = std.fmt.bufPrint(&name_buffer, "{d}", .{proc.pid}) catch return false;
            fillDirent(dirent, rendered, encodeNode(.pid_dir, proc.pid), .Directory);
            return true;
        },
        .pid_dir => {
            if (liveProcess(node.pid) == null) return vfs.VFSError.NotFound;
            if (index >= pid_entries.len) return false;
            const entry = pid_entries[@intCast(index)];
            fillDirent(dirent, entry.name, encodeNode(entry.kind, node.pid), .Regular);
            return true;
        },
        else => return vfs.VFSError.NotDirectory,
    }
}

fn procfsTruncate(_: *vfs.VNode, _: u64) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn procfsChmod(_: *vfs.VNode, _: vfs.FileMode) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn procfsChown(_: *vfs.VNode, _: u32, _: u32) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const procfs_file_ops = vfs.FileOps{
    .read = procfsRead,
    .write = procfsWrite,
    .open = procfsOpen,
    .close = procfsClose,
    .seek = procfsSeek,
    .ioctl = procfsIoctl,
    .stat = procfsStat,
    .readdir = procfsReaddir,
    .truncate = procfsTruncate,
    .chmod = procfsChmod,
    .chown = procfsChown,
};

fn procfsMount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn procfsUnmount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn procfsGetRoot(mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    return createVNode("/", .Directory, dir_mode, encodeNode(.root, 0), mp);
}

fn procfsLookup(parent: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const node = decodeNode(parent.inode);
    switch (node.kind) {
        .root => {
            for (root_entries) |entry| {
                if (std.mem.eql(u8, entry.name, name)) {
                    return createVNode(name, entry.file_type, file_mode, encodeNode(entry.kind, 0), parent.mount_point.?);
                }
            }

            const pid = parsePid(name) orelse return vfs.VFSError.NotFound;
            if (liveProcess(pid) == null) return vfs.VFSError.NotFound;
            return createVNode(name, .Directory, dir_mode, encodeNode(.pid_dir, pid), parent.mount_point.?);
        },
        .pid_dir => {
            if (liveProcess(node.pid) == null) return vfs.VFSError.NotFound;
            for (pid_entries) |entry| {
                if (std.mem.eql(u8, entry.name, name)) {
                    return createVNode(name, .Regular, file_mode, encodeNode(entry.kind, node.pid), parent.mount_point.?);
                }
            }
            return vfs.VFSError.NotFound;
        },
        else => return vfs.VFSError.NotDirectory,
    }
}

fn procfsCreate(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn procfsMkdir(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn procfsUnlink(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn procfsRmdir(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn procfsRename(_: *vfs.VNode, _: []const u8, _: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const procfs_ops = vfs.FileSystemOps{
    .mount = procfsMount,
    .unmount = procfsUnmount,
    .get_root = procfsGetRoot,
    .lookup = procfsLookup,
    .create = procfsCreate,
    .mkdir = procfsMkdir,
    .unlink = procfsUnlink,
    .rmdir = procfsRmdir,
    .rename = procfsRename,
};

var procfs_type = vfs.FileSystemType{
    .name = blk: {
        var name = [_]u8{0} ** 32;
        name[0] = 'p';
        name[1] = 'r';
        name[2] = 'o';
        name[3] = 'c';
        name[4] = 'f';
        name[5] = 's';
        break :blk name;
    },
    .ops = &procfs_ops,
    .next = null,
};

pub fn init() void {
    vfs.registerFileSystem(&procfs_type) catch {
        vga.print("Failed to register procfs\n");
        return;
    };
    vga.print("procfs filesystem registered\n");
}
