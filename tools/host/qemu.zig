const std = @import("std");
const common = @import("common.zig");
const images = @import("images.zig");
const markers = @import("native_smoke_markers");
const process = @import("qemu/process.zig");
const log = @import("qemu/log.zig");
const efi_fixture = @import("efi_fixture.zig");

const Args = std.ArrayList([]const u8);
const success_exit = 33;
var failure_exit_code: u8 = 1;

pub fn interruptionExitCode() u8 {
    return process.interruptionExitCode();
}

pub fn failureExitCode() u8 {
    return failure_exit_code;
}

fn fmt(ctx: *common.Context, comptime format: []const u8, values: anytype) ![]const u8 {
    return std.fmt.allocPrint(ctx.allocator, format, values);
}

fn env(ctx: *common.Context, name: []const u8, default: []const u8) []const u8 {
    const value = ctx.env(name) orelse return default;
    return if (value.len == 0) default else value;
}

fn arg(args: []const []const u8, index: usize, default: []const u8) []const u8 {
    return if (index < args.len) args[index] else default;
}

fn require(args: []const []const u8, count: usize) !void {
    if (args.len < count) return error.InvalidArguments;
}

fn fail(ctx: *common.Context, comptime format: []const u8, values: anytype) anyerror {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stderr().writer(ctx.io, &buffer);
    writer.interface.print(format, values) catch {};
    writer.interface.flush() catch {};
    return error.ValidationFailed;
}

fn dump(ctx: *common.Context, bytes: []const u8) void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stderr().writer(ctx.io, &buffer);
    writer.interface.writeAll(bytes) catch {};
    writer.interface.flush() catch {};
}

fn readOptional(ctx: *common.Context, path: []const u8) ![]const u8 {
    return ctx.read(path) catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
}

fn remove(ctx: *common.Context, path: []const u8) !void {
    std.Io.Dir.cwd().deleteFile(ctx.io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn stem(path: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, path, ".log")) path[0 .. path.len - 4] else path;
}

fn regularFile(ctx: *common.Context, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(ctx.io, path, .{}) catch return false;
    return stat.kind == .file;
}

// macOS's Unix-domain socket paths are limited to 104 bytes. The ordinary
// per-user TMPDIR can exceed that once the emulator's control path is added.
fn socketTempDir(ctx: *common.Context, prefix: []const u8) ![]const u8 {
    for (0..32) |_| {
        var random: [16]u8 = undefined;
        try std.Io.randomSecure(ctx.io, &random);
        const path = try fmt(ctx, "/tmp/{s}-{s}", .{ prefix, std.fmt.bytesToHex(random, .lower) });
        std.Io.Dir.cwd().createDir(ctx.io, path, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        return path;
    }
    return error.TemporaryDirectoryCollision;
}

fn checkGroup(ctx: *common.Context, bytes: []const u8, group: []const []const u8) !void {
    for (group) |marker| {
        if (!log.contains(bytes, marker)) {
            dump(ctx, bytes);
            return fail(ctx, "Missing boot proof: {s}\n", .{marker});
        }
    }
}

fn absentGroup(ctx: *common.Context, bytes: []const u8, group: []const []const u8) !void {
    for (group) |marker| {
        if (log.contains(bytes, marker)) {
            dump(ctx, bytes);
            return fail(ctx, "Unexpected boot proof: {s}\n", .{marker});
        }
    }
}

fn healthy(ctx: *common.Context, bytes: []const u8, failure: []const u8) !void {
    if (!log.healthy(bytes, failure)) {
        dump(ctx, bytes);
        return fail(ctx, "QEMU boot failed: no serial output or panic/failure marker observed\n", .{});
    }
}

const Harness = struct {
    ctx: *common.Context,
    boot_iso: ?[]const u8,
    vars_override: ?[]const u8 = null,
    code_override: ?[]const u8 = null,
    cpu_override: ?[]const u8 = null,
    cache_override: ?[]const u8 = null,
    write_cache_override: ?[]const u8 = null,
    // Only the full kernel entry smoke treats baseline rejection as an early
    // unsupported target. Deliberate negative CPU proofs keep their own markers.
    reject_cpu_baseline: bool = false,

    fn binary(self: Harness) []const u8 {
        return env(self.ctx, "QEMU_BIN", "qemu-system-x86_64");
    }

    fn memory(self: Harness) []const u8 {
        return env(self.ctx, "QEMU_MEMORY", "256M");
    }

    fn smokeMemory(self: Harness) []const u8 {
        return env(self.ctx, "QEMU_NATIVE_SMOKE_MEMORY", self.memory());
    }

    fn profileMemory(self: Harness) []const u8 {
        return env(self.ctx, "QEMU_PROFILE_MEMORY", self.memory());
    }

    fn accelerator(self: Harness) []const u8 {
        if (self.ctx.env("QEMU_ACCELERATOR")) |value| if (value.len > 0) return value;
        const kvm = std.Io.Dir.cwd().openFile(self.ctx.io, "/dev/kvm", .{ .mode = .read_write }) catch return "";
        defer kvm.close(self.ctx.io);
        const stat = kvm.stat(self.ctx.io) catch return "";
        return if (stat.kind == .character_device) "kvm" else "";
    }

    fn cpu(self: Harness) ![]const u8 {
        if (self.cpu_override) |value| return value;
        if (self.ctx.env("QEMU_CPU_MODEL")) |value| if (value.len > 0) return value;
        if (std.mem.startsWith(u8, self.accelerator(), "kvm")) return "host";
        var model: []const u8 = "max,+x2apic,+pdpe1gb,+pcid,+invpcid,+smap,+smep,+umip,+pku,+xsaves,+cet,+fred,+lkgs,+lass,tsc-frequency=2400000000";
        const help = self.ctx.capture(&.{ self.binary(), "-device", "max-x86_64-cpu,help" }) catch return model;
        const combined = try fmt(self.ctx, "{s}{s}", .{ help.stdout, help.stderr });
        if (combined.len == 0) return model;
        if (!log.contains(combined, "  cet=<bool>") and log.contains(combined, "  cet-ibt=<bool>"))
            model = try std.mem.replaceOwned(u8, self.ctx.allocator, model, "+cet,", "+cet-ibt,+cet-ss,");
        if (!log.contains(combined, "  lass=<bool>"))
            model = try std.mem.replaceOwned(u8, self.ctx.allocator, model, "+lass,", "");
        return model;
    }

    fn firmware(self: Harness, code: bool) !?[]const u8 {
        const key = if (code) "OVMF_CODE" else "OVMF_VARS";
        if (if (code) self.code_override else self.vars_override) |path| {
            if (!regularFile(self.ctx, path)) return error.FirmwareNotFound;
            return path;
        }
        if (self.ctx.env(key)) |path| {
            if (path.len > 0) {
                if (!regularFile(self.ctx, path)) {
                    try self.ctx.print("{s} is set but does not exist: {s}\n", .{ key, path });
                    return error.FirmwareNotFound;
                }
                return path;
            }
        }
        const paths = if (code) &[_][]const u8{
            "/usr/share/OVMF/OVMF_CODE.fd",                 "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",            "/usr/share/edk2/ovmf/OVMF_CODE_4M.fd",
            "/usr/share/edk2/x64/OVMF_CODE.fd",             "/usr/share/qemu/edk2-x86_64-code.fd",
            "/opt/homebrew/share/qemu/edk2-x86_64-code.fd", "/usr/local/share/qemu/edk2-x86_64-code.fd",
        } else &[_][]const u8{
            "/usr/share/OVMF/OVMF_VARS.fd",                 "/usr/share/OVMF/OVMF_VARS_4M.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",            "/usr/share/edk2/ovmf/OVMF_VARS_4M.fd",
            "/usr/share/edk2/x64/OVMF_VARS.fd",             "/usr/share/qemu/edk2-x86_64-vars.fd",
            "/opt/homebrew/share/qemu/edk2-x86_64-vars.fd", "/usr/local/share/qemu/edk2-x86_64-vars.fd",
        };
        for (paths) |path| if (regularFile(self.ctx, path)) return path;
        if (code) {
            try self.ctx.print("No OVMF firmware found. Set OVMF_CODE or install OVMF/edk2-ovmf.\n", .{});
            return error.FirmwareNotFound;
        }
        return null;
    }

    fn build(self: Harness, iso: []const u8, memory_size: []const u8, serial: []const u8, debug_exit: bool, no_shutdown: bool) !Args {
        const ctx = self.ctx;
        if (try ctx.findExecutable(self.binary()) == null) {
            try ctx.print("QEMU binary '{s}' not found. Set QEMU_BIN or install QEMU.\n", .{self.binary()});
            return error.QemuNotFound;
        }
        const code = (try self.firmware(true)).?;
        var command: Args = .empty;
        try command.appendSlice(ctx.allocator, &.{ self.binary(), "-machine", "q35,sata=off", "-m", memory_size, "-display", "none", "-serial", serial, "-monitor", "none", "-no-reboot", "-drive", try fmt(ctx, "if=pflash,format=raw,readonly=on,file={s}", .{code}) });
        const accel = self.accelerator();
        if (accel.len > 0) try command.appendSlice(ctx.allocator, &.{ "-accel", accel });
        try command.appendSlice(ctx.allocator, &.{ "-cpu", try self.cpu() });
        if (try self.firmware(false)) |vars| {
            const destination = env(ctx, "QEMU_OVMF_VARS_COPY", if (std.mem.startsWith(u8, serial, "file:"))
                try fmt(ctx, "{s}.ovmf-vars.fd", .{serial[5..]})
            else
                try fmt(ctx, "build/ovmf-vars-{d}.fd", .{std.c.getpid()}));
            try ctx.mkdir(std.fs.path.dirname(destination) orelse ".");
            try ctx.copy(vars, destination);
            try command.appendSlice(ctx.allocator, &.{ "-drive", try fmt(ctx, "if=pflash,format=raw,file={s}", .{destination}) });
        }
        try command.appendSlice(ctx.allocator, &.{ "-drive", try fmt(ctx, "if=none,file={s},format=raw,readonly=on,media=cdrom,id=zigos_boot_media", .{iso}), "-device", "virtio-scsi-pci,id=zigos_boot_scsi", "-device", "scsi-cd,drive=zigos_boot_media,bus=zigos_boot_scsi.0,bootindex=1", "-boot", "order=c,strict=on" });
        if (no_shutdown) try command.append(ctx.allocator, "-no-shutdown");
        if (debug_exit) try command.appendSlice(ctx.allocator, &.{ "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04" });
        // Match Bash read -a: whitespace-separated literal arguments, no eval.
        var extra = std.mem.tokenizeAny(u8, env(ctx, "QEMU_EXTRA_ARGS", ""), " \t\r\n");
        while (extra.next()) |value| try command.append(ctx.allocator, value);
        return command;
    }

    fn kernel(self: Harness, memory_size: []const u8, serial: []const u8, debug_exit: bool, no_shutdown: bool) !Args {
        const iso = self.boot_iso orelse return error.BootIsoRequired;
        if (iso.len == 0) return error.BootIsoRequired;
        return self.build(iso, memory_size, serial, debug_exit, no_shutdown);
    }

    fn appendStore(self: Harness, command: *Args, image: []const u8) !void {
        const cache = self.cache_override orelse env(self.ctx, "ZIGOS_NATIVE_STORE_CACHE", "writethrough");
        const write_cache = self.write_cache_override orelse env(self.ctx, "ZIGOS_NVME_WRITE_CACHE", "auto");
        if (!std.mem.eql(u8, cache, "writeback") and !std.mem.eql(u8, cache, "writethrough")) return error.InvalidStoreCache;
        if (!std.mem.eql(u8, write_cache, "on") and !std.mem.eql(u8, write_cache, "off") and !std.mem.eql(u8, write_cache, "auto")) return error.InvalidNvmeWriteCache;
        try command.appendSlice(self.ctx.allocator, &.{ "-drive", try fmt(self.ctx, "file={s},if=none,format=raw,id=disk0,cache={s}", .{ image, cache }), "-device", try fmt(self.ctx, "nvme,drive=disk0,serial=zigosnvme0,write-cache={s}", .{write_cache}) });
    }

    fn until(self: Harness, store: ?[]const u8, path: []const u8, marker: []const u8, failure_marker: ?[]const u8, limit: u32, memory_size: []const u8, extra: []const []const u8) !void {
        const ctx = self.ctx;
        try ctx.mkdir(std.fs.path.dirname(path) orelse ".");
        try remove(ctx, path);
        const qemu_log = try fmt(ctx, "{s}.qemu.log", .{stem(path)});
        var command = try self.kernel(memory_size, try fmt(ctx, "file:{s}", .{path}), true, false);
        if (store) |image| try self.appendStore(&command, image);
        try command.appendSlice(ctx.allocator, extra);
        var child = try process.Child.start(ctx, command.items, qemu_log);
        defer child.stop(ctx, process.grace(ctx));
        const start = std.Io.Timestamp.now(ctx.io, .awake);
        while (try child.poll()) {
            const bytes = try readOptional(ctx, path);
            defer ctx.allocator.free(bytes);
            // Serial emits the marker and feature name in separate writes.
            // Once rejection arrives, do not accept another marker or stop the
            // child until its complete reason is available (or it exits/times out).
            const cpu_rejection = if (self.reject_cpu_baseline) entryCpuRejection(bytes) else null;
            if (cpu_rejection) |reason| if (reason.len != 0) {
                child.stop(ctx, process.grace(ctx));
                return reportEntryCpuRejection(ctx, bytes, reason, path);
            };
            if (cpu_rejection == null and (log.contains(bytes, marker) or (if (failure_marker) |failure| log.contains(bytes, failure) else false))) {
                if (store != null) {
                    const seconds = std.fmt.parseFloat(f64, env(ctx, "QEMU_MARKER_STOP_DELAY", "1")) catch return error.InvalidArguments;
                    if (!std.math.isFinite(seconds) or seconds < 0 or seconds > 86400) return error.InvalidArguments;
                    try process.pause(ctx, @intFromFloat(seconds * 1000));
                }
                child.stop(ctx, process.grace(ctx));
                break;
            }
            if (process.elapsed(ctx, start) >= @as(i64, limit) * 1000) {
                child.stop(ctx, process.grace(ctx));
                break;
            }
            try process.pause(ctx, 1000);
        }
        const bytes = try readOptional(ctx, path);
        if (self.reject_cpu_baseline) {
            if (entryCpuRejection(bytes)) |reason|
                return reportEntryCpuRejection(ctx, bytes, reason, path);
        }
        if (bytes.len == 0 or !log.contains(bytes, marker)) {
            dump(ctx, bytes);
            dump(ctx, try readOptional(ctx, qemu_log));
            return fail(ctx, "QEMU run failed: validation marker '{s}' not observed in {s}\n", .{ marker, path });
        }
    }

    fn forSeconds(self: Harness, iso: []const u8, path: []const u8, limit: u32, memory_size: []const u8) !void {
        const ctx = self.ctx;
        try ctx.mkdir(std.fs.path.dirname(path) orelse ".");
        try remove(ctx, path);
        const command = try self.build(iso, memory_size, try fmt(ctx, "file:{s}", .{path}), true, false);
        var child = try process.Child.start(ctx, command.items, try fmt(ctx, "{s}.qemu.log", .{stem(path)}));
        defer child.stop(ctx, process.grace(ctx));
        try process.pause(ctx, @as(i64, limit) * 1000);
        child.stop(ctx, process.grace(ctx));
    }
};

pub fn run(ctx: *common.Context, command: []const u8, input: []const []const u8) !void {
    failure_exit_code = 1;
    const signals = process.Signals.install();
    defer signals.restore();
    var args = input;
    var harness: Harness = .{ .ctx = ctx, .boot_iso = ctx.env("QEMU_BOOT_ISO") };
    if (args.len >= 2 and std.mem.eql(u8, args[0], "--boot-iso")) {
        harness.boot_iso = args[1];
        args = args[2..];
    }
    if (std.mem.eql(u8, command, "run-with-qemu-boot-iso")) {
        try require(args, 2);
        const wrapped = try ctx.allocator.alloc([]const u8, args.len);
        wrapped[0] = "--boot-iso";
        wrapped[1] = args[0];
        @memcpy(wrapped[2..], args[2..]);
        const basename = std.fs.path.basename(args[1]);
        const name = if (std.mem.endsWith(u8, basename, ".sh")) basename[0 .. basename.len - 3] else basename;
        return run(ctx, name, wrapped);
    }
    if (std.mem.eql(u8, command, "qemu-harness")) return runHarness(harness, args);
    if (std.mem.eql(u8, command, "run-headless-qemu")) {
        try require(args, 1);
        const argv = try harness.kernel(arg(args, 1, harness.profileMemory()), arg(args, 2, env(ctx, "QEMU_SERIAL_TARGET", "stdio")), true, false);
        const status = try process.run(ctx, argv.items, null);
        if (status != 0 and status != success_exit) {
            failure_exit_code = @intCast(@min(status, 255));
            return error.QemuFailed;
        }
        return;
    }
    if (std.mem.eql(u8, command, "run-uefi-boot-test")) return uefiBoot(harness, args);
    if (std.mem.eql(u8, command, "run-long-mode-entry-smoke")) return entrySmoke(harness, args, true);
    if (std.mem.eql(u8, command, "run-native-crypto-smoke")) return nativeCryptoSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-high-half-smoke")) return highHalfSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-mapping-xstate-smoke")) return mappingXstateSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-ap-cache-rejection-smoke")) return apCacheRejectionSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-smp-cache-enabled-match-smoke")) return smpCacheEnabledMatchSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-x86-64-kernel-smoke")) return entrySmoke(harness, args, false);
    if (std.mem.eql(u8, command, "capture-kernel-benchmark")) return benchmark(harness, args);
    if (std.mem.eql(u8, command, "run-kernel-recovery")) return recovery(harness, args);
    if (std.mem.eql(u8, command, "run-zigos-native-smoke")) return nativeSmoke(harness, args);
    if (std.mem.eql(u8, command, "run-storage-durability-qemu")) return storageDurability(harness, args);
    if (std.mem.eql(u8, command, "run-sync-two-node-qemu")) return twoNode(harness, args);
    if (std.mem.eql(u8, command, "run-tpm2-qemu")) return tpm2(harness, args);
    if (std.mem.eql(u8, command, "run-unified-efi-qemu")) return unifiedEfi(harness, args);
    return error.UnknownCommand;
}

fn runHarness(h: Harness, args: []const []const u8) !void {
    try require(args, 1);
    const ctx = h.ctx;
    if (std.mem.eql(u8, args[0], "uefi-cdrom")) {
        try require(args, 4);
        return h.forSeconds(args[1], args[2], try std.fmt.parseInt(u32, args[3], 10), arg(args, 4, h.memory()));
    }
    const store = std.mem.eql(u8, args[0], "native-store");
    if (!store and !std.mem.eql(u8, args[0], "kernel")) return error.InvalidArguments;
    try require(args, if (store) 3 else 2);
    const offset: usize = if (store) 3 else 2;
    var command = try h.kernel(arg(args, offset + 1, if (store) h.memory() else h.profileMemory()), arg(args, offset, "stdio"), !store, store);
    if (store) try h.appendStore(&command, args[2]);
    if (args.len > offset + 3) try command.appendSlice(ctx.allocator, args[offset + 3 ..]);
    const output = arg(args, offset + 2, "");
    const status = try process.run(ctx, command.items, if (output.len > 0) output else null);
    if (status != 0 and status != success_exit) {
        failure_exit_code = @intCast(@min(status, 255));
        return error.QemuFailed;
    }
}

fn uefiBoot(h: Harness, args: []const []const u8) !void {
    try require(args, 3);
    if (!std.mem.eql(u8, args[2], "production") and !std.mem.eql(u8, args[2], "verification")) return error.InvalidArguments;
    try h.forSeconds(args[0], args[1], try process.seconds(h.ctx, "UEFI_BOOT_TEST_SECONDS", "20"), h.memory());
    const bytes = try h.ctx.read(args[1]);
    try healthy(h.ctx, bytes, "FAIL");
    try checkGroup(h.ctx, bytes, &.{ "BOOT:START", try fmt(h.ctx, "BOOT:ROLE:{s}", .{args[2]}), "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY", "ZIGOS:CPU:NX:ENABLED", "ZIGOS:CPU:PGE:ENABLED", "ZIGOS:CPU:SYSCALL:ENABLED", "ZIGOS:CPU:PCID:READY", "ZIGOS:KERNEL:W_X:ENFORCED", "Welcome to Zigos", "Initializing GDT", "BOOT:CORE_READY" });
    try h.ctx.print("UEFI boot test passed. Log: {s}\n", .{args[1]});
}

// null means no complete rejection marker; an empty reason means the marker
// arrived but the separately written diagnostic line has not completed yet.
fn entryCpuRejection(bytes: []const u8) ?[]const u8 {
    const rejected = "ZIGOS:CPU:BASELINE:MODERN_X86_64:REJECTED";
    const reason_prefix = "Unsupported CPU: missing ";
    var remaining = bytes;
    var observed = false;
    while (std.mem.indexOfScalar(u8, remaining, '\n')) |end| {
        const raw = remaining[0..end];
        const line = if (std.mem.endsWith(u8, raw, "\r")) raw[0 .. raw.len - 1] else raw;
        if (std.mem.eql(u8, line, rejected)) observed = true;
        if (observed and std.mem.startsWith(u8, line, reason_prefix) and line.len > reason_prefix.len)
            return line;
        remaining = remaining[end + 1 ..];
    }
    return if (observed) "" else null;
}

fn reportEntryCpuRejection(ctx: *common.Context, bytes: []const u8, reason: []const u8, path: []const u8) anyerror {
    dump(ctx, bytes);
    if (reason.len != 0) {
        ctx.warn("QEMU target unsupported: {s}. Log: {s}\n", .{ reason, path }) catch {};
    } else {
        ctx.warn("QEMU target unsupported: CPU baseline rejected without a complete feature diagnostic. Log: {s}\n", .{path}) catch {};
    }
    return error.UnsupportedCpuTarget;
}

fn entrySmoke(h: Harness, args: []const []const u8, long_mode: bool) !void {
    try require(args, 2);
    const ready = if (long_mode) "ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:READY" else "ZIGOS:USERSPACE:RESUME:OK";
    var configured = h;
    configured.boot_iso = args[0];
    configured.reject_cpu_baseline = !long_mode;
    try configured.until(null, args[1], ready, if (long_mode) "ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:FAIL" else null, try process.seconds(h.ctx, if (long_mode) "ZIGOS_LONG_MODE_ENTRY_SECONDS" else "ZIGOS_X86_64_KERNEL_SECONDS", "30"), if (long_mode) "128M" else h.memory(), &.{});
    const bytes = try h.ctx.read(args[1]);
    if (long_mode) {
        try absentGroup(h.ctx, bytes, &.{"ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:FAIL"});
    } else {
        try checkGroup(h.ctx, bytes, &.{ "BOOT:START", "BOOT:PROFILE:zigos_native", "BOOT:ROLE:production", "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY", "ZIGOS:CPU:NX:ENABLED", "ZIGOS:CPU:PGE:ENABLED", "ZIGOS:CPU:SYSCALL:ENABLED", "ZIGOS:CPU:PCID:READY", "ZIGOS:ARCH:X86_64:PAGING:READY", "ZIGOS:KERNEL:W_X:ENFORCED", "BOOT:CORE_READY", "ZIGOS:USERSPACE:ARTIFACTS:READY", "ZIGOS:USERSPACE:EXEC_PROBE:OK" });
    }
    try h.ctx.print("{s} smoke test passed. Log: {s}\n", .{ if (long_mode) "Long-mode entry" else "x86-64 kernel and userspace launch", args[1] });
}

const native_crypto_proofs = [_][]const u8{
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:INITIAL_FP_CONTROLS:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:AVX2:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:AES128:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:SHA256:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:GHASH:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:CHECKSUM_XXH64:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:XSTATE_X87_XMM_YMM_128:PASS",
    "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:PASS",
};

fn nativeCryptoSmoke(h: Harness, args: []const []const u8) !void {
    try require(args, 2);
    var configured = h;
    configured.boot_iso = args[0];
    try configured.until(null, args[1], native_crypto_proofs[native_crypto_proofs.len - 1], "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:FAIL", try process.seconds(h.ctx, "ZIGOS_NATIVE_CRYPTO_SECONDS", "30"), "256M", &.{});
    const bytes = try h.ctx.read(args[1]);
    try healthy(h.ctx, bytes, "FAIL");
    log.exactOrdered(bytes, &native_crypto_proofs) catch |err| {
        dump(h.ctx, bytes);
        return err;
    };
    try h.ctx.print("Native AVX2, crypto and xstate smoke test passed. Log: {s}\n", .{args[1]});
}

const high_half_proofs = [_][]const u8{
    "ZIGOS:ARCH:X86_64:HIGH_HALF:ENTRY:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:STACK:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:IMAGE_LMA:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:DIRECT_MAP:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:CR3:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:BOOT_ARENA_SIZING:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:FP_CONTROLS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMAP_AC:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:DESCRIPTORS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:FINAL_CR3:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:BOOT_ARENA_RECLAIM:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:W_X:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:HEAP_GUARD:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:USER_ROOT:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SHARED_FRAMES:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_ENTRY:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_CONTROLS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_CACHE_POLICY:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_IDENTITY:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_TIMERS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_DESCRIPTORS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_TRAP_STACKS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_CONTINUATION:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_STOP:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_ROOTS:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_DISPATCH:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_IPC:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_BROKER:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_PREPARED:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_LOW_RETIRED:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_IPI_STATE:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_GLOBAL_TLB:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_DEVICE_CACHE:PASS",
    "ZIGOS:ARCH:X86_64:HIGH_HALF:PASS",
};

fn highHalfSmoke(h: Harness, args: []const []const u8) !void {
    try require(args, 2);
    var configured = h;
    configured.boot_iso = args[0];
    configured.cpu_override = try fmt(h.ctx, "{s},tsc-frequency=2400000000", .{try h.cpu()});
    // Count-sized arenas exercise the full sixteen-core architecture fixture
    // at 192MiB, including its unchanged 32MiB heap and firmware overhead.
    try configured.until(null, args[1], high_half_proofs[high_half_proofs.len - 1], "ZIGOS:ARCH:X86_64:HIGH_HALF:FAIL", try process.seconds(h.ctx, "ZIGOS_HIGH_HALF_SECONDS", "30"), "192M", &.{ "-smp", "cpus=16,sockets=1,cores=16,threads=1" });
    const bytes = try h.ctx.read(args[1]);
    try healthy(h.ctx, bytes, "FAIL");
    log.exactOrdered(bytes, &high_half_proofs) catch |err| {
        dump(h.ctx, bytes);
        return err;
    };
    try h.ctx.print("Isolated 16-CPU upper-half entry/SIPI, timer and execution ownership, remote stop, copied IPC and syscall broker delivery, acknowledged retirement, descriptors, SMAP, paging, shared frames and global-TLB proof passed. Log: {s}\n", .{args[1]});
}

const MappingXstateMode = enum { positive, unsupported };
const mapping_xstate_namespace = "ZIGOS:ARCH:X86_64:MAPPING_XSTATE:";
const mapping_xstate_proofs = [_][]const u8{
    mapping_xstate_namespace ++ "BSP_ADMISSION:PASS",
    mapping_xstate_namespace ++ "MAPPING_A_SEED:PASS",
    mapping_xstate_namespace ++ "MAPPING_B_SEED:PASS",
    mapping_xstate_namespace ++ "MAPPING_A_RESTORE:PASS",
    mapping_xstate_namespace ++ "MAPPING_B_UPDATE:PASS",
    mapping_xstate_namespace ++ "OWNERSHIP:PASS",
    mapping_xstate_namespace ++ "RETIREMENT:PASS",
    mapping_xstate_namespace ++ "PASS",
};

// Serial evidence and the actual debug-exit status form one contract. The
// unsupported mode verifies early admission failure, never compacted execution.
fn validateMappingXstateResult(status: u32, mode: MappingXstateMode, bytes: []const u8) !void {
    if (status != (if (mode == .positive) @as(u32, success_exit) else 37))
        return error.UnexpectedMappingXstateExit;
    if (!log.healthy(bytes, "FAIL")) return error.UnhealthyMappingXstateEvidence;
    switch (mode) {
        .positive => {
            if (log.contains(bytes, "UNSUPPORTED")) return error.UnsupportedCpuTarget;
            if (!std.mem.endsWith(u8, bytes, "\n")) return error.IncompleteMappingXstateEvidence;
            if (log.countContaining(bytes, mapping_xstate_namespace) != mapping_xstate_proofs.len or
                log.countContaining(bytes, "ZIGOS:ARCH:X86_64:HIGH_HALF:") != high_half_proofs.len or
                log.countContaining(bytes, "ZIGOS:ARCH:X86_64:") != mapping_xstate_proofs.len + high_half_proofs.len)
                return error.UnexpectedMappingXstateEvidence;
            try log.exactOrdered(bytes, &mapping_xstate_proofs);
            try log.exactOrdered(bytes, &high_half_proofs);
            try log.ordered(bytes, &.{ mapping_xstate_proofs[0], high_half_proofs[0] });
            try log.ordered(bytes, &.{ mapping_xstate_proofs[mapping_xstate_proofs.len - 1], high_half_proofs[high_half_proofs.len - 1] });
        },
        .unsupported => {
            const prefix = mapping_xstate_namespace ++ "UNSUPPORTED:";
            if (log.countContaining(bytes, mapping_xstate_namespace) != 1 or
                log.countContaining(bytes, "ZIGOS:") != 1 or log.contains(bytes, ":PASS") or
                log.contains(bytes, "AP:ONLINE") or log.contains(bytes, "AP_HIGH_ENTRY"))
                return error.UnexpectedMappingXstateEvidence;
            inline for (.{ "CPUID", "XSAVE", "AVX", "XSAVES", "YMM_LAYOUT" }) |reason| {
                if (log.exact(bytes, prefix ++ reason) and std.mem.endsWith(u8, bytes, "\n")) return;
            }
            return error.InvalidMappingXstateUnsupportedReason;
        },
    }
}

fn mappingXstateSmoke(h: Harness, args: []const []const u8) !void {
    if (args.len != 3) return error.InvalidArguments;
    const mode = std.meta.stringToEnum(MappingXstateMode, args[2]) orelse return error.InvalidArguments;
    const ctx = h.ctx;
    const path = args[1];
    try ctx.mkdir(std.fs.path.dirname(path) orelse ".");
    try remove(ctx, path);
    const status_path = try fmt(ctx, "{s}.qemu-status", .{stem(path)});
    try remove(ctx, status_path);
    var command = try h.build(args[0], "192M", try fmt(ctx, "file:{s}", .{path}), true, false);
    try command.appendSlice(ctx.allocator, &.{ "-smp", "cpus=16,sockets=1,cores=16,threads=1" });
    const qemu_log = try fmt(ctx, "{s}.qemu.log", .{stem(path)});
    const status = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, "ZIGOS_MAPPING_XSTATE_SECONDS", "30"));
    try ctx.write(status_path, try fmt(ctx, "{d}\n", .{status}));
    const bytes = try readOptional(ctx, path);
    validateMappingXstateResult(status, mode, bytes) catch |err| {
        dump(ctx, bytes);
        dump(ctx, try readOptional(ctx, qemu_log));
        ctx.warn("Mapping xstate {s} evidence rejected: QEMU exit {d}. Log: {s}\n", .{ @tagName(mode), status, path }) catch {};
        return err;
    };
    // Subprocess fixtures run this same path under Zig's test server, which
    // reserves stdout for its framed protocol.
    try ctx.warn("Mapping xstate {s} evidence validated with QEMU exit {d}. Log: {s}\n", .{ @tagName(mode), status, path });
}

const ApCacheCase = enum { none, version, default_reserved, mask_reserved, enabled };

fn apCacheFirst(case: ApCacheCase) []const u8 {
    return switch (case) {
        .none => "ZIGOS:ARCH:X86_64:AP_CACHE:CONTROL:ARMED",
        .version => "ZIGOS:ARCH:X86_64:AP_CACHE:VERSION:ARMED",
        .default_reserved => "ZIGOS:ARCH:X86_64:AP_CACHE:DEFAULT_RESERVED:ARMED",
        .mask_reserved => "ZIGOS:ARCH:X86_64:AP_CACHE:MASK_RESERVED:ARMED",
        .enabled => "ZIGOS:ARCH:X86_64:AP_CACHE:FIRST_ENABLED:PASS",
    };
}

fn apCacheLast(case: ApCacheCase) []const u8 {
    return switch (case) {
        .none => "ZIGOS:ARCH:X86_64:AP_CACHE:CONTROL_HIGH_ENTRY:PASS",
        .enabled => "ZIGOS:ARCH:X86_64:AP_CACHE:SMP_CACHE_ENABLED_MATCH:PASS",
        else => "ZIGOS:BOOT:CACHE:AP:REJECT:5",
    };
}

// Accept exactly the two executed records. Only the AP's single CRLF suffix
// is normalized; prefixes, appended text and duplicate/foreign proofs fail.
fn validateApCacheEvidence(bytes: []const u8, case: ApCacheCase) !void {
    if (!log.healthy(bytes, "FAIL")) return error.UnhealthyApCacheEvidence;
    var observed: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = if (std.mem.endsWith(u8, raw, "\r")) raw[0 .. raw.len - 1] else raw;
        if (!log.contains(line, "ZIGOS:ARCH:X86_64:AP_CACHE:") and
            !log.contains(line, "ZIGOS:BOOT:CACHE:") and
            !log.contains(line, ":PASS") and !log.contains(line, "HIGH_ENTRY") and
            !log.contains(line, "AP:ONLINE")) continue;
        if (observed >= 2 or !std.mem.eql(u8, line, if (observed == 0) apCacheFirst(case) else apCacheLast(case)))
            return error.UnexpectedApCacheEvidence;
        observed += 1;
    }
    if (observed != 2) return error.MissingApCacheEvidence;
}

fn apCacheHarness(h: Harness, iso: []const u8) !Harness {
    var configured = h;
    configured.boot_iso = iso;
    configured.cpu_override = try fmt(h.ctx, "{s},tsc-frequency=2400000000", .{try h.cpu()});
    return configured;
}

fn apCacheRejectionSmoke(h: Harness, args: []const []const u8) !void {
    try require(args, 3);
    const case = std.meta.stringToEnum(ApCacheCase, args[2]) orelse return error.InvalidArguments;
    if (case == .enabled) return error.InvalidArguments;
    const configured = try apCacheHarness(h, args[0]);
    try configured.until(null, args[1], apCacheLast(case), "FAIL", try process.seconds(h.ctx, "ZIGOS_AP_CACHE_SECONDS", "30"), "192M", &.{ "-smp", "cpus=2,sockets=1,cores=2,threads=1" });
    const bytes = try h.ctx.read(args[1]);
    validateApCacheEvidence(bytes, case) catch |err| {
        dump(h.ctx, bytes);
        return err;
    };
    try h.ctx.print("AP cache {s} control/rejection evidence passed. Log: {s}\n", .{ args[2], args[1] });
}

fn smpCacheEnabledMatchSmoke(h: Harness, args: []const []const u8) !void {
    try require(args, 2);
    const configured = try apCacheHarness(h, args[0]);
    try configured.until(null, args[1], apCacheLast(.enabled), "FAIL", try process.seconds(h.ctx, "ZIGOS_AP_CACHE_SECONDS", "30"), "192M", &.{ "-smp", "cpus=2,sockets=1,cores=2,threads=1" });
    const bytes = try h.ctx.read(args[1]);
    validateApCacheEvidence(bytes, .enabled) catch |err| {
        dump(h.ctx, bytes);
        return err;
    };
    try h.ctx.print("Paging-off AP enabled-MTRR match and independent register readback passed. Log: {s}\n", .{args[1]});
}

fn captureKernel(h: Harness, path: []const u8, limit: u32) ![]const u8 {
    const ctx = h.ctx;
    try ctx.mkdir(std.fs.path.dirname(path) orelse ".");
    try remove(ctx, path);
    const command = try h.kernel(h.profileMemory(), try fmt(ctx, "file:{s}", .{path}), true, false);
    const status = try process.timed(ctx, command.items, null, limit);
    if (status != 0 and status != success_exit) {
        dump(ctx, try readOptional(ctx, path));
        return fail(ctx, "Kernel capture failed: QEMU exited with status {d} (timeout {d}s)\n", .{ status, limit });
    }
    return ctx.read(path);
}

fn benchmark(h: Harness, args: []const []const u8) !void {
    try require(args, 2);
    if (std.mem.startsWith(u8, env(h.ctx, "ZIGOS_BENCHMARK_SECONDS", "300"), "0")) return error.InvalidArguments;
    if (args.len > 2 and args[2].len > 0) try remove(h.ctx, args[2]);
    const bytes = try captureKernel(h, args[1], try process.seconds(h.ctx, "ZIGOS_BENCHMARK_SECONDS", "300"));
    try healthy(h.ctx, bytes, "BENCH:FAIL");
    try checkGroup(h.ctx, bytes, &.{ "BOOT:START", "BOOT:PROFILE:benchmark", "BOOT:ROLE:verification", "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY", "ZIGOS:CPU:NX:ENABLED", "ZIGOS:CPU:PGE:ENABLED", "ZIGOS:CPU:SYSCALL:ENABLED", "ZIGOS:CPU:PCID:READY", "ZIGOS:KERNEL:W_X:ENFORCED", "BOOT:CORE_READY", "BENCH:START", "BENCH:QUALITY_SUMMARY", "BENCH:SUMMARY", "BENCH:PASS" });
    try absentGroup(h.ctx, bytes, &.{"BENCH:ENV:"});
    const accelerator = h.accelerator();
    const label = if (std.mem.eql(u8, accelerator, "kvm") or std.mem.startsWith(u8, accelerator, "kvm,")) "kvm" else if (accelerator.len == 0 or std.mem.eql(u8, accelerator, "tcg") or std.mem.startsWith(u8, accelerator, "tcg,")) "tcg" else return error.UnsupportedAccelerator;
    try h.ctx.write(args[1], try fmt(h.ctx, "{s}BENCH:ENV:accelerator={s}\n", .{ bytes, label }));
    try h.ctx.print("Kernel benchmark capture complete. Run the typed gate with 'zig build benchmark'. Log: {s}\n", .{args[1]});
}

fn recovery(h: Harness, args: []const []const u8) !void {
    try require(args, 2);
    const bytes = try captureKernel(h, args[1], try process.seconds(h.ctx, "RECOVERY_QEMU_SECONDS", "180"));
    try healthy(h.ctx, bytes, "RECOVERY:FAIL");
    try checkGroup(h.ctx, bytes, &markers.recovery_required);
    try h.ctx.print("Kernel recovery run passed. Log: {s}\n", .{args[1]});
}

const SmokeMode = enum {
    production,
    full,
    driver_restart,
    tampered_artifact_manifest,
    tampered_bootloader_measurement,
    tampered_kernel,
    tampered_userspace_image,
    tampered_policy,
    tampered_driver_set,
    rollback_slot_failure,

    fn group(self: SmokeMode) []const []const u8 {
        return switch (self) {
            .production => &markers.production_required,
            .full => &.{markers.ready},
            .driver_restart => &markers.driver_restart_required,
            .tampered_artifact_manifest => &markers.tampered_artifact_manifest_required,
            .tampered_bootloader_measurement => &markers.tampered_bootloader_measurement_required,
            .tampered_kernel => &markers.tampered_kernel_required,
            .tampered_userspace_image => &markers.tampered_userspace_image_required,
            .tampered_policy => &markers.tampered_policy_required,
            .tampered_driver_set => &markers.tampered_driver_set_required,
            .rollback_slot_failure => &markers.rollback_slot_failure_required,
        };
    }
};

fn buildStore(ctx: *common.Context, path: []const u8, reset: bool) !void {
    try images.run(ctx, "build-native-store", &.{ path, env(ctx, "NATIVE_STORE_SIZE_MIB", "8"), if (reset) "reset" else "preserve" });
}

fn smokeBoot(h: Harness, store: []const u8, path: []const u8, marker: []const u8, reset: bool, limit: u32) ![]const u8 {
    try buildStore(h.ctx, store, reset);
    try h.until(store, path, marker, null, limit, h.smokeMemory(), &.{});
    const bytes = try h.ctx.read(path);
    try healthy(h.ctx, bytes, "FAIL");
    if (std.mem.eql(u8, env(h.ctx, "ZIGOS_REQUIRE_HIGH_MEMORY", "0"), "1"))
        try checkGroup(h.ctx, bytes, &.{"High-memory direct map: online"});
    return bytes;
}

fn productionProof(ctx: *common.Context, bytes: []const u8) !void {
    try checkGroup(ctx, bytes, &markers.production_required);
    try absentGroup(ctx, bytes, &markers.production_forbidden);
    try images.validateProductionBootLog(bytes);
    if (!log.exact(bytes, "ZIGOS:IDENTITY:DISCOVERY:UNAVAILABLE")) return error.MissingIdentityDiscovery;
}

fn stackProof(bytes: []const u8) !void {
    try log.stackHeadroom(bytes, "ZIGOS:PLATFORM:BOOT_STACK:PEAK");
    try log.stackHeadroom(bytes, "ZIGOS:PLATFORM:TRAP_STACK:PEAK");
}

fn restartProof(ctx: *common.Context, bytes: []const u8, full: bool) !void {
    try checkGroup(ctx, bytes, &markers.driver_restart_required);
    const boot_marker = markers.cold_boot_required[0];
    if (log.countContaining(bytes, boot_marker) != 1) return error.UnexpectedReboot;
    var ordered: Args = .empty;
    try ordered.append(ctx.allocator, boot_marker);
    try ordered.appendSlice(ctx.allocator, &markers.driver_restart_required);
    if (full) try ordered.append(ctx.allocator, markers.ready);
    try log.ordered(bytes, ordered.items);
}

fn measurementComparison(ctx: *common.Context, first: []const u8, second: []const u8) ![]const u8 {
    const root1 = log.field(first, "ZIGOS:PLATFORM:MEASURED_BOOT:ROOT ") orelse "";
    const root2 = log.field(second, "ZIGOS:PLATFORM:MEASURED_BOOT:ROOT ") orelse "";
    const comparison = if (root1.len > 0 and std.mem.eql(u8, root1, root2)) "MATCH" else if (log.contains(second, "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_ROOT") and
        log.contains(second, "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_SHAPE")) "MATCH_REPORTED_BY_BOOT_JOURNAL" else return error.MeasuredBootMismatch;
    return fmt(ctx, "\n=== MEASURED BOOT COMPARISON ===\nMEASURED_BOOT:BOOT1_ROOT {s}\nMEASURED_BOOT:BOOT2_ROOT {s}\nMEASURED_BOOT:ROOT_COMPARE {s}\n", .{ root1, root2, comparison });
}

fn measurements(ctx: *common.Context, kernel: []const u8, directory: []const u8, bootloader: []const u8, production: bool) ![]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(ctx.io, directory, .{ .iterate = true });
    defer dir.close(ctx.io);
    var names: Args = .empty;
    var iterator = dir.iterate();
    while (try iterator.next(ctx.io)) |entry| {
        if (entry.kind != .file or !std.mem.startsWith(u8, entry.name, "userspace-") or !std.mem.endsWith(u8, entry.name, ".elf")) continue;
        if (production and (std.mem.eql(u8, entry.name, "userspace-notes-daily.elf") or std.mem.eql(u8, entry.name, "userspace-transport-probe.elf") or
            std.mem.eql(u8, entry.name, "userspace-termination-probe.elf") or std.mem.eql(u8, entry.name, "userspace-service-client.elf") or
            std.mem.eql(u8, entry.name, "userspace-mmu-isolation-proof.elf"))) continue;
        try names.append(ctx.allocator, try ctx.allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    var result = try fmt(ctx, "\n=== BUILD ARTIFACT MEASUREMENTS ===\nMEASURED_BOOT:BUILD_ARTIFACT bootloader source={s} sha256={s}\nMEASURED_BOOT:BUILD_ARTIFACT kernel path={s} sha256={s}\n", .{ bootloader, try ctx.sha256File(bootloader), kernel, try ctx.sha256File(kernel) });
    const root = try std.process.currentPathAlloc(ctx.io, ctx.allocator);
    const root_prefix = try fmt(ctx, "{s}/", .{root});
    for (names.items) |name| {
        const path = try fmt(ctx, "{s}/{s}", .{ directory, name });
        const relative = if (std.mem.startsWith(u8, path, root_prefix)) path[root_prefix.len..] else path;
        result = try fmt(ctx, "{s}MEASURED_BOOT:BUILD_ARTIFACT userspace path={s} sha256={s}\n", .{ result, relative, try ctx.sha256File(path) });
    }
    return result;
}

fn nativeSmoke(h: Harness, args: []const []const u8) !void {
    try require(args, 3);
    const ctx = h.ctx;
    const mode = std.meta.stringToEnum(SmokeMode, arg(args, 3, "full")) orelse return error.InvalidArguments;
    const group = mode.group();
    const validation_marker = group[group.len - 1];
    const limit = try process.seconds(ctx, "ZIGOS_NATIVE_SECONDS", "420");
    const first_path = try fmt(ctx, "{s}.boot1.log", .{stem(args[1])});
    const second_path = try fmt(ctx, "{s}.boot2.log", .{stem(args[1])});
    try remove(ctx, args[1]);
    try remove(ctx, first_path);
    try remove(ctx, second_path);
    const first = try smokeBoot(h, args[2], first_path, validation_marker, true, limit);
    if (mode == .driver_restart) {
        try restartProof(ctx, first, false);
        try ctx.write(args[1], first);
        try ctx.print("Zigos driver restart QEMU test passed. Logs: {s}\n", .{args[1]});
        return;
    }
    if (mode != .production and mode != .full) {
        try checkGroup(ctx, first, group);
        try absentGroup(ctx, first, &.{markers.ready});
        try ctx.write(args[1], first);
        try ctx.print("Zigos {s} negative smoke test passed. Logs: {s}\n", .{ @tagName(mode), args[1] });
        return;
    }
    try stackProof(first);
    if (mode == .production) {
        try productionProof(ctx, first);
        try checkGroup(ctx, first, &markers.production_first_boot_required);
    } else {
        try checkGroup(ctx, first, &markers.cold_boot_required);
        try checkGroup(ctx, first, &markers.first_boot_required);
        try checkGroup(ctx, first, &markers.ab_rollback_required);
        try checkGroup(ctx, first, &.{"ZIGOS:PLATFORM:BASE_SELECTOR:ACTIVE_SLOT 0 "});
        try restartProof(ctx, first, true);
    }
    const second = try smokeBoot(h, args[2], second_path, validation_marker, false, limit);
    try stackProof(second);
    if (mode == .production) {
        try productionProof(ctx, second);
        try checkGroup(ctx, second, &markers.production_reboot_required);
    } else {
        try checkGroup(ctx, second, &markers.cold_boot_required);
        try checkGroup(ctx, second, &markers.cold_reboot_required);
        try checkGroup(ctx, second, &markers.ab_rollback_required);
        try checkGroup(ctx, second, &.{"ZIGOS:PLATFORM:BASE_SELECTOR:ACTIVE_SLOT 0 "});
        try restartProof(ctx, second, true);
    }
    if (std.mem.eql(u8, try log.bootInstance(first), try log.bootInstance(second))) return error.ReusedBootInstance;
    const combined = try fmt(ctx, "{s}\n=== COLD REBOOT ===\n{s}{s}{s}", .{ first, second, try measurementComparison(ctx, first, second), try measurements(ctx, args[0], arg(args, 4, "zig-out/bin"), arg(args, 5, "src/boot/efi_stub.zig"), mode == .production) });
    try ctx.write(args[1], combined);
    if (log.countContaining(combined, "MEASURED_BOOT:BUILD_ARTIFACT userspace path=") != @as(usize, if (mode == .production) 8 else 13)) return error.ArtifactMeasurementCountMismatch;
    if (mode == .production) {
        try absentGroup(ctx, combined, &markers.production_forbidden);
        var negative = h;
        negative.cpu_override = try fmt(ctx, "{s},-rdseed", .{try h.cpu()});
        const negative_path = try fmt(ctx, "{s}.no-rdseed.log", .{stem(args[1])});
        try negative.until(args[2], negative_path, "ZIGOS:CPU:BASELINE:MODERN_X86_64:REJECTED", null, limit, h.smokeMemory(), &.{});
        const bytes = try ctx.read(negative_path);
        if (!log.exact(bytes, "Unsupported CPU: missing rdseed") or log.exact(bytes, "ZIGOS:RANDOM:READY") or
            log.exact(bytes, "BOOT:CORE_READY") or log.exact(bytes, "ZIGOS:NATIVE:READY")) return error.EntropyBaselineNotRejected;
        try ctx.print("Zigos missing RDSEED negative smoke test passed. Log: {s}\n", .{negative_path});
    }
    try ctx.print("Zigos {s} smoke test passed across cold reboot. Logs: {s}\n", .{ if (mode == .production) "production" else "native", args[1] });
}

fn storageDurability(initial: Harness, args: []const []const u8) !void {
    try require(args, 4);
    var h = initial;
    h.cache_override = "writeback";
    h.write_cache_override = "on";
    const ctx = h.ctx;
    const block_bytes = try std.fmt.parseInt(u64, args[3], 10);
    if (block_bytes == 0) return error.InvalidArguments;
    const limit = try process.seconds(ctx, "ZIGOS_NATIVE_SECONDS", "420");
    const milestones = [_][]const u8{ "ZIGOS:STORAGE:DURABILITY:BASELINE_CHECKPOINTED", "ZIGOS:STORAGE:DURABILITY:INTERRUPTED_WRITE_STAGED", "ZIGOS:STORAGE:DURABILITY:FINAL_CHECKPOINTED", "ZIGOS:STORAGE:DURABILITY:BAD_ROOT_SLOT_FALLBACK_OK" };
    var boots: [4][]const u8 = undefined;
    try remove(ctx, args[1]);
    for (milestones, 0..) |marker, index| {
        if (index == 3) {
            const file = try std.Io.Dir.cwd().openFile(ctx.io, args[2], .{ .mode = .read_write });
            defer file.close(ctx.io);
            try file.writePositionalAll(ctx.io, &.{255}, block_bytes);
        }
        const path = try fmt(ctx, "{s}.boot{d}.log", .{ stem(args[1]), index + 1 });
        boots[index] = try smokeBoot(h, args[2], path, marker, index == 0, limit);
    }
    const combined = try fmt(ctx, "{s}\n=== FORCED REBOOT: INTERRUPTED WRITE ===\n{s}\n=== FORCED REBOOT: RECOVERY AND FINAL CHECKPOINT ===\n{s}\n=== HOST ROOT SLOT CORRUPTION ===\nSTORAGE_DURABILITY:CORRUPTED_ROOT_SLOT 1 offset={d}\n\n=== FORCED REBOOT: BAD ROOT SLOT RECOVERY ===\n{s}", .{ boots[0], boots[1], boots[2], block_bytes, boots[3] });
    try ctx.write(args[1], combined);
    try checkGroup(ctx, combined, &markers.storage_durability_required);
    try ctx.print("Zigos storage durability QEMU test passed across forced reboots and one bad root slot. Logs: {s}\n", .{args[1]});
}

fn copySparse(ctx: *common.Context, source: []const u8, destination: []const u8) !void {
    try ctx.mkdir(std.fs.path.dirname(destination) orelse ".");
    const input = try std.Io.Dir.cwd().openFile(ctx.io, source, .{});
    defer input.close(ctx.io);
    const output = try std.Io.Dir.cwd().createFile(ctx.io, destination, .{});
    defer output.close(ctx.io);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const size = try input.readPositionalAll(ctx.io, &buffer, offset);
        if (size == 0) break;
        if (std.mem.indexOfNone(u8, buffer[0..size], &.{0}) != null) try output.writePositionalAll(ctx.io, buffer[0..size], offset);
        offset += size;
    }
    try output.setLength(ctx.io, offset);
}

fn nodeCommand(h: Harness, store: []const u8, path: []const u8, socket: []const u8, mac: []const u8) !Args {
    const ctx = h.ctx;
    var command = try h.kernel(h.smokeMemory(), try fmt(ctx, "file:{s}", .{path}), true, false);
    if (std.mem.startsWith(u8, h.accelerator(), "kvm")) try command.appendSlice(ctx.allocator, &.{ "-machine", "kernel-irqchip=split" });
    try command.appendSlice(ctx.allocator, &.{ "-netdev", try fmt(ctx, "socket,id=syncnet,{s}", .{socket}), "-device", "intel-iommu,intremap=on,eim=on,aw-bits=48", "-device", try fmt(ctx, "virtio-net-pci,netdev=syncnet,disable-legacy=on,packed=off,iommu_platform=on,mac={s}", .{mac}), "-object", try fmt(ctx, "filter-dump,id=sync_capture,netdev=syncnet,file={s}.pcap", .{stem(path)}) });
    try h.appendStore(&command, store);
    return command;
}

fn twoNode(h: Harness, args: []const []const u8) !void {
    try require(args, 4);
    const ctx = h.ctx;
    const limit = try process.seconds(ctx, "SYNC_TWO_NODE_SECONDS", "180");
    const drops = env(ctx, "SYNC_TWO_NODE_DROP_CONFIRMATIONS", "2");
    if (!std.mem.eql(u8, drops, "0") and !std.mem.eql(u8, drops, "2")) return error.InvalidArguments;
    const port = env(ctx, "SYNC_TWO_NODE_PORT", try fmt(ctx, "{d}", .{@as(u32, @intCast(40000 + @mod(std.c.getpid(), 10000)))}));
    const a_path = try fmt(ctx, "{s}.node-a.log", .{stem(args[1])});
    const b_path = try fmt(ctx, "{s}.node-b.log", .{stem(args[1])});
    const relay_path = try fmt(ctx, "{s}.relay.log", .{stem(args[1])});
    for ([_][]const u8{ args[1], a_path, b_path, relay_path }) |path| try remove(ctx, path);
    try buildStore(ctx, args[2], true);
    try buildStore(ctx, args[3], true);
    const a_cmd = try nodeCommand(h, args[2], a_path, try fmt(ctx, "listen=127.0.0.1:{s}", .{port}), "02:5a:47:00:00:01");
    var a = try process.Child.start(ctx, a_cmd.items, try fmt(ctx, "{s}.qemu.log", .{stem(a_path)}));
    defer a.stop(ctx, process.grace(ctx));
    const executable = try std.process.executablePathAlloc(ctx.io, ctx.allocator);
    var relay = try process.Child.start(ctx, &.{ executable, "qemu-peer-relay", "--upstream-port", port, "--drop-confirmations", drops }, relay_path);
    defer relay.stop(ctx, process.grace(ctx));
    var relay_port: ?[]const u8 = null;
    for (0..150) |_| {
        if (!(try relay.poll())) break;
        const bytes = try readOptional(ctx, relay_path);
        if (log.field(bytes, "SYNC_RELAY:READY ")) |value| {
            if (value.len > 0 and std.mem.indexOfNone(u8, value, "0123456789") == null) {
                relay_port = value;
                break;
            }
        }
        try process.pause(ctx, 100);
    }
    if (relay_port == null) {
        dump(ctx, try readOptional(ctx, relay_path));
        return error.RelayNotReady;
    }
    const b_cmd = try nodeCommand(h, args[3], b_path, try fmt(ctx, "connect=127.0.0.1:{s}", .{relay_port.?}), "02:5a:47:00:00:02");
    var b = try process.Child.start(ctx, b_cmd.items, try fmt(ctx, "{s}.qemu.log", .{stem(b_path)}));
    defer b.stop(ctx, process.grace(ctx));
    const start = std.Io.Timestamp.now(ctx.io, .awake);
    while (true) {
        if (!(try a.poll()) or !(try b.poll()) or !(try relay.poll())) break;
        if (log.contains(try readOptional(ctx, a_path), markers.ready) and log.contains(try readOptional(ctx, b_path), markers.ready)) break;
        if (process.elapsed(ctx, start) >= @as(i64, limit) * 1000) break;
        try process.pause(ctx, 1000);
    }
    a.stop(ctx, process.grace(ctx));
    b.stop(ctx, process.grace(ctx));
    relay.stop(ctx, process.grace(ctx));
    const a_log = try readOptional(ctx, a_path);
    const b_log = try readOptional(ctx, b_path);
    for ([_][]const u8{ a_log, b_log }) |bytes| {
        try healthy(ctx, bytes, "FAIL");
        try checkGroup(ctx, bytes, &markers.sync_two_node_required);
        try checkGroup(ctx, bytes, &.{ "ZIGOS:SYNC:PEER_CHANNEL:ADMITTED", "ZIGOS:SYNC:PEER_CHANNEL:COMPLETED", "ZIGOS:SYNC:PEER_CHANNEL:SUSPENDED_RETIRED", "ZIGOS:SYNC:PEER_CONNECTION:PROMOTED", "ZIGOS:SYNC:PEER_CONNECTION:OWNER_RETIRED" });
    }
    const relay_log = try ctx.read(relay_path);
    if (std.mem.eql(u8, drops, "2") and (log.countPrefix(relay_log, "SYNC_RELAY:DROPPED_CONFIRMATION ") != 2 or !log.exact(relay_log, "SYNC_RELAY:RETRIED_CONFIRMATION"))) return error.MissingRelayRetryProof;
    try checkGroup(ctx, a_log, &.{ "ZIGOS:SYNC:PEER_OBJECT:ACKNOWLEDGED", "ZIGOS:SYNC:PEER_OBJECT:SENDER_ADMITTED", "ZIGOS:SYNC:PEER_OBJECT:SENDER_RETIRED" });
    try checkGroup(ctx, b_log, &.{ "ZIGOS:SYNC:PEER_OBJECT:REOPENED", "ZIGOS:SYNC:PEER_OBJECT:ADMITTED", "ZIGOS:SYNC:PEER_OBJECT:RETIRED" });
    try ctx.write(args[1], try fmt(ctx, "=== SYNC TWO NODE: NODE A listen=127.0.0.1:{s} ===\n{s}\n=== SYNC TWO NODE: NODE B connect=127.0.0.1:{s} ===\n{s}", .{ port, a_log, relay_port.?, b_log }));
    try ctx.print("Zigos two-node sync QEMU test passed. Logs: {s}\n", .{args[1]});
}

fn proof(bytes: []const u8, prefix: []const u8, expected: []const u8, count: usize) !void {
    if (log.countPrefix(bytes, prefix) != count or (count > 0 and !log.exact(bytes, expected))) return error.TpmProofMismatch;
}

fn bootMeasurement(bytes: []const u8) !void {
    try proof(bytes, "ZIGOS:TPM2:BOOT_MEASUREMENT:", "ZIGOS:TPM2:BOOT_MEASUREMENT:VERIFIED", 1);
    try proof(bytes, "ZIGOS:TPM2:FINAL_EVENTS:", "ZIGOS:TPM2:FINAL_EVENTS:VERIFIED", 1);
}

fn transportProof(bytes: []const u8) !void {
    try bootMeasurement(bytes);
    try proof(bytes, "ZIGOS:TPM2:ASYNC_TRANSPORT:", "ZIGOS:TPM2:ASYNC_TRANSPORT:VERIFIED", 1);
}

const Tpm = struct {
    h: Harness,
    work: []const u8,
    directory: []const u8,
    store: []const u8,
    child: ?process.Child = null,

    fn stop(self: *Tpm) void {
        if (self.child) |*child| child.stop(self.h.ctx, process.grace(self.h.ctx));
        self.child = null;
    }

    fn cleanup(self: *Tpm) void {
        self.stop();
        self.h.ctx.removeTree(self.work) catch {};
    }

    fn socket(self: Tpm) ![]const u8 {
        return fmt(self.h.ctx, "{s}/control.sock", .{self.work});
    }

    fn start(self: *Tpm, name: []const u8) !void {
        const ctx = self.h.ctx;
        const control = try self.socket();
        try remove(ctx, control);
        const output = try fmt(ctx, "{s}/{s}.swtpm.log", .{ self.directory, name });
        self.child = try process.Child.start(ctx, &.{ env(ctx, "SWTPM_BIN", "swtpm"), "socket", "--tpm2", "--tpmstate", try fmt(ctx, "dir={s}/state", .{self.work}), "--ctrl", try fmt(ctx, "type=unixio,path={s}", .{control}) }, output);
        for (0..50) |_| {
            if (!(try self.child.?.poll())) break;
            const stat = std.Io.Dir.cwd().statFile(ctx.io, control, .{}) catch null;
            if (stat) |s| if (s.kind == .unix_domain_socket) return;
            try process.pause(ctx, 100);
        }
        dump(ctx, try readOptional(ctx, output));
        return error.TpmNotReady;
    }

    fn extra(self: Tpm, device: []const u8) ![]const []const u8 {
        const ctx = self.h.ctx;
        if (std.mem.eql(u8, device, "none")) return &.{};
        return ctx.allocator.dupe([]const u8, &.{ "-chardev", try fmt(ctx, "socket,id=zigos_tpm_socket,path={s}", .{try self.socket()}), "-tpmdev", "emulator,id=zigos_tpm,chardev=zigos_tpm_socket", "-device", try fmt(ctx, "{s},tpmdev=zigos_tpm", .{device}) });
    }

    fn capture(self: *Tpm, name: []const u8, device: []const u8, marker: []const u8) ![]const u8 {
        const ctx = self.h.ctx;
        const path = try fmt(ctx, "{s}/{s}.log", .{ self.directory, name });
        if (!std.mem.eql(u8, device, "none")) try self.start(name);
        defer self.stop();
        try self.h.until(self.store, path, marker, null, try process.seconds(ctx, "TPM2_QEMU_SECONDS", "90"), self.h.smokeMemory(), try self.extra(device));
        return ctx.read(path);
    }

    fn boot(self: *Tpm, name: []const u8, device: []const u8, expected: []const u8, sealing: ?[]const u8, vault_override: ?[]const u8) !void {
        const ctx = self.h.ctx;
        const bytes = try self.capture(name, device, markers.ready);
        if (log.countPrefix(bytes, "ZIGOS:TPM2:CRB_READY") + log.countPrefix(bytes, "ZIGOS:TPM2:UNAVAILABLE") != 1 or !log.exact(bytes, expected)) return error.TpmDeviceResultMismatch;
        if (std.mem.eql(u8, device, "tpm-crb")) try bootMeasurement(bytes) else if (log.contains(bytes, "ZIGOS:TPM2:BOOT_MEASUREMENT:VERIFIED")) return error.UnsupportedTransportClaimedVerified;
        if (sealing) |sealing_marker| {
            try transportProof(bytes);
            const different = std.mem.eql(u8, name, "different-tpm");
            const session_count: usize = if (different) 0 else 1;
            for ([_][]const u8{ "SESSION", "PIN_INPUT", "PIN_WORKER" }) |kind|
                try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{kind}), try fmt(ctx, "ZIGOS:TPM2:{s}:VERIFIED", .{kind}), session_count);
            try proof(bytes, "ZIGOS:TPM2:PIN:", if (different) "ZIGOS:TPM2:PIN:WRONG_DEVICE" else "ZIGOS:TPM2:PIN:VERIFIED", 1);
            try proof(bytes, "ZIGOS:TPM2:ENROLLMENT_RECOVERY:", if (different) "ZIGOS:TPM2:ENROLLMENT_RECOVERY:MISSING" else if (std.mem.eql(u8, name, "cold")) "ZIGOS:TPM2:ENROLLMENT_RECOVERY:COMMITTED" else "ZIGOS:TPM2:ENROLLMENT_RECOVERY:VERIFIED", 1);
            try proof(bytes, "ZIGOS:TPM2:SEAL:", sealing_marker, 1);
            const vault = vault_override orelse try std.mem.replaceOwned(u8, ctx.allocator, sealing_marker, ":SEAL:", ":VAULT:");
            try proof(bytes, "ZIGOS:TPM2:VAULT:", vault, 1);
            const expected_proofs: usize = if (std.mem.endsWith(u8, vault, ":WRONG_DEVICE") or std.mem.endsWith(u8, vault, ":ROLLBACK_REJECTED")) 0 else 1;
            for ([_][]const u8{ "IDENTITY:SIGNED", "KEYGEN:DISTINCT", "DOCUMENT:SIGNING", "PEER:AUTHENTICATED" }) |marker| {
                const colon = std.mem.indexOfScalar(u8, marker, ':').?;
                try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{marker[0..colon]}), try fmt(ctx, "ZIGOS:TPM2:{s}", .{marker}), expected_proofs);
            }
            for ([_][]const u8{ "CATALOG", "CREDENTIALS", "ENROLLMENT", "PUBLIC_ENROLLMENT", "PUBLIC_ROTATION", "KEY_RETIREMENT" }) |kind|
                try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{kind}), try fmt(ctx, "ZIGOS:TPM2:{s}:{s}", .{ kind, if (std.mem.eql(u8, name, "reboot")) "RESTORED" else "COMMITTED" }), expected_proofs);
            try proof(bytes, "ZIGOS:TPM2:UNLOCK:", if (std.mem.eql(u8, name, "reboot")) "ZIGOS:TPM2:UNLOCK:REPLAY_REJECTED" else "ZIGOS:TPM2:UNLOCK:BOUND", expected_proofs);
            const reboot = std.mem.eql(u8, name, "reboot");
            const cold = std.mem.eql(u8, name, "cold");
            const rollback = std.mem.eql(u8, name, "rollback");
            try proof(bytes, "ZIGOS:TPM2:ANCHOR:", if (reboot) "ZIGOS:TPM2:ANCHOR:ADVANCED" else if (rollback) "ZIGOS:TPM2:ANCHOR:ROLLBACK_REJECTED" else "ZIGOS:TPM2:ANCHOR:PROVISIONED", if (different) 0 else 1);
            try proof(bytes, "ZIGOS:TPM2:NV:", "ZIGOS:TPM2:NV:AUTHENTICATED", if (cold) 1 else 0);
            try proof(bytes, "ZIGOS:TPM2:ANCHOR_RETRY:", "ZIGOS:TPM2:ANCHOR_RETRY:RECONCILED", if (reboot) 1 else 0);
            try proof(bytes, "ZIGOS:TPM2:ANCHOR_RECOVERY:", "ZIGOS:TPM2:ANCHOR_RECOVERY:COMMITTED", if (reboot) 1 else 0);
        } else try images.validateProductionBootLog(bytes);
        try ctx.print("TPM2 QEMU {s}: PASS\n", .{name});
    }

    fn boundary(self: *Tpm, name: []const u8, marker: []const u8) !void {
        const ctx = self.h.ctx;
        const bytes = try self.capture(name, "tpm-crb", marker);
        try transportProof(bytes);
        if (!log.exact(bytes, "ZIGOS:TPM2:CRB_READY") or !log.exact(bytes, marker) or log.contains(bytes, "FAIL")) return error.TpmBoundaryMismatch;
        if (std.mem.eql(u8, name, "interrupted-checkpoint")) {
            if (!log.exact(bytes, "ZIGOS:TPM2:SEAL:RECOVERED") or log.countPrefix(bytes, "ZIGOS:TPM2:ANCHOR_RECOVERY:") != 1 or
                log.countPrefix(bytes, "ZIGOS:TPM2:IDENTITY:") > 0 or log.countPrefix(bytes, "ZIGOS:TPM2:VAULT:") > 0) return error.TpmBoundaryMismatch;
        } else if (std.mem.eql(u8, name, "interrupted-enrollment")) {
            try proof(bytes, "ZIGOS:TPM2:PIN:", "ZIGOS:TPM2:PIN:VERIFIED", 1);
            for ([_][]const u8{ "SESSION", "PIN_INPUT", "PIN_WORKER" }) |kind|
                try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{kind}), try fmt(ctx, "ZIGOS:TPM2:{s}:VERIFIED", .{kind}), 1);
            try proof(bytes, "ZIGOS:TPM2:ENROLLMENT_RECOVERY:", marker, 1);
            if (log.countPrefix(bytes, "ZIGOS:TPM2:SEAL:") > 0 or log.countPrefix(bytes, "ZIGOS:TPM2:IDENTITY:") > 0 or log.countPrefix(bytes, "ZIGOS:TPM2:VAULT:") > 0) return error.TpmBoundaryMismatch;
        } else {
            try proof(bytes, "ZIGOS:TPM2:PIN:", marker, 1);
            try proof(bytes, "ZIGOS:TPM2:SESSION:", "ZIGOS:TPM2:SESSION:VERIFIED", 1);
            if (log.countPrefix(bytes, "ZIGOS:TPM2:SEAL:") > 0 or log.countPrefix(bytes, "ZIGOS:TPM2:IDENTITY:") > 0 or
                log.countPrefix(bytes, "ZIGOS:TPM2:VAULT:") > 0 or log.countPrefix(bytes, "ZIGOS:TPM2:ENROLLMENT_RECOVERY:") > 0) return error.TpmBoundaryMismatch;
        }
        try ctx.print("TPM2 QEMU {s}: PASS\n", .{name});
    }

    fn ownership(self: *Tpm, name: []const u8, marker: []const u8) !void {
        const ctx = self.h.ctx;
        const bytes = try self.capture(name, "tpm-crb", marker);
        try transportProof(bytes);
        if (log.contains(bytes, "FAIL")) return error.TpmOwnershipMismatch;
        try proof(bytes, "ZIGOS:TPM2:OWNER:", marker, 1);
        const reboot = std.mem.eql(u8, name, "reboot");
        const enrolled = std.mem.eql(u8, name, "enrolled");
        const interrupted_name = std.mem.eql(u8, name, "interrupted") or std.mem.endsWith(u8, name, "-interrupted");
        try proof(bytes, "ZIGOS:TPM2:SETUP:", if (enrolled) "ZIGOS:TPM2:SETUP:VERIFIED" else "ZIGOS:TPM2:SETUP:INTERRUPTED", if (interrupted_name or enrolled) 1 else 0);
        for ([_][]const u8{ "BOOT_ENROLLMENT", "IDENTITY_OWNER", "IDENTITY_REQUEST" }) |kind|
            try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{kind}), try fmt(ctx, "ZIGOS:TPM2:{s}:VERIFIED", .{kind}), if (reboot) 1 else 0);
        try ctx.print("TPM2 QEMU ownership {s}: PASS\n", .{name});
    }

    fn quote(self: *Tpm, name: []const u8, marker: []const u8) !void {
        const ctx = self.h.ctx;
        const bytes = try self.capture(name, "tpm-crb", markers.ready);
        try transportProof(bytes);
        if (log.contains(bytes, "FAIL")) return error.TpmQuoteMismatch;
        try proof(bytes, "ZIGOS:TPM2:QUOTE:", marker, 1);
        const count: usize = if (std.mem.eql(u8, name, "replacement")) 0 else 1;
        for ([_][]const u8{ "REMOTE_ATTESTATION", "PEER_ATTESTATION", "QUOTE_WORKER" }) |kind|
            try proof(bytes, try fmt(ctx, "ZIGOS:TPM2:{s}:", .{kind}), try fmt(ctx, "ZIGOS:TPM2:{s}:VERIFIED", .{kind}), count);
        try ctx.print("TPM2 QEMU quote {s}: PASS\n", .{name});
    }

    fn replace(self: *Tpm) !void {
        const ctx = self.h.ctx;
        const state = try fmt(ctx, "{s}/state", .{self.work});
        try std.Io.Dir.cwd().rename(state, .cwd(), try fmt(ctx, "{s}/original-state", .{self.work}), ctx.io);
        try ctx.mkdir(state);
    }
};

fn tpm2(h: Harness, args: []const []const u8) !void {
    try require(args, 1);
    const mode = arg(args, 1, "transport");
    if (!std.mem.eql(u8, mode, "transport") and !std.mem.eql(u8, mode, "sealing") and !std.mem.eql(u8, mode, "ownership") and !std.mem.eql(u8, mode, "quote")) return error.InvalidArguments;
    const ctx = h.ctx;
    if (try ctx.findExecutable(env(ctx, "SWTPM_BIN", "swtpm")) == null) return error.SwtpmNotFound;
    const directory = if (std.mem.eql(u8, mode, "transport")) "build/tpm2-qemu" else try fmt(ctx, "build/tpm2-{s}-qemu", .{mode});
    var tpm: Tpm = .{ .h = h, .work = try socketTempDir(ctx, "zigos-tpm2"), .directory = directory, .store = try fmt(ctx, "{s}/native-store.img", .{directory}) };
    defer tpm.cleanup();
    try ctx.mkdir(try fmt(ctx, "{s}/state", .{tpm.work}));
    try ctx.mkdir(directory);
    try images.run(ctx, "build-native-store", &.{ tpm.store, "8", "reset" });
    if (std.mem.eql(u8, mode, "quote")) {
        try tpm.quote("cold", "ZIGOS:TPM2:QUOTE:CREATED");
        const snapshot = try fmt(ctx, "{s}/quote-store.img", .{tpm.work});
        try copySparse(ctx, tpm.store, snapshot);
        try tpm.quote("reboot", "ZIGOS:TPM2:QUOTE:RECOVERED");
        try copySparse(ctx, snapshot, tpm.store);
        try tpm.replace();
        try tpm.quote("replacement", "ZIGOS:TPM2:QUOTE:WRONG_DEVICE");
    } else if (std.mem.eql(u8, mode, "ownership")) {
        const cases = [_][]const u8{ "interrupted", "owner-interrupted", "lockout-interrupted", "policy-interrupted", "define-interrupted", "write-interrupted", "boot-define-interrupted", "boot-write-interrupted", "boot-lock-interrupted" };
        const outcomes = [_][]const u8{ "INTERRUPTED", "OWNER_INTERRUPTED", "LOCKOUT_INTERRUPTED", "POLICY_INTERRUPTED", "DEFINE_INTERRUPTED", "WRITE_INTERRUPTED", "BOOT_DEFINE_INTERRUPTED", "BOOT_WRITE_INTERRUPTED", "BOOT_LOCK_INTERRUPTED" };
        for (cases, outcomes) |name, outcome| try tpm.ownership(name, try fmt(ctx, "ZIGOS:TPM2:OWNER:{s}", .{outcome}));
        const snapshot = try fmt(ctx, "{s}/setup-store.img", .{tpm.work});
        try copySparse(ctx, tpm.store, snapshot);
        try tpm.ownership("enrolled", "ZIGOS:TPM2:OWNER:ENROLLED");
        try tpm.ownership("reboot", "ZIGOS:TPM2:OWNER:VERIFIED");
        try tpm.replace();
        try tpm.ownership("replacement", "ZIGOS:TPM2:OWNER:REPLACEMENT_REJECTED");
        try copySparse(ctx, snapshot, tpm.store);
        try tpm.ownership("setup-replacement", "ZIGOS:TPM2:OWNER:SETUP_REPLACEMENT_REJECTED");
    } else if (std.mem.eql(u8, mode, "sealing")) {
        try tpm.boundary("pin-lockout", "ZIGOS:TPM2:PIN:LOCKED");
        try tpm.boundary("interrupted-enrollment", "ZIGOS:TPM2:ENROLLMENT_RECOVERY:INTERRUPTED");
        try tpm.boot("cold", "tpm-crb", "ZIGOS:TPM2:CRB_READY", "ZIGOS:TPM2:SEAL:CREATED", null);
        const snapshot = try fmt(ctx, "{s}/sealed-store.img", .{tpm.work});
        try copySparse(ctx, tpm.store, snapshot);
        try tpm.boundary("interrupted-checkpoint", "ZIGOS:TPM2:ANCHOR_RECOVERY:INTERRUPTED");
        try tpm.boot("reboot", "tpm-crb", "ZIGOS:TPM2:CRB_READY", "ZIGOS:TPM2:SEAL:RECOVERED", null);
        try copySparse(ctx, snapshot, tpm.store);
        try tpm.boot("rollback", "tpm-crb", "ZIGOS:TPM2:CRB_READY", "ZIGOS:TPM2:SEAL:RECOVERED", "ZIGOS:TPM2:VAULT:ROLLBACK_REJECTED");
        try copySparse(ctx, snapshot, tpm.store);
        try tpm.replace();
        try tpm.boot("different-tpm", "tpm-crb", "ZIGOS:TPM2:CRB_READY", "ZIGOS:TPM2:SEAL:WRONG_DEVICE", null);
    } else {
        try tpm.boot("cold", "tpm-crb", "ZIGOS:TPM2:CRB_READY", null, null);
        try tpm.boot("reboot", "tpm-crb", "ZIGOS:TPM2:CRB_READY", null, null);
        try tpm.boot("unsupported-fifo", "tpm-tis", "ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice", null, null);
        try tpm.boot("absent", "none", "ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice", null, null);
    }
}

fn copyTree(ctx: *common.Context, source: []const u8, destination: []const u8) !void {
    try ctx.mkdir(destination);
    var directory = try std.Io.Dir.cwd().openDir(ctx.io, source, .{ .iterate = true });
    defer directory.close(ctx.io);
    var iterator = directory.iterate();
    while (try iterator.next(ctx.io)) |entry| {
        const input = try fmt(ctx, "{s}/{s}", .{ source, entry.name });
        const output = try fmt(ctx, "{s}/{s}", .{ destination, entry.name });
        switch (entry.kind) {
            .directory => try copyTree(ctx, input, output),
            .file => try ctx.copy(input, output),
            else => return error.UnexpectedStagingEntry,
        }
    }
}

fn unifiedCase(initial: Harness, directory: []const u8, temporary: []const u8, name: []const u8, vars: []const u8, expected: []const u8, banks: ?[]const u8) !void {
    var h = initial;
    h.vars_override = vars;
    const ctx = h.ctx;
    const store = try fmt(ctx, "{s}/{s}.store", .{ directory, name });
    const path = try fmt(ctx, "{s}/{s}.log", .{ directory, name });
    try images.run(ctx, "build-native-store", &.{ store, "8", "reset" });
    try remove(ctx, path);
    var tpm: Tpm = .{ .h = h, .directory = directory, .work = try fmt(ctx, "{s}/{s}", .{ temporary, name }), .store = store };
    defer tpm.stop();
    const state = try fmt(ctx, "{s}/state", .{tpm.work});
    try ctx.mkdir(state);
    if (banks) |value| {
        const swtpm = (try ctx.findExecutable(env(ctx, "SWTPM_BIN", "swtpm"))) orelse return error.SwtpmNotFound;
        const setup_status = try process.run(ctx, &.{ env(ctx, "SWTPM_SETUP_BIN", "swtpm_setup"), "--tpm2", "--tpm", try fmt(ctx, "{s} socket", .{swtpm}), "--tpmstate", state, "--config", "/dev/null", "--pcr-banks", value }, try fmt(ctx, "{s}/{s}.setup.log", .{ directory, name }));
        if (setup_status != 0) return error.TpmSetupFailed;
    }
    try tpm.start(name);
    var command = try h.build(try fmt(ctx, "{s}/{s}.iso", .{ directory, name }), h.memory(), try fmt(ctx, "file:{s}", .{path}), true, false);
    try command.appendSlice(ctx.allocator, &.{ "-machine", "smm=on", "-global", "driver=cfi.pflash01,property=secure,value=on" });
    try command.appendSlice(ctx.allocator, try tpm.extra("tpm-crb"));
    try h.appendStore(&command, store);
    const qemu_log = try fmt(ctx, "{s}/{s}.qemu.log", .{ directory, name });
    const status = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, "EFI_TEST_SECONDS", "20"));
    tpm.stop();
    try remove(ctx, try tpm.socket());
    if (status != 0 and status != 124 and status != success_exit) {
        dump(ctx, try readOptional(ctx, qemu_log));
        return error.QemuFailed;
    }
    const bytes = try readOptional(ctx, path);
    if (std.mem.eql(u8, expected, "measurement-rejected")) {
        if (log.contains(bytes, "BOOT:START") or !log.contains(bytes, "EFI:FAIL:tpm-measurement")) return fail(ctx, "Loader did not reject unsupported TPM banks before kernel entry\n", .{});
    } else if (std.mem.eql(u8, expected, "rejected")) {
        if (log.contains(bytes, "BOOT:START") or (!log.contains(bytes, "Security Violation") and !log.contains(bytes, "Access Denied"))) return fail(ctx, "Firmware did not reject {s} before kernel entry\n", .{name});
    } else {
        for ([_][]const u8{ markers.ready, "ZIGOS:TPM2:BOOT_MEASUREMENT:VERIFIED", "ZIGOS:TPM2:FINAL_EVENTS:VERIFIED", try fmt(ctx, "ZIGOS:PLATFORM:BOOT_IMAGE:{s}", .{expected}) }) |marker| if (!log.exact(bytes, marker)) return error.MissingFirmwareBootProof;
        try absentGroup(ctx, bytes, &.{ "PANIC", ":FAIL", "System Halted" });
        if (std.mem.eql(u8, expected, "UNVERIFIED")) try absentGroup(ctx, bytes, &.{ "BOOT_IMAGE:FIRMWARE_AUTHENTICATED", "MEASURED_BOOT:VERIFIED_ROOT" }) else if (!log.exact(bytes, "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT")) return error.MissingVerifiedRoot;
    }
    try ctx.print("Unified EFI firmware case passed: {s}\n", .{name});
}

fn unifiedEfi(initial: Harness, args: []const []const u8) !void {
    try require(args, 4);
    var h = initial;
    const ctx = h.ctx;
    h.code_override = ctx.env("OVMF_SECURE_BOOT_CODE") orelse return error.SecureBootFirmwareRequired;
    if (h.code_override.?.len == 0) return error.SecureBootFirmwareRequired;
    const vars = env(ctx, "OVMF_SECURE_BOOT_VARS", (try h.firmware(false)) orelse return error.FirmwareVariablesRequired);
    const work = try socketTempDir(ctx, "zigos-efi-tpm");
    defer ctx.removeTree(work) catch {};
    const directory = args[3];
    try ctx.mkdir(directory);
    try efi_fixture.run(ctx, &.{ args[0], args[1], args[2], directory });
    const authorized = try fmt(ctx, "{s}/authorized-vars.fd", .{directory});
    const image_hash = std.mem.trim(u8, try ctx.read(try fmt(ctx, "{s}/image.sha256", .{directory})), "\r\n");
    try ctx.run(&.{ env(ctx, "EFI_VARS_TOOL", "virt-fw-vars"), "--input", vars, "--output", authorized, "--enroll-generate", "Zigos disposable firmware test", "--no-microsoft", "--microsoft-kek", "none", "--add-db-hash", "4ea05883-5aa1-4b23-a876-0e36079efa1d", image_hash, "--secure-boot" });
    for ([_][]const u8{ "original", "tampered-kernel", "tampered-cmdline" }) |name| {
        const image = try fmt(ctx, "{s}/{s}.efi", .{ directory, name });
        const iso = try fmt(ctx, "{s}/{s}.iso", .{ directory, name });
        const staging = try fmt(ctx, "{s}/{s}.staging", .{ directory, name });
        try images.run(ctx, "build-efi-iso", &.{ image, iso, staging });
        try ctx.write(try fmt(ctx, "{s}/{s}.media.log", .{ directory, name }), try fmt(ctx, "Validated x86-64 UEFI native boot media: {s}\n", .{iso}));
    }
    const original = try fmt(ctx, "{s}/original.iso", .{directory});
    try ctx.copy(original, try fmt(ctx, "{s}/unverified.iso", .{directory}));
    try unifiedCase(h, directory, work, "unverified", vars, "UNVERIFIED", null);
    try unifiedCase(h, directory, work, "original", authorized, "FIRMWARE_AUTHENTICATED", null);
    try unifiedCase(h, directory, work, "tampered-kernel", authorized, "rejected", null);
    try unifiedCase(h, directory, work, "tampered-cmdline", authorized, "rejected", null);
    const sidecars = try fmt(ctx, "{s}/sidecars.staging", .{directory});
    try ctx.removeTree(sidecars);
    try copyTree(ctx, try fmt(ctx, "{s}/original.staging", .{directory}), sidecars);
    const kernel = try fmt(ctx, "{s}/kernel.elf", .{directory});
    const cmdline = try fmt(ctx, "{s}/cmdline.txt", .{directory});
    try ctx.write(kernel, "invalid ELF\n");
    try ctx.write(cmdline, "untrusted_external_options\n");
    const esp = try fmt(ctx, "{s}/esp.img", .{sidecars});
    try ctx.run(&.{ "mmd", "-i", esp, "::/boot" });
    try ctx.run(&.{ "mcopy", "-i", esp, kernel, cmdline, "::/boot/" });
    const media_status = try process.run(ctx, &.{ "xorriso", "-as", "mkisofs", "-R", "-J", "-e", "esp.img", "-no-emul-boot", "-o", try fmt(ctx, "{s}/sidecars.iso", .{directory}), sidecars }, try fmt(ctx, "{s}/sidecars.media.log", .{directory}));
    if (media_status != 0) return error.MediaBuildFailed;
    try unifiedCase(h, directory, work, "sidecars", authorized, "FIRMWARE_AUTHENTICATED", null);
    try ctx.copy(original, try fmt(ctx, "{s}/no-sha256.iso", .{directory}));
    try unifiedCase(h, directory, work, "no-sha256", authorized, "measurement-rejected", "sha1");
    try ctx.print("Unified EFI authentication, TPM measurement, payload tampering, and external override checks passed. Logs: {s}\n", .{directory});
}

fn mappingXstateEvidenceFixture(allocator: std.mem.Allocator) ![]const u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, "firmware output\n");
    try bytes.appendSlice(allocator, mapping_xstate_proofs[0] ++ "\n");
    for (high_half_proofs[0 .. high_half_proofs.len - 1]) |marker| {
        try bytes.appendSlice(allocator, marker);
        try bytes.append(allocator, '\n');
    }
    for (mapping_xstate_proofs[1..]) |marker| {
        try bytes.appendSlice(allocator, marker);
        try bytes.append(allocator, '\n');
    }
    try bytes.appendSlice(allocator, high_half_proofs[high_half_proofs.len - 1] ++ "\n");
    return bytes.toOwnedSlice(allocator);
}

test "Mapping xstate evidence binds all ordered proofs to the actual positive exit" {
    const allocator = std.testing.allocator;
    const valid = try mappingXstateEvidenceFixture(allocator);
    defer allocator.free(valid);
    try validateMappingXstateResult(33, .positive, valid);
    for ([_]u32{ 0, 1, 35, 37, 124, 137, 143, 255 }) |status|
        try std.testing.expectError(error.UnexpectedMappingXstateExit, validateMappingXstateResult(status, .positive, valid));
    try std.testing.expectError(error.UnexpectedMappingXstateEvidence, validateMappingXstateResult(37, .unsupported, valid));
    inline for (.{
        mapping_xstate_namespace ++ "UNKNOWN:PASS\n",
        "prefix " ++ mapping_xstate_namespace ++ "UNKNOWN:PASS\n",
        mapping_xstate_proofs[1] ++ "\n",
        "ZIGOS:ARCH:X86_64:HIGH_HALF:UNKNOWN:PASS\n",
        "ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:PASS\n",
    }) |extra| {
        const bytes = try std.mem.concat(allocator, u8, &.{ valid, extra });
        defer allocator.free(bytes);
        try std.testing.expectError(error.UnexpectedMappingXstateEvidence, validateMappingXstateResult(33, .positive, bytes));
    }
    const failed = try std.mem.concat(allocator, u8, &.{ valid, "panic\n" });
    defer allocator.free(failed);
    try std.testing.expectError(error.UnhealthyMappingXstateEvidence, validateMappingXstateResult(33, .positive, failed));
    const forged = try std.mem.replaceOwned(u8, allocator, valid, mapping_xstate_proofs[2], mapping_xstate_proofs[2] ++ " forged");
    defer allocator.free(forged);
    try std.testing.expectError(error.MissingMarker, validateMappingXstateResult(33, .positive, forged));
    const reversed = try std.mem.replaceOwned(u8, allocator, valid, mapping_xstate_proofs[2] ++ "\n" ++ mapping_xstate_proofs[3], mapping_xstate_proofs[3] ++ "\n" ++ mapping_xstate_proofs[2]);
    defer allocator.free(reversed);
    try std.testing.expectError(error.MarkersOutOfOrder, validateMappingXstateResult(33, .positive, reversed));
    try std.testing.expectError(error.UnhealthyMappingXstateEvidence, validateMappingXstateResult(33, .positive, ""));
    try std.testing.expectError(error.IncompleteMappingXstateEvidence, validateMappingXstateResult(33, .positive, valid[0 .. valid.len - 1]));
}

test "Mapping xstate unsupported evidence requires one complete allowlisted rejection and exit 37" {
    const prefix = mapping_xstate_namespace ++ "UNSUPPORTED:";
    inline for (.{ "CPUID", "XSAVE", "AVX", "XSAVES", "YMM_LAYOUT" }) |reason| {
        const valid = "firmware output\n" ++ prefix ++ reason ++ "\n";
        try validateMappingXstateResult(37, .unsupported, valid);
        try std.testing.expectError(error.UnexpectedMappingXstateExit, validateMappingXstateResult(37, .positive, valid));
        try std.testing.expectError(error.UnsupportedCpuTarget, validateMappingXstateResult(33, .positive, valid));
        for ([_]u32{ 0, 1, 33, 35, 124, 137 }) |status|
            try std.testing.expectError(error.UnexpectedMappingXstateExit, validateMappingXstateResult(status, .unsupported, valid));
        try std.testing.expectError(error.UnexpectedMappingXstateEvidence, validateMappingXstateResult(37, .unsupported, valid ++ prefix ++ reason ++ "\n"));
        try std.testing.expectError(error.UnexpectedMappingXstateEvidence, validateMappingXstateResult(37, .unsupported, valid ++ "ZIGOS:ARCH:X86_64:HIGH_HALF:ENTRY:PASS\n"));
        try std.testing.expectError(error.UnexpectedMappingXstateEvidence, validateMappingXstateResult(37, .unsupported, valid ++ "AP:ONLINE\n"));
        try std.testing.expectError(error.InvalidMappingXstateUnsupportedReason, validateMappingXstateResult(37, .unsupported, "prefix " ++ prefix ++ reason ++ "\n"));
        try std.testing.expectError(error.InvalidMappingXstateUnsupportedReason, validateMappingXstateResult(37, .unsupported, prefix ++ reason ++ " forged\n"));
        try std.testing.expectError(error.InvalidMappingXstateUnsupportedReason, validateMappingXstateResult(37, .unsupported, prefix ++ reason));
    }
    try std.testing.expectError(error.InvalidMappingXstateUnsupportedReason, validateMappingXstateResult(37, .unsupported, prefix ++ "UNKNOWN\n"));
    try std.testing.expectError(error.UnhealthyMappingXstateEvidence, validateMappingXstateResult(37, .unsupported, prefix ++ "XSAVES\npanic\n"));
}

test "Mapping xstate smoke waits for subprocess exit and rejects proof-only timeout" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environment };
    const temporary = try ctx.tempDir("zigos-mapping-xstate-test");
    defer ctx.removeTree(temporary) catch {};
    const binary = try fmt(&ctx, "{s}/qemu", .{temporary});
    const firmware = try fmt(&ctx, "{s}/firmware", .{temporary});
    const serial = try fmt(&ctx, "{s}/serial.log", .{temporary});
    const evidence = try fmt(&ctx, "{s}/evidence.log", .{temporary});
    try ctx.write(firmware, "fixture");
    try ctx.write(evidence, try mappingXstateEvidenceFixture(ctx.allocator));
    try ctx.write(binary,
        \\#!/bin/sh
        \\while [ "$#" -gt 0 ]; do
        \\    if [ "$1" = "-serial" ]; then shift; serial=${1#file:}; break; fi
        \\    shift
        \\done
        \\/bin/cat "$MAPPING_XSTATE_FIXTURE" > "$serial"
        \\if [ "$MAPPING_XSTATE_STATUS" = "wait" ]; then exec /bin/sleep 30; fi
        \\exit "$MAPPING_XSTATE_STATUS"
        \\
    );
    const executable = try std.Io.Dir.cwd().openFile(ctx.io, binary, .{});
    defer executable.close(ctx.io);
    try executable.setPermissions(ctx.io, .fromMode(0o700));
    try environment.put("QEMU_BIN", binary);
    try environment.put("QEMU_STOP_GRACE_SECONDS", "1");
    try environment.put("ZIGOS_MAPPING_XSTATE_SECONDS", "1");
    try environment.put("MAPPING_XSTATE_FIXTURE", evidence);
    const harness: Harness = .{ .ctx = &ctx, .boot_iso = null, .code_override = firmware, .vars_override = firmware, .cpu_override = "fixture" };
    try environment.put("MAPPING_XSTATE_STATUS", "33");
    try mappingXstateSmoke(harness, &.{ "fixture.iso", serial, "positive" });
    try std.testing.expectEqualStrings("33\n", try ctx.read(try fmt(&ctx, "{s}.qemu-status", .{stem(serial)})));
    for ([_][]const u8{ "0", "35", "wait" }) |status| {
        try environment.put("MAPPING_XSTATE_STATUS", status);
        try std.testing.expectError(error.UnexpectedMappingXstateExit, mappingXstateSmoke(harness, &.{ "fixture.iso", serial, "positive" }));
        try std.testing.expectEqualStrings(if (std.mem.eql(u8, status, "wait")) "124\n" else try fmt(&ctx, "{s}\n", .{status}), try ctx.read(try fmt(&ctx, "{s}.qemu-status", .{stem(serial)})));
    }
    try ctx.write(evidence, mapping_xstate_namespace ++ "UNSUPPORTED:XSAVES\n");
    try environment.put("MAPPING_XSTATE_STATUS", "37");
    try mappingXstateSmoke(harness, &.{ "fixture.iso", serial, "unsupported" });
    try std.testing.expectError(error.InvalidArguments, mappingXstateSmoke(harness, &.{ "fixture.iso", serial, "unknown" }));
}

test "entry smoke CPU rejection preserves complete exact feature diagnostics" {
    const marker = "ZIGOS:CPU:BASELINE:MODERN_X86_64:REJECTED";
    try std.testing.expectEqualStrings("Unsupported CPU: missing xsaves", entryCpuRejection("BOOT:START\n" ++ marker ++ "\nUnsupported CPU: missing xsaves\n").?);
    try std.testing.expectEqualStrings("Unsupported CPU: missing fred", entryCpuRejection(marker ++ "\r\nUnsupported CPU: missing fred\r\n").?);
    try std.testing.expectEqualStrings("", entryCpuRejection(marker ++ "\nUnsupported CPU: missing xsa").?);
    try std.testing.expectEqualStrings("Unsupported CPU: missing xsaves", entryCpuRejection(marker ++ "\nUnsupported CPU: missing xsaves\nZIGOS:USERSPACE:RESUME:OK\n").?);
    try std.testing.expectEqualStrings("", entryCpuRejection(marker ++ "\n").?);
    for ([_][]const u8{
        marker,
        "prefix " ++ marker ++ "\nUnsupported CPU: missing xsaves\n",
        marker ++ " forged\nUnsupported CPU: missing xsaves\n",
        "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY\nUnsupported CPU: missing xsaves\n",
        "Unsupported CPU: missing xsaves\n",
        "ZIGOS:USERSPACE:RESUME:OK\n",
    }) |bytes| try std.testing.expect(entryCpuRejection(bytes) == null);
}

test "entry smoke waits for exact reason stops unsupported target before deadline and reaps child" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environment };
    const temporary = try ctx.tempDir("zigos-entry-smoke-test");
    defer ctx.removeTree(temporary) catch {};
    const binary = try fmt(&ctx, "{s}/qemu", .{temporary});
    const firmware = try fmt(&ctx, "{s}/firmware", .{temporary});
    const serial = try fmt(&ctx, "{s}/serial.log", .{temporary});
    try ctx.write(firmware, "fixture");
    try ctx.write(binary,
        \\#!/bin/sh
        \\while [ "$#" -gt 0 ]; do
        \\    if [ "$1" = "-serial" ]; then shift; serial=${1#file:}; break; fi
        \\    shift
        \\done
        \\printf '%s\n' "$$"
        \\printf '%s\n' 'BOOT:START' 'ZIGOS:CPU:BASELINE:MODERN_X86_64:REJECTED' 'ZIGOS:USERSPACE:RESUME:OK' > "$serial"
        \\/bin/sleep 1
        \\printf '%s\n' 'Unsupported CPU: missing xsaves' >> "$serial"
        \\exec /bin/sleep 30
        \\
    );
    const executable = try std.Io.Dir.cwd().openFile(ctx.io, binary, .{});
    defer executable.close(ctx.io);
    try executable.setPermissions(ctx.io, .fromMode(0o700));
    try environment.put("QEMU_BIN", binary);
    try environment.put("QEMU_STOP_GRACE_SECONDS", "1");
    try environment.put("ZIGOS_X86_64_KERNEL_SECONDS", "20");
    const harness: Harness = .{ .ctx = &ctx, .boot_iso = null, .code_override = firmware, .vars_override = firmware, .cpu_override = "fixture" };
    const start = std.Io.Timestamp.now(ctx.io, .awake);
    try std.testing.expectError(error.UnsupportedCpuTarget, entrySmoke(harness, &.{ "fixture.iso", serial }, false));
    const elapsed = process.elapsed(&ctx, start);
    try std.testing.expect(elapsed >= 1000 and elapsed < 5000);
    const bytes = try ctx.read(serial);
    try std.testing.expect(log.exact(bytes, "Unsupported CPU: missing xsaves"));
    try std.testing.expect(log.exact(bytes, "ZIGOS:USERSPACE:RESUME:OK"));
    const pid_text = std.mem.trim(u8, try ctx.read(try fmt(&ctx, "{s}.qemu.log", .{stem(serial)})), "\r\n");
    const pid = try std.fmt.parseInt(std.posix.pid_t, pid_text, 10);
    const group_result = std.c.kill(-pid, @fromBackingInt(@intCast(0)));
    const group_error = std.posix.errno(group_result);
    try std.testing.expect(group_result < 0);
    try std.testing.expectEqual(std.posix.E.SRCH, group_error);
}

test {
    std.testing.refAllDecls(log);
    std.testing.refAllDecls(process);
}

test "AP cache evidence requires actual ordered unique control rejection and enabled records" {
    inline for (.{ ApCacheCase.none, ApCacheCase.version, ApCacheCase.default_reserved, ApCacheCase.mask_reserved, ApCacheCase.enabled }) |case| {
        const allocator = std.testing.allocator;
        const valid = try std.fmt.allocPrint(allocator, "firmware output\n{s}\n{s}\r\n", .{ apCacheFirst(case), apCacheLast(case) });
        defer allocator.free(valid);
        try validateApCacheEvidence(valid, case);
        const missing = try std.fmt.allocPrint(allocator, "{s}\n", .{apCacheFirst(case)});
        defer allocator.free(missing);
        try std.testing.expectError(error.MissingApCacheEvidence, validateApCacheEvidence(missing, case));
        const reversed = try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ apCacheLast(case), apCacheFirst(case) });
        defer allocator.free(reversed);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(reversed, case));
        const duplicate = try std.fmt.allocPrint(allocator, "{s}{s}\n", .{ valid, apCacheLast(case) });
        defer allocator.free(duplicate);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(duplicate, case));
        const prefixed = try std.fmt.allocPrint(allocator, "prefix {s}\n{s}\n", .{ apCacheFirst(case), apCacheLast(case) });
        defer allocator.free(prefixed);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(prefixed, case));
        const suffixed = try std.fmt.allocPrint(allocator, "{s}\n{s} forged\n", .{ apCacheFirst(case), apCacheLast(case) });
        defer allocator.free(suffixed);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(suffixed, case));
        const double_cr = try std.fmt.allocPrint(allocator, "{s}\n{s}\r\r\n", .{ apCacheFirst(case), apCacheLast(case) });
        defer allocator.free(double_cr);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(double_cr, case));
    }
}

test "AP cache evidence rejects concurrent failure high entry foreign success and wrong rejection" {
    const allocator = std.testing.allocator;
    const valid = "ZIGOS:ARCH:X86_64:AP_CACHE:VERSION:ARMED\nZIGOS:BOOT:CACHE:AP:REJECT:5\r\n";
    inline for (.{ "ZIGOS:ARCH:X86_64:AP_CACHE:FAIL:UNEXPECTED_HIGH_ENTRY\n", "panic\n" }) |failure| {
        const bytes = try std.fmt.allocPrint(allocator, "{s}{s}", .{ valid, failure });
        defer allocator.free(bytes);
        try std.testing.expectError(error.UnhealthyApCacheEvidence, validateApCacheEvidence(bytes, .version));
    }
    inline for (.{ "AP_HIGH_ENTRY\n", "ZIGOS:ARCH:X86_64:HIGH_HALF:PASS\n", "ZIGOS:BOOT:CACHE:AP:ONLINE\n", "ZIGOS:BOOT:CACHE:AP:REJECT:4\n" }) |foreign| {
        const bytes = try std.fmt.allocPrint(allocator, "{s}{s}", .{ valid, foreign });
        defer allocator.free(bytes);
        try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(bytes, .version));
    }
    try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence(valid, .default_reserved));
    try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence("ZIGOS:ARCH:X86_64:AP_CACHE:VERSION:ARMED ZIGOS:BOOT:CACHE:AP:REJECT:5\n", .version));
    try std.testing.expectError(error.UnexpectedApCacheEvidence, validateApCacheEvidence("ZIGOS:ARCH:X86_64:AP_CACHE:VERSION:ARMED\nZIGOS:BOOT:CACHE:AP:REJECT:4\n", .version));
}

test "TPM control sockets use short private directories despite a long TMPDIR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    try environment.put("TMPDIR", "/var/folders/long/per-user/temporary/directory/that/exceeds/socket/path/limits");
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environment };
    const temporary = try socketTempDir(&ctx, "zigos-efi-tpm");
    defer ctx.removeTree(temporary) catch {};
    const socket_path = try fmt(&ctx, "{s}/tampered-cmdline/control.sock", .{temporary});
    try std.testing.expect(socket_path.len < 104);
    const stat = try std.Io.Dir.cwd().statFile(ctx.io, temporary, .{});
    try std.testing.expectEqual(@as(u32, 0o700), stat.permissions.toMode() & 0o777);
}
