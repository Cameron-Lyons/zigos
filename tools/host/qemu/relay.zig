//! Bounded localhost relay for final Noise confirmation loss in QEMU tests.
//! QEMU's socket backend prefixes each Ethernet frame with a big endian u32.
//! Only visible routing fields and the nonce select losses; encrypted bytes
//! are preserved exactly, including the confirmation's immutable retries.
const std = @import("std");
const common = @import("../common.zig");

const max_frame = 65536;
const mac_a = [_]u8{ 0x02, 0x5a, 0x47, 0, 0, 1 };
const mac_b = [_]u8{ 0x02, 0x5a, 0x47, 0, 0, 2 };

const Options = struct {
    upstream_port: u16,
    drop_confirmations: u8 = 2,
};

fn parseArgs(args: []const []const u8) !Options {
    var port: ?u16 = null;
    var losses: u8 = 2;
    var index: usize = 0;
    while (index < args.len) {
        const option = args[index];
        const equals = std.mem.indexOfScalar(u8, option, '=');
        const name = option[0 .. equals orelse option.len];
        const value = if (equals) |offset| option[offset + 1 ..] else value: {
            index += 1;
            if (index == args.len) return error.InvalidArguments;
            break :value args[index];
        };
        if (std.mem.eql(u8, name, "--upstream-port")) {
            port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidArguments;
            if (port.? == 0) return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--drop-confirmations")) {
            losses = std.fmt.parseInt(u8, value, 10) catch return error.InvalidArguments;
            if (losses != 0 and losses != 2) return error.InvalidArguments;
        } else return error.InvalidArguments;
        index += 1;
    }
    return .{ .upstream_port = port orelse return error.InvalidArguments, .drop_confirmations = losses };
}

pub fn run(ctx: *common.Context, args: []const []const u8) !void {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return ctx.print("usage: qemu-peer-relay --upstream-port PORT [--drop-confirmations {{0,2}}]\n", .{});
        }
    }
    const options = try parseArgs(args);
    var log_buffer: [4096]u8 = undefined;
    var logger = std.Io.File.stdout().writer(ctx.io, &log_buffer);
    try serve(ctx.io, options.upstream_port, options.drop_confirmations, &logger.interface, null);
}

fn finalConfirmation(frame: []const u8) bool {
    return frame.len == 104 and
        std.mem.eql(u8, frame[0..6], &mac_b) and
        std.mem.eql(u8, frame[6..12], &mac_a) and
        std.mem.eql(u8, frame[12..20], "\x88\xb5ZGNP\x01\x04") and
        std.mem.readInt(u64, frame[20..28], .little) == 1 and
        std.mem.readInt(u64, frame[28..36], .little) == 2 and
        std.mem.readInt(u64, frame[52..60], .little) == 0;
}

const ConfirmationLoss = struct {
    limit: u8,
    dropped: u8 = 0,
    first: ?[104]u8 = null,
    recovered: bool = false,

    fn drop(self: *ConfirmationLoss, frame: []const u8, logger: *std.Io.Writer) !bool {
        if (!finalConfirmation(frame)) return false;
        if (self.first) |first| {
            if (!std.mem.eql(u8, frame, &first)) return error.ConfirmationChanged;
        } else self.first = frame[0..104].*;
        if (self.dropped < self.limit) {
            self.dropped += 1;
            try logger.print("SYNC_RELAY:DROPPED_CONFIRMATION {d}\n", .{self.dropped});
            try logger.flush();
            return true;
        }
        if (self.dropped != 0 and !self.recovered) {
            self.recovered = true;
            try logger.writeAll("SYNC_RELAY:RETRIED_CONFIRMATION\n");
            try logger.flush();
        }
        return false;
    }
};

fn readFrame(reader: *std.Io.Reader, buffer: *[max_frame]u8) !?[]const u8 {
    var header: [4]u8 = undefined;
    const amount = try reader.readSliceShort(&header);
    if (amount == 0) return null;
    if (amount != header.len) return error.TruncatedFrameLength;
    const size = std.mem.readInt(u32, &header, .big);
    if (size < 14 or size > max_frame) return error.InvalidFrameLength;
    const frame = buffer[0..size];
    reader.readSliceAll(frame) catch |err| switch (err) {
        error.EndOfStream => return error.TruncatedEthernetFrame,
        else => return err,
    };
    return frame;
}

fn writeFrame(writer: *std.Io.Writer, frame: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(frame.len), .big);
    try writer.writeAll(&header);
    try writer.writeAll(frame);
    try writer.flush();
}

fn forward(reader: *std.Io.Reader, writer: *std.Io.Writer, loss: ?*ConfirmationLoss, logger: *std.Io.Writer) !void {
    var buffer: [max_frame]u8 = undefined;
    while (try readFrame(reader, &buffer)) |frame| {
        if (loss) |rule| if (try rule.drop(frame, logger)) continue;
        try writeFrame(writer, frame);
    }
}

fn forwardStream(io: std.Io, source: std.Io.net.Stream, destination: std.Io.net.Stream, loss: ?*ConfirmationLoss, logger: *std.Io.Writer) anyerror!void {
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var reader = source.reader(io, &read_buffer);
    var writer = destination.writer(io, &write_buffer);
    forward(&reader.interface, &writer.interface, loss, logger) catch |err| switch (err) {
        error.ReadFailed => return reader.err orelse error.ReadFailed,
        error.WriteFailed => return writer.err orelse error.WriteFailed,
        else => return err,
    };
}

fn connectRetry(io: std.Io, port: u16) anyerror!std.Io.net.Stream {
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    while (true) {
        return address.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch |err| switch (err) {
            error.ConnectionRefused => {
                try std.Io.sleep(io, .fromMilliseconds(50), .awake);
                continue;
            },
            error.Timeout => return error.UpstreamListenTimeout,
            else => return err,
        };
    }
}

fn connectUpstream(io: std.Io, port: u16, timeout: std.Io.Duration) !std.Io.net.Stream {
    // The pinned Threaded I/O implementation does not implement ConnectOptions
    // timeouts. Race the entire cancellable connect/retry loop against a timer.
    const Result = union(enum) { connected: anyerror!std.Io.net.Stream, expired: anyerror!void };
    var results: [2]Result = undefined;
    var select = std.Io.Select(Result).init(io, &results);
    defer while (select.cancel()) |result| switch (result) {
        .connected => |connected| if (connected) |stream| stream.close(io) else |_| {},
        .expired => {},
    };
    try select.concurrent(.connected, connectRetry, .{ io, port });
    try select.concurrent(.expired, expire, .{ io, timeout });
    return switch (try select.await()) {
        .connected => |stream| try stream,
        .expired => |result| {
            try result;
            return error.UpstreamListenTimeout;
        },
    };
}

fn acceptStream(io: std.Io, server: *std.Io.net.Server) anyerror!std.Io.net.Stream {
    return server.accept(io);
}

fn expire(io: std.Io, duration: std.Io.Duration) anyerror!void {
    try std.Io.sleep(io, duration, .awake);
}

fn acceptDeadline(io: std.Io, server: *std.Io.net.Server, duration: std.Io.Duration) !std.Io.net.Stream {
    const Result = union(enum) { accepted: anyerror!std.Io.net.Stream, expired: anyerror!void };
    var results: [2]Result = undefined;
    var select = std.Io.Select(Result).init(io, &results);
    // A canceled accept can have just completed; drain and close that socket.
    defer while (select.cancel()) |result| switch (result) {
        .accepted => |accepted| if (accepted) |stream| stream.close(io) else |_| {},
        .expired => {},
    };
    try select.concurrent(.accepted, acceptStream, .{ io, server });
    try select.concurrent(.expired, expire, .{ io, duration });
    return switch (try select.await()) {
        .accepted => |stream| try stream,
        .expired => |result| {
            try result;
            return error.DownstreamAcceptTimeout;
        },
    };
}

fn relayStreams(io: std.Io, upstream: std.Io.net.Stream, downstream: std.Io.net.Stream, losses: u8, logger: *std.Io.Writer) !void {
    var loss: ConfirmationLoss = .{ .limit = losses };
    const Result = union(enum) { upstream: anyerror!void, downstream: anyerror!void };
    var results: [2]Result = undefined;
    var select = std.Io.Select(Result).init(io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.upstream, forwardStream, .{ io, upstream, downstream, &loss, logger });
    try select.concurrent(.downstream, forwardStream, .{ io, downstream, upstream, null, logger });
    var failure: ?anyerror = null;
    switch (try select.await()) {
        inline else => |result| result catch |err| {
            failure = err;
        },
    }
    // Surface errors that completed concurrently with the first EOF as well.
    // Only the cancellation of the other forwarding task is expected here.
    while (select.cancel()) |result| switch (result) {
        inline else => |outcome| outcome catch |err| {
            if (err != error.Canceled and failure == null) failure = err;
        },
    };
    if (failure) |err| return err;
}

fn serve(io: std.Io, upstream_port: u16, losses: u8, logger: *std.Io.Writer, ready: ?*std.Io.Queue(u16)) anyerror!void {
    const upstream = try connectUpstream(io, upstream_port, .fromSeconds(10));
    defer upstream.close(io);
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true, .mode = .stream, .protocol = .tcp });
    var listening = true;
    defer if (listening) server.deinit(io);
    const port = server.socket.address.getPort();
    try logger.print("SYNC_RELAY:READY {d}\n", .{port});
    try logger.flush();
    if (ready) |queue| try queue.putOne(io, port);
    const downstream = try acceptDeadline(io, &server, .fromSeconds(20));
    defer downstream.close(io);
    server.deinit(io);
    listening = false;
    try relayStreams(io, upstream, downstream, losses, logger);
}

fn confirmation() [104]u8 {
    var frame: [104]u8 = @splat(0);
    @memcpy(frame[0..6], &mac_b);
    @memcpy(frame[6..12], &mac_a);
    @memcpy(frame[12..20], "\x88\xb5ZGNP\x01\x04");
    std.mem.writeInt(u64, frame[20..28], 1, .little);
    std.mem.writeInt(u64, frame[28..36], 2, .little);
    for (frame[36..52], 0..) |*byte, index| byte.* = @intCast(index);
    for (frame[60..], 0..) |*byte, index| byte.* = @intCast(index);
    return frame;
}

test "QEMU relay validates command line ports and loss counts" {
    try std.testing.expectEqual(Options{ .upstream_port = 12345 }, try parseArgs(&.{ "--upstream-port", "12345" }));
    try std.testing.expectEqual(Options{ .upstream_port = 65535, .drop_confirmations = 0 }, try parseArgs(&.{ "--upstream-port=65535", "--drop-confirmations=0" }));
    for ([_][]const []const u8{ &.{}, &.{"--upstream-port"}, &.{ "--upstream-port", "0" }, &.{ "--upstream-port", "65536" }, &.{ "--upstream-port", "1", "--drop-confirmations", "1" }, &.{ "--upstream-port", "1", "--other", "2" } }) |args| {
        try std.testing.expectError(error.InvalidArguments, parseArgs(args));
    }
}

const FragmentReader = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    bytes: []const u8,
    position: usize = 0,
    fragment: usize = 1,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *FragmentReader = @fieldParentPtr("interface", reader);
        if (self.position == self.bytes.len) return error.EndOfStream;
        const amount = limit.minInt(@min(self.fragment, self.bytes.len - self.position));
        try writer.writeAll(self.bytes[self.position..][0..amount]);
        self.position += amount;
        return amount;
    }
};

test "QEMU relay reads fragmented and coalesced bounded frames" {
    const packet = confirmation();
    var wire: [3 * (4 + packet.len)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    for (0..3) |_| try writeFrame(&writer, &packet);
    var reader: FragmentReader = .{ .bytes = &wire };
    var buffer: [max_frame]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &packet, (try readFrame(&reader.interface, &buffer)).?);
    reader.fragment = wire.len;
    for (0..2) |_| try std.testing.expectEqualSlices(u8, &packet, (try readFrame(&reader.interface, &buffer)).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try readFrame(&reader.interface, &buffer));
}

test "QEMU relay rejects frame truncation and invalid lengths" {
    var buffer: [max_frame]u8 = undefined;
    var reader: std.Io.Reader = .fixed("\x00");
    try std.testing.expectError(error.TruncatedFrameLength, readFrame(&reader, &buffer));
    reader = .fixed("\x00\x00\x00\x68short");
    try std.testing.expectError(error.TruncatedEthernetFrame, readFrame(&reader, &buffer));
    reader = .fixed("\x00\x00\x00\x0d");
    try std.testing.expectError(error.InvalidFrameLength, readFrame(&reader, &buffer));
    reader = .fixed("\x00\x01\x00\x01");
    try std.testing.expectError(error.InvalidFrameLength, readFrame(&reader, &buffer));
}

test "QEMU relay drops only two identical final confirmations" {
    const packet = confirmation();
    var log_buffer: [512]u8 = undefined;
    var logger: std.Io.Writer = .fixed(&log_buffer);
    var rule: ConfirmationLoss = .{ .limit = 2 };
    for ([_]usize{ 0, 6, 12, 14, 18, 19, 20, 28, 52 }) |offset| {
        var wrong = packet;
        wrong[offset] ^= 1;
        try std.testing.expect(!try rule.drop(&wrong, &logger));
    }
    try std.testing.expect(!try rule.drop(packet[0 .. packet.len - 1], &logger));
    try std.testing.expectEqual(@as(u8, 0), rule.dropped);
    try std.testing.expect(try rule.drop(&packet, &logger));
    try std.testing.expect(try rule.drop(&packet, &logger));
    try std.testing.expect(!try rule.drop(&packet, &logger));
    try std.testing.expect(!try rule.drop(&packet, &logger));
    try std.testing.expectEqual(@as(u8, 2), rule.dropped);
    try std.testing.expect(rule.recovered);
    var changed = packet;
    changed[changed.len - 1] ^= 1;
    try std.testing.expectError(error.ConfirmationChanged, rule.drop(&changed, &logger));
    try std.testing.expectEqualStrings("SYNC_RELAY:DROPPED_CONFIRMATION 1\nSYNC_RELAY:DROPPED_CONFIRMATION 2\nSYNC_RELAY:RETRIED_CONFIRMATION\n", logger.buffered());

    var no_loss: ConfirmationLoss = .{ .limit = 0 };
    var silent: std.Io.Writer = .fixed(&.{});
    try std.testing.expect(!try no_loss.drop(&packet, &silent));
    try std.testing.expect(!no_loss.recovered);
    try std.testing.expectError(error.ConfirmationChanged, no_loss.drop(&changed, &silent));
}

test "QEMU relay preserves framing and unrelated payloads" {
    const packet = confirmation();
    const other = "ordinary frame";
    var input: [4 * (max_frame + 4)]u8 = undefined;
    var input_writer: std.Io.Writer = .fixed(&input);
    for ([_][]const u8{ &packet, other, &packet, &packet }) |frame| try writeFrame(&input_writer, frame);
    var reader: std.Io.Reader = .fixed(input_writer.buffered());
    var output: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    var log_buffer: [512]u8 = undefined;
    var logger: std.Io.Writer = .fixed(&log_buffer);
    var rule: ConfirmationLoss = .{ .limit = 2 };
    try forward(&reader, &writer, &rule, &logger);
    var expected: [256]u8 = undefined;
    var expected_writer: std.Io.Writer = .fixed(&expected);
    try writeFrame(&expected_writer, other);
    try writeFrame(&expected_writer, &packet);
    try std.testing.expectEqualSlices(u8, expected_writer.buffered(), writer.buffered());
}

fn liveExercise(io: std.Io) anyerror!void {
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .mode = .stream, .protocol = .tcp });
    defer server.deinit(io);
    var ready_buffer: [1]u16 = undefined;
    var ready: std.Io.Queue(u16) = .init(&ready_buffer);
    defer ready.close(io);
    var log_buffer: [1024]u8 = undefined;
    var logger: std.Io.Writer = .fixed(&log_buffer);
    var running = try std.Io.concurrent(io, serve, .{ io, server.socket.address.getPort(), 2, &logger, &ready });
    defer running.cancel(io) catch {};
    const relay_port = try ready.getOne(io);
    const upstream = try server.accept(io);
    defer upstream.close(io);
    const relay_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(relay_port) };
    const downstream = try relay_address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    var downstream_open = true;
    defer if (downstream_open) downstream.close(io);

    var write_buffer_a: [512]u8 = undefined;
    var writer_a = upstream.writer(io, &write_buffer_a);
    const packet = confirmation();
    for (0..3) |_| try writeFrame(&writer_a.interface, &packet);
    var read_buffer_b: [512]u8 = undefined;
    var reader_b = downstream.reader(io, &read_buffer_b);
    var frame_buffer: [max_frame]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &packet, (try readFrame(&reader_b.interface, &frame_buffer)).?);

    var write_buffer_b: [512]u8 = undefined;
    var writer_b = downstream.writer(io, &write_buffer_b);
    try writeFrame(&writer_b.interface, "reverse traffic");
    var read_buffer_a: [512]u8 = undefined;
    var reader_a = upstream.reader(io, &read_buffer_a);
    try std.testing.expectEqualStrings("reverse traffic", (try readFrame(&reader_a.interface, &frame_buffer)).?);
    downstream.close(io);
    downstream_open = false;
    try running.await(io);
    try std.testing.expectEqual(@as(?[]const u8, null), try readFrame(&reader_a.interface, &frame_buffer));
    try std.testing.expect(std.mem.startsWith(u8, logger.buffered(), "SYNC_RELAY:READY "));
    try std.testing.expect(std.mem.endsWith(u8, logger.buffered(), "SYNC_RELAY:DROPPED_CONFIRMATION 1\nSYNC_RELAY:DROPPED_CONFIRMATION 2\nSYNC_RELAY:RETRIED_CONFIRMATION\n"));
}

test "QEMU relay forwards both live TCP directions and closes" {
    const io = std.testing.io;
    const Result = union(enum) { exercise: anyerror!void, timeout: anyerror!void };
    var results: [2]Result = undefined;
    var select = std.Io.Select(Result).init(io, &results);
    defer select.cancelDiscard();
    try select.concurrent(.exercise, liveExercise, .{io});
    try select.concurrent(.timeout, expire, .{ io, std.Io.Duration.fromSeconds(3) });
    switch (try select.await()) {
        .exercise => |result| try result,
        .timeout => |result| {
            try result;
            return error.LiveRelayTestTimeout;
        },
    }
}

test "QEMU relay bounds connect and accept deadlines" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .mode = .stream, .protocol = .tcp });
    const unused_port = server.socket.address.getPort();
    try std.testing.expectError(error.DownstreamAcceptTimeout, acceptDeadline(io, &server, .fromMilliseconds(10)));
    server.deinit(io);
    try std.testing.expectError(error.UpstreamListenTimeout, connectUpstream(io, unused_port, .fromMilliseconds(10)));
}
