const std = @import("std");

pub const PROTOCOL_NUMBER: u8 = 6;
pub const MSS: u16 = 536;

pub const OPT_END: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_MSS: u8 = 2;
pub const OPT_WINDOW_SCALE: u8 = 3;
pub const OPT_SACK_PERMITTED: u8 = 4;
pub const OPT_SACK: u8 = 5;
pub const OPT_TIMESTAMPS: u8 = 8;

pub const SACKBlock = struct {
    left_edge: u32,
    right_edge: u32,
};

pub const Flags = struct {
    pub const FIN: u8 = 1 << 0;
    pub const SYN: u8 = 1 << 1;
    pub const RST: u8 = 1 << 2;
    pub const PSH: u8 = 1 << 3;
    pub const ACK: u8 = 1 << 4;
    pub const URG: u8 = 1 << 5;
};

pub const State = enum {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
};

pub const Header = packed struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_and_flags: u16,
    window_size: u16,
    checksum: u16,
    urgent_ptr: u16,

    pub fn getDataOffset(self: *const Header) u8 {
        return @intCast((@byteSwap(self.data_offset_and_flags) >> 12) * 4);
    }

    pub fn getFlags(self: *const Header) u8 {
        return @intCast(@byteSwap(self.data_offset_and_flags) & 0x3F);
    }

    pub fn setDataOffsetAndFlags(self: *Header, data_offset: u8, flags: u8) void {
        const offset_in_words = data_offset / 4;
        self.data_offset_and_flags = @byteSwap(@as(u16, offset_in_words) << 12 | @as(u16, flags));
    }
};

pub fn calculateChecksumIPv4(src_ip: u32, dst_ip: u32, tcp_header: *const Header, data: []const u8) u16 {
    var sum: u32 = 0;

    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += PROTOCOL_NUMBER;
    sum += @sizeOf(Header) + data.len;

    addBytesToChecksum(&sum, headerBytes(tcp_header));
    addBytesToChecksum(&sum, data);
    return finalizeChecksum(sum);
}

pub fn calculateChecksumIPv6(src_octets: *const [16]u8, dst_octets: *const [16]u8, tcp_header: *const Header, data: []const u8) u16 {
    var sum: u32 = 0;

    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, src_octets[i]) << 8 | src_octets[i + 1];
        sum += @as(u32, dst_octets[i]) << 8 | dst_octets[i + 1];
    }
    sum += @as(u16, @intCast(@sizeOf(Header) + data.len));
    sum += PROTOCOL_NUMBER;

    addBytesToChecksum(&sum, headerBytes(tcp_header));
    addBytesToChecksum(&sum, data);
    return finalizeChecksum(sum);
}

pub fn seqLessThan(a: u32, b: u32) bool {
    const diff: i32 = @bitCast(a -% b);
    return diff < 0;
}

pub fn seqLessThanEq(a: u32, b: u32) bool {
    return a == b or seqLessThan(a, b);
}

pub fn parseOptions(data: []const u8, conn: anytype, now: u32) ?u32 {
    var measured_rtt: ?u32 = null;
    var i: usize = 0;
    while (i < data.len) {
        const kind = data[i];
        if (kind == OPT_END) break;
        if (kind == OPT_NOP) {
            i += 1;
            continue;
        }

        if (i + 1 >= data.len) break;
        const opt_len = data[i + 1];
        if (opt_len < 2 or i + opt_len > data.len) break;

        switch (kind) {
            OPT_MSS => {
                if (opt_len == 4 and i + 3 < data.len) {
                    conn.mss = @as(u16, data[i + 2]) << 8 | data[i + 3];
                }
            },
            OPT_WINDOW_SCALE => {
                if (opt_len == 3 and i + 2 < data.len) {
                    conn.window_scale_recv = data[i + 2];
                    if (conn.window_scale_recv > 14) conn.window_scale_recv = 14;
                }
            },
            OPT_SACK_PERMITTED => {
                if (opt_len == 2) {
                    conn.sack_permitted = true;
                }
            },
            OPT_SACK => {
                const num_blocks = (opt_len - 2) / 8;
                var b: usize = 0;
                while (b < num_blocks and b < conn.sack_blocks.len) : (b += 1) {
                    const base = i + 2 + b * 8;
                    if (base + 7 < data.len) {
                        conn.sack_blocks[b] = SACKBlock{
                            .left_edge = @as(u32, data[base]) << 24 | @as(u32, data[base + 1]) << 16 | @as(u32, data[base + 2]) << 8 | data[base + 3],
                            .right_edge = @as(u32, data[base + 4]) << 24 | @as(u32, data[base + 5]) << 16 | @as(u32, data[base + 6]) << 8 | data[base + 7],
                        };
                    }
                }
            },
            OPT_TIMESTAMPS => {
                if (opt_len == 10 and i + 9 < data.len) {
                    const tsval = @as(u32, data[i + 2]) << 24 | @as(u32, data[i + 3]) << 16 | @as(u32, data[i + 4]) << 8 | data[i + 5];
                    const tsecr = @as(u32, data[i + 6]) << 24 | @as(u32, data[i + 7]) << 16 | @as(u32, data[i + 8]) << 8 | data[i + 9];
                    conn.ts_enabled = true;
                    conn.ts_recent = tsval;
                    conn.ts_ecr = tsval;
                    if (tsecr != 0) {
                        const rtt = now -% tsecr;
                        if (rtt > 0 and rtt < 60000) {
                            measured_rtt = rtt;
                        }
                    }
                    conn.ts_val = now;
                }
            },
            else => {},
        }

        i += opt_len;
    }

    return measured_rtt;
}

pub fn buildOptions(conn: anytype, buf: []u8, is_syn: bool) usize {
    var offset: usize = 0;

    if (is_syn) {
        if (offset + 4 <= buf.len) {
            buf[offset] = OPT_MSS;
            buf[offset + 1] = 4;
            buf[offset + 2] = @intCast((conn.mss >> 8) & 0xFF);
            buf[offset + 3] = @intCast(conn.mss & 0xFF);
            offset += 4;
        }

        if (offset + 3 <= buf.len) {
            buf[offset] = OPT_WINDOW_SCALE;
            buf[offset + 1] = 3;
            buf[offset + 2] = conn.window_scale_send;
            offset += 3;
        }

        if (offset + 2 <= buf.len) {
            buf[offset] = OPT_SACK_PERMITTED;
            buf[offset + 1] = 2;
            offset += 2;
        }

        if (offset + 1 <= buf.len) {
            buf[offset] = OPT_NOP;
            offset += 1;
        }
    }

    if (conn.ts_enabled) {
        while (offset % 4 != 0 and offset < buf.len) {
            buf[offset] = OPT_NOP;
            offset += 1;
        }

        if (offset + 10 <= buf.len) {
            buf[offset] = OPT_TIMESTAMPS;
            buf[offset + 1] = 10;
            const ts = conn.ts_val;
            buf[offset + 2] = @intCast((ts >> 24) & 0xFF);
            buf[offset + 3] = @intCast((ts >> 16) & 0xFF);
            buf[offset + 4] = @intCast((ts >> 8) & 0xFF);
            buf[offset + 5] = @intCast(ts & 0xFF);
            const ecr = conn.ts_ecr;
            buf[offset + 6] = @intCast((ecr >> 24) & 0xFF);
            buf[offset + 7] = @intCast((ecr >> 16) & 0xFF);
            buf[offset + 8] = @intCast((ecr >> 8) & 0xFF);
            buf[offset + 9] = @intCast(ecr & 0xFF);
            offset += 10;
        }
    }

    while (offset % 4 != 0 and offset < buf.len) {
        buf[offset] = OPT_NOP;
        offset += 1;
    }

    return offset;
}

pub fn applySACKBlocks(conn: anytype) void {
    if (!conn.sack_permitted) return;

    for (&conn.sack_blocks) |*block| {
        if (block.left_edge == 0 and block.right_edge == 0) continue;

        for (&conn.retx_queue) |*entry| {
            if (entry.active) {
                const entry_end = entry.seq_num +% entry.data_len;
                if (seqLessThanEq(block.left_edge, entry.seq_num) and seqLessThanEq(entry_end, block.right_edge)) {
                    entry.active = false;
                    conn.bytes_in_flight -|= entry.data_len;
                }
            }
        }

        block.left_edge = 0;
        block.right_edge = 0;
    }
}

fn headerBytes(tcp_header: *const Header) []const u8 {
    const header_bytes_ptr: [*]const u8 = @ptrCast(tcp_header);
    return header_bytes_ptr[0..@sizeOf(Header)];
}

fn addBytesToChecksum(sum: *u32, bytes: []const u8) void {
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum.* += @as(u16, bytes[i]) << 8 | bytes[i + 1];
    }
    if (bytes.len & 1 != 0) {
        sum.* += @as(u16, bytes[bytes.len - 1]) << 8;
    }
}

fn finalizeChecksum(initial_sum: u32) u16 {
    var sum = initial_sum;
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const result: u16 = @intCast(sum);
    return ~result;
}

const FakeRetxEntry = struct {
    seq_num: u32 = 0,
    data_len: u16 = 0,
    active: bool = false,
};

const FakeConn = struct {
    mss: u16 = MSS,
    window_scale_send: u8 = 0,
    window_scale_recv: u8 = 0,
    sack_permitted: bool = false,
    sack_blocks: [4]SACKBlock = [_]SACKBlock{SACKBlock{ .left_edge = 0, .right_edge = 0 }} ** 4,
    ts_enabled: bool = false,
    ts_val: u32 = 0,
    ts_ecr: u32 = 0,
    ts_recent: u32 = 0,
    retx_queue: [2]FakeRetxEntry = [_]FakeRetxEntry{FakeRetxEntry{}} ** 2,
    bytes_in_flight: u32 = 0,
};

test "header roundtrips data offset and flags" {
    var header = Header{
        .src_port = 0,
        .dst_port = 0,
        .seq_num = 0,
        .ack_num = 0,
        .data_offset_and_flags = 0,
        .window_size = 0,
        .checksum = 0,
        .urgent_ptr = 0,
    };
    header.setDataOffsetAndFlags(24, Flags.SYN | Flags.ACK);

    try std.testing.expectEqual(@as(u8, 24), header.getDataOffset());
    try std.testing.expectEqual(@as(u8, Flags.SYN | Flags.ACK), header.getFlags());
}

test "sequence comparisons handle wraparound" {
    try std.testing.expect(seqLessThan(0xFFFFFFFE, 2));
    try std.testing.expect(seqLessThanEq(0xFFFFFFFE, 2));
    try std.testing.expect(!seqLessThan(2, 0xFFFFFFFE));
    try std.testing.expect(seqLessThanEq(7, 7));
}

test "buildOptions emits SYN and timestamp options on aligned boundaries" {
    var conn = FakeConn{
        .window_scale_send = 7,
        .ts_enabled = true,
        .ts_val = 0x01020304,
        .ts_ecr = 0x05060708,
    };
    var buf: [40]u8 = [_]u8{0} ** 40;

    const len = buildOptions(&conn, &buf, true);
    try std.testing.expectEqual(@as(usize, 24), len);
    try std.testing.expectEqual(@as(u8, OPT_MSS), buf[0]);
    try std.testing.expectEqual(@as(u8, OPT_WINDOW_SCALE), buf[4]);
    try std.testing.expectEqual(@as(u8, OPT_SACK_PERMITTED), buf[7]);
    try std.testing.expectEqual(@as(u8, OPT_TIMESTAMPS), buf[12]);
    try std.testing.expectEqual(@as(u8, 0x01), buf[14]);
    try std.testing.expectEqual(@as(u8, 0x08), buf[21]);
}

test "parseOptions updates option state and reports timestamp RTT" {
    var conn = FakeConn{};
    const options = [_]u8{
        OPT_MSS, 4, 0x12, 0x34,
        OPT_WINDOW_SCALE, 3, 20,
        OPT_SACK_PERMITTED, 2,
        OPT_NOP,
        OPT_TIMESTAMPS, 10, 0, 0, 0, 5, 0, 0, 0, 90,
    };

    const rtt = parseOptions(&options, &conn, 100);
    try std.testing.expectEqual(@as(u16, 0x1234), conn.mss);
    try std.testing.expectEqual(@as(u8, 14), conn.window_scale_recv);
    try std.testing.expect(conn.sack_permitted);
    try std.testing.expect(conn.ts_enabled);
    try std.testing.expectEqual(@as(u32, 5), conn.ts_recent);
    try std.testing.expectEqual(@as(u32, 5), conn.ts_ecr);
    try std.testing.expectEqual(@as(u32, 100), conn.ts_val);
    try std.testing.expectEqual(@as(?u32, 10), rtt);
}

test "applySACKBlocks clears covered retransmits" {
    var conn = FakeConn{
        .sack_permitted = true,
        .bytes_in_flight = 100,
        .sack_blocks = .{
            .{ .left_edge = 1000, .right_edge = 1040 },
            .{ .left_edge = 0, .right_edge = 0 },
            .{ .left_edge = 0, .right_edge = 0 },
            .{ .left_edge = 0, .right_edge = 0 },
        },
        .retx_queue = .{
            .{ .seq_num = 1000, .data_len = 40, .active = true },
            .{ .seq_num = 2000, .data_len = 20, .active = true },
        },
    };

    applySACKBlocks(&conn);
    try std.testing.expect(!conn.retx_queue[0].active);
    try std.testing.expect(conn.retx_queue[1].active);
    try std.testing.expectEqual(@as(u32, 60), conn.bytes_in_flight);
    try std.testing.expectEqual(@as(u32, 0), conn.sack_blocks[0].left_edge);
    try std.testing.expectEqual(@as(u32, 0), conn.sack_blocks[0].right_edge);
}
