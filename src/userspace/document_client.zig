const std = @import("std");
const protocol = @import("document_protocol.zig");

// One open document, one immutable save attempt. Transport backpressure never
// advances the frame cursor; receipt correlation includes the service endpoint.
pub const Client = struct {
    service_endpoint_id: u64,
    object_id: u64,
    version_id: u64,
    request_id: u64 = 0,
    snapshot: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined,
    length: u16 = 0,
    offset: u16 = 0,
    phase: enum { idle, reading, awaiting_read, loaded, begin, chunks, commit, awaiting_receipt, retryable, failed } = .idle,
    last_status: ?protocol.Status = null,
    saved_receipt: ?protocol.Receipt = null,

    pub fn open(self: *Client) error{ Busy, RequestIdsExhausted }!void {
        if (self.phase != .idle) return error.Busy;
        if (self.request_id == std.math.maxInt(u64)) return error.RequestIdsExhausted;
        self.request_id += 1;
        self.length = 0;
        self.offset = 0;
        self.last_status = null;
        self.saved_receipt = null;
        self.phase = .reading;
    }

    pub fn finishOpen(self: *Client) ?[]const u8 {
        if (self.phase != .loaded) return null;
        self.phase = .idle;
        return self.snapshot[0..self.length];
    }

    pub fn start(self: *Client, text: []const u8) error{ Busy, TooLarge, RequestIdsExhausted }!void {
        if (self.phase != .idle) return error.Busy;
        if (text.len > self.snapshot.len) return error.TooLarge;
        if (self.request_id == std.math.maxInt(u64)) return error.RequestIdsExhausted;
        self.request_id += 1;
        @memcpy(self.snapshot[0..text.len], text);
        self.length = @intCast(text.len);
        self.offset = 0;
        self.last_status = null;
        self.saved_receipt = null;
        self.phase = .begin;
    }

    pub fn nextFrame(self: *const Client, out: *[protocol.MAX_FRAME_BYTES]u8) protocol.Error!?[]const u8 {
        const body: protocol.Body = switch (self.phase) {
            .reading => .{ .read = .{ .version_id = self.version_id, .offset = self.offset } },
            .begin => .{ .begin = .{ .expected_version_id = self.version_id, .length = self.length, .digest = protocol.digest(self.snapshot[0..self.length]) } },
            .chunks => .{ .chunk = .{ .offset = self.offset, .bytes = self.snapshot[self.offset..@min(self.length, self.offset + protocol.CHUNK_BYTES)] } },
            .commit => .{ .commit = {} },
            else => return null,
        };
        return try protocol.encode(out, .{ .request_id = self.request_id, .body = body });
    }

    pub fn sent(self: *Client) void {
        switch (self.phase) {
            .reading => self.phase = .awaiting_read,
            .begin => self.phase = if (self.length == 0) .commit else .chunks,
            .chunks => {
                self.offset = @intCast(@min(self.length, self.offset + protocol.CHUNK_BYTES));
                if (self.offset == self.length) self.phase = .commit;
            },
            .commit => self.phase = .awaiting_receipt,
            else => {},
        }
    }

    pub fn accept(self: *Client, sender_endpoint_id: u64, correlation_id: u64, bytes: []const u8) bool {
        if (self.phase == .idle or sender_endpoint_id != self.service_endpoint_id or correlation_id != self.request_id) return false;
        const frame = protocol.decode(bytes) catch return false;
        if (frame.request_id != self.request_id) return false;
        if (frame.body == .read_data) {
            if (self.phase != .awaiting_read) return false;
            const read = frame.body.read_data;
            if (read.version_id != self.version_id or read.offset != self.offset or
                (self.offset != 0 and read.total_length != self.length)) return false;
            @memcpy(self.snapshot[read.offset..][0..read.bytes.len], read.bytes);
            self.length = read.total_length;
            self.offset += @intCast(read.bytes.len);
            self.phase = if (self.offset == self.length) .loaded else .reading;
            return true;
        }
        if (frame.body != .receipt) return false;
        const receipt = frame.body.receipt;
        if (receipt.status == .saved) {
            if (self.phase == .reading or self.phase == .awaiting_read or self.phase == .loaded) return false;
            if (receipt.object_id != self.object_id or receipt.previous_version_id != self.version_id) return false;
            self.version_id = receipt.version_id;
            self.saved_receipt = receipt;
            self.phase = .idle;
        } else {
            const opening = self.phase == .reading or self.phase == .awaiting_read or self.phase == .loaded;
            self.phase = if (!opening and receipt.status == .durability_failed) .retryable else .failed;
        }
        self.last_status = receipt.status;
        return true;
    }

    // A lost response retransmits the same snapshot and request id; the server
    // replays its receipt. A failed durable barrier retries just the commit.
    pub fn retry(self: *Client) bool {
        switch (self.phase) {
            .awaiting_read => self.phase = .reading,
            .awaiting_receipt => {
                self.offset = 0;
                self.phase = .begin;
            },
            .retryable => self.phase = .commit,
            else => return false,
        }
        return true;
    }

    pub fn acknowledgedText(self: *const Client) ?[]const u8 {
        if (self.saved_receipt == null) return null;
        return self.snapshot[0..self.length];
    }
};
