const crypto_hash = @import("../core/crypto_hash.zig");
const native_util = @import("../core/util.zig");
const std = @import("std");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_layout = @import("../core/userspace_layout.zig");

pub const SYNTHETIC_SEGMENT_BYTES: u32 = 4096;
pub const SYNTHETIC_SEGMENT_ALIGNMENT: u32 = 0x1000;
pub const USER_PAGE_SIZE: u64 = userspace_layout.page_size;
pub const USER_VIRTUAL_ADDRESS_MIN: u64 = userspace_layout.image_start;
pub const USER_IMAGE_ADDRESS_MAX_EXCLUSIVE: u64 = userspace_layout.image_end_exclusive;
pub const USER_STACK_ADDRESS_MIN: u64 = userspace_layout.stack_start;
pub const USER_VIRTUAL_ADDRESS_MAX_EXCLUSIVE: u64 = userspace_layout.user_end_exclusive;

comptime {
    if (userspace_bootstrap_mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR != userspace_layout.shared_start) {
        @compileError("userspace isolation probe must target the shared-memory aperture");
    }
}

const UserRange = struct {
    start: u64,
    end: u64,
    unrounded_end: u64,
};

pub fn zeroExecutionComponent(RecordType: type) RecordType {
    var record = std.mem.zeroes(RecordType);
    record.substrate = .typed_component_abi;
    return record;
}

pub fn zeroLaunchProvenance(RecordType: type) RecordType {
    var record = std.mem.zeroes(RecordType);
    record.boundary = .direct_request;
    return record;
}

pub fn componentClassLabel(component_class: anytype) []const u8 {
    return switch (component_class) {
        .session_manager => "session-manager",
        .app_component => "app-component",
        .service_component => "service-component",
    };
}

pub fn componentClassEntry(component_class: anytype) []const u8 {
    return switch (component_class) {
        .session_manager => "zigos.session.manager",
        .app_component => "zigos.app.component",
        .service_component => "zigos.service.component",
    };
}

pub fn defaultInitialComponent(request: anytype) @TypeOf(request.initial_component) {
    var component = request.initial_component;
    if (component.label.len == 0) {
        component.label = componentClassLabel(request.component_class);
    }
    if (component.entry.len == 0) {
        component.entry = componentClassEntry(request.component_class);
    }
    return component;
}

pub fn makeLaunchProvenance(RecordType: type, spec: anytype) RecordType {
    var record = zeroLaunchProvenance(RecordType);
    record.boundary = spec.boundary;
    record.image_id = spec.image_id;
    record.component_abi_version = spec.component_abi_version;
    record.signed = spec.signed;
    record.bundle_id_len = native_util.copyTextWithReserve(record.bundle_id[0..], spec.bundle_id, 1);
    record.source_identity_len = native_util.copyTextWithReserve(record.source_identity[0..], spec.source_identity, 1);
    record.release_transparency_sequence = spec.release_transparency_sequence;
    record.release_transparency_root = spec.release_transparency_root;
    record.release_transparency_log_head = spec.release_transparency_log_head;
    return record;
}

pub fn validateUserspaceImage(
    ErrorSet: type,
    max_executable_segments: usize,
    image: anytype,
) ErrorSet!@TypeOf(image) {
    if (!image.isPresent()) return error.InvalidUserspaceImage;
    if (image.segment_count > max_executable_segments or image.segment_count > image.segments.len) {
        return error.InvalidUserspaceImage;
    }

    const image_file_size = std.math.cast(u64, image.file_size_bytes) orelse
        return error.InvalidUserspaceImage;
    if (image_file_size == 0) return error.InvalidUserspaceImage;

    const stack_size = std.math.cast(u64, image.stack_size_bytes) orelse
        return error.InvalidUserspaceImage;
    if (stack_size == 0 or image.stack_top % USER_PAGE_SIZE != 0) {
        return error.InvalidUserspaceImage;
    }
    const stack_start = std.math.sub(u64, image.stack_top, stack_size) catch
        return error.InvalidUserspaceImage;
    const stack_range = checkedUserRange(
        stack_start,
        stack_size,
        USER_STACK_ADDRESS_MIN,
        USER_VIRTUAL_ADDRESS_MAX_EXCLUSIVE,
    ) orelse
        return error.InvalidUserspaceImage;
    if (stack_range.unrounded_end != image.stack_top) return error.InvalidUserspaceImage;

    if (image.entry_point < USER_VIRTUAL_ADDRESS_MIN or
        image.entry_point >= USER_IMAGE_ADDRESS_MAX_EXCLUSIVE)
    {
        return error.InvalidUserspaceImage;
    }

    var entry_is_executable = false;
    var index: usize = 0;
    while (index < image.segment_count) : (index += 1) {
        const segment = image.segments[index];
        if (segment.memory_size == 0) return error.InvalidUserspaceImage;
        if (segment.file_size > segment.memory_size) return error.InvalidUserspaceImage;
        // Admission policy forbids ambiguous W+X declarations. Hardware NX
        // remains a separate paging capability on the current i386 target.
        if (segment.access.write and segment.access.execute) return error.InvalidUserspaceImage;

        const alignment: u64 = segment.alignment;
        if (alignment < USER_PAGE_SIZE or !std.math.isPowerOfTwo(alignment)) {
            return error.InvalidUserspaceImage;
        }
        if (segment.virtual_address % alignment != 0) {
            return error.InvalidUserspaceImage;
        }

        const segment_range = checkedUserRange(
            segment.virtual_address,
            segment.memory_size,
            USER_VIRTUAL_ADDRESS_MIN,
            USER_IMAGE_ADDRESS_MAX_EXCLUSIVE,
        ) orelse
            return error.InvalidUserspaceImage;
        if (rangesOverlap(segment_range, stack_range)) return error.InvalidUserspaceImage;

        const file_end = std.math.add(
            u64,
            @as(u64, segment.file_offset),
            @as(u64, segment.file_size),
        ) catch return error.InvalidUserspaceImage;
        if (file_end > image_file_size) return error.InvalidUserspaceImage;

        var previous_index: usize = 0;
        while (previous_index < index) : (previous_index += 1) {
            const previous = image.segments[previous_index];
            const previous_range = checkedUserRange(
                previous.virtual_address,
                previous.memory_size,
                USER_VIRTUAL_ADDRESS_MIN,
                USER_IMAGE_ADDRESS_MAX_EXCLUSIVE,
            ) orelse
                return error.InvalidUserspaceImage;
            if (rangesOverlap(segment_range, previous_range)) return error.InvalidUserspaceImage;
        }

        if (segment.access.execute and
            image.entry_point >= segment_range.start and
            image.entry_point < segment_range.unrounded_end)
        {
            entry_is_executable = true;
        }
    }
    if (!entry_is_executable) return error.InvalidUserspaceImage;

    if (@hasField(@TypeOf(image), "bootstrap_mailbox_address")) {
        if (image.bootstrap_mailbox_address == 0) return error.InvalidUserspaceImage;
        const mailbox_alignment = userspace_bootstrap_mailbox.ABI_ALIGNMENT;
        if (image.bootstrap_mailbox_address % mailbox_alignment != 0) {
            return error.InvalidUserspaceImage;
        }
        const mailbox_end = std.math.add(
            u64,
            image.bootstrap_mailbox_address,
            userspace_bootstrap_mailbox.ABI_SIZE_BYTES,
        ) catch return error.InvalidUserspaceImage;
        if (image.bootstrap_mailbox_address < USER_VIRTUAL_ADDRESS_MIN or
            mailbox_end > USER_IMAGE_ADDRESS_MAX_EXCLUSIVE or
            mailbox_end <= image.bootstrap_mailbox_address)
        {
            return error.InvalidUserspaceImage;
        }

        var mailbox_is_writable = false;
        index = 0;
        while (index < image.segment_count) : (index += 1) {
            const segment = image.segments[index];
            if (!segment.access.write) continue;
            const segment_end = std.math.add(
                u64,
                segment.virtual_address,
                @as(u64, segment.memory_size),
            ) catch return error.InvalidUserspaceImage;
            if (image.bootstrap_mailbox_address >= segment.virtual_address and
                mailbox_end <= segment_end)
            {
                mailbox_is_writable = true;
                break;
            }
        }
        if (!mailbox_is_writable) return error.InvalidUserspaceImage;
    }
    return image;
}

fn checkedUserRange(start: u64, size: u64, minimum: u64, maximum_exclusive: u64) ?UserRange {
    if (size == 0 or start < minimum) return null;
    if (start % USER_PAGE_SIZE != 0) return null;

    const unrounded_end = std.math.add(u64, start, size) catch return null;
    const rounded_input = std.math.add(u64, unrounded_end, USER_PAGE_SIZE - 1) catch return null;
    const end = rounded_input & ~(USER_PAGE_SIZE - 1);
    if (end <= start or end > maximum_exclusive) return null;
    return .{
        .start = start,
        .end = end,
        .unrounded_end = unrounded_end,
    };
}

fn rangesOverlap(lhs: UserRange, rhs: UserRange) bool {
    return lhs.start < rhs.end and rhs.start < lhs.end;
}

pub fn syntheticUserspaceImage(
    ImageType: type,
    label: []const u8,
    entry: []const u8,
    default_entry_point: u64,
    default_stack_top: u64,
    default_stack_size_bytes: usize,
    default_file_size_bytes: usize,
) ImageType {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "label", label);
    crypto_hash.updateBytes(&hasher, "entry", entry);

    var image = std.mem.zeroes(ImageType);
    image.entry_point = default_entry_point;
    image.stack_top = default_stack_top;
    image.stack_size_bytes = default_stack_size_bytes;
    image.file_size_bytes = default_file_size_bytes;
    image.file_sha256 = crypto_hash.finalize(&hasher);
    image.segment_count = 2;
    image.segments[0] = .{
        .virtual_address = default_entry_point,
        .file_offset = 0,
        .file_size = SYNTHETIC_SEGMENT_BYTES,
        .memory_size = SYNTHETIC_SEGMENT_BYTES,
        .alignment = SYNTHETIC_SEGMENT_ALIGNMENT,
        .access = .{
            .read = true,
            .execute = true,
        },
    };
    image.segments[1] = .{
        .virtual_address = default_entry_point + SYNTHETIC_SEGMENT_ALIGNMENT,
        .file_offset = SYNTHETIC_SEGMENT_BYTES,
        .file_size = SYNTHETIC_SEGMENT_BYTES,
        .memory_size = SYNTHETIC_SEGMENT_BYTES,
        .alignment = SYNTHETIC_SEGMENT_ALIGNMENT,
        .access = .{
            .read = true,
            .write = true,
        },
    };
    if (@hasField(ImageType, "bootstrap_mailbox_address")) {
        image.bootstrap_mailbox_address = default_entry_point + SYNTHETIC_SEGMENT_ALIGNMENT;
    }
    return image;
}
