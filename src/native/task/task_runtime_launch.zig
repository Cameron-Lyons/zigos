const crypto_hash = @import("../core/crypto_hash.zig");
const std = @import("std");

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
    record.bundle_id_len = copyTruncated(record.bundle_id[0..], spec.bundle_id);
    return record;
}

pub fn makeExecutionComponent(RecordType: type, runtime: anytype, component: anytype) RecordType {
    var record = zeroExecutionComponent(RecordType);
    record.id = runtime.next_component_id;
    runtime.next_component_id += 1;
    record.substrate = component.substrate;
    record.label_len = copyTruncated(record.label[0..], component.label);
    record.entry_len = copyTruncated(record.entry[0..], component.entry);
    return record;
}

pub fn validateUserspaceImage(
    ErrorSet: type,
    max_executable_segments: usize,
    image: anytype,
) ErrorSet!@TypeOf(image) {
    if (!image.isPresent()) return error.InvalidUserspaceImage;
    if (image.segment_count > max_executable_segments) return error.InvalidUserspaceImage;
    if (image.stack_top == 0 or image.stack_size_bytes == 0) return error.InvalidUserspaceImage;

    var has_executable_region = false;
    var index: usize = 0;
    while (index < image.segment_count) : (index += 1) {
        const segment = image.segments[index];
        if (segment.virtual_address == 0 or segment.memory_size == 0) return error.InvalidUserspaceImage;
        if (segment.file_size > segment.memory_size) return error.InvalidUserspaceImage;
        if (segment.alignment == 0) return error.InvalidUserspaceImage;
        has_executable_region = has_executable_region or segment.access.execute;
    }
    if (!has_executable_region) return error.InvalidUserspaceImage;
    return image;
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
        .file_size = 4096,
        .memory_size = 4096,
        .alignment = 0x1000,
        .access = .{
            .read = true,
            .execute = true,
        },
    };
    image.segments[1] = .{
        .virtual_address = default_entry_point + 0x1000,
        .file_offset = 4096,
        .file_size = 4096,
        .memory_size = 4096,
        .alignment = 0x1000,
        .access = .{
            .read = true,
            .write = true,
        },
    };
    return image;
}

fn copyTruncated(buffer: []u8, source: []const u8) usize {
    const len = @min(buffer.len - 1, source.len);
    @memcpy(buffer[0..len], source[0..len]);
    return len;
}
