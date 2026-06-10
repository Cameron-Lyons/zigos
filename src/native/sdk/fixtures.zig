const std = @import("std");
const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");
const task_runtime = @import("../task/task_runtime_model.zig");

pub const Error = generated_image_fixtures.Error;

pub const ImageFixture = struct {
    bundle_id: []const u8,
    image: task_runtime.ExecutableImageSpec,

    pub fn hasExecutableSegments(self: *const ImageFixture) bool {
        return self.image.segment_count != 0 and self.image.entry_point != 0;
    }

    pub fn digestPrefix(self: *const ImageFixture) u32 {
        return std.mem.readInt(u32, self.image.file_sha256[0..4], .big);
    }
};

pub fn app() Error!ImageFixture {
    return .{
        .bundle_id = generated_image_fixtures.app_fixture_bundle_id,
        .image = try generated_image_fixtures.appImage(),
    };
}

pub fn serviceRegistry() Error!ImageFixture {
    return .{
        .bundle_id = generated_image_fixtures.service_fixture_bundle_id,
        .image = try generated_image_fixtures.serviceImage(),
    };
}

pub fn storageService() Error!ImageFixture {
    return .{
        .bundle_id = generated_image_fixtures.storage_service_fixture_bundle_id,
        .image = try generated_image_fixtures.storageServiceImage(),
    };
}

pub fn syncService() Error!ImageFixture {
    return .{
        .bundle_id = generated_image_fixtures.sync_service_fixture_bundle_id,
        .image = try generated_image_fixtures.syncServiceImage(),
    };
}

pub fn expectArchiveBackedFixtures() !void {
    const fixtures = [_]ImageFixture{
        try app(),
        try serviceRegistry(),
        try storageService(),
        try syncService(),
    };
    for (fixtures) |fixture| {
        try std.testing.expect(fixture.hasExecutableSegments());
        try std.testing.expect(fixture.image.file_size_bytes > task_runtime.DEFAULT_SYNTHETIC_IMAGE_BYTES);
        try std.testing.expect(fixture.digestPrefix() != 0);
    }
}

test "SDK fixtures are derived from real generated userspace images" {
    try expectArchiveBackedFixtures();
}
