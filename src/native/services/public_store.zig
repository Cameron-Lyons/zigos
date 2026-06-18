const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("package_service.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_RELEASES_PER_CHANNEL: usize = 8;
pub const MAX_ASSET_DIGEST_BYTES: usize = 96;
pub const MAX_TRUSTED_PUBLISHERS_PER_CHANNEL: usize = 8;
const SHA256_PREFIX = "sha256:";
const SHA256_HEX_BYTES: usize = 64;

pub const ReleaseAsset = struct {
    path: []const u8,
    content_type: []const u8,
    digest: []const u8,
    size_bytes: usize,
};

pub const Release = struct {
    bundle: manifest.BundleManifest,
    assets: []const ReleaseAsset,
    data_schema_version: u32 = 1,
    transparency: ReleaseTransparency = .{},
};

pub const ReleaseTransparency = struct {
    sequence: u64 = 0,
    previous_root: crypto_hash.Digest = crypto_hash.zero_digest,
    root: crypto_hash.Digest = crypto_hash.zero_digest,
};

pub const ResolvedRelease = struct {
    bundle: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    asset_count: usize,
    transparency_sequence: u64,
    transparency_root: crypto_hash.Digest,
    transparency_log_head: crypto_hash.Digest,

    pub fn installRequest(self: ResolvedRelease) package_service.InstallRequest {
        return .{
            .bundle = self.bundle,
            .source_identity = self.source_identity,
            .data_schema_version = self.data_schema_version,
            .release_transparency = .{
                .sequence = self.transparency_sequence,
                .root = self.transparency_root,
                .log_head = self.transparency_log_head,
            },
        };
    }
};

pub const Error = error{
    StoreSourceMissing,
    StoreSourceTooLong,
    StoreSourceInvalid,
    StoreChannelFull,
    StoreReleaseAlreadyPublished,
    StoreReleaseMissing,
    StoreReleaseUnsigned,
    StoreReleaseSignatureInvalid,
    StoreReleaseChannelMismatch,
    StoreReleaseInvalidSchema,
    StoreReleaseMissingAssets,
    StoreAssetCatalogMismatch,
    StoreAssetDigestMissing,
    StoreAssetDigestInvalid,
    StoreAssetDigestTooLong,
    StoreAssetSizeMissing,
    StoreSupplyChainMissing,
    StorePublisherMissing,
    StorePublisherTooLong,
    StoreTrustedPublisherTableFull,
    StoreTrustedPublisherMissing,
    StoreReleasePublisherUntrusted,
    StoreTransparencyMissing,
    StoreTransparencySequenceInvalid,
    StoreTransparencyPreviousRootMismatch,
    StoreTransparencyRootMismatch,
    StoreReleaseVersionRegressionRejected,
};

const ReleaseRecord = struct {
    in_use: bool = false,
    release: Release = .{
        .bundle = .{
            .bundle_id = "",
            .display_name = "",
            .publisher = "",
        },
        .assets = &.{},
    },
};

const TrustedPublisherRecord = struct {
    in_use: bool = false,
    revoked: bool = false,
    publisher: []const u8 = "",
    public_key: signing.PublicKey = [_]u8{0} ** signing.PUBLIC_KEY_BYTES,
};

pub const Channel = struct {
    source_identity: []const u8,
    update_channel: manifest.UpdateChannel,
    releases: [MAX_RELEASES_PER_CHANNEL]ReleaseRecord = [_]ReleaseRecord{.{}} ** MAX_RELEASES_PER_CHANNEL,
    release_count: usize = 0,
    transparency_root: crypto_hash.Digest = crypto_hash.zero_digest,
    trusted_publishers: [MAX_TRUSTED_PUBLISHERS_PER_CHANNEL]TrustedPublisherRecord = [_]TrustedPublisherRecord{.{}} ** MAX_TRUSTED_PUBLISHERS_PER_CHANNEL,
    trusted_publisher_count: usize = 0,

    pub fn init(source_identity: []const u8, update_channel: manifest.UpdateChannel) Channel {
        return .{
            .source_identity = source_identity,
            .update_channel = update_channel,
        };
    }

    pub fn prepareRelease(
        self: *const Channel,
        bundle: manifest.BundleManifest,
        assets: []const ReleaseAsset,
        data_schema_version: u32,
    ) Release {
        return .{
            .bundle = bundle,
            .assets = assets,
            .data_schema_version = data_schema_version,
            .transparency = self.nextTransparencyProof(bundle, assets, data_schema_version),
        };
    }

    pub fn nextTransparencyProof(
        self: *const Channel,
        bundle: manifest.BundleManifest,
        assets: []const ReleaseAsset,
        data_schema_version: u32,
    ) ReleaseTransparency {
        const sequence: u64 = @intCast(self.release_count + 1);
        return .{
            .sequence = sequence,
            .previous_root = self.transparency_root,
            .root = transparencyRoot(
                self.source_identity,
                self.update_channel,
                sequence,
                self.transparency_root,
                bundle,
                assets,
                data_schema_version,
            ),
        };
    }

    pub fn trustPublisher(self: *Channel, publisher: []const u8, public_key: signing.PublicKey) Error!void {
        try validatePublisherIdentity(publisher);
        for (self.trusted_publishers[0..self.trusted_publisher_count]) |*record| {
            if (!record.in_use) continue;
            if (std.mem.eql(u8, record.publisher, publisher) and std.mem.eql(u8, &record.public_key, &public_key)) {
                record.revoked = false;
                return;
            }
        }
        if (self.trusted_publisher_count >= self.trusted_publishers.len) return error.StoreTrustedPublisherTableFull;
        self.trusted_publishers[self.trusted_publisher_count] = .{
            .in_use = true,
            .revoked = false,
            .publisher = publisher,
            .public_key = public_key,
        };
        self.trusted_publisher_count += 1;
    }

    pub fn revokePublisher(self: *Channel, publisher: []const u8, public_key: signing.PublicKey) Error!void {
        try validatePublisherIdentity(publisher);
        for (self.trusted_publishers[0..self.trusted_publisher_count]) |*record| {
            if (!record.in_use) continue;
            if (!std.mem.eql(u8, record.publisher, publisher)) continue;
            if (!std.mem.eql(u8, &record.public_key, &public_key)) continue;
            record.revoked = true;
            return;
        }
        return error.StoreTrustedPublisherMissing;
    }

    pub fn publish(self: *Channel, release: Release) Error!void {
        try validateSourceIdentity(self.source_identity);
        try self.validateRelease(release);
        if (self.findExactIndex(
            release.bundle.bundle_id,
            release.bundle.version_major,
            release.bundle.version_minor,
        ) != null) return error.StoreReleaseAlreadyPublished;
        try self.validateVersionAdvances(release);
        try self.validateTransparency(release);
        if (self.release_count >= self.releases.len) return error.StoreChannelFull;

        self.releases[self.release_count] = .{
            .in_use = true,
            .release = release,
        };
        self.release_count += 1;
        self.transparency_root = release.transparency.root;
    }

    pub fn resolveVersion(
        self: *const Channel,
        bundle_id: []const u8,
        version_major: u16,
        version_minor: u16,
    ) Error!ResolvedRelease {
        const index = self.findExactIndex(bundle_id, version_major, version_minor) orelse return error.StoreReleaseMissing;
        return self.resolveChecked(index);
    }

    pub fn resolveLatest(self: *const Channel, bundle_id: []const u8) Error!ResolvedRelease {
        var selected: ?usize = null;
        var matching_bundle_seen = false;
        for (self.releases[0..self.release_count], 0..) |record, index| {
            if (!record.in_use) continue;
            if (!std.mem.eql(u8, record.release.bundle.bundle_id, bundle_id)) continue;
            matching_bundle_seen = true;
            if (!self.releaseSignedByTrustedPublisher(record.release.bundle)) continue;
            if (selected == null or versionGreaterThan(record.release, self.releases[selected.?].release)) {
                selected = index;
            }
        }
        const index = selected orelse {
            if (matching_bundle_seen) return error.StoreReleasePublisherUntrusted;
            return error.StoreReleaseMissing;
        };
        return self.resolveChecked(index);
    }

    pub fn resolveNext(
        self: *const Channel,
        bundle_id: []const u8,
        current_major: u16,
        current_minor: u16,
    ) Error!ResolvedRelease {
        var selected: ?usize = null;
        var matching_update_seen = false;
        for (self.releases[0..self.release_count], 0..) |record, index| {
            if (!record.in_use) continue;
            if (!std.mem.eql(u8, record.release.bundle.bundle_id, bundle_id)) continue;
            if (!versionNewerThan(record.release, current_major, current_minor)) continue;
            matching_update_seen = true;
            if (!self.releaseSignedByTrustedPublisher(record.release.bundle)) continue;
            if (selected == null or versionGreaterThan(record.release, self.releases[selected.?].release)) {
                selected = index;
            }
        }
        const index = selected orelse {
            if (matching_update_seen) return error.StoreReleasePublisherUntrusted;
            return error.StoreReleaseMissing;
        };
        return self.resolveChecked(index);
    }

    fn findExactIndex(
        self: *const Channel,
        bundle_id: []const u8,
        version_major: u16,
        version_minor: u16,
    ) ?usize {
        for (self.releases[0..self.release_count], 0..) |record, index| {
            if (!record.in_use) continue;
            const bundle = record.release.bundle;
            if (std.mem.eql(u8, bundle.bundle_id, bundle_id) and
                bundle.version_major == version_major and
                bundle.version_minor == version_minor)
            {
                return index;
            }
        }
        return null;
    }

    fn validateRelease(self: *const Channel, release: Release) Error!void {
        if (!release.bundle.signature.isComplete()) return error.StoreReleaseUnsigned;
        if (!signing.verifyWithDefaultRegistry(release.bundle.signature, &package_service.digestBundle(release.bundle))) {
            return error.StoreReleaseSignatureInvalid;
        }
        if (!self.releaseSignedByTrustedPublisher(release.bundle)) return error.StoreReleasePublisherUntrusted;
        if (release.bundle.update_channel != self.update_channel) return error.StoreReleaseChannelMismatch;
        if (release.data_schema_version == 0) return error.StoreReleaseInvalidSchema;
        if (release.bundle.assets.len == 0 or release.assets.len == 0) return error.StoreReleaseMissingAssets;
        if (release.bundle.assets.len != release.assets.len) return error.StoreAssetCatalogMismatch;
        if (release.assets.len > package_service.MAX_ASSETS_PER_BUNDLE) return error.StoreAssetCatalogMismatch;
        if (!supplyChainComplete(release.bundle.supply_chain)) return error.StoreSupplyChainMissing;

        for (release.assets, 0..) |asset, index| {
            const declared = release.bundle.assets[index];
            if (!std.mem.eql(u8, declared.path, asset.path) or
                !std.mem.eql(u8, declared.content_type, asset.content_type))
            {
                return error.StoreAssetCatalogMismatch;
            }
            if (asset.digest.len == 0) return error.StoreAssetDigestMissing;
            if (asset.digest.len > MAX_ASSET_DIGEST_BYTES) return error.StoreAssetDigestTooLong;
            if (!digestLooksLikeSha256(asset.digest)) return error.StoreAssetDigestInvalid;
            if (asset.size_bytes == 0) return error.StoreAssetSizeMissing;
        }
    }

    fn validateVersionAdvances(self: *const Channel, release: Release) Error!void {
        for (self.releases[0..self.release_count]) |record| {
            if (!record.in_use) continue;
            if (!std.mem.eql(u8, record.release.bundle.bundle_id, release.bundle.bundle_id)) continue;
            if (!versionNewerThan(
                release,
                record.release.bundle.version_major,
                record.release.bundle.version_minor,
            )) return error.StoreReleaseVersionRegressionRejected;
        }
    }

    fn validateTransparency(self: *const Channel, release: Release) Error!void {
        if (release.transparency.sequence == 0 or std.mem.eql(u8, &release.transparency.root, &crypto_hash.zero_digest)) {
            return error.StoreTransparencyMissing;
        }
        const expected_sequence: u64 = @intCast(self.release_count + 1);
        if (release.transparency.sequence != expected_sequence) return error.StoreTransparencySequenceInvalid;
        if (!std.mem.eql(u8, &release.transparency.previous_root, &self.transparency_root)) {
            return error.StoreTransparencyPreviousRootMismatch;
        }
        const expected_root = transparencyRoot(
            self.source_identity,
            self.update_channel,
            release.transparency.sequence,
            release.transparency.previous_root,
            release.bundle,
            release.assets,
            release.data_schema_version,
        );
        if (!std.mem.eql(u8, &release.transparency.root, &expected_root)) return error.StoreTransparencyRootMismatch;
    }

    fn releaseSignedByTrustedPublisher(self: *const Channel, bundle: manifest.BundleManifest) bool {
        const key = bundle.signature.publicKeySlice();
        if (key.len != signing.PUBLIC_KEY_BYTES) return false;
        for (self.trusted_publishers[0..self.trusted_publisher_count]) |record| {
            if (!record.in_use) continue;
            if (record.revoked) continue;
            if (!std.mem.eql(u8, record.publisher, bundle.publisher)) continue;
            if (std.mem.eql(u8, &record.public_key, key)) return true;
        }
        return false;
    }

    fn resolveChecked(self: *const Channel, index: usize) Error!ResolvedRelease {
        const release = self.releases[index].release;
        if (!self.releaseSignedByTrustedPublisher(release.bundle)) return error.StoreReleasePublisherUntrusted;
        try self.validatePublishedTransparency(index);
        return self.resolvedRelease(release);
    }

    fn resolvedRelease(self: *const Channel, release: Release) ResolvedRelease {
        return .{
            .bundle = release.bundle,
            .source_identity = self.source_identity,
            .data_schema_version = release.data_schema_version,
            .asset_count = release.assets.len,
            .transparency_sequence = release.transparency.sequence,
            .transparency_root = release.transparency.root,
            .transparency_log_head = self.transparency_root,
        };
    }

    fn validatePublishedTransparency(self: *const Channel, index: usize) Error!void {
        const release = self.releases[index].release;
        if (release.transparency.sequence != index + 1) return error.StoreTransparencySequenceInvalid;
        const expected_previous = if (index == 0) crypto_hash.zero_digest else self.releases[index - 1].release.transparency.root;
        if (!std.mem.eql(u8, &release.transparency.previous_root, &expected_previous)) {
            return error.StoreTransparencyPreviousRootMismatch;
        }
        const expected_root = transparencyRoot(
            self.source_identity,
            self.update_channel,
            release.transparency.sequence,
            release.transparency.previous_root,
            release.bundle,
            release.assets,
            release.data_schema_version,
        );
        if (!std.mem.eql(u8, &release.transparency.root, &expected_root)) return error.StoreTransparencyRootMismatch;
    }
};

fn validateSourceIdentity(source_identity: []const u8) Error!void {
    if (source_identity.len == 0) return error.StoreSourceMissing;
    if (source_identity.len > package_service.MAX_INSTALL_SOURCE_BYTES) return error.StoreSourceTooLong;
    for (source_identity) |byte| {
        const allowed =
            (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or
            byte == ':' or byte == '.' or byte == '_' or byte == '-' or byte == '/';
        if (!allowed) return error.StoreSourceInvalid;
    }
}

fn validatePublisherIdentity(publisher: []const u8) Error!void {
    if (publisher.len == 0) return error.StorePublisherMissing;
    if (publisher.len > principal.MAX_PUBLISHER_BYTES) return error.StorePublisherTooLong;
}

fn supplyChainComplete(supply_chain: manifest.SupplyChainDecl) bool {
    return digestLooksLikeSha256(supply_chain.sbom_digest) and
        digestLooksLikeSha256(supply_chain.source_archive_digest) and
        digestLooksLikeSha256(supply_chain.build_recipe_digest) and
        digestLooksLikeSha256(supply_chain.vulnerability_scan_digest) and
        supply_chain.build_provenance_identity.len != 0 and
        supply_chain.reproducible_build and
        supply_chain.trusted_builder;
}

fn digestLooksLikeSha256(digest: []const u8) bool {
    if (!std.mem.startsWith(u8, digest, SHA256_PREFIX)) return false;
    const hex = digest[SHA256_PREFIX.len..];
    if (hex.len != SHA256_HEX_BYTES) return false;
    for (hex) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    }
    return true;
}

fn transparencyRoot(
    source_identity: []const u8,
    update_channel: manifest.UpdateChannel,
    sequence: u64,
    previous_root: crypto_hash.Digest,
    bundle: manifest.BundleManifest,
    assets: []const ReleaseAsset,
    data_schema_version: u32,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", "zigos.public-store.transparency.v1");
    crypto_hash.updateBytes(&hasher, "source-identity", source_identity);
    crypto_hash.updateEnum(&hasher, "update-channel", update_channel);
    crypto_hash.updateInt(&hasher, "sequence", sequence);
    crypto_hash.updateBytes(&hasher, "previous-root", &previous_root);
    const bundle_digest = package_service.digestBundle(bundle);
    crypto_hash.updateBytes(&hasher, "bundle-digest", &bundle_digest);
    crypto_hash.updateInt(&hasher, "data-schema-version", data_schema_version);
    crypto_hash.updateInt(&hasher, "asset-count", assets.len);
    for (assets, 0..) |asset, index| {
        crypto_hash.updateInt(&hasher, "asset-index", index);
        crypto_hash.updateBytes(&hasher, "asset-path", asset.path);
        crypto_hash.updateBytes(&hasher, "asset-content-type", asset.content_type);
        crypto_hash.updateBytes(&hasher, "asset-digest", asset.digest);
        crypto_hash.updateInt(&hasher, "asset-size-bytes", asset.size_bytes);
    }
    return crypto_hash.finalize(&hasher);
}

fn versionNewerThan(release: Release, current_major: u16, current_minor: u16) bool {
    return release.bundle.version_major > current_major or
        (release.bundle.version_major == current_major and release.bundle.version_minor > current_minor);
}

fn versionGreaterThan(left: Release, right: Release) bool {
    return left.bundle.version_major > right.bundle.version_major or
        (left.bundle.version_major == right.bundle.version_major and
            left.bundle.version_minor > right.bundle.version_minor);
}

fn signStoreTestBundle(identity: signing.SignerIdentity, bundle: manifest.BundleManifest) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &package_service.digestBundle(bundle),
    );
}

test "public store publishes signed asset releases and resolves package install requests" {
    const signer = signing.SignerIdentity{
        .label = "public-store-test",
        .seed = signing.seedFromByte(0x65),
    };
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "app.notes.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm" },
    };
    const v1_release_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:1010101010101010101010101010101010101010101010101010101010101010", .size_bytes = 1536 },
    };
    const v2_release_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:2020202020202020202020202020202020202020202020202020202020202020", .size_bytes = 1600 },
        .{ .path = "assets/notes/editor.wasm", .content_type = "application/wasm", .digest = "sha256:2121212121212121212121212121212121212121212121212121212121212121", .size_bytes = 16 * 1024 },
    };

    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .provided_interfaces = &interfaces,
        .components = &components,
        .assets = &v1_assets,
        .supply_chain = .{
            .sbom_digest = "sha256:3030303030303030303030303030303030303030303030303030303030303030",
            .source_archive_digest = "sha256:3131313131313131313131313131313131313131313131313131313131313131",
            .build_recipe_digest = "sha256:3232323232323232323232323232323232323232323232323232323232323232",
            .vulnerability_scan_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            .build_provenance_identity = "builder:zigos/reproducible",
            .reproducible_build = true,
            .trusted_builder = true,
        },
        .update_channel = .beta,
    };
    v1.signature = try signStoreTestBundle(signer, v1);
    var v2 = v1;
    v2.version_minor = 1;
    v2.assets = &v2_assets;
    v2.supply_chain = .{
        .sbom_digest = "sha256:3434343434343434343434343434343434343434343434343434343434343434",
        .source_archive_digest = "sha256:3535353535353535353535353535353535353535353535353535353535353535",
        .build_recipe_digest = "sha256:3636363636363636363636363636363636363636363636363636363636363636",
        .vulnerability_scan_digest = "sha256:3737373737373737373737373737373737373737373737373737373737373737",
        .build_provenance_identity = "builder:zigos/reproducible",
        .reproducible_build = true,
        .trusted_builder = true,
    };
    v2.signature = try signStoreTestBundle(signer, v2);

    var channel = Channel.init("store:zigos/public", .beta);
    try channel.trustPublisher("zigos.dev", try signing.publicKey(signer));
    try channel.publish(channel.prepareRelease(v1, &v1_release_assets, 1));
    try channel.publish(channel.prepareRelease(v2, &v2_release_assets, 2));

    const resolved = try channel.resolveVersion("app.notes", 1, 0);
    const request = resolved.installRequest();
    try std.testing.expectEqualStrings("store:zigos/public", request.source_identity);
    try std.testing.expectEqual(@as(u32, 1), request.data_schema_version);
    try std.testing.expectEqual(@as(u64, 1), request.release_transparency.sequence);
    try std.testing.expect(std.mem.eql(u8, &resolved.transparency_root, &request.release_transparency.root));
    try std.testing.expect(std.mem.eql(u8, &resolved.transparency_log_head, &request.release_transparency.log_head));
    try std.testing.expectEqual(@as(usize, 1), resolved.asset_count);
    try std.testing.expectEqual(@as(u64, 1), resolved.transparency_sequence);
    try std.testing.expect(!std.mem.eql(u8, &resolved.transparency_root, &crypto_hash.zero_digest));

    const latest = try channel.resolveLatest("app.notes");
    try std.testing.expectEqual(@as(u16, 1), latest.bundle.version_minor);
    try std.testing.expectEqual(@as(usize, 2), latest.asset_count);
    try std.testing.expectEqual(@as(u64, 2), latest.transparency_sequence);
    try std.testing.expect(std.mem.eql(u8, &latest.transparency_root, &latest.transparency_log_head));
    const next = try channel.resolveNext("app.notes", 1, 0);
    try std.testing.expectEqual(@as(u32, 2), next.data_schema_version);
}

test "public store refuses unsigned tampered digestless or catalog-mismatched releases" {
    const signer = signing.SignerIdentity{
        .label = "public-store-reject-test",
        .seed = signing.seedFromByte(0x66),
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "app.notes.ui" },
    };
    const declared_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    const release_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:4040404040404040404040404040404040404040404040404040404040404040", .size_bytes = 1536 },
    };
    const digestless_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "", .size_bytes = 1536 },
    };
    const mismatched_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/other.svg", .content_type = "image/svg+xml", .digest = "sha256:4040404040404040404040404040404040404040404040404040404040404040", .size_bytes = 1536 },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .components = &components,
        .assets = &declared_assets,
        .supply_chain = .{
            .sbom_digest = "sha256:4141414141414141414141414141414141414141414141414141414141414141",
            .source_archive_digest = "sha256:4242424242424242424242424242424242424242424242424242424242424242",
            .build_recipe_digest = "sha256:4343434343434343434343434343434343434343434343434343434343434343",
            .vulnerability_scan_digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            .build_provenance_identity = "builder:zigos/reproducible",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    };
    var channel = Channel.init("store:zigos/public", .stable);
    try std.testing.expectError(error.StoreReleaseUnsigned, channel.publish(channel.prepareRelease(bundle, &release_assets, 1)));

    bundle.signature = try signStoreTestBundle(signer, bundle);
    var tampered = bundle;
    tampered.display_name = "Notes Plus";
    try std.testing.expectError(error.StoreReleaseSignatureInvalid, channel.publish(channel.prepareRelease(tampered, &release_assets, 1)));
    try std.testing.expectError(error.StoreReleasePublisherUntrusted, channel.publish(channel.prepareRelease(bundle, &release_assets, 1)));
    try channel.trustPublisher("zigos.dev", try signing.publicKey(signer));
    var weak_digest_assets = release_assets;
    weak_digest_assets[0].digest = "sha256:notes-icon";
    try std.testing.expectError(error.StoreAssetDigestInvalid, channel.publish(channel.prepareRelease(bundle, &weak_digest_assets, 1)));
    try std.testing.expectError(error.StoreAssetDigestMissing, channel.publish(channel.prepareRelease(bundle, &digestless_assets, 1)));
    try std.testing.expectError(error.StoreAssetCatalogMismatch, channel.publish(channel.prepareRelease(bundle, &mismatched_assets, 1)));
    try channel.publish(channel.prepareRelease(bundle, &release_assets, 1));
    _ = try channel.resolveLatest("app.notes");
    try channel.revokePublisher("zigos.dev", try signing.publicKey(signer));
    try std.testing.expectError(error.StoreReleasePublisherUntrusted, channel.resolveVersion("app.notes", 1, 0));
    try std.testing.expectError(error.StoreReleasePublisherUntrusted, channel.resolveLatest("app.notes"));
    try std.testing.expectError(error.StoreReleasePublisherUntrusted, channel.resolveNext("app.notes", 0, 0));
    try std.testing.expectError(error.StoreReleasePublisherUntrusted, channel.publish(channel.prepareRelease(bundle, &release_assets, 1)));
    try channel.trustPublisher("zigos.dev", try signing.publicKey(signer));
    _ = try channel.resolveLatest("app.notes");
    try std.testing.expectError(error.StoreReleaseAlreadyPublished, channel.publish(channel.prepareRelease(bundle, &release_assets, 1)));
}

test "public store enforces append-only transparency sequencing" {
    const signer = signing.SignerIdentity{
        .label = "public-store-transparency-test",
        .seed = signing.seedFromByte(0x67),
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "app.notes.ui" },
    };
    const declared_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    const release_assets = [_]ReleaseAsset{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml", .digest = "sha256:5050505050505050505050505050505050505050505050505050505050505050", .size_bytes = 1536 },
    };

    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .components = &components,
        .assets = &declared_assets,
        .supply_chain = .{
            .sbom_digest = "sha256:5151515151515151515151515151515151515151515151515151515151515151",
            .source_archive_digest = "sha256:5252525252525252525252525252525252525252525252525252525252525252",
            .build_recipe_digest = "sha256:5353535353535353535353535353535353535353535353535353535353535353",
            .vulnerability_scan_digest = "sha256:5454545454545454545454545454545454545454545454545454545454545454",
            .build_provenance_identity = "builder:zigos/reproducible",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    };
    v1.signature = try signStoreTestBundle(signer, v1);
    var v2 = v1;
    v2.version_minor = 1;
    v2.signature = try signStoreTestBundle(signer, v2);

    var channel = Channel.init("store:zigos/public", .stable);
    try channel.trustPublisher("zigos.dev", try signing.publicKey(signer));

    var skipped_sequence = channel.prepareRelease(v1, &release_assets, 1);
    skipped_sequence.transparency.sequence += 1;
    try std.testing.expectError(error.StoreTransparencySequenceInvalid, channel.publish(skipped_sequence));

    try channel.publish(channel.prepareRelease(v1, &release_assets, 1));

    var stale_previous = channel.prepareRelease(v2, &release_assets, 1);
    stale_previous.transparency.previous_root = crypto_hash.zero_digest;
    stale_previous.transparency.root = transparencyRoot(
        channel.source_identity,
        channel.update_channel,
        stale_previous.transparency.sequence,
        stale_previous.transparency.previous_root,
        stale_previous.bundle,
        stale_previous.assets,
        stale_previous.data_schema_version,
    );
    try std.testing.expectError(error.StoreTransparencyPreviousRootMismatch, channel.publish(stale_previous));

    var forged_root = channel.prepareRelease(v2, &release_assets, 1);
    forged_root.transparency.root = crypto_hash.digestFromByte(0xf0);
    try std.testing.expectError(error.StoreTransparencyRootMismatch, channel.publish(forged_root));

    var older = v1;
    older.version_major = 0;
    older.version_minor = 9;
    older.signature = try signStoreTestBundle(signer, older);
    try std.testing.expectError(
        error.StoreReleaseVersionRegressionRejected,
        channel.publish(channel.prepareRelease(older, &release_assets, 1)),
    );

    try channel.publish(channel.prepareRelease(v2, &release_assets, 1));
    const latest = try channel.resolveLatest("app.notes");
    try std.testing.expectEqual(@as(u64, 2), latest.transparency_sequence);
    try std.testing.expect(std.mem.eql(u8, &latest.transparency_root, &latest.transparency_log_head));
}
