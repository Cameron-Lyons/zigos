const abi = @import("../core/abi.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const component_port = @import("../kernel_api/component_port.zig");
const embedded_file = @import("embedded_file.zig");
const elf_image_inspector = @import("elf_image_inspector.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const std = @import("std");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_manifest_signing = @import("userspace_manifest_signing.zig");

pub const MAX_IMAGES: usize = 32;
const BUNDLE_INDEX_CAPACITY: usize = MAX_IMAGES * 2;
const IMAGE_ID_INDEX_CAPACITY: usize = MAX_IMAGES * 2;
const MAX_BUNDLE_ID_BYTES: usize = 64;
const MAX_DISPLAY_NAME_BYTES: usize = 48;
const MAX_PUBLISHER_BYTES: usize = 48;
const MAX_LABEL_BYTES: usize = 48;
const MAX_ENTRY_BYTES: usize = 64;
const MAX_IMAGE_HASH_BYTES: usize = task_runtime.MAX_IMAGE_HASH_BYTES;
const SYNTHETIC_ELF_PROGRAM_HEADERS: usize = 3;
const SYNTHETIC_ELF_SEGMENT_FILE_BYTES: usize = userspace_bootstrap_mailbox.ABI_SIZE_BYTES;
const SYNTHETIC_ELF_SEGMENT_MEMORY_BYTES: usize = userspace_bootstrap_mailbox.ABI_SIZE_BYTES;
const SYNTHETIC_ELF_SEGMENT_ALIGNMENT: u32 = 0x1000;
const SYNTHETIC_ELF_SECTION_NAMES = "\x00.shstrtab\x00.zigos_userspace_bootstrap\x00";
const SYNTHETIC_ELF_SECTION_COUNT: usize = 3;
const SYNTHETIC_ELF_SEGMENTS_OFFSET: usize = @sizeOf(std.elf.Elf32_Ehdr) +
    SYNTHETIC_ELF_PROGRAM_HEADERS * @sizeOf(std.elf.Elf32_Phdr);
const SYNTHETIC_ELF_SECTION_NAMES_OFFSET: usize = SYNTHETIC_ELF_SEGMENTS_OFFSET +
    SYNTHETIC_ELF_PROGRAM_HEADERS * SYNTHETIC_ELF_SEGMENT_MEMORY_BYTES;
const SYNTHETIC_ELF_SECTION_HEADERS_OFFSET: usize =
    (SYNTHETIC_ELF_SECTION_NAMES_OFFSET + SYNTHETIC_ELF_SECTION_NAMES.len + 3) & ~@as(usize, 3);
const SYNTHETIC_ELF_BYTES: usize = SYNTHETIC_ELF_SECTION_HEADERS_OFFSET +
    SYNTHETIC_ELF_SECTION_COUNT * @sizeOf(std.elf.Elf32_Shdr);
const TEST_TASK_MEMORY_BYTES: usize = units.kibibytes(4);
const TEST_TASK_SHARED_MEMORY_BYTES: usize = units.kibibytes(2);
const copyTextExact = native_util.copyTextExact;

comptime {
    const byte_capacities = [_]usize{
        MAX_IMAGES,
        MAX_BUNDLE_ID_BYTES,
        MAX_DISPLAY_NAME_BYTES,
        MAX_PUBLISHER_BYTES,
        MAX_LABEL_BYTES,
        MAX_ENTRY_BYTES,
        task_runtime.MAX_EXECUTABLE_SEGMENTS,
    };
    for (byte_capacities) |capacity| {
        if (capacity > std.math.maxInt(u8)) {
            @compileError("userspace catalog capacity exceeds its compact field");
        }
    }
}

pub const Error = manifest.ValidationError || component_port.Error || task_runtime.Error || elf_image_inspector.Error || error{
    EmptyLabel,
    EmptyEntry,
    EmbeddedArtifactRequired,
    EmbeddedArtifactMetadataMismatch,
    InvalidElfHeader,
    InvalidElfMagic,
    InvalidLoadableSegment,
    InvalidProgramHeaderTable,
    InitialComponentNotDeclared,
    ImageConflict,
    ImageNotFound,
    ImageTableFull,
    InitialComponentEntryTooLong,
    InitialComponentLabelTooLong,
    InitialComponentAbiMismatch,
    MissingBundleComponent,
    MissingBundleSignature,
    InvalidBundleSignature,
    MissingLoadableSegment,
    TooManyLoadableSegments,
    UnsupportedElfClass,
    UnsupportedElfEndian,
    UnsupportedElfMachine,
};

pub const ImageRegisterRequest = struct {
    bundle: manifest.BundleManifest,
    component_class: task_runtime.ComponentClass,
    initial_component: task_runtime.ExecutionComponentSpec,
    role_tag: u32 = 0,
    heartbeat_increment: u32 = 0,
    contract_flags: u32 = 0,
};

pub const EmbeddedImageRegisterRequest = struct {
    bundle: manifest.BundleManifest,
    component_class: task_runtime.ComponentClass,
    initial_component: task_runtime.ExecutionComponentSpec,
    role_tag: u32 = 0,
    heartbeat_increment: u32 = 0,
    contract_flags: u32 = 0,
    elf_file: embedded_file.File,
};

pub const ArtifactSource = enum(u8) {
    metadata_only,
    embedded_elf,
};

pub const EmbeddedElfInfo = elf_image_inspector.Inspection;

pub const LaunchRequest = struct {
    owner: principal.PrincipalId,
    budget: task_runtime.ResourceBudget,
    ui_surface_id: ?u64 = null,
    local_only: bool = true,
    source_identity: []const u8 = "",
    release_transparency_sequence: u64 = 0,
    release_transparency_root: crypto_hash.Digest = crypto_hash.zero_digest,
    release_transparency_log_head: crypto_hash.Digest = crypto_hash.zero_digest,
};

pub const KernelLaunchAuthority = struct {
    port: *component_port.KernelPort,
    authority_capability_id: u64,
    controller_task_id: u64,
    correlation_id: u64,
    now_ticks: u64,
};

pub const ImageRecord = struct {
    id: u64,
    component_class: task_runtime.ComponentClass,
    component_abi_version: u16,
    bundle_signed: bool,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
    substrate: task_runtime.ExecutionSubstrate,
    artifact_source: ArtifactSource,
    entry_point: u64,
    loadable_segment_count: u8,
    byte_len: usize,
    bootstrap_mailbox_address: u64,
    file_sha256: crypto_hash.Digest,
    executable_image: task_runtime.ExecutableImageSpec,
    elf_file: embedded_file.File,
    bundle_id_len: u8,
    bundle_id: [MAX_BUNDLE_ID_BYTES]u8,
    display_name_len: u8,
    display_name: [MAX_DISPLAY_NAME_BYTES]u8,
    publisher_len: u8,
    publisher: [MAX_PUBLISHER_BYTES]u8,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    entry_len: u8,
    entry: [MAX_ENTRY_BYTES]u8,

    pub fn bundleIdSlice(self: *const ImageRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn displayNameSlice(self: *const ImageRecord) []const u8 {
        return self.display_name[0..self.display_name_len];
    }

    pub fn publisherSlice(self: *const ImageRecord) []const u8 {
        return self.publisher[0..self.publisher_len];
    }

    pub fn labelSlice(self: *const ImageRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn entrySlice(self: *const ImageRecord) []const u8 {
        return self.entry[0..self.entry_len];
    }

    pub fn embedsElf(self: *const ImageRecord) bool {
        return self.artifact_source == .embedded_elf;
    }

    pub fn hasTypedContract(self: *const ImageRecord) bool {
        return self.role_tag != 0 and self.heartbeat_increment != 0;
    }
};

const ImageSlot = struct {
    in_use: bool = false,
    image: ImageRecord = zeroImage(),
};

const ImageArena = indexed_arena.IndexedArenaWithKey(u64, ImageSlot, MAX_IMAGES, IMAGE_ID_INDEX_CAPACITY, imageSlotImageIdKey);
const BundleIndex = indexed_arena.UniqueIndex(BUNDLE_INDEX_CAPACITY);

pub const Catalog = struct {
    next_image_id: u64 = 1,
    bundle_index: BundleIndex = BundleIndex.init(),
    images: ImageArena = ImageArena.init(),

    pub fn init() Catalog {
        return Catalog{};
    }

    pub fn initializeAllocated(self: *Catalog) void {
        @memset(std.mem.asBytes(self), 0);
        self.next_image_id = 1;
        self.images.free_head = indexed_arena.reusableNoIndex(MAX_IMAGES);
    }

    pub fn reset(self: *Catalog) void {
        self.initializeAllocated();
    }

    pub fn register(self: *Catalog, request: ImageRegisterRequest) Error!*const ImageRecord {
        return self.registerWithEmbeddedElf(request, null, .{});
    }

    pub fn registerEmbeddedArtifact(
        self: *Catalog,
        request: EmbeddedImageRegisterRequest,
    ) Error!*const ImageRecord {
        return self.registerEmbeddedArtifactWithInfo(request, try elf_image_inspector.inspectFile(request.elf_file));
    }

    pub fn registerEmbeddedArtifactWithInfo(
        self: *Catalog,
        request: EmbeddedImageRegisterRequest,
        embedded_info: EmbeddedElfInfo,
    ) Error!*const ImageRecord {
        try validateEmbeddedElfInfo(request.elf_file, embedded_info);
        return self.registerWithEmbeddedElf(.{
            .bundle = request.bundle,
            .component_class = request.component_class,
            .initial_component = request.initial_component,
            .role_tag = request.role_tag,
            .heartbeat_increment = request.heartbeat_increment,
            .contract_flags = request.contract_flags,
        }, embedded_info, request.elf_file);
    }

    pub fn findByBundleId(self: *Catalog, bundle_id: []const u8) ?*const ImageRecord {
        const key = bundleIndexKey(bundle_id);
        const slot = self.images.findConstByUniqueIndex(
            &self.bundle_index,
            key,
            bundle_id,
            imageSlotMatchesBundleId,
        ) orelse return null;
        return &slot.image;
    }

    pub fn findById(self: *Catalog, image_id: u64) ?*const ImageRecord {
        if (image_id == 0) return null;
        const slot = self.images.getConst(image_id) orelse return null;
        return &slot.image;
    }

    pub fn imageCount(self: *const Catalog) usize {
        return self.images.countInUse();
    }

    pub fn launchDirect(
        self: *Catalog,
        runtime: *task_runtime.Runtime,
        bundle_id: []const u8,
        request: LaunchRequest,
    ) Error!*task_runtime.TaskRecord {
        const image = self.findByBundleId(bundle_id) orelse return error.ImageNotFound;
        return runtime.createTask(taskCreateRequest(image, request));
    }

    pub fn launchViaKernel(
        self: *Catalog,
        authority: KernelLaunchAuthority,
        bundle_id: []const u8,
        request: LaunchRequest,
    ) Error!abi.TaskDescriptor {
        const image = self.findByBundleId(bundle_id) orelse return error.ImageNotFound;
        return authority.port.taskCreate(.{
            .header = component_port.makeHeader(
                .task_create,
                authority.correlation_id,
                authority.controller_task_id,
            ),
            .authority_capability_id = authority.authority_capability_id,
            .request = taskCreateRequest(image, request),
        }, authority.now_ticks);
    }

    fn registerWithEmbeddedElf(
        self: *Catalog,
        request: ImageRegisterRequest,
        embedded: ?EmbeddedElfInfo,
        elf_file: embedded_file.File,
    ) Error!*const ImageRecord {
        try manifest.validate(request.bundle);
        try manifest.validateApplicationPackaging(request.bundle);
        try validateStoredMetadata(request.bundle, request.initial_component);
        if (request.initial_component.label.len == 0) return error.EmptyLabel;
        if (request.initial_component.entry.len == 0) return error.EmptyEntry;
        try validateExecutableBundle(request.bundle, request.initial_component, embedded != null);

        if (self.findByBundleId(request.bundle.bundle_id)) |existing| {
            if (!imageMatchesRequest(existing, request, embedded)) return error.ImageConflict;
            return existing;
        }

        const embedded_info = embedded orelse return error.EmbeddedArtifactRequired;
        const image_id = self.nextReservableImageId() orelse return error.ImageTableFull;
        var image = zeroImage();
        const executable_image = embedded_info.executable_image;
        image.id = image_id;
        image.component_class = request.component_class;
        image.component_abi_version = componentAbiVersion(request.initial_component.substrate);
        image.bundle_signed = request.bundle.signature.isPresent();
        image.role_tag = request.role_tag;
        image.heartbeat_increment = request.heartbeat_increment;
        image.contract_flags = request.contract_flags;
        image.substrate = request.initial_component.substrate;
        image.artifact_source = .embedded_elf;
        image.entry_point = executable_image.entry_point;
        image.loadable_segment_count = @intCast(executable_image.segment_count);
        image.byte_len = executable_image.file_size_bytes;
        image.bootstrap_mailbox_address = embedded_info.bootstrap_mailbox_address;
        image.file_sha256 = executable_image.file_sha256;
        image.executable_image = executable_image;
        image.elf_file = elf_file;
        image.bundle_id_len = @intCast(copyTextExact(image.bundle_id[0..], request.bundle.bundle_id) catch return error.BundleIdTooLong);
        image.display_name_len = @intCast(copyTextExact(image.display_name[0..], request.bundle.display_name) catch return error.DisplayNameTooLong);
        image.publisher_len = @intCast(copyTextExact(image.publisher[0..], request.bundle.publisher) catch return error.PublisherTooLong);
        image.label_len = @intCast(copyTextExact(image.label[0..], request.initial_component.label) catch return error.InitialComponentLabelTooLong);
        image.entry_len = @intCast(copyTextExact(image.entry[0..], request.initial_component.entry) catch return error.InitialComponentEntryTooLong);

        const slot_index = self.images.reserveIndex(image.id) orelse return error.ImageTableFull;
        const slot = &self.images.slots[slot_index];
        slot.image = image;
        self.bundle_index.insert(bundleIndexKey(slot.image.bundleIdSlice()), slot_index);
        self.advanceNextImageIdFrom(image_id);
        return &slot.image;
    }

    fn nextReservableImageId(self: *Catalog) ?u64 {
        if (self.imageCount() >= MAX_IMAGES) return null;

        var image_id = normalizeImageId(self.next_image_id);
        var attempts: usize = 0;
        while (attempts <= MAX_IMAGES) : (attempts += 1) {
            if (self.findById(image_id) == null) return image_id;
            image_id = nextImageIdAfter(image_id);
        }
        return null;
    }

    fn advanceNextImageIdFrom(self: *Catalog, image_id: u64) void {
        self.next_image_id = nextImageIdAfter(image_id);
    }
};

test "userspace catalog uses capacity-sized resident metadata" {
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(@FieldType(ImageRecord, "loadable_segment_count")));
    try std.testing.expectEqual(@as(usize, 728), @sizeOf(ImageRecord));
    try std.testing.expectEqual(@as(usize, 736), @sizeOf(ImageSlot));
    try std.testing.expectEqual(@as(usize, 25_136), @sizeOf(Catalog));
}

fn normalizeImageId(image_id: u64) u64 {
    return if (image_id == 0) 1 else image_id;
}

fn nextImageIdAfter(image_id: u64) u64 {
    const next = image_id +% 1;
    return normalizeImageId(next);
}

fn bundleIndexKey(bundle_id: []const u8) u64 {
    const hash = native_util.fnv1a64(bundle_id);
    return if (hash == 0) 1 else hash;
}

fn imageSlotImageIdKey(slot: *const ImageSlot) u64 {
    return slot.image.id;
}

fn imageSlotMatchesBundleId(bundle_id: []const u8, slot: *const ImageSlot) bool {
    return std.mem.eql(u8, slot.image.bundleIdSlice(), bundle_id);
}

fn taskCreateRequest(image: *const ImageRecord, request: LaunchRequest) task_runtime.TaskCreateRequest {
    return .{
        .owner = request.owner,
        .component_class = image.component_class,
        .budget = request.budget,
        .ui_surface_id = request.ui_surface_id,
        .local_only = request.local_only,
        .initial_component = .{
            .substrate = image.substrate,
            .label = image.labelSlice(),
            .entry = image.entrySlice(),
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = image.id,
            .component_abi_version = image.component_abi_version,
            .signed = image.bundle_signed,
            .bundle_id = image.bundleIdSlice(),
            .source_identity = request.source_identity,
            .release_transparency_sequence = request.release_transparency_sequence,
            .release_transparency_root = request.release_transparency_root,
            .release_transparency_log_head = request.release_transparency_log_head,
        },
        .userspace_image = &image.executable_image,
    };
}

fn validateExecutableBundle(
    bundle: manifest.BundleManifest,
    initial_component: task_runtime.ExecutionComponentSpec,
    has_embedded_artifact: bool,
) Error!void {
    if (!bundle.signature.isPresent()) return error.MissingBundleSignature;
    if (!userspace_manifest_signing.verifyBundle(bundle)) return error.InvalidBundleSignature;
    if (!manifest.isApplicationBundle(bundle.bundle_id) and bundle.components.len == 0) {
        return error.MissingBundleComponent;
    }
    if (declaredInitialComponent(bundle, initial_component) == null) {
        return error.InitialComponentNotDeclared;
    }
    if (initial_component.substrate != .typed_component_abi) {
        return error.InitialComponentAbiMismatch;
    }
    if (!has_embedded_artifact) {
        return error.EmbeddedArtifactRequired;
    }
}

fn declaredInitialComponent(
    bundle: manifest.BundleManifest,
    initial_component: task_runtime.ExecutionComponentSpec,
) ?manifest.ExecutionComponentDecl {
    for (bundle.components) |component| {
        if (std.mem.eql(u8, component.id, initial_component.label) and
            std.mem.eql(u8, component.entry, initial_component.entry))
        {
            return component;
        }
    }
    return null;
}

fn zeroImage() ImageRecord {
    return .{
        .id = 0,
        .component_class = .service_component,
        .component_abi_version = 0,
        .bundle_signed = false,
        .role_tag = 0,
        .heartbeat_increment = 0,
        .contract_flags = 0,
        .substrate = .typed_component_abi,
        .artifact_source = .metadata_only,
        .entry_point = 0,
        .loadable_segment_count = 0,
        .byte_len = 0,
        .bootstrap_mailbox_address = 0,
        .file_sha256 = crypto_hash.zero_digest,
        .executable_image = .{},
        .elf_file = .{},
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_BUNDLE_ID_BYTES,
        .display_name_len = 0,
        .display_name = [_]u8{0} ** MAX_DISPLAY_NAME_BYTES,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** MAX_PUBLISHER_BYTES,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .entry_len = 0,
        .entry = [_]u8{0} ** MAX_ENTRY_BYTES,
    };
}

fn imageMatchesRequest(
    existing: *const ImageRecord,
    request: ImageRegisterRequest,
    embedded: ?EmbeddedElfInfo,
) bool {
    const embedded_info = embedded orelse return false;
    const expected_source: ArtifactSource = .embedded_elf;
    const expected_image = embedded_info.executable_image;
    const expected_entry_point: u64 = expected_image.entry_point;
    const expected_segment_count: u16 = @intCast(expected_image.segment_count);
    const expected_byte_len: usize = expected_image.file_size_bytes;
    const expected_bootstrap_mailbox_address: u64 = embedded_info.bootstrap_mailbox_address;
    const expected_hash = expected_image.file_sha256;

    return existing.component_class == request.component_class and
        existing.bundle_signed == request.bundle.signature.isPresent() and
        existing.role_tag == request.role_tag and
        existing.heartbeat_increment == request.heartbeat_increment and
        existing.contract_flags == request.contract_flags and
        existing.substrate == request.initial_component.substrate and
        existing.artifact_source == expected_source and
        existing.entry_point == expected_entry_point and
        existing.loadable_segment_count == expected_segment_count and
        existing.byte_len == expected_byte_len and
        existing.bootstrap_mailbox_address == expected_bootstrap_mailbox_address and
        std.mem.eql(u8, &existing.file_sha256, &expected_hash) and
        std.mem.eql(u8, existing.bundleIdSlice(), request.bundle.bundle_id) and
        std.mem.eql(u8, existing.displayNameSlice(), request.bundle.display_name) and
        std.mem.eql(u8, existing.publisherSlice(), request.bundle.publisher) and
        std.mem.eql(u8, existing.labelSlice(), request.initial_component.label) and
        std.mem.eql(u8, existing.entrySlice(), request.initial_component.entry);
}

fn validateEmbeddedElfInfo(
    elf_file: embedded_file.File,
    embedded_info: EmbeddedElfInfo,
) Error!void {
    const inspected = try elf_image_inspector.inspectFile(elf_file);
    if (inspected.entry_point != embedded_info.entry_point) return error.EmbeddedArtifactMetadataMismatch;
    if (inspected.loadable_segment_count != embedded_info.loadable_segment_count) return error.EmbeddedArtifactMetadataMismatch;
    if (inspected.byte_len != embedded_info.byte_len) return error.EmbeddedArtifactMetadataMismatch;
    if (inspected.bootstrap_mailbox_address != embedded_info.bootstrap_mailbox_address) return error.EmbeddedArtifactMetadataMismatch;
    if (!std.mem.eql(u8, &inspected.file_sha256, &embedded_info.file_sha256)) return error.EmbeddedArtifactMetadataMismatch;
    if (!inspected.executable_image.eql(&embedded_info.executable_image)) {
        return error.EmbeddedArtifactMetadataMismatch;
    }
}

fn componentAbiVersion(substrate: task_runtime.ExecutionSubstrate) u16 {
    return switch (substrate) {
        .typed_component_abi => 1,
        .early_elf_runner => 1,
    };
}

fn validateStoredMetadata(
    bundle: manifest.BundleManifest,
    initial_component: task_runtime.ExecutionComponentSpec,
) Error!void {
    if (bundle.bundle_id.len > arrayFieldLen(ImageRecord, "bundle_id")) return error.BundleIdTooLong;
    if (bundle.display_name.len > arrayFieldLen(ImageRecord, "display_name")) return error.DisplayNameTooLong;
    if (bundle.publisher.len > arrayFieldLen(ImageRecord, "publisher")) return error.PublisherTooLong;
    if (initial_component.label.len > arrayFieldLen(ImageRecord, "label")) return error.InitialComponentLabelTooLong;
    if (initial_component.entry.len > arrayFieldLen(ImageRecord, "entry")) return error.InitialComponentEntryTooLong;
}

fn arrayFieldLen(comptime T: type, comptime field_name: []const u8) usize {
    return switch (@typeInfo(@FieldType(T, field_name))) {
        .array => |array| array.len,
        else => @compileError("userspace_loader metadata fields must be fixed-size arrays"),
    };
}

pub fn makeSyntheticElf32ForTest(entry_point: u32, phnum: u16, loadable_segments: u16) [SYNTHETIC_ELF_BYTES]u8 {
    var bytes = [_]u8{0} ** SYNTHETIC_ELF_BYTES;
    bytes[0] = 0x7F;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[std.elf.EI_CLASS] = std.elf.ELFCLASS32;
    bytes[std.elf.EI_DATA] = std.elf.ELFDATA2LSB;
    bytes[std.elf.EI_VERSION] = 1;

    std.mem.writeInt(u16, bytes[16..18], @intFromEnum(std.elf.ET.EXEC), .little);
    std.mem.writeInt(u16, bytes[18..20], @intFromEnum(std.elf.EM.@"386"), .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u32, bytes[24..28], entry_point, .little);
    std.mem.writeInt(u32, bytes[28..32], @sizeOf(std.elf.Elf32_Ehdr), .little);
    std.mem.writeInt(u32, bytes[32..36], SYNTHETIC_ELF_SECTION_HEADERS_OFFSET, .little);
    std.mem.writeInt(u16, bytes[40..42], @sizeOf(std.elf.Elf32_Ehdr), .little);
    std.mem.writeInt(u16, bytes[42..44], @sizeOf(std.elf.Elf32_Phdr), .little);
    std.mem.writeInt(u16, bytes[44..46], phnum, .little);
    std.mem.writeInt(u16, bytes[46..48], @sizeOf(std.elf.Elf32_Shdr), .little);
    std.mem.writeInt(u16, bytes[48..50], SYNTHETIC_ELF_SECTION_COUNT, .little);
    std.mem.writeInt(u16, bytes[50..52], 1, .little);

    var index: usize = 0;
    while (index < phnum) : (index += 1) {
        const program_offset = @sizeOf(std.elf.Elf32_Ehdr) + index * @sizeOf(std.elf.Elf32_Phdr);
        const p_type: u32 = if (index < loadable_segments) std.elf.PT_LOAD else 0;
        std.mem.writeInt(u32, bytes[program_offset..][0..4], p_type, .little);
        if (p_type == std.elf.PT_LOAD) {
            const file_offset = SYNTHETIC_ELF_SEGMENTS_OFFSET + index * SYNTHETIC_ELF_SEGMENT_MEMORY_BYTES;
            const virtual_address = entry_point + @as(u32, @intCast(index)) * SYNTHETIC_ELF_SEGMENT_ALIGNMENT;
            const flags: u32 = if (index == 0)
                std.elf.PF_R | std.elf.PF_X
            else
                std.elf.PF_R | std.elf.PF_W;

            std.mem.writeInt(u32, bytes[program_offset + 4 ..][0..4], @intCast(file_offset), .little);
            std.mem.writeInt(u32, bytes[program_offset + 8 ..][0..4], virtual_address, .little);
            std.mem.writeInt(u32, bytes[program_offset + 16 ..][0..4], @intCast(SYNTHETIC_ELF_SEGMENT_FILE_BYTES), .little);
            std.mem.writeInt(u32, bytes[program_offset + 20 ..][0..4], @intCast(SYNTHETIC_ELF_SEGMENT_MEMORY_BYTES), .little);
            std.mem.writeInt(u32, bytes[program_offset + 24 ..][0..4], flags, .little);
            std.mem.writeInt(u32, bytes[program_offset + 28 ..][0..4], SYNTHETIC_ELF_SEGMENT_ALIGNMENT, .little);

            @memset(bytes[file_offset..][0..SYNTHETIC_ELF_SEGMENT_FILE_BYTES], @intCast(index + 1));
        }
    }

    @memcpy(
        bytes[SYNTHETIC_ELF_SECTION_NAMES_OFFSET..][0..SYNTHETIC_ELF_SECTION_NAMES.len],
        SYNTHETIC_ELF_SECTION_NAMES,
    );

    const string_table_header = SYNTHETIC_ELF_SECTION_HEADERS_OFFSET + @sizeOf(std.elf.Elf32_Shdr);
    writeSyntheticSectionHeader(
        &bytes,
        string_table_header,
        1,
        3,
        0,
        0,
        SYNTHETIC_ELF_SECTION_NAMES_OFFSET,
        SYNTHETIC_ELF_SECTION_NAMES.len,
        1,
    );
    const mailbox_header = string_table_header + @sizeOf(std.elf.Elf32_Shdr);
    writeSyntheticSectionHeader(
        &bytes,
        mailbox_header,
        11,
        1,
        0x1 | 0x2,
        entry_point + SYNTHETIC_ELF_SEGMENT_ALIGNMENT,
        SYNTHETIC_ELF_SEGMENTS_OFFSET + SYNTHETIC_ELF_SEGMENT_MEMORY_BYTES,
        userspace_bootstrap_mailbox.ABI_SIZE_BYTES,
        userspace_bootstrap_mailbox.ABI_ALIGNMENT,
    );

    return bytes;
}

fn writeSyntheticSectionHeader(
    bytes: []u8,
    offset: usize,
    name_offset: u32,
    section_type: u32,
    flags: u32,
    address: u32,
    file_offset: usize,
    size: usize,
    alignment: usize,
) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], name_offset, .little);
    std.mem.writeInt(u32, bytes[offset + 4 ..][0..4], section_type, .little);
    std.mem.writeInt(u32, bytes[offset + 8 ..][0..4], flags, .little);
    std.mem.writeInt(u32, bytes[offset + 12 ..][0..4], address, .little);
    std.mem.writeInt(u32, bytes[offset + 16 ..][0..4], @intCast(file_offset), .little);
    std.mem.writeInt(u32, bytes[offset + 20 ..][0..4], @intCast(size), .little);
    std.mem.writeInt(u32, bytes[offset + 32 ..][0..4], @intCast(alignment), .little);
}

const test_main_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "main", .entry = "app.main" },
};

const test_main_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.workspace.document" },
    .{ .name = "zigos.object.workspace" },
};

const test_main_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
};

fn signedTestBundle(bundle_id: []const u8, display_name: []const u8) !manifest.BundleManifest {
    var bundle = manifest.BundleManifest{
        .bundle_id = bundle_id,
        .display_name = display_name,
        .publisher = "zigos.dev",
        .provided_interfaces = test_main_interfaces[0..1],
        .consumed_interfaces = test_main_interfaces[1..2],
        .components = &test_main_components,
        .assets = &test_main_assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    return bundle;
}

test "allocated userspace catalog initialization preserves empty catalog invariants" {
    var catalog: Catalog = undefined;
    catalog.initializeAllocated();

    try std.testing.expectEqual(@as(usize, 0), catalog.imageCount());
    const bundle = try signedTestBundle("app.allocated-catalog", "Allocated Catalog");
    const image_bytes = makeSyntheticElf32ForTest(0x4000_5000, 2, 2);
    const image = try catalog.registerEmbeddedArtifact(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.main",
        },
        .elf_file = embedded_file.File.fromBytes(&image_bytes),
    });

    try std.testing.expectEqual(@as(u64, 1), image.id);
    try std.testing.expectEqual(image.id, catalog.findById(image.id).?.id);
    try std.testing.expectEqualStrings(bundle.bundle_id, catalog.findByBundleId(bundle.bundle_id).?.bundleIdSlice());
}

test "userspace image launch records bundle provenance and isolated process state" {
    var catalog = Catalog.init();
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes", .entry = "app.notes" },
        },
        .assets = &assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    const image_bytes = makeSyntheticElf32ForTest(0x4000_6000, 2, 2);
    _ = try catalog.registerEmbeddedArtifact(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
        .role_tag = 0xA107,
        .heartbeat_increment = 7,
        .contract_flags = 0x2,
        .elf_file = embedded_file.File.fromBytes(&image_bytes),
    });

    var runtime = task_runtime.Runtime.init();
    const launched = try catalog.launchDirect(&runtime, "app.notes", .{
        .owner = .{ .kind = .user, .serial = 1 },
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 4,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .ui_surface_id = 3,
        .local_only = true,
    });

    try std.testing.expect(launched.runsAsUserspaceProcess());
    try std.testing.expect(launched.hasDedicatedHost());
    try std.testing.expect(launched.hasLoadedExecutable());
    try std.testing.expectEqualStrings("app.notes", launched.launchBundleIdSlice());
    try std.testing.expectEqualStrings("notes", launched.executionComponents()[0].labelSlice());
    try std.testing.expect(runtime.findAddressSpaceConst(launched.address_space_id).?.hasMappedExecutable());
}

test "kernel-launched userspace images surface a userspace task flag" {
    var catalog = Catalog.init();
    var bundle = manifest.BundleManifest{
        .bundle_id = "zigos.service.storage",
        .display_name = "Storage Service",
        .publisher = "zigos.system",
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "workspace-storage", .entry = "zigos.object.workspace" },
        },
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    const image_bytes = makeSyntheticElf32ForTest(0x4000_7000, 2, 2);
    _ = try catalog.registerEmbeddedArtifact(.{
        .bundle = bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
        },
        .role_tag = 0xA10C,
        .heartbeat_increment = 12,
        .contract_flags = 0x11,
        .elf_file = embedded_file.File.fromBytes(&image_bytes),
    });

    var runtime = task_runtime.Runtime.init();
    var capabilities = @import("../kernel_api/capability.zig").CapabilityTable.init();
    var endpoints = @import("../kernel_api/endpoint.zig").Table.init();
    var shared = @import("../kernel_api/shared_memory.zig").Table.init();
    var kernel = @import("../kernel_api/native_kernel.zig").Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = component_port.KernelPort.init(&kernel);

    const controller = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = 8,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const authority = try capabilities.mintBootRoot(.{
        .holder = controller.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .service = .{
            .task_create = true,
            .capability_query = true,
        } },
        .scope = .{ .local_only = true },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
            .renewable = true,
        },
    });
    try runtime.grantCapability(controller.id, authority.id);

    const descriptor = try catalog.launchViaKernel(.{
        .port = &port,
        .authority_capability_id = authority.id,
        .controller_task_id = controller.id,
        .correlation_id = 1,
        .now_ticks = 5,
    }, "zigos.service.storage", .{
        .owner = .{ .kind = .service, .serial = 4 },
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });

    try std.testing.expect(abi.taskFlagsHas(descriptor.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expectEqualStrings(
        "zigos.service.storage",
        runtime.find(descriptor.task_id).?.launchBundleIdSlice(),
    );
    try std.testing.expect(runtime.find(descriptor.task_id).?.hasLoadedExecutable());
}

test "embedded elf inspection records entry points loadable segments and measurements" {
    const bytes = makeSyntheticElf32ForTest(0x4000_1000, 3, 2);
    const info = try elf_image_inspector.inspect(&bytes);

    try std.testing.expectEqual(@as(u64, 0x4000_1000), info.entry_point);
    try std.testing.expectEqual(@as(u16, 2), info.loadable_segment_count);
    try std.testing.expectEqual(bytes.len, info.byte_len);
    try std.testing.expect(!std.mem.eql(u8, &info.file_sha256, &crypto_hash.zero_digest));
    try std.testing.expectEqual(@as(usize, 2), info.executable_image.segment_count);
    try std.testing.expectEqual(@as(u64, 0x4000_1000), info.executable_image.segments[0].virtual_address);
    try std.testing.expect(info.executable_image.segments[0].access.execute);
}

test "embedded elf inspection rejects malformed section extents and mailbox flags" {
    var invalid_table = makeSyntheticElf32ForTest(0x4000_1000, 3, 2);
    std.mem.writeInt(u32, invalid_table[32..36], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidSectionHeaderTable, elf_image_inspector.inspect(&invalid_table));

    var invalid_mailbox = makeSyntheticElf32ForTest(0x4000_1000, 3, 2);
    const mailbox_header = SYNTHETIC_ELF_SECTION_HEADERS_OFFSET + 2 * @sizeOf(std.elf.Elf32_Shdr);
    std.mem.writeInt(u32, invalid_mailbox[mailbox_header + 8 ..][0..4], 0x2, .little);
    try std.testing.expectError(error.InvalidBootstrapMailboxSection, elf_image_inspector.inspect(&invalid_mailbox));

    var missing_mailbox = makeSyntheticElf32ForTest(0x4000_1000, 3, 2);
    std.mem.writeInt(u16, missing_mailbox[48..50], 2, .little);
    try std.testing.expectError(error.MissingBootstrapMailbox, elf_image_inspector.inspect(&missing_mailbox));
}

test "catalog stores embedded elf metadata for registered userspace artifacts" {
    var catalog = Catalog.init();
    const bytes = makeSyntheticElf32ForTest(0x4000_2000, 2, 2);
    var bundle = manifest.BundleManifest{
        .bundle_id = "zigos.system.compositor",
        .display_name = "Compositor Session",
        .publisher = "zigos.system",
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "compositor-session", .entry = "zigos.ui.session" },
        },
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    const image = try catalog.registerEmbeddedArtifact(.{
        .bundle = bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "compositor-session",
            .entry = "zigos.ui.session",
        },
        .role_tag = 0xA10F,
        .heartbeat_increment = 15,
        .contract_flags = 0x3,
        .elf_file = embedded_file.File.fromBytes(&bytes),
    });

    try std.testing.expect(image.embedsElf());
    try std.testing.expect(image.hasTypedContract());
    try std.testing.expectEqual(@as(u64, 0x4000_2000), image.entry_point);
    try std.testing.expectEqual(@as(u16, 2), image.loadable_segment_count);
    try std.testing.expectEqual(bytes.len, image.byte_len);
    try std.testing.expect(image.executable_image.isPresent());
    try std.testing.expectEqual(@as(usize, 2), image.executable_image.segment_count);
    try std.testing.expect(image.bootstrap_mailbox_address != 0);
    try std.testing.expectEqual(@as(u32, 0xA10F), image.role_tag);
    try std.testing.expectEqual(@as(u32, 15), image.heartbeat_increment);
}

test "catalog image ids wrap without zero and skip active images" {
    var catalog = Catalog.init();
    const bytes = makeSyntheticElf32ForTest(0x4000_2000, 2, 2);

    catalog.next_image_id = std.math.maxInt(u64);
    const max_image = try catalog.registerEmbeddedArtifact(.{
        .bundle = try signedTestBundle("app.image-wrap-max", "Image Wrap Max"),
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.main",
        },
        .elf_file = embedded_file.File.fromBytes(&bytes),
    });
    try std.testing.expectEqual(std.math.maxInt(u64), max_image.id);
    try std.testing.expectEqual(@as(u64, 1), catalog.next_image_id);
    try std.testing.expect(catalog.findById(0) == null);

    const wrapped_image = try catalog.registerEmbeddedArtifact(.{
        .bundle = try signedTestBundle("app.image-wrap-one", "Image Wrap One"),
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.main",
        },
        .elf_file = embedded_file.File.fromBytes(&bytes),
    });
    try std.testing.expectEqual(@as(u64, 1), wrapped_image.id);
    try std.testing.expectEqual(@as(u64, 2), catalog.next_image_id);
    try std.testing.expect(catalog.findById(0) == null);

    catalog.next_image_id = 1;
    const skipped_image = try catalog.registerEmbeddedArtifact(.{
        .bundle = try signedTestBundle("app.image-wrap-two", "Image Wrap Two"),
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.main",
        },
        .elf_file = embedded_file.File.fromBytes(&bytes),
    });
    try std.testing.expectEqual(@as(u64, 2), skipped_image.id);
    try std.testing.expectEqual(@as(u64, 3), catalog.next_image_id);
    try std.testing.expect(catalog.findById(0) == null);

    var full_catalog = Catalog.init();
    var bundle_id_buffer: [MAX_BUNDLE_ID_BYTES]u8 = undefined;
    var display_name_buffer: [MAX_DISPLAY_NAME_BYTES]u8 = undefined;
    for (0..MAX_IMAGES) |index| {
        const bundle_id = try std.fmt.bufPrint(&bundle_id_buffer, "app.full-image-{d}", .{index});
        const display_name = try std.fmt.bufPrint(&display_name_buffer, "Full Image {d}", .{index});
        _ = try full_catalog.registerEmbeddedArtifact(.{
            .bundle = try signedTestBundle(bundle_id, display_name),
            .component_class = .app_component,
            .initial_component = .{
                .label = "main",
                .entry = "app.main",
            },
            .elf_file = embedded_file.File.fromBytes(&bytes),
        });
    }
    const next_before_full = full_catalog.next_image_id;
    try std.testing.expectError(error.ImageTableFull, full_catalog.registerEmbeddedArtifact(.{
        .bundle = try signedTestBundle("app.full-image-rejected", "Full Image Rejected"),
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.main",
        },
        .elf_file = embedded_file.File.fromBytes(&bytes),
    }));
    try std.testing.expectEqual(next_before_full, full_catalog.next_image_id);
    try std.testing.expectEqual(MAX_IMAGES, full_catalog.imageCount());
}

test "catalog rejects generated artifact metadata that no longer matches embedded elf bytes" {
    const bytes = makeSyntheticElf32ForTest(0x4000_4000, 3, 2);
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "provenance-check", .entry = "zigos.provenance.check" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "zigos.system.provenance-check",
        .display_name = "Provenance Check",
        .publisher = "zigos.system",
        .components = &components,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    const request = EmbeddedImageRegisterRequest{
        .bundle = bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "provenance-check",
            .entry = "zigos.provenance.check",
        },
        .role_tag = 0xA120,
        .heartbeat_increment = 32,
        .contract_flags = 0x11,
        .elf_file = embedded_file.File.fromBytes(&bytes),
    };
    const valid_info = try elf_image_inspector.inspect(&bytes);

    var valid_catalog = Catalog.init();
    _ = try valid_catalog.registerEmbeddedArtifactWithInfo(request, valid_info);

    var stale_digest = valid_info;
    stale_digest.file_sha256[0] = stale_digest.file_sha256[0] ^ 0x5A;
    var digest_catalog = Catalog.init();
    try std.testing.expectError(
        error.EmbeddedArtifactMetadataMismatch,
        digest_catalog.registerEmbeddedArtifactWithInfo(request, stale_digest),
    );

    var stale_entry = valid_info;
    stale_entry.entry_point += SYNTHETIC_ELF_SEGMENT_ALIGNMENT;
    var entry_catalog = Catalog.init();
    try std.testing.expectError(
        error.EmbeddedArtifactMetadataMismatch,
        entry_catalog.registerEmbeddedArtifactWithInfo(request, stale_entry),
    );

    var stale_segment = valid_info;
    stale_segment.executable_image.segments[0].file_size += 1;
    var segment_catalog = Catalog.init();
    try std.testing.expectError(
        error.EmbeddedArtifactMetadataMismatch,
        segment_catalog.registerEmbeddedArtifactWithInfo(request, stale_segment),
    );

    var missing_bytes_request = request;
    missing_bytes_request.elf_file = .{};
    var missing_catalog = Catalog.init();
    try std.testing.expectError(
        error.InvalidElfHeader,
        missing_catalog.registerEmbeddedArtifactWithInfo(missing_bytes_request, valid_info),
    );

    var malformed_bytes = bytes;
    malformed_bytes[0] = 0;
    var malformed_request = request;
    malformed_request.elf_file = embedded_file.File.fromBytes(&malformed_bytes);
    var malformed_catalog = Catalog.init();
    try std.testing.expectError(
        error.InvalidElfMagic,
        malformed_catalog.registerEmbeddedArtifactWithInfo(malformed_request, valid_info),
    );
}

test "catalog preserves exact-limit identity and component labels without truncation" {
    var catalog = Catalog.init();
    const bundle_id = [_]u8{'b'} ** MAX_BUNDLE_ID_BYTES;
    const display_name = [_]u8{'d'} ** MAX_DISPLAY_NAME_BYTES;
    const entry = [_]u8{'e'} ** MAX_ENTRY_BYTES;
    const label = [_]u8{'l'} ** MAX_LABEL_BYTES;
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/default/icon.svg", .content_type = "image/svg+xml" },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = bundle_id[0..],
        .display_name = display_name[0..],
        .publisher = "zigos.dev",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = label[0..], .entry = entry[0..] },
        },
        .assets = &assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);

    const image_bytes = makeSyntheticElf32ForTest(0x4000_8000, 2, 2);
    const image = try catalog.registerEmbeddedArtifact(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = label[0..],
            .entry = entry[0..],
        },
        .elf_file = embedded_file.File.fromBytes(&image_bytes),
    });

    try std.testing.expectEqualStrings(bundle_id[0..], image.bundleIdSlice());
    try std.testing.expectEqualStrings(display_name[0..], image.displayNameSlice());
    try std.testing.expectEqualStrings(label[0..], image.labelSlice());
    try std.testing.expectEqualStrings(entry[0..], image.entrySlice());
}

test "catalog rejects metadata-only executable registration" {
    var catalog = Catalog.init();
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.metadata-only",
        .display_name = "Metadata Only",
        .publisher = "zigos.dev",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "metadata-only", .entry = "app.metadata-only" },
        },
        .assets = &assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);

    try std.testing.expectError(error.EmbeddedArtifactRequired, catalog.register(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = "metadata-only",
            .entry = "app.metadata-only",
        },
    }));
}

test "catalog rejects unsigned bundles and missing declared components for userspace launch" {
    var catalog = Catalog.init();
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/default/icon.svg", .content_type = "image/svg+xml" },
    };

    try std.testing.expectError(error.MissingBundleSignature, catalog.register(.{
        .bundle = .{
            .bundle_id = "app.unsigned",
            .display_name = "Unsigned",
            .publisher = "zigos.dev",
            .provided_interfaces = interfaces[0..1],
            .consumed_interfaces = interfaces[1..2],
            .components = &[_]manifest.ExecutionComponentDecl{
                .{ .id = "unsigned", .entry = "app.unsigned" },
            },
            .assets = &assets,
        },
        .component_class = .app_component,
        .initial_component = .{
            .label = "unsigned",
            .entry = "app.unsigned",
        },
    }));

    try std.testing.expectError(error.MissingExecutableComponent, catalog.register(.{
        .bundle = blk: {
            var bundle = manifest.BundleManifest{
                .bundle_id = "app.no-components",
                .display_name = "No Components",
                .publisher = "zigos.dev",
                .provided_interfaces = interfaces[0..1],
                .consumed_interfaces = interfaces[1..2],
                .assets = &assets,
            };
            bundle.signature = try userspace_manifest_signing.signBundle(bundle);
            break :blk bundle;
        },
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.no-components",
        },
    }));

    try std.testing.expectError(error.InitialComponentNotDeclared, catalog.register(.{
        .bundle = blk: {
            var bundle = manifest.BundleManifest{
                .bundle_id = "app.mismatch",
                .display_name = "Mismatch",
                .publisher = "zigos.dev",
                .provided_interfaces = interfaces[0..1],
                .consumed_interfaces = interfaces[1..2],
                .components = &[_]manifest.ExecutionComponentDecl{
                    .{ .id = "worker", .entry = "app.mismatch.worker" },
                },
                .assets = &assets,
            };
            bundle.signature = try userspace_manifest_signing.signBundle(bundle);
            break :blk bundle;
        },
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.mismatch.main",
        },
    }));

    try std.testing.expectError(error.InitialComponentNotDeclared, catalog.register(.{
        .bundle = blk: {
            var bundle = manifest.BundleManifest{
                .bundle_id = "app.label-spoof",
                .display_name = "Label Spoof",
                .publisher = "zigos.dev",
                .provided_interfaces = interfaces[0..1],
                .consumed_interfaces = interfaces[1..2],
                .components = &[_]manifest.ExecutionComponentDecl{
                    .{ .id = "declared-main", .entry = "app.label-spoof" },
                },
                .assets = &assets,
            };
            bundle.signature = try userspace_manifest_signing.signBundle(bundle);
            break :blk bundle;
        },
        .component_class = .app_component,
        .initial_component = .{
            .label = "spoofed-main",
            .entry = "app.label-spoof",
        },
    }));

    try std.testing.expectError(error.InitialComponentAbiMismatch, catalog.register(.{
        .bundle = blk: {
            var bundle = manifest.BundleManifest{
                .bundle_id = "app.abi-mismatch",
                .display_name = "ABI Mismatch",
                .publisher = "zigos.dev",
                .provided_interfaces = interfaces[0..1],
                .consumed_interfaces = interfaces[1..2],
                .components = &[_]manifest.ExecutionComponentDecl{
                    .{ .id = "typed-main", .entry = "app.abi-mismatch" },
                },
                .assets = &assets,
            };
            bundle.signature = try userspace_manifest_signing.signBundle(bundle);
            break :blk bundle;
        },
        .component_class = .app_component,
        .initial_component = .{
            .substrate = .early_elf_runner,
            .label = "typed-main",
            .entry = "app.abi-mismatch",
        },
    }));

    const long_label = [_]u8{'l'} ** (MAX_LABEL_BYTES + 1);
    try std.testing.expectError(error.InitialComponentLabelTooLong, catalog.register(.{
        .bundle = blk: {
            var bundle = manifest.BundleManifest{
                .bundle_id = "app.long-label",
                .display_name = "Long Label",
                .publisher = "zigos.dev",
                .provided_interfaces = interfaces[0..1],
                .consumed_interfaces = interfaces[1..2],
                .components = &[_]manifest.ExecutionComponentDecl{
                    .{ .id = "main", .entry = "app.long-label" },
                },
                .assets = &assets,
            };
            bundle.signature = try userspace_manifest_signing.signBundle(bundle);
            break :blk bundle;
        },
        .component_class = .app_component,
        .initial_component = .{
            .label = long_label[0..],
            .entry = "app.long-label",
        },
    }));
}

test "catalog rejects invalid bundle signatures" {
    var catalog = Catalog.init();
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/default/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.invalid-signature",
        .display_name = "Invalid Signature",
        .publisher = "zigos.dev",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "main", .entry = "app.invalid-signature" },
        },
        .assets = &assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    bundle.display_name = "Tampered Signature";

    try std.testing.expectError(error.InvalidBundleSignature, catalog.register(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = "main",
            .entry = "app.invalid-signature",
        },
        .role_tag = 0xB001,
        .heartbeat_increment = 1,
    }));
}
