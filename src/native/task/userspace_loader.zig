const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const component_port = @import("../kernel_api/component_port.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const std = @import("std");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_manifest_signing = @import("userspace_manifest_signing.zig");

pub const MAX_IMAGES: usize = 24;
const MAX_BUNDLE_ID_BYTES: usize = 64;
const MAX_DISPLAY_NAME_BYTES: usize = 48;
const MAX_PUBLISHER_BYTES: usize = 48;
const MAX_IMAGE_HASH_BYTES: usize = 32;

pub const Error = manifest.ValidationError || component_port.Error || task_runtime.Error || error{
    EmptyLabel,
    EmptyEntry,
    EmbeddedArtifactRequired,
    InvalidElfHeader,
    InvalidElfMagic,
    InvalidLoadableSegment,
    InvalidProgramHeaderTable,
    InitialComponentNotDeclared,
    ImageConflict,
    ImageNotFound,
    ImageTableFull,
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
    elf_bytes: []const u8,
};

pub const ArtifactSource = enum(u8) {
    metadata_only,
    embedded_elf,
};

pub const EmbeddedElfInfo = struct {
    entry_point: u64,
    loadable_segment_count: u16,
    byte_len: usize,
    bootstrap_mailbox_address: u64,
    file_sha256: [MAX_IMAGE_HASH_BYTES]u8,
    executable_image: task_runtime.ExecutableImageSpec,
};

pub const LaunchRequest = struct {
    owner: principal.PrincipalId,
    budget: task_runtime.ResourceBudget,
    ui_surface_id: ?u64 = null,
    local_only: bool = true,
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
    loadable_segment_count: u16,
    byte_len: usize,
    bootstrap_mailbox_address: u64,
    file_sha256: [MAX_IMAGE_HASH_BYTES]u8,
    executable_image: task_runtime.ExecutableImageSpec,
    elf_bytes: []const u8,
    bundle_id_len: usize,
    bundle_id: [MAX_BUNDLE_ID_BYTES]u8,
    display_name_len: usize,
    display_name: [MAX_DISPLAY_NAME_BYTES]u8,
    publisher_len: usize,
    publisher: [MAX_PUBLISHER_BYTES]u8,
    label_len: usize,
    label: [48]u8,
    entry_len: usize,
    entry: [64]u8,

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

pub const Catalog = struct {
    next_image_id: u64 = 1,
    images: [MAX_IMAGES]ImageSlot = [_]ImageSlot{ImageSlot{}} ** MAX_IMAGES,

    pub fn init() Catalog {
        return Catalog{};
    }

    pub fn register(self: *Catalog, request: ImageRegisterRequest) Error!*const ImageRecord {
        return self.registerWithEmbeddedElf(request, null, &.{});
    }

    pub fn registerEmbeddedArtifact(
        self: *Catalog,
        request: EmbeddedImageRegisterRequest,
    ) Error!*const ImageRecord {
        return self.registerWithEmbeddedElf(.{
            .bundle = request.bundle,
            .component_class = request.component_class,
            .initial_component = request.initial_component,
            .role_tag = request.role_tag,
            .heartbeat_increment = request.heartbeat_increment,
            .contract_flags = request.contract_flags,
        }, try inspectEmbeddedElf(request.elf_bytes), request.elf_bytes);
    }

    pub fn findByBundleId(self: *Catalog, bundle_id: []const u8) ?*const ImageRecord {
        for (&self.images) |*slot| {
            if (!slot.in_use) continue;
            if (std.mem.eql(u8, slot.image.bundleIdSlice(), bundle_id)) return &slot.image;
        }
        return null;
    }

    pub fn findById(self: *Catalog, image_id: u64) ?*const ImageRecord {
        for (&self.images) |*slot| {
            if (slot.in_use and slot.image.id == image_id) return &slot.image;
        }
        return null;
    }

    pub fn imageCount(self: *const Catalog) usize {
        var count: usize = 0;
        for (self.images) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
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
        elf_bytes: []const u8,
    ) Error!*const ImageRecord {
        try manifest.validate(request.bundle);
        try manifest.validateApplicationPackaging(request.bundle);
        if (request.initial_component.label.len == 0) return error.EmptyLabel;
        if (request.initial_component.entry.len == 0) return error.EmptyEntry;
        try validateExecutableBundle(request.bundle, request.initial_component, embedded != null);

        if (self.findByBundleId(request.bundle.bundle_id)) |existing| {
            if (!imageMatchesRequest(existing, request, embedded)) return error.ImageConflict;
            return existing;
        }

        for (&self.images) |*slot| {
            if (slot.in_use) continue;

            var image = zeroImage();
            const executable_image = if (embedded) |info|
                info.executable_image
            else
                syntheticExecutableImage(request);
            image.id = self.next_image_id;
            image.component_class = request.component_class;
            image.component_abi_version = componentAbiVersion(request.initial_component.substrate);
            image.bundle_signed = request.bundle.signature.isPresent();
            image.role_tag = request.role_tag;
            image.heartbeat_increment = request.heartbeat_increment;
            image.contract_flags = request.contract_flags;
            image.substrate = request.initial_component.substrate;
            image.artifact_source = if (embedded != null) .embedded_elf else .metadata_only;
            image.entry_point = executable_image.entry_point;
            image.loadable_segment_count = @intCast(executable_image.segment_count);
            image.byte_len = executable_image.file_size_bytes;
            image.bootstrap_mailbox_address = if (embedded) |info| info.bootstrap_mailbox_address else 0;
            image.file_sha256 = executable_image.file_sha256;
            image.executable_image = executable_image;
            image.elf_bytes = elf_bytes;
            image.bundle_id_len = copyTruncated(image.bundle_id[0..], request.bundle.bundle_id);
            image.display_name_len = copyTruncated(image.display_name[0..], request.bundle.display_name);
            image.publisher_len = copyTruncated(image.publisher[0..], request.bundle.publisher);
            image.label_len = copyTruncated(image.label[0..], request.initial_component.label);
            image.entry_len = copyTruncated(image.entry[0..], request.initial_component.entry);

            slot.in_use = true;
            slot.image = image;
            self.next_image_id += 1;
            return &slot.image;
        }

        return error.ImageTableFull;
    }
};

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
        },
        .userspace_image = image.executable_image,
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
    if (!bundleDeclaresInitialComponent(bundle, initial_component)) return error.InitialComponentNotDeclared;
    if (builtin.target.os.tag == .freestanding and !has_embedded_artifact) {
        return error.EmbeddedArtifactRequired;
    }
}

fn bundleDeclaresInitialComponent(
    bundle: manifest.BundleManifest,
    initial_component: task_runtime.ExecutionComponentSpec,
) bool {
    for (bundle.components) |component| {
        if (std.mem.eql(u8, component.entry, initial_component.entry)) return true;
    }
    return false;
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
        .file_sha256 = [_]u8{0} ** MAX_IMAGE_HASH_BYTES,
        .executable_image = .{},
        .elf_bytes = &.{},
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_BUNDLE_ID_BYTES,
        .display_name_len = 0,
        .display_name = [_]u8{0} ** MAX_DISPLAY_NAME_BYTES,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** MAX_PUBLISHER_BYTES,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .entry_len = 0,
        .entry = [_]u8{0} ** 64,
    };
}

fn imageMatchesRequest(
    existing: *const ImageRecord,
    request: ImageRegisterRequest,
    embedded: ?EmbeddedElfInfo,
) bool {
    const expected_source: ArtifactSource = if (embedded != null) .embedded_elf else .metadata_only;
    const expected_image = if (embedded) |info|
        info.executable_image
    else
        syntheticExecutableImage(request);
    const expected_entry_point: u64 = expected_image.entry_point;
    const expected_segment_count: u16 = @intCast(expected_image.segment_count);
    const expected_byte_len: usize = expected_image.file_size_bytes;
    const expected_bootstrap_mailbox_address: u64 = if (embedded) |info| info.bootstrap_mailbox_address else 0;
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

fn componentAbiVersion(substrate: task_runtime.ExecutionSubstrate) u16 {
    return switch (substrate) {
        .typed_component_abi => 1,
        .early_elf_runner => 1,
    };
}

fn copyTruncated(buffer: []u8, source: []const u8) usize {
    const len = @min(buffer.len - 1, source.len);
    @memcpy(buffer[0..len], source[0..len]);
    return len;
}

fn syntheticExecutableImage(request: ImageRegisterRequest) task_runtime.ExecutableImageSpec {
    return task_runtime.syntheticUserspaceImage(request.bundle.bundle_id, request.initial_component.entry);
}

fn inspectEmbeddedElf(elf_bytes: []const u8) Error!EmbeddedElfInfo {
    if (elf_bytes.len < @sizeOf(std.elf.Elf32_Ehdr)) return error.InvalidElfHeader;

    var header: std.elf.Elf32_Ehdr = undefined;
    @memcpy(std.mem.asBytes(&header), elf_bytes[0..@sizeOf(std.elf.Elf32_Ehdr)]);

    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS32) return error.UnsupportedElfClass;
    if (header.e_ident[std.elf.EI_DATA] != std.elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != .@"386") return error.UnsupportedElfMachine;
    if (header.e_phentsize != @sizeOf(std.elf.Elf32_Phdr)) return error.InvalidProgramHeaderTable;

    const program_headers_end = @as(usize, header.e_phoff) +
        @as(usize, header.e_phentsize) * @as(usize, header.e_phnum);
    if (header.e_phoff == 0 or program_headers_end > elf_bytes.len) {
        return error.InvalidProgramHeaderTable;
    }

    const bootstrap_mailbox_address = findOptionalSectionAddress(
        elf_bytes,
        header,
        userspace_bootstrap_mailbox.SECTION_NAME,
    ) orelse 0;

    var executable_image = task_runtime.ExecutableImageSpec{};
    executable_image.entry_point = header.e_entry;
    executable_image.stack_top = task_runtime.DEFAULT_USER_STACK_TOP;
    executable_image.stack_size_bytes = task_runtime.DEFAULT_USER_STACK_SIZE_BYTES;
    executable_image.file_size_bytes = elf_bytes.len;

    var loadable_segment_count: usize = 0;
    var offset: usize = header.e_phoff;
    var index: usize = 0;
    while (index < header.e_phnum) : (index += 1) {
        var program_header: std.elf.Elf32_Phdr = undefined;
        @memcpy(
            std.mem.asBytes(&program_header),
            elf_bytes[offset..][0..@sizeOf(std.elf.Elf32_Phdr)],
        );
        if (program_header.p_type == std.elf.PT_LOAD) {
            if (loadable_segment_count >= task_runtime.MAX_EXECUTABLE_SEGMENTS) {
                return error.TooManyLoadableSegments;
            }
            if (program_header.p_vaddr == 0 or program_header.p_memsz == 0) {
                return error.InvalidLoadableSegment;
            }
            if (program_header.p_filesz > program_header.p_memsz) return error.InvalidLoadableSegment;

            const segment_end = @as(usize, program_header.p_offset) + @as(usize, program_header.p_filesz);
            if (segment_end > elf_bytes.len) return error.InvalidLoadableSegment;

            executable_image.segments[loadable_segment_count] = .{
                .virtual_address = program_header.p_vaddr,
                .file_offset = program_header.p_offset,
                .file_size = @intCast(program_header.p_filesz),
                .memory_size = @intCast(program_header.p_memsz),
                .alignment = if (program_header.p_align == 0) 1 else program_header.p_align,
                .access = .{
                    .read = (program_header.p_flags & std.elf.PF_R) != 0,
                    .write = (program_header.p_flags & std.elf.PF_W) != 0,
                    .execute = (program_header.p_flags & std.elf.PF_X) != 0,
                },
            };
            loadable_segment_count += 1;
        }
        offset += @sizeOf(std.elf.Elf32_Phdr);
    }
    if (loadable_segment_count == 0) return error.MissingLoadableSegment;

    var hasher = crypto_hash.init();
    hasher.update(elf_bytes);

    executable_image.segment_count = loadable_segment_count;
    executable_image.file_sha256 = crypto_hash.finalize(&hasher);

    return .{
        .entry_point = header.e_entry,
        .loadable_segment_count = @intCast(loadable_segment_count),
        .byte_len = elf_bytes.len,
        .bootstrap_mailbox_address = bootstrap_mailbox_address,
        .file_sha256 = executable_image.file_sha256,
        .executable_image = executable_image,
    };
}

fn findOptionalSectionAddress(
    elf_bytes: []const u8,
    header: std.elf.Elf32_Ehdr,
    section_name: []const u8,
) ?u64 {
    const section_count: usize = header.e_shnum;
    if (header.e_shoff == 0 or header.e_shentsize != @sizeOf(std.elf.Elf32_Shdr)) return null;
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) return null;

    const section_headers_end = @as(usize, header.e_shoff) + @as(usize, header.e_shentsize) * section_count;
    if (section_headers_end > elf_bytes.len) return null;

    const names_header_offset = @as(usize, header.e_shoff) + @as(usize, header.e_shstrndx) * @sizeOf(std.elf.Elf32_Shdr);
    var names_header: std.elf.Elf32_Shdr = undefined;
    @memcpy(std.mem.asBytes(&names_header), elf_bytes[names_header_offset..][0..@sizeOf(std.elf.Elf32_Shdr)]);

    const names_start = @as(usize, names_header.sh_offset);
    const names_end = names_start + @as(usize, names_header.sh_size);
    if (names_end > elf_bytes.len) return null;
    const section_names = elf_bytes[names_start..names_end];

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section_offset = @as(usize, header.e_shoff) + index * @sizeOf(std.elf.Elf32_Shdr);
        var section: std.elf.Elf32_Shdr = undefined;
        @memcpy(std.mem.asBytes(&section), elf_bytes[section_offset..][0..@sizeOf(std.elf.Elf32_Shdr)]);
        const name = readOptionalSectionName(section_names, section.sh_name) orelse continue;
        if (std.mem.eql(u8, name, section_name)) return section.sh_addr;
    }
    return null;
}

fn readOptionalSectionName(section_names: []const u8, offset: u32) ?[]const u8 {
    if (offset >= section_names.len) return null;
    var end: usize = offset;
    while (end < section_names.len and section_names[end] != 0) : (end += 1) {}
    return section_names[offset..end];
}

fn makeSyntheticElf32(entry_point: u32, phnum: u16, loadable_segments: u16) [@sizeOf(std.elf.Elf32_Ehdr) + 3 * @sizeOf(std.elf.Elf32_Phdr) + 3 * 128]u8 {
    var bytes = [_]u8{0} ** (@sizeOf(std.elf.Elf32_Ehdr) + 3 * @sizeOf(std.elf.Elf32_Phdr) + 3 * 128);
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
    std.mem.writeInt(u16, bytes[40..42], @sizeOf(std.elf.Elf32_Ehdr), .little);
    std.mem.writeInt(u16, bytes[42..44], @sizeOf(std.elf.Elf32_Phdr), .little);
    std.mem.writeInt(u16, bytes[44..46], phnum, .little);

    var index: usize = 0;
    while (index < phnum) : (index += 1) {
        const program_offset = @sizeOf(std.elf.Elf32_Ehdr) + index * @sizeOf(std.elf.Elf32_Phdr);
        const p_type: u32 = if (index < loadable_segments) std.elf.PT_LOAD else 0;
        std.mem.writeInt(u32, bytes[program_offset..][0..4], p_type, .little);
        if (p_type == std.elf.PT_LOAD) {
            const file_offset = @sizeOf(std.elf.Elf32_Ehdr) + 3 * @sizeOf(std.elf.Elf32_Phdr) + index * 128;
            const virtual_address = entry_point + @as(u32, @intCast(index)) * 0x1000;
            const flags: u32 = if (index == 0)
                std.elf.PF_R | std.elf.PF_X
            else
                std.elf.PF_R | std.elf.PF_W;

            std.mem.writeInt(u32, bytes[program_offset + 4 ..][0..4], @intCast(file_offset), .little);
            std.mem.writeInt(u32, bytes[program_offset + 8 ..][0..4], virtual_address, .little);
            std.mem.writeInt(u32, bytes[program_offset + 16 ..][0..4], 64, .little);
            std.mem.writeInt(u32, bytes[program_offset + 20 ..][0..4], 128, .little);
            std.mem.writeInt(u32, bytes[program_offset + 24 ..][0..4], flags, .little);
            std.mem.writeInt(u32, bytes[program_offset + 28 ..][0..4], 0x1000, .little);

            @memset(bytes[file_offset..][0..64], @intCast(index + 1));
        }
    }

    return bytes;
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
    _ = try catalog.register(.{
        .bundle = bundle,
        .component_class = .app_component,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
        .role_tag = 0xA107,
        .heartbeat_increment = 7,
        .contract_flags = 0x2,
    });

    var runtime = task_runtime.Runtime.init();
    const launched = try catalog.launchDirect(&runtime, "app.notes", .{
        .owner = .{ .kind = .user, .serial = 1 },
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 4096,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
        },
        .ui_surface_id = 3,
        .local_only = true,
    });

    try std.testing.expect(launched.runsAsUserspaceProcess());
    try std.testing.expect(launched.hasDedicatedHost());
    try std.testing.expect(launched.hasLoadedExecutable());
    try std.testing.expectEqualStrings("app.notes", launched.launchBundleIdSlice());
    try std.testing.expectEqualStrings("notes", launched.execution_components[0].labelSlice());
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
    _ = try catalog.register(.{
        .bundle = bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
        },
        .role_tag = 0xA10C,
        .heartbeat_increment = 12,
        .contract_flags = 0x11,
    });

    var runtime = task_runtime.Runtime.init();
    var capabilities = @import("../kernel_api/capability.zig").CapabilityTable.init();
    var endpoints = @import("../kernel_api/endpoint.zig").Table.init();
    var shared = @import("../kernel_api/shared_memory.zig").Table.init();
    var registry = @import("../kernel_api/service_registry.zig").Registry.init();
    var kernel = @import("../kernel_api/native_kernel.zig").Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
    );
    var port = component_port.KernelPort.init(&kernel);

    const controller = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 2048,
        },
        .local_only = true,
    });
    const authority = try capabilities.mint(.{
        .holder = controller.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{
            .task_create = true,
            .capability_query = true,
        },
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
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
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
    const bytes = makeSyntheticElf32(0x401000, 3, 2);
    const info = try inspectEmbeddedElf(&bytes);

    try std.testing.expectEqual(@as(u64, 0x401000), info.entry_point);
    try std.testing.expectEqual(@as(u16, 2), info.loadable_segment_count);
    try std.testing.expectEqual(bytes.len, info.byte_len);
    try std.testing.expect(!std.mem.eql(u8, &info.file_sha256, &([_]u8{0} ** MAX_IMAGE_HASH_BYTES)));
    try std.testing.expectEqual(@as(usize, 2), info.executable_image.segment_count);
    try std.testing.expectEqual(@as(u64, 0x401000), info.executable_image.segments[0].virtual_address);
    try std.testing.expect(info.executable_image.segments[0].access.execute);
}

test "catalog stores embedded elf metadata for registered userspace artifacts" {
    var catalog = Catalog.init();
    const bytes = makeSyntheticElf32(0x402000, 2, 1);
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
        .elf_bytes = &bytes,
    });

    try std.testing.expect(image.embedsElf());
    try std.testing.expect(image.hasTypedContract());
    try std.testing.expectEqual(@as(u64, 0x402000), image.entry_point);
    try std.testing.expectEqual(@as(u16, 1), image.loadable_segment_count);
    try std.testing.expectEqual(bytes.len, image.byte_len);
    try std.testing.expect(image.executable_image.isPresent());
    try std.testing.expectEqual(@as(usize, 1), image.executable_image.segment_count);
    try std.testing.expectEqual(@as(u32, 0xA10F), image.role_tag);
    try std.testing.expectEqual(@as(u32, 15), image.heartbeat_increment);
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
