const std = @import("std");
const host_tools = @import("host_tools.zig");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");
const codegen_target = @import("../src/arch/codegen_target.zig");

const kernel_linker_script = "src/arch/x86_64/linker.ld";

pub const KernelArtifacts = struct {
    zigos_native: shared.KernelArtifact,
    zigos_native_verification: shared.KernelArtifact,
    recovery: shared.KernelArtifact,
    benchmark: shared.KernelArtifact,
};

pub const KernelSteps = struct {
    kernel: *std.Build.Step,
    zigos_native_verification: *std.Build.Step,
    benchmark: *std.Build.Step,
    recovery: *std.Build.Step,
};

pub const BootImage = struct {
    efi: std.Build.LazyPath,
    iso: std.Build.LazyPath,
};

// Firmware can authenticate one PE image containing the exact kernel and command
// line. Neither boot-volume files nor LoadedImage options can replace them.
// Every probe boots through this same loader, so it only admits upper-half
// images linked by src/arch/x86_64/linker.ld.
pub fn addEfiImage(b: *std.Build, kernel: std.Build.LazyPath, cmdline: std.Build.LazyPath) *std.Build.Step.Compile {
    const files = b.addWriteFiles();
    _ = files.addCopyFile(kernel, "kernel.elf");
    _ = files.addCopyFile(cmdline, "cmdline.txt");
    const payload = files.add("payload.zig", "pub const kernel = @embedFile(\"kernel.elf\");\npub const cmdline = @embedFile(\"cmdline.txt\");\n");
    // Firmware entry and its CPUID preflight must execute before the native
    // floor is established. Keep this image on the architectural baseline.
    // Shipped media and every QEMU proof boot the same ReleaseSmall loader.
    const target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .uefi, .abi = .none, .cpu_model = .baseline });
    const module = b.createModule(.{
        .root_source_file = b.path("src/efi_entry.zig"),
        .target = target,
        .optimize = .small,
        .strip = true,
        .red_zone = false,
    });
    module.addImport("boot_payload", b.createModule(.{ .root_source_file = payload, .target = target, .optimize = .small }));
    return b.addExecutable(.{ .name = "bootx64", .root_module = module });
}

/// Validates `efi_stub` and wraps it in El Torito boot media.
fn addBootMedia(b: *std.Build, name: []const u8, efi_stub: *std.Build.Step.Compile) BootImage {
    const validate_image = host_tools.addRun(b, "check-efi-image");
    validate_image.addFileArg(efi_stub.getEmittedBin());
    const iso = host_tools.addRun(b, "build-efi-iso");
    iso.addFileArg(efi_stub.getEmittedBin());
    const iso_path = iso.addOutputFileArg(b.fmt("{s}.iso", .{name}));
    _ = iso.addOutputDirectoryArg(b.fmt("{s}-staging", .{name}));
    shared.addEfiIsoEpochArg(b, iso);
    iso.step.dependOn(&validate_image.step);
    return .{ .efi = efi_stub.getEmittedBin(), .iso = iso_path };
}

pub fn addBootImage(b: *std.Build, name: []const u8, kernel: std.Build.LazyPath, cmdline: std.Build.LazyPath) BootImage {
    return addBootMedia(b, name, addEfiImage(b, kernel, cmdline));
}

/// The QEMU command line plus `flag`, so one linked kernel or probe can boot
/// several authenticated images that differ only in that selection.
pub fn addQemuCommandLine(b: *std.Build, flag: []const u8) std.Build.LazyPath {
    const command = host_tools.addRun(b, "build-cmdline");
    command.addFileArg(b.path(shared.qemu_cmdline_path));
    const output = command.addOutputFileArg("cmdline.txt");
    command.addArg(flag);
    return output;
}

const LinkOptions = struct {
    /// Whole-kernel LTO codegen with CET indirect-branch tracking.
    lto: bool = false,
    strip_debug: bool = false,
};

fn addLldLink(
    b: *std.Build,
    script: []const u8,
    name: []const u8,
    objects: []const std.Build.LazyPath,
    options: LinkOptions,
) std.Build.LazyPath {
    // Configure graphs survive cache relocation. Resolve the invoking compiler
    // during execution rather than serializing its temporary installation path.
    const link = b.addRunFile(std.Build.LazyPath.zig_exe);
    link.addArg("ld.lld");
    if (options.lto) link.addArgs(&.{
        // LLVM emits probe calls after LTO dead-code elimination. Keep the
        // bundled routine alive so large frames still touch each stack page.
        "--undefined=__zig_probe_stack",
        // CET requires ENDBR at every generated indirect target. The pinned
        // compiler exposes the LLVM pass through the LTO linker. Switches use
        // direct branches because this LLVM pass does not mark jump-table
        // targets; supervisor IBT remains enforced without NOTRACK exemptions.
        "-mllvm",
        "-x86-indirect-branch-tracking",
        "-mllvm",
        "-min-jump-table-entries=4294967295",
    });
    link.addArgs(&.{ "-m", "elf_x86_64", "--gc-sections" });
    if (options.strip_debug) link.addArg("--strip-debug");
    link.addArgs(&.{ "-z", "common-page-size=4096", "-z", "max-page-size=4096", "-T" });
    link.addFileArg(b.path(script));
    link.addArg("-o");
    const output = link.addOutputFileArg(name);
    for (objects) |object| link.addFileArg(object);
    return output;
}

pub fn addNativeCryptoCheck(
    b: *std.Build,
    optimize: std.lang.Optimize,
) *std.Build.Step {
    const target = b.resolveTargetQuery(codegen_target.query());
    const module = b.createModule(.{
        .root_source_file = b.path("src/probes/native_crypto_probe.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
        .red_zone = false,
    });
    module.addImport("x86", b.createModule(.{
        .root_source_file = b.path("src/arch/x86.zig"),
        .target = target,
        .optimize = optimize,
        .red_zone = false,
    }));
    module.addImport("xstate_roundtrip_model", b.createModule(.{
        .root_source_file = b.path("src/arch/xstate_roundtrip_model.zig"),
        .target = target,
        .optimize = optimize,
        .red_zone = false,
    }));
    module.addAssemblyFile(b.path("src/probes/native_crypto_entry.S"));
    module.addImport("volume_checksum", b.createModule(.{
        .root_source_file = b.path("src/native/storage/volume/checksum.zig"),
        .target = target,
        .optimize = optimize,
        .red_zone = false,
    }));
    module.addAssemblyFile(b.path("src/tests/host/xstate_roundtrip64.S"));
    configureKernelModuleGraph(module);
    const probe = b.addObject(.{
        .name = "native-crypto-probe",
        .root_module = module,
    });
    probe.bundle_compiler_rt = true;
    const linked_probe = addLldLink(b, kernel_linker_script, "native-crypto-probe.elf", &.{probe.getEmittedBin()}, .{});
    const image = addBootMedia(b, "native-crypto", addEfiImage(b, linked_probe, b.path(shared.qemu_cmdline_path)));

    // The dedicated checker requires every proof marker in execution order,
    // including default FP controls and complete x87/SSE/YMM owner round trips.
    const run = host_tools.addRun(b, "run-native-crypto-smoke");
    run.addFileArg(image.iso);
    run.addArg("build/native-crypto.log");
    const step = b.step("native-crypto-check", "Boot native hardware AES, SHA, GHASH, and complete AVX2 state round trips in QEMU");
    step.dependOn(&run.step);
    return step;
}

/// Links an isolated upper-half probe through the production linker script and
/// EFI address contract, with production build options and code model.
fn addProbeElf(
    b: *std.Build,
    optimize: std.lang.Optimize,
    name: []const u8,
    root_source: []const u8,
    assembly: []const []const u8,
) std.Build.LazyPath {
    const module = b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = b.resolveTargetQuery(codegen_target.query()),
        .optimize = optimize,
        .strip = true,
        .red_zone = false,
        .code_model = .kernel,
    });
    module.addOptions("build_options", shared.kernelOptions(b, .zigos_native, .production));
    configureKernelModuleGraph(module);
    for (assembly) |path| module.addAssemblyFile(b.path(path));
    const probe = b.addObject(.{ .name = name, .root_module = module });
    probe.bundle_compiler_rt = true;
    return addLldLink(b, kernel_linker_script, b.fmt("{s}.elf", .{name}), &.{probe.getEmittedBin()}, .{});
}

pub fn addHighHalfEntryCheck(b: *std.Build, optimize: std.lang.Optimize) *std.Build.Step {
    const image = addUpperHalfProbeImage(b, optimize, .entry);
    const run = host_tools.addRun(b, "run-high-half-smoke");
    run.addFileArg(image.boot.iso);
    run.addArg("build/high-half-entry.log");
    const step = b.step("high-half-entry-check", "Boot isolated 16-CPU entry/SIPI, copied syscall broker, descriptor, SMAP, standard-xstate IPI and global-TLB proof in QEMU");
    step.dependOn(&run.step);
    return step;
}

pub fn addMappingXstateProof(b: *std.Build, optimize: std.lang.Optimize) *std.Build.Step {
    const image = addUpperHalfProbeImage(b, optimize, .mapping_xstate);
    const artifact_step = b.step("mapping-xstate-proof-image", "Build the isolated fixed-topology Mapping-owned compacted-state probe without running it");
    artifact_step.dependOn(&b.addInstallFile(image.elf, "bin/mapping-xstate-probe.elf").step);
    artifact_step.dependOn(&b.addInstallFile(image.boot.efi, "bin/mapping-xstate-probe.efi").step);
    artifact_step.dependOn(&b.addInstallFile(image.boot.iso, "mapping-xstate.iso").step);

    const positive = host_tools.addRun(b, "run-mapping-xstate-smoke");
    positive.addFileArg(image.boot.iso);
    positive.addArg("build/mapping-xstate.log");
    positive.addArg("positive");
    const step = b.step("mapping-xstate-proof-check", "Require actual Mapping-owned XSAVES/XRSTORS, independent register readback and acknowledged lifetime; reject unsupported targets");
    step.dependOn(&positive.step);

    const unsupported = host_tools.addRun(b, "run-mapping-xstate-smoke");
    unsupported.addFileArg(image.boot.iso);
    unsupported.addArg("build/mapping-xstate-unsupported.log");
    unsupported.addArg("unsupported");
    const unsupported_step = b.step("mapping-xstate-unsupported-check", "Require explicit unsupported compacted-state admission before any privileged state operation");
    unsupported_step.dependOn(&unsupported.step);
    return step;
}

const UpperHalfProbeKind = enum { entry, mapping_xstate };

// Exercise the production entry and linker through the production EFI address
// contract. Only the separately admitted Mapping probe executes compacted state
// operations; the ordinary entry proof uses standard state.
const upper_half_probe_assembly = [_][]const u8{
    "src/boot/boot_x86_64.S",
    "src/arch/x86/invpcid.S",
    "src/kernel/interrupts/gdt_flush64.S",
    "src/kernel/smp/ap_trampoline.S",
    "src/probes/high_half_ipi_probe.S",
    // Execute the unchanged kernel-origin ISR on the selected guarded stack.
    // The entry object supplies its real initial kernel xstate and continuation
    // symbols; this CPL0 fixture never takes the native userspace branches.
    "src/kernel/interrupts/interrupt64.S",
    // The cold stack transaction authenticates the real FRED entry address.
    // This isolated guest keeps FRED off and rejects any native syscall path.
    "src/kernel/interrupts/fred64.S",
    "src/native/task/userspace_entry64.S",
};

fn addUpperHalfProbeImage(b: *std.Build, optimize: std.lang.Optimize, kind: UpperHalfProbeKind) struct { elf: std.Build.LazyPath, boot: BootImage } {
    const name = switch (kind) {
        .entry => "high-half-entry",
        .mapping_xstate => "mapping-xstate",
    };
    const elf = switch (kind) {
        .entry => addProbeElf(b, optimize, "high-half-entry-probe", "src/high_half_entry.zig", &upper_half_probe_assembly),
        .mapping_xstate => addProbeElf(b, optimize, "mapping-xstate-probe", "src/mapping_xstate_entry.zig", &(upper_half_probe_assembly ++ [_][]const u8{"src/probes/mapping_xstate_probe.S"})),
    };
    return .{ .elf = elf, .boot = addBootImage(b, name, elf, b.path(shared.qemu_cmdline_path)) };
}

const ap_cache_probe_assembly = [_][]const u8{
    "src/boot/boot_x86_64.S",
    "src/arch/x86/invpcid.S",
    "src/kernel/interrupts/gdt_flush64.S",
};

pub fn addApCacheRejectionCheck(b: *std.Build, optimize: std.lang.Optimize) *std.Build.Step {
    const step = b.step("ap-cache-rejection-check", "Verify production pre-paging AP cache rejection and a successful high-entry control in QEMU");
    const elf = addProbeElf(b, optimize, "ap-cache-rejection", "src/ap_cache_rejection_entry.zig", &(ap_cache_probe_assembly ++ [_][]const u8{"src/kernel/smp/ap_trampoline.S"}));
    // One linked probe; each boot image selects its fault on the command line.
    for ([_][]const u8{ "none", "version", "default_reserved", "mask_reserved" }) |fault| {
        const name = b.fmt("ap-cache-rejection-{s}", .{fault});
        const image = addBootImage(b, name, elf, addQemuCommandLine(b, b.fmt("ap_cache_fault_{s}", .{fault})));
        const run = host_tools.addRun(b, "run-ap-cache-rejection-smoke");
        run.addFileArg(image.iso);
        run.addArg(b.fmt("build/{s}.log", .{name}));
        run.addArg(fault);
        step.dependOn(&run.step);
    }
    return step;
}

pub fn addSmpCacheEnabledMatchCheck(b: *std.Build, optimize: std.lang.Optimize) *std.Build.Step {
    const name = "smp-cache-enabled-match";
    const elf = addProbeElf(b, optimize, name, "src/smp_cache_enabled_entry.zig", &(ap_cache_probe_assembly ++ [_][]const u8{"src/probes/smp_cache_enabled_probe.S"}));
    const image = addBootImage(b, name, elf, b.path(shared.qemu_cmdline_path));
    const run = host_tools.addRun(b, "run-smp-cache-enabled-match-smoke");
    run.addFileArg(image.iso);
    run.addArg("build/smp-cache-enabled-match.log");
    const step = b.step("smp-cache-enabled-match-check", "Execute the actual AP MTRR macro twice without reset and verify the enabled-match branch in QEMU");
    step.dependOn(&run.step);
    return step;
}

pub fn addKernelProfiles(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    userspace_images: userspace_build.ArtifactSet,
) KernelArtifacts {
    const assembly = addKernelAssemblyObject(b, target, optimize);
    const debug_step = b.step("kernel-debug", "Link every kernel with complete DWARF into zig-out/kernel-debug for address-to-line diagnostics");
    const builder: KernelBuilder = .{ .b = b, .target = target, .optimize = optimize, .assembly = assembly, .debug_step = debug_step };
    return .{
        .zigos_native = builder.add(
            "kernel-zigos-native.elf",
            .zigos_native,
            .production,
            userspace_images.production_archive_module,
            userspace_images.production_manifest_module,
        ),
        .zigos_native_verification = builder.add(
            "kernel-zigos-native-verification.elf",
            .zigos_native,
            .verification,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .recovery = builder.add(
            "kernel-recovery.elf",
            .recovery,
            .verification,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .benchmark = builder.add(
            "kernel-benchmark.elf",
            .benchmark,
            .verification,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
    };
}

pub fn addKernelProfileSteps(
    b: *std.Build,
    kernels: KernelArtifacts,
    userspace_images: userspace_build.ArtifactSet,
) KernelSteps {
    return .{
        .kernel = addKernelInstallStep(b, "kernel", "Build the native-only Zigos kernel", kernels.zigos_native, userspace_images.production_step),
        .zigos_native_verification = addKernelInstallStep(b, "kernel-zigos-native-verification", "Build the Zigos native verification kernel", kernels.zigos_native_verification, userspace_images.verification_step),
        .benchmark = addKernelInstallStep(b, "kernel-benchmark", "Build the spec-aligned native benchmark kernel", kernels.benchmark, userspace_images.verification_step),
        .recovery = addKernelInstallStep(b, "kernel-recovery", "Build the freestanding recovery-mode kernel", kernels.recovery, userspace_images.verification_step),
    };
}

fn addKernelInstallStep(
    b: *std.Build,
    name: []const u8,
    description: []const u8,
    kernel: shared.KernelArtifact,
    userspace_step: *std.Build.Step,
) *std.Build.Step {
    const step = b.step(name, description);
    step.dependOn(kernel.install_step);
    step.dependOn(userspace_step);
    return step;
}

const KernelBuilder = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    assembly: *std.Build.Step.Compile,
    debug_step: *std.Build.Step,

    fn add(
        self: KernelBuilder,
        name: []const u8,
        boot_profile: shared.BootProfile,
        kernel_role: shared.KernelRole,
        userspace_archive: *std.Build.Module,
        production_manifest: *std.Build.Module,
    ) shared.KernelArtifact {
        const b = self.b;
        std.debug.assert(kernel_role == .verification or boot_profile == .zigos_native);
        const kernel_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = self.target,
            .optimize = self.optimize,
            .strip = false,
            .red_zone = false,
            .code_model = .kernel,
        });
        kernel_module.addImport("binary_cursor", b.createModule(.{
            .root_source_file = b.path("src/native/core/binary_cursor.zig"),
            .target = self.target,
            .optimize = self.optimize,
        }));
        kernel_module.addImport("userspace_archive", kernelDataModule(b, self.target, self.optimize, userspace_archive));
        kernel_module.addImport("production_artifact_manifest", kernelDataModule(b, self.target, self.optimize, production_manifest));
        kernel_module.addOptions("build_options", shared.kernelOptions(b, boot_profile, kernel_role));
        configureKernelModuleGraph(kernel_module);

        const kernel_object = b.addObject(.{
            .name = name,
            .root_module = kernel_module,
        });
        kernel_object.use_llvm = true;
        kernel_object.lto = .full;
        kernel_object.bundle_compiler_rt = true;
        kernel_object.link_function_sections = true;
        kernel_object.link_data_sections = true;
        const objects = [_]std.Build.LazyPath{ kernel_object.getEmittedBin(), self.assembly.getEmittedBin() };

        // Run whole-kernel LTO once. Publish the same stripped ELF that firmware
        // measures; complete DWARF is an opt-in second link with identical load
        // segments and static symbol addresses.
        const kernel = addLldLink(b, kernel_linker_script, name, &objects, .{ .lto = true, .strip_debug = true });
        const debug_kernel = addLldLink(b, kernel_linker_script, name, &objects, .{ .lto = true });
        self.debug_step.dependOn(&b.addInstallFile(debug_kernel, b.fmt("kernel-debug/{s}", .{name})).step);

        const qemu_image = addBootImage(b, b.fmt("{s}.qemu", .{name}), kernel, b.path(shared.qemu_cmdline_path));
        const install = b.addInstallBinFile(kernel, name);
        return .{
            .output_file = kernel,
            .install_step = &install.step,
            .output_path = b.graph.path(.install_bin, name),
            .kernel_role = kernel_role,
            .qemu_boot_iso_path = qemu_image.iso,
        };
    }
};

fn addKernelAssemblyObject(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Step.Compile {
    const module = b.createModule(.{ .target = target, .optimize = optimize, .code_model = .kernel, .red_zone = false });
    for ([_][]const u8{
        "src/boot/boot_x86_64.S",
        "src/arch/x86/invpcid.S",
        "src/kernel/interrupts/interrupt64.S",
        "src/kernel/interrupts/syscall64.S",
        "src/kernel/interrupts/fred64.S",
        "src/kernel/interrupts/gdt_flush64.S",
        "src/kernel/smp/ap_trampoline.S",
        "src/native/task/userspace_entry64.S",
        "src/native/task/cooperative_worker64.S",
    }) |path| module.addAssemblyFile(b.path(path));
    return b.addObject(.{ .name = "kernel-assembly", .root_module = module });
}

fn kernelDataModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    source: *std.Build.Module,
) *std.Build.Module {
    // Generated archives/manifests also serve host tests. Give the kernel its
    // own module so their pointers use the signed upper-half code model.
    std.debug.assert(source.root_source_file != null and source.import_table.count() == 0);
    return b.createModule(.{
        .root_source_file = source.root_source_file,
        .target = target,
        .optimize = optimize,
        .code_model = .kernel,
        .red_zone = false,
    });
}

fn configureKernelModuleGraph(root: *std.Build.Module) void {
    // Code model is a per-module setting, including options and future imports.
    // All graph members are private to this kernel compilation.
    for (root.getGraph().modules) |module| {
        module.code_model = .kernel;
        module.red_zone = false;
    }
}
