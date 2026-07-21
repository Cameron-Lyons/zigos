const std = @import("std");

const max_elf_bytes: usize = 256 * 1024 * 1024;
const maximum_production_writable_load_size: u64 = 16 * 1024 * 1024;
const minimum_verification_writable_load_delta: u64 = 7 * 1024 * 1024;

const elf_header_size: usize = 52;
const program_header_size: usize = 32;
const section_header_size: usize = 40;
const symbol_size: usize = 16;

const ei_class: usize = 4;
const ei_data: usize = 5;
const ei_version: usize = 6;
const elf_class_32: u8 = 1;
const elf_data_little_endian: u8 = 1;
const elf_current_version: u8 = 1;

const sht_null: u32 = 0;
const sht_progbits: u32 = 1;
const sht_symtab: u32 = 2;
const sht_strtab: u32 = 3;
const sht_nobits: u32 = 8;
const sht_dynsym: u32 = 11;

const shf_write: u32 = 1 << 0;
const shf_alloc: u32 = 1 << 1;

const pt_load: u32 = 1;
const pf_execute: u32 = 1 << 0;
const pf_write: u32 = 1 << 1;

const shn_undef: u16 = 0;
const shn_loreserve: u16 = 0xff00;
const shn_xindex: u16 = 0xffff;

const runtime_proof_symbol_prefix = "native.session.proofs.runtime_negative_proofs";
const booted_evidence_symbol_prefix = "native.session.booted_evidence";
const demo_symbol_prefix = "native.demo.";
const benchmark_symbol_prefix = "kernel.boot.benchmark.";
const recovery_symbol_prefix = "kernel.boot.recovery_suite.";
const verification_orchestration_symbol_prefixes = [_][]const u8{
    "native.session.session_service_bootstrap.connectClient",
    "native.session.session_service_bootstrap.proveDriverCrashRestart",
    "native.session.trust_boot.TrustBoot.proveProductionAbImageRollback",
    "native.session.trust_boot.TrustBoot.proveProductionPostActivationHealthChecks",
};
const verification_only_signatures = [_][]const u8{
    "ZIGOS:RUNTIME_PROOF:PROCESS_ISOLATION:PASS",
    "ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED",
    "ZIGOS:PLATFORM:HEALTH_CHECKS:BOOT_ROLLBACK",
    "ZIGOS:NOTES_DAILY:COMPLETE",
    "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK",
    "app.notes.daily",
    "userspace-notes-daily.elf",
    "zigos.system.transport-probe",
    "userspace-transport-probe.elf",
    "zigos.system.termination-probe",
    "userspace-termination-probe.elf",
    "zigos.system.service-client",
    "userspace-service-client.elf",
    "zigos.proof.mmu-isolation",
    "userspace-mmu-isolation-proof.elf",
};

const production_userspace_count: usize = 24;
const verification_only_userspace_count: usize = 5;
const production_userspace_marker = "--production-userspace";
const verification_userspace_marker = "--verification-userspace";
const expected_cli_arg_count = 1 + 2 + 1 + production_userspace_count + 1 + verification_only_userspace_count;

const VerificationUserspaceIdentity = struct {
    bundle_id: []const u8,
    artifact_name: []const u8,
};

const verification_userspace_identities = [_]VerificationUserspaceIdentity{
    .{ .bundle_id = "app.notes.daily", .artifact_name = "userspace-notes-daily.elf" },
    .{ .bundle_id = "zigos.system.transport-probe", .artifact_name = "userspace-transport-probe.elf" },
    .{ .bundle_id = "zigos.system.termination-probe", .artifact_name = "userspace-termination-probe.elf" },
    .{ .bundle_id = "zigos.system.service-client", .artifact_name = "userspace-service-client.elf" },
    .{ .bundle_id = "zigos.proof.mmu-isolation", .artifact_name = "userspace-mmu-isolation-proof.elf" },
};
const mmu_proof_identity_index = verification_userspace_identities.len - 1;

// These encoded proof constants are stable across supported optimization
// modes. They are searched only inside executable PT_LOAD segments. The
// foreign address is additionally required to be followed closely by the
// proof fault code, preventing unrelated userspace-layout constants from
// satisfying the second machine-code sentinel.
const mmu_probe_role_tag_machine_code = [_]u8{ 0x16, 0xa1, 0x00, 0x00 };
const mmu_probe_foreign_address_machine_code = [_]u8{ 0x00, 0x00, 0x00, 0x70 };
const mmu_probe_fault_code_imm32_machine_code = [_]u8{ 0x72, 0x00, 0x00, 0x00 };
const mmu_probe_fault_code_push_imm8_machine_code = [_]u8{ 0x6a, 0x72 };
const mmu_probe_fault_code_max_distance: usize = 24;
const mmu_probe_machine_code_sentinel_count: usize = 2;

comptime {
    if (verification_userspace_identities.len != verification_only_userspace_count) {
        @compileError("verification userspace identity count must match the role-check command contract");
    }
}

const ParseError = error{
    UnexpectedEndOfFile,
    InvalidElfMagic,
    UnsupportedElfClass,
    UnsupportedElfEndian,
    UnsupportedElfVersion,
    InvalidElfHeaderSize,
    MissingProgramHeaderTable,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderTable,
    InvalidLoadSegment,
    MissingWritableLoadSegment,
    MissingSectionHeaderTable,
    InvalidSectionHeaderSize,
    InvalidSectionHeaderTable,
    InvalidNullSection,
    InvalidSectionNameTable,
    InvalidSectionName,
    InvalidSectionAlignment,
    InvalidSectionEntrySize,
    SectionOutOfBounds,
    MissingDataSection,
    DuplicateDataSection,
    InvalidDataSection,
    MissingSymbolTable,
    InvalidSymbolTable,
    InvalidSymbolStringTable,
    InvalidSymbolName,
    InvalidSymbolSectionIndex,
    UnsupportedExtendedSymbolIndex,
    IntegerOverflow,
};

const RoleError = error{
    ProductionWritableLoadTooLarge,
    ProductionContainsRuntimeProofSymbols,
    ProductionContainsBootedEvidenceSymbols,
    ProductionContainsDemoSymbols,
    ProductionContainsBenchmarkSymbols,
    ProductionContainsRecoverySymbols,
    ProductionContainsVerificationOrchestrationSymbols,
    ProductionContainsVerificationSignatures,
    VerificationMissingRuntimeProofSymbols,
    VerificationMissingBootedEvidenceSymbols,
    VerificationMissingExpectedSignatures,
    VerificationWritableLoadNotLarger,
    VerificationWritableLoadDeltaTooSmall,
};

const CliError = error{
    InvalidArgumentCount,
    MissingProductionUserspaceMarker,
    MissingVerificationUserspaceMarker,
};

const UserspaceRoleError = error{
    DuplicateProductionUserspaceArtifact,
    ProductionUsesVerificationArtifactName,
    ProductionContainsVerificationSignature,
    ProductionContainsMmuProbeMachineCode,
    VerificationArtifactNameMismatch,
    VerificationIdentityMismatch,
    VerificationArtifactContainsUnexpectedMmuProbeMachineCode,
    MmuProofMissingMachineCodeSentinels,
};

const Header = struct {
    program_offset: u32,
    section_offset: u32,
    header_size: u16,
    program_entry_size: u16,
    program_count: u16,
    section_entry_size: u16,
    section_count: u16,
    section_name_index: u16,
};

const ProgramHeader = struct {
    segment_type: u32,
    offset: u32,
    virtual_address: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    alignment: u32,
};

const ProgramTable = struct {
    offset: usize,
    count: usize,
};

const Section = struct {
    name_offset: u32,
    section_type: u32,
    flags: u32,
    address: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: u32,
    alignment: u32,
    entry_size: u32,
};

const Symbol = struct {
    name_offset: u32,
    section_index: u16,
};

const SectionTable = struct {
    offset: usize,
    count: usize,
    names_index: usize,
};

const Analysis = struct {
    data_size: u64,
    writable_load_size: u64,
    symbol_count: usize,
    runtime_proof_symbols: usize,
    booted_evidence_symbols: usize,
    demo_symbols: usize,
    benchmark_symbols: usize,
    recovery_symbols: usize,
    verification_orchestration_symbols: usize,
    verification_only_signatures: usize,
};

const UserspaceAnalysis = struct {
    verification_only_signatures: usize,
    verification_identity_mask: u8,
    mmu_probe_machine_code_sentinels: usize,
};

const CliInputs = struct {
    production_kernel_path: []const u8,
    verification_kernel_path: []const u8,
    production_userspace_paths: []const []const u8,
    verification_userspace_paths: []const []const u8,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    const inputs = parseCliInputs(args) catch |err| {
        std.debug.print(
            "Kernel role check failed: invalid artifact arguments: {s}.\n" ++
                "usage: {s} <production-kernel> <verification-kernel> {s} <{d} production userspace ELFs> {s} <{d} verification-only userspace ELFs>\n",
            .{
                @errorName(err),
                args[0],
                production_userspace_marker,
                production_userspace_count,
                verification_userspace_marker,
                verification_only_userspace_count,
            },
        );
        std.process.exit(2);
    };

    const production_path = inputs.production_kernel_path;
    const verification_path = inputs.verification_kernel_path;
    const production_bytes = readElf(allocator, io, production_path) catch |err| {
        std.debug.print(
            "Kernel role check failed: unable to read production ELF '{s}': {s}\n",
            .{ production_path, @errorName(err) },
        );
        std.process.exit(1);
    };
    const verification_bytes = readElf(allocator, io, verification_path) catch |err| {
        std.debug.print(
            "Kernel role check failed: unable to read verification ELF '{s}': {s}\n",
            .{ verification_path, @errorName(err) },
        );
        std.process.exit(1);
    };

    const production = analyzeElf(production_bytes) catch |err| {
        printParseFailure("production", production_path, err);
    };
    const verification = analyzeElf(verification_bytes) catch |err| {
        printParseFailure("verification", verification_path, err);
    };

    validateRoles(production, verification) catch |err| {
        printRoleFailure(err, production, verification);
    };

    validateDistinctProductionUserspaceArtifacts(inputs.production_userspace_paths) catch |err| {
        printUserspaceRoleFailure("production", "<artifact set>", null, err, .{
            .verification_only_signatures = 0,
            .verification_identity_mask = 0,
            .mmu_probe_machine_code_sentinels = 0,
        });
    };
    for (inputs.production_userspace_paths) |path| {
        const bytes = readElf(allocator, io, path) catch |err| {
            printUserspaceReadFailure("production", path, err);
        };
        const analysis = analyzeUserspaceElf(bytes) catch |err| {
            printParseFailure("production userspace", path, err);
        };
        validateProductionUserspaceArtifact(path, analysis) catch |err| {
            printUserspaceRoleFailure("production", path, null, err, analysis);
        };
    }

    for (inputs.verification_userspace_paths, 0..) |path, identity_index| {
        const bytes = readElf(allocator, io, path) catch |err| {
            printUserspaceReadFailure("verification", path, err);
        };
        const analysis = analyzeUserspaceElf(bytes) catch |err| {
            printParseFailure("verification userspace", path, err);
        };
        const expected = verification_userspace_identities[identity_index];
        validateVerificationUserspaceArtifact(path, identity_index, analysis) catch |err| {
            printUserspaceRoleFailure("verification", path, expected.artifact_name, err, analysis);
        };
    }

    const writable_load_delta = verification.writable_load_size - production.writable_load_size;
    var stdout_buffer: [768]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    try stdout_writer.interface.print(
        "Kernel role check passed: production writable-load={d} bytes (.data={d}, maximum={d}, {d} symbols, no verification workloads); verification writable-load={d} bytes (.data={d}, {d} symbols, runtime-proof={d}, booted-evidence={d}, signatures={d}); delta={d} bytes (minimum={d}); userspace production={d} clean, verification-only={d}, MMU-proof machine-code sentinels={d}.\n",
        .{
            production.writable_load_size,
            production.data_size,
            maximum_production_writable_load_size,
            production.symbol_count,
            verification.writable_load_size,
            verification.data_size,
            verification.symbol_count,
            verification.runtime_proof_symbols,
            verification.booted_evidence_symbols,
            verification.verification_only_signatures,
            writable_load_delta,
            minimum_verification_writable_load_delta,
            inputs.production_userspace_paths.len,
            inputs.verification_userspace_paths.len,
            mmu_probe_machine_code_sentinel_count,
        },
    );
    try stdout_writer.interface.flush();
}

fn parseCliInputs(args: []const []const u8) CliError!CliInputs {
    if (args.len != expected_cli_arg_count) return error.InvalidArgumentCount;

    const production_marker_index: usize = 3;
    if (!std.mem.eql(u8, args[production_marker_index], production_userspace_marker)) {
        return error.MissingProductionUserspaceMarker;
    }
    const production_start = production_marker_index + 1;
    const production_end = production_start + production_userspace_count;
    if (!std.mem.eql(u8, args[production_end], verification_userspace_marker)) {
        return error.MissingVerificationUserspaceMarker;
    }
    const verification_start = production_end + 1;
    const verification_end = verification_start + verification_only_userspace_count;

    return .{
        .production_kernel_path = args[1],
        .verification_kernel_path = args[2],
        .production_userspace_paths = args[production_start..production_end],
        .verification_userspace_paths = args[verification_start..verification_end],
    };
}

fn readElf(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_elf_bytes));
}

fn analyzeElf(bytes: []const u8) ParseError!Analysis {
    const header = try parseHeader(bytes);
    const programs = try resolveProgramTable(bytes, header);
    const program_analysis = try analyzeProgramHeaders(bytes, programs);
    const sections = try resolveSectionTable(bytes, header);
    const null_section = try parseSection(bytes, sections, 0);
    if (null_section.section_type != sht_null) return error.InvalidNullSection;

    const name_section = try parseSection(bytes, sections, sections.names_index);
    if (name_section.section_type != sht_strtab) return error.InvalidSectionNameTable;
    const section_names = try sectionBytes(bytes, name_section);
    if (section_names.len == 0 or section_names[0] != 0) return error.InvalidSectionNameTable;

    var data_size: ?u64 = null;
    var symbol_table_count: usize = 0;
    var symbol_count: usize = 0;
    var runtime_proof_symbols: usize = 0;
    var booted_evidence_symbols: usize = 0;
    var demo_symbols: usize = 0;
    var benchmark_symbols: usize = 0;
    var recovery_symbols: usize = 0;
    var verification_orchestration_symbols: usize = 0;

    var section_index: usize = 0;
    while (section_index < sections.count) : (section_index += 1) {
        const section = try parseSection(bytes, sections, section_index);
        try validateSection(bytes, section);
        const section_name = try readString(section_names, section.name_offset);

        if (section.flags & shf_alloc != 0 and
            !sectionCoveredByLoad(bytes, programs, section))
        {
            return error.InvalidLoadSegment;
        }

        if (std.mem.eql(u8, section_name, ".data")) {
            if (data_size != null) return error.DuplicateDataSection;
            if (section.section_type != sht_progbits or
                section.flags & (shf_write | shf_alloc) != (shf_write | shf_alloc))
            {
                return error.InvalidDataSection;
            }
            data_size = section.size;
        }

        if (section.section_type == sht_symtab or section.section_type == sht_dynsym) {
            if (section.section_type == sht_symtab) symbol_table_count += 1;
            const counts = try inspectSymbolTable(bytes, sections, programs, section);
            symbol_count = std.math.add(usize, symbol_count, counts.symbol_count) catch return error.IntegerOverflow;
            runtime_proof_symbols = std.math.add(
                usize,
                runtime_proof_symbols,
                counts.runtime_proof_symbols,
            ) catch return error.IntegerOverflow;
            booted_evidence_symbols = std.math.add(
                usize,
                booted_evidence_symbols,
                counts.booted_evidence_symbols,
            ) catch return error.IntegerOverflow;
            demo_symbols = std.math.add(usize, demo_symbols, counts.demo_symbols) catch return error.IntegerOverflow;
            benchmark_symbols = std.math.add(usize, benchmark_symbols, counts.benchmark_symbols) catch return error.IntegerOverflow;
            recovery_symbols = std.math.add(usize, recovery_symbols, counts.recovery_symbols) catch return error.IntegerOverflow;
            verification_orchestration_symbols = std.math.add(
                usize,
                verification_orchestration_symbols,
                counts.verification_orchestration_symbols,
            ) catch return error.IntegerOverflow;
        }
    }

    if (data_size == null) return error.MissingDataSection;
    if (symbol_table_count == 0) return error.MissingSymbolTable;
    return .{
        .data_size = data_size.?,
        .writable_load_size = program_analysis.writable_load_size,
        .symbol_count = symbol_count,
        .runtime_proof_symbols = runtime_proof_symbols,
        .booted_evidence_symbols = booted_evidence_symbols,
        .demo_symbols = demo_symbols,
        .benchmark_symbols = benchmark_symbols,
        .recovery_symbols = recovery_symbols,
        .verification_orchestration_symbols = verification_orchestration_symbols,
        .verification_only_signatures = countLoadedSignatures(bytes, programs, &verification_only_signatures),
    };
}

fn analyzeUserspaceElf(bytes: []const u8) ParseError!UserspaceAnalysis {
    const header = try parseHeader(bytes);
    const programs = try resolveProgramTable(bytes, header);
    _ = try analyzeProgramHeaders(bytes, programs);

    var verification_identity_mask: u8 = 0;
    for (verification_userspace_identities, 0..) |identity, identity_index| {
        if (programsContainSignature(bytes, programs, 0, identity.bundle_id)) {
            verification_identity_mask |= @as(u8, 1) << @intCast(identity_index);
        }
    }

    return .{
        .verification_only_signatures = countProgramSignatures(
            bytes,
            programs,
            0,
            &verification_only_signatures,
        ),
        .verification_identity_mask = verification_identity_mask,
        .mmu_probe_machine_code_sentinels = countMmuProbeMachineCodeSentinels(bytes, programs),
    };
}

const SymbolCounts = struct {
    symbol_count: usize,
    runtime_proof_symbols: usize,
    booted_evidence_symbols: usize,
    demo_symbols: usize,
    benchmark_symbols: usize,
    recovery_symbols: usize,
    verification_orchestration_symbols: usize,
};

fn inspectSymbolTable(
    bytes: []const u8,
    sections: SectionTable,
    programs: ProgramTable,
    symbol_table: Section,
) ParseError!SymbolCounts {
    if (symbol_table.entry_size != symbol_size or symbol_table.size % symbol_table.entry_size != 0) {
        return error.InvalidSymbolTable;
    }
    if (symbol_table.link >= sections.count) return error.InvalidSymbolStringTable;
    const strings_section = try parseSection(bytes, sections, symbol_table.link);
    if (strings_section.section_type != sht_strtab) return error.InvalidSymbolStringTable;
    const strings = try sectionBytes(bytes, strings_section);
    if (strings.len == 0 or strings[0] != 0) return error.InvalidSymbolStringTable;
    const symbol_bytes = try sectionBytes(bytes, symbol_table);
    const count = symbol_bytes.len / symbol_size;
    if (symbol_table.info > count) return error.InvalidSymbolTable;

    var runtime_proof_symbols: usize = 0;
    var booted_evidence_symbols: usize = 0;
    var demo_symbols: usize = 0;
    var benchmark_symbols: usize = 0;
    var recovery_symbols: usize = 0;
    var verification_orchestration_symbols: usize = 0;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const symbol = try parseSymbol(symbol_bytes, index * symbol_size);
        if (symbol.section_index == shn_xindex) return error.UnsupportedExtendedSymbolIndex;
        if (symbol.section_index != shn_undef and
            symbol.section_index < shn_loreserve and
            symbol.section_index >= sections.count)
        {
            return error.InvalidSymbolSectionIndex;
        }
        const name = readString(strings, symbol.name_offset) catch return error.InvalidSymbolName;
        if (symbol.section_index == shn_undef or symbol.section_index >= shn_loreserve) continue;
        const defining_section = try parseSection(bytes, sections, symbol.section_index);
        if (defining_section.flags & shf_alloc == 0 or
            !sectionCoveredByLoad(bytes, programs, defining_section))
        {
            continue;
        }
        if (std.mem.startsWith(u8, name, runtime_proof_symbol_prefix)) {
            runtime_proof_symbols += 1;
        }
        if (std.mem.startsWith(u8, name, booted_evidence_symbol_prefix)) {
            booted_evidence_symbols += 1;
        }
        if (std.mem.startsWith(u8, name, demo_symbol_prefix)) demo_symbols += 1;
        if (std.mem.startsWith(u8, name, benchmark_symbol_prefix)) benchmark_symbols += 1;
        if (std.mem.startsWith(u8, name, recovery_symbol_prefix)) recovery_symbols += 1;
        for (verification_orchestration_symbol_prefixes) |prefix| {
            if (std.mem.startsWith(u8, name, prefix)) {
                verification_orchestration_symbols += 1;
                break;
            }
        }
    }

    return .{
        .symbol_count = count,
        .runtime_proof_symbols = runtime_proof_symbols,
        .booted_evidence_symbols = booted_evidence_symbols,
        .demo_symbols = demo_symbols,
        .benchmark_symbols = benchmark_symbols,
        .recovery_symbols = recovery_symbols,
        .verification_orchestration_symbols = verification_orchestration_symbols,
    };
}

fn countLoadedSignatures(
    bytes: []const u8,
    programs: ProgramTable,
    signatures: []const []const u8,
) usize {
    return countProgramSignatures(bytes, programs, 0, signatures);
}

fn countProgramSignatures(
    bytes: []const u8,
    programs: ProgramTable,
    required_flags: u32,
    signatures: []const []const u8,
) usize {
    var count: usize = 0;
    for (signatures) |signature| {
        if (programsContainSignature(bytes, programs, required_flags, signature)) count += 1;
    }
    return count;
}

fn programsContainSignature(
    bytes: []const u8,
    programs: ProgramTable,
    required_flags: u32,
    signature: []const u8,
) bool {
    var program_index: usize = 0;
    while (program_index < programs.count) : (program_index += 1) {
        const program = parseProgramHeader(bytes, programs, program_index) catch continue;
        if (program.segment_type != pt_load or program.file_size == 0) continue;
        if (program.flags & required_flags != required_flags) continue;
        const loaded_bytes = checkedSlice(bytes, program.offset, program.file_size) catch continue;
        if (std.mem.indexOf(u8, loaded_bytes, signature) != null) return true;
    }
    return false;
}

fn countMmuProbeMachineCodeSentinels(bytes: []const u8, programs: ProgramTable) usize {
    var count: usize = 0;
    if (programsContainSignature(bytes, programs, pf_execute, &mmu_probe_role_tag_machine_code)) {
        count += 1;
    }
    if (programsContainOrderedSignatures(
        bytes,
        programs,
        pf_execute,
        &mmu_probe_foreign_address_machine_code,
        &mmu_probe_fault_code_imm32_machine_code,
        mmu_probe_fault_code_max_distance,
    ) or programsContainOrderedSignatures(
        bytes,
        programs,
        pf_execute,
        &mmu_probe_foreign_address_machine_code,
        &mmu_probe_fault_code_push_imm8_machine_code,
        mmu_probe_fault_code_max_distance,
    )) {
        count += 1;
    }
    return count;
}

fn programsContainOrderedSignatures(
    bytes: []const u8,
    programs: ProgramTable,
    required_flags: u32,
    first: []const u8,
    second: []const u8,
    max_distance: usize,
) bool {
    var program_index: usize = 0;
    while (program_index < programs.count) : (program_index += 1) {
        const program = parseProgramHeader(bytes, programs, program_index) catch continue;
        if (program.segment_type != pt_load or program.file_size == 0) continue;
        if (program.flags & required_flags != required_flags) continue;
        const loaded_bytes = checkedSlice(bytes, program.offset, program.file_size) catch continue;

        var search_offset: usize = 0;
        while (std.mem.indexOfPos(u8, loaded_bytes, search_offset, first)) |first_offset| {
            const second_start = first_offset + first.len;
            const second_end = @min(loaded_bytes.len, second_start + max_distance + second.len);
            if (std.mem.indexOf(u8, loaded_bytes[second_start..second_end], second) != null) return true;
            search_offset = first_offset + 1;
        }
    }
    return false;
}

fn parseHeader(bytes: []const u8) ParseError!Header {
    if (bytes.len < elf_header_size) return error.UnexpectedEndOfFile;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (bytes[ei_class] != elf_class_32) return error.UnsupportedElfClass;
    if (bytes[ei_data] != elf_data_little_endian) return error.UnsupportedElfEndian;
    if (bytes[ei_version] != elf_current_version or try readU32(bytes, 20) != elf_current_version) {
        return error.UnsupportedElfVersion;
    }

    const header = Header{
        .program_offset = try readU32(bytes, 28),
        .section_offset = try readU32(bytes, 32),
        .header_size = try readU16(bytes, 40),
        .program_entry_size = try readU16(bytes, 42),
        .program_count = try readU16(bytes, 44),
        .section_entry_size = try readU16(bytes, 46),
        .section_count = try readU16(bytes, 48),
        .section_name_index = try readU16(bytes, 50),
    };
    if (header.header_size != elf_header_size) return error.InvalidElfHeaderSize;
    if (header.program_offset == 0 or header.program_count == 0) {
        return error.MissingProgramHeaderTable;
    }
    if (header.program_entry_size != program_header_size) return error.InvalidProgramHeaderSize;
    if (header.section_offset == 0) return error.MissingSectionHeaderTable;
    if (header.section_entry_size != section_header_size) return error.InvalidSectionHeaderSize;
    return header;
}

fn resolveProgramTable(bytes: []const u8, header: Header) ParseError!ProgramTable {
    const offset: usize = header.program_offset;
    const count: usize = header.program_count;
    if (count == 0xffff) return error.InvalidProgramHeaderTable;
    const table_bytes = std.math.mul(usize, count, program_header_size) catch
        return error.IntegerOverflow;
    _ = checkedSlice(bytes, offset, table_bytes) catch return error.InvalidProgramHeaderTable;
    return .{ .offset = offset, .count = count };
}

fn parseProgramHeader(
    bytes: []const u8,
    table: ProgramTable,
    index: usize,
) ParseError!ProgramHeader {
    if (index >= table.count) return error.InvalidProgramHeaderTable;
    const delta = std.math.mul(usize, index, program_header_size) catch
        return error.IntegerOverflow;
    const offset = std.math.add(usize, table.offset, delta) catch return error.IntegerOverflow;
    _ = try checkedSlice(bytes, offset, program_header_size);
    return .{
        .segment_type = try readU32(bytes, offset),
        .offset = try readU32(bytes, offset + 4),
        .virtual_address = try readU32(bytes, offset + 8),
        .file_size = try readU32(bytes, offset + 16),
        .memory_size = try readU32(bytes, offset + 20),
        .flags = try readU32(bytes, offset + 24),
        .alignment = try readU32(bytes, offset + 28),
    };
}

const ProgramAnalysis = struct {
    writable_load_size: u64,
};

fn analyzeProgramHeaders(bytes: []const u8, table: ProgramTable) ParseError!ProgramAnalysis {
    var load_count: usize = 0;
    var writable_load_count: usize = 0;
    var writable_load_size: u64 = 0;
    var index: usize = 0;
    while (index < table.count) : (index += 1) {
        const program = try parseProgramHeader(bytes, table, index);
        if (program.file_size != 0) {
            _ = checkedSlice(bytes, program.offset, program.file_size) catch
                return error.InvalidLoadSegment;
        }
        if (program.segment_type != pt_load) continue;
        load_count += 1;
        if (program.file_size > program.memory_size) return error.InvalidLoadSegment;
        if (program.alignment != 0 and program.alignment != 1) {
            if (!std.math.isPowerOfTwo(program.alignment) or
                program.offset % program.alignment != program.virtual_address % program.alignment)
            {
                return error.InvalidLoadSegment;
            }
        }
        if (program.flags & pf_write != 0) {
            writable_load_count += 1;
            writable_load_size = std.math.add(u64, writable_load_size, program.memory_size) catch
                return error.IntegerOverflow;
        }
    }
    if (load_count == 0) return error.InvalidProgramHeaderTable;
    if (writable_load_count == 0) return error.MissingWritableLoadSegment;
    return .{ .writable_load_size = writable_load_size };
}

fn sectionCoveredByLoad(bytes: []const u8, table: ProgramTable, section: Section) bool {
    const section_start: u64 = section.address;
    const section_end = std.math.add(u64, section_start, section.size) catch return false;
    var index: usize = 0;
    while (index < table.count) : (index += 1) {
        const program = parseProgramHeader(bytes, table, index) catch return false;
        if (program.segment_type != pt_load) continue;
        if (section.flags & shf_write != 0 and program.flags & pf_write == 0) continue;
        const load_start: u64 = program.virtual_address;
        const load_end = std.math.add(u64, load_start, program.memory_size) catch return false;
        if (section_start >= load_start and section_end <= load_end) return true;
    }
    return false;
}

fn resolveSectionTable(bytes: []const u8, header: Header) ParseError!SectionTable {
    const offset: usize = header.section_offset;
    _ = try checkedSlice(bytes, offset, section_header_size);
    const section_zero = try parseSectionAt(bytes, offset);
    const count: usize = if (header.section_count == 0)
        section_zero.size
    else
        header.section_count;
    if (count == 0) return error.InvalidSectionHeaderTable;

    const table_bytes = std.math.mul(usize, count, section_header_size) catch return error.IntegerOverflow;
    _ = try checkedSlice(bytes, offset, table_bytes);

    const names_index: usize = if (header.section_name_index == shn_xindex)
        section_zero.link
    else
        header.section_name_index;
    if (names_index == 0 or names_index >= count) return error.InvalidSectionNameTable;
    return .{ .offset = offset, .count = count, .names_index = names_index };
}

fn parseSection(bytes: []const u8, table: SectionTable, index: usize) ParseError!Section {
    if (index >= table.count) return error.InvalidSectionHeaderTable;
    const delta = std.math.mul(usize, index, section_header_size) catch return error.IntegerOverflow;
    const offset = std.math.add(usize, table.offset, delta) catch return error.IntegerOverflow;
    return parseSectionAt(bytes, offset);
}

fn parseSectionAt(bytes: []const u8, offset: usize) ParseError!Section {
    _ = try checkedSlice(bytes, offset, section_header_size);
    return .{
        .name_offset = try readU32(bytes, offset),
        .section_type = try readU32(bytes, offset + 4),
        .flags = try readU32(bytes, offset + 8),
        .address = try readU32(bytes, offset + 12),
        .offset = try readU32(bytes, offset + 16),
        .size = try readU32(bytes, offset + 20),
        .link = try readU32(bytes, offset + 24),
        .info = try readU32(bytes, offset + 28),
        .alignment = try readU32(bytes, offset + 32),
        .entry_size = try readU32(bytes, offset + 36),
    };
}

fn validateSection(bytes: []const u8, section: Section) ParseError!void {
    if (section.alignment != 0 and !std.math.isPowerOfTwo(section.alignment)) {
        return error.InvalidSectionAlignment;
    }
    if (section.entry_size != 0 and section.size % section.entry_size != 0) {
        return error.InvalidSectionEntrySize;
    }
    if (section.section_type != sht_null and section.section_type != sht_nobits) {
        _ = try sectionBytes(bytes, section);
    }
}

fn sectionBytes(bytes: []const u8, section: Section) ParseError![]const u8 {
    return checkedSlice(bytes, section.offset, section.size) catch |err| switch (err) {
        error.IntegerOverflow => error.IntegerOverflow,
        else => error.SectionOutOfBounds,
    };
}

fn parseSymbol(bytes: []const u8, offset: usize) ParseError!Symbol {
    _ = try checkedSlice(bytes, offset, symbol_size);
    return .{
        .name_offset = try readU32(bytes, offset),
        .section_index = try readU16(bytes, offset + 14),
    };
}

fn readString(strings: []const u8, raw_offset: u32) ParseError![]const u8 {
    const offset: usize = raw_offset;
    if (offset >= strings.len) return error.InvalidSectionName;
    const terminator = std.mem.indexOfScalarPos(u8, strings, offset, 0) orelse
        return error.InvalidSectionName;
    return strings[offset..terminator];
}

fn readU16(bytes: []const u8, offset: usize) ParseError!u16 {
    const value = try checkedSlice(bytes, offset, @sizeOf(u16));
    return std.mem.readInt(u16, value[0..2], .little);
}

fn readU32(bytes: []const u8, offset: usize) ParseError!u32 {
    const value = try checkedSlice(bytes, offset, @sizeOf(u32));
    return std.mem.readInt(u32, value[0..4], .little);
}

fn checkedSlice(bytes: []const u8, offset: anytype, length: anytype) ParseError![]const u8 {
    const start: usize = @intCast(offset);
    const count: usize = @intCast(length);
    const end = std.math.add(usize, start, count) catch return error.IntegerOverflow;
    if (end > bytes.len) return error.UnexpectedEndOfFile;
    return bytes[start..end];
}

fn validateDistinctProductionUserspaceArtifacts(paths: []const []const u8) UserspaceRoleError!void {
    for (paths, 0..) |path, index| {
        const artifact_name = std.fs.path.basename(path);
        for (paths[0..index]) |prior_path| {
            if (std.mem.eql(u8, artifact_name, std.fs.path.basename(prior_path))) {
                return error.DuplicateProductionUserspaceArtifact;
            }
        }
    }
}

fn validateProductionUserspaceArtifact(
    path: []const u8,
    analysis: UserspaceAnalysis,
) UserspaceRoleError!void {
    const artifact_name = std.fs.path.basename(path);
    for (verification_userspace_identities) |identity| {
        if (std.mem.eql(u8, artifact_name, identity.artifact_name)) {
            return error.ProductionUsesVerificationArtifactName;
        }
    }
    if (analysis.verification_only_signatures != 0 or analysis.verification_identity_mask != 0) {
        return error.ProductionContainsVerificationSignature;
    }
    if (analysis.mmu_probe_machine_code_sentinels != 0) {
        return error.ProductionContainsMmuProbeMachineCode;
    }
}

fn validateVerificationUserspaceArtifact(
    path: []const u8,
    identity_index: usize,
    analysis: UserspaceAnalysis,
) UserspaceRoleError!void {
    const expected = verification_userspace_identities[identity_index];
    if (!std.mem.eql(u8, std.fs.path.basename(path), expected.artifact_name)) {
        return error.VerificationArtifactNameMismatch;
    }
    const expected_identity_mask = @as(u8, 1) << @intCast(identity_index);
    if (analysis.verification_identity_mask != expected_identity_mask) {
        return error.VerificationIdentityMismatch;
    }
    if (identity_index == mmu_proof_identity_index) {
        if (analysis.mmu_probe_machine_code_sentinels != mmu_probe_machine_code_sentinel_count) {
            return error.MmuProofMissingMachineCodeSentinels;
        }
    } else if (analysis.mmu_probe_machine_code_sentinels != 0) {
        return error.VerificationArtifactContainsUnexpectedMmuProbeMachineCode;
    }
}

fn printUserspaceReadFailure(role: []const u8, path: []const u8, err: anyerror) noreturn {
    std.debug.print(
        "Kernel role check failed: unable to read {s} userspace ELF '{s}': {s}\n",
        .{ role, path, @errorName(err) },
    );
    std.process.exit(1);
}

fn printUserspaceRoleFailure(
    role: []const u8,
    path: []const u8,
    expected_artifact_name: ?[]const u8,
    err: UserspaceRoleError,
    analysis: UserspaceAnalysis,
) noreturn {
    switch (err) {
        error.DuplicateProductionUserspaceArtifact => std.debug.print(
            "Kernel role check failed: the production userspace input set contains a duplicate artifact name.\n",
            .{},
        ),
        error.ProductionUsesVerificationArtifactName => std.debug.print(
            "Kernel role check failed: production userspace ELF '{s}' uses a verification-only artifact name.\n",
            .{path},
        ),
        error.ProductionContainsVerificationSignature => std.debug.print(
            "Kernel role check failed: production userspace ELF '{s}' contains {d} verification-only loaded signature(s) (identity mask 0x{x}).\n",
            .{ path, analysis.verification_only_signatures, analysis.verification_identity_mask },
        ),
        error.ProductionContainsMmuProbeMachineCode => std.debug.print(
            "Kernel role check failed: production userspace ELF '{s}' contains {d} MMU-proof executable machine-code sentinel(s).\n",
            .{ path, analysis.mmu_probe_machine_code_sentinels },
        ),
        error.VerificationArtifactNameMismatch => std.debug.print(
            "Kernel role check failed: verification userspace ELF '{s}' does not have expected artifact name '{s}'.\n",
            .{ path, expected_artifact_name.? },
        ),
        error.VerificationIdentityMismatch => std.debug.print(
            "Kernel role check failed: verification userspace ELF '{s}' has identity mask 0x{x}, which does not match its expected role identity.\n",
            .{ path, analysis.verification_identity_mask },
        ),
        error.VerificationArtifactContainsUnexpectedMmuProbeMachineCode => std.debug.print(
            "Kernel role check failed: non-MMU verification userspace ELF '{s}' contains {d} MMU-proof executable machine-code sentinel(s).\n",
            .{ path, analysis.mmu_probe_machine_code_sentinels },
        ),
        error.MmuProofMissingMachineCodeSentinels => std.debug.print(
            "Kernel role check failed: MMU-proof userspace ELF '{s}' contains only {d} of {d} required executable machine-code sentinels.\n",
            .{ path, analysis.mmu_probe_machine_code_sentinels, mmu_probe_machine_code_sentinel_count },
        ),
    }
    _ = role;
    std.process.exit(1);
}

fn validateRoles(production: Analysis, verification: Analysis) RoleError!void {
    if (production.writable_load_size > maximum_production_writable_load_size) {
        return error.ProductionWritableLoadTooLarge;
    }
    if (production.runtime_proof_symbols != 0) return error.ProductionContainsRuntimeProofSymbols;
    if (production.booted_evidence_symbols != 0) return error.ProductionContainsBootedEvidenceSymbols;
    if (production.demo_symbols != 0) return error.ProductionContainsDemoSymbols;
    if (production.benchmark_symbols != 0) return error.ProductionContainsBenchmarkSymbols;
    if (production.recovery_symbols != 0) return error.ProductionContainsRecoverySymbols;
    if (production.verification_orchestration_symbols != 0) {
        return error.ProductionContainsVerificationOrchestrationSymbols;
    }
    if (production.verification_only_signatures != 0) return error.ProductionContainsVerificationSignatures;
    if (verification.runtime_proof_symbols == 0) return error.VerificationMissingRuntimeProofSymbols;
    if (verification.booted_evidence_symbols == 0) return error.VerificationMissingBootedEvidenceSymbols;
    if (verification.verification_only_signatures != verification_only_signatures.len) {
        return error.VerificationMissingExpectedSignatures;
    }
    if (verification.writable_load_size < production.writable_load_size) {
        return error.VerificationWritableLoadNotLarger;
    }
    if (verification.writable_load_size - production.writable_load_size < minimum_verification_writable_load_delta) {
        return error.VerificationWritableLoadDeltaTooSmall;
    }
}

fn printParseFailure(role: []const u8, path: []const u8, err: ParseError) noreturn {
    std.debug.print(
        "Kernel role check failed: {s} ELF '{s}' is invalid: {s} ({s}).\n",
        .{ role, path, parseErrorDescription(err), @errorName(err) },
    );
    std.process.exit(1);
}

fn parseErrorDescription(err: ParseError) []const u8 {
    return switch (err) {
        error.UnexpectedEndOfFile => "a required ELF structure extends past the end of the file",
        error.InvalidElfMagic => "the ELF magic is missing",
        error.UnsupportedElfClass => "the file is not ELF32",
        error.UnsupportedElfEndian => "the file is not little-endian ELF",
        error.UnsupportedElfVersion => "the ELF version is unsupported",
        error.InvalidElfHeaderSize => "the ELF32 header size is invalid",
        error.MissingProgramHeaderTable => "the program-header table is missing",
        error.InvalidProgramHeaderSize => "the program-header entry size is invalid",
        error.InvalidProgramHeaderTable => "the program-header table is invalid",
        error.InvalidLoadSegment => "an allocated section or load segment is invalid",
        error.MissingWritableLoadSegment => "the ELF has no writable load segment",
        error.MissingSectionHeaderTable => "the section-header table is missing",
        error.InvalidSectionHeaderSize => "the section-header entry size is invalid",
        error.InvalidSectionHeaderTable => "the section-header table is invalid",
        error.InvalidNullSection => "section zero is not a null section",
        error.InvalidSectionNameTable => "the section-name string table is invalid",
        error.InvalidSectionName => "a section name is outside its string table or is unterminated",
        error.InvalidSectionAlignment => "a section alignment is not zero or a power of two",
        error.InvalidSectionEntrySize => "a section size is not divisible by its entry size",
        error.SectionOutOfBounds => "a section extends past the end of the file",
        error.MissingDataSection => "the .data section is missing",
        error.DuplicateDataSection => "more than one .data section is present",
        error.InvalidDataSection => "the .data section is not writable, allocated PROGBITS",
        error.MissingSymbolTable => "a static symbol table is required",
        error.InvalidSymbolTable => "a symbol table has invalid sizing or metadata",
        error.InvalidSymbolStringTable => "a symbol table does not reference a valid string table",
        error.InvalidSymbolName => "a symbol name is outside its string table or is unterminated",
        error.InvalidSymbolSectionIndex => "a symbol references a nonexistent section",
        error.UnsupportedExtendedSymbolIndex => "extended symbol section indexes are unsupported",
        error.IntegerOverflow => "ELF offsets or sizes overflow the host address space",
    };
}

fn printRoleFailure(err: RoleError, production: Analysis, verification: Analysis) noreturn {
    switch (err) {
        error.ProductionWritableLoadTooLarge => std.debug.print(
            "Kernel role check failed: production writable load state is {d} bytes; at most {d} bytes are allowed.\n",
            .{ production.writable_load_size, maximum_production_writable_load_size },
        ),
        error.ProductionContainsRuntimeProofSymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} runtime-negative-proof symbol(s) with prefix '{s}'.\n",
            .{ production.runtime_proof_symbols, runtime_proof_symbol_prefix },
        ),
        error.ProductionContainsBootedEvidenceSymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} booted-evidence proof symbol(s) with prefix '{s}'.\n",
            .{ production.booted_evidence_symbols, booted_evidence_symbol_prefix },
        ),
        error.ProductionContainsDemoSymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} demo symbol(s) with prefix '{s}'.\n",
            .{ production.demo_symbols, demo_symbol_prefix },
        ),
        error.ProductionContainsBenchmarkSymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} benchmark symbol(s) with prefix '{s}'.\n",
            .{ production.benchmark_symbols, benchmark_symbol_prefix },
        ),
        error.ProductionContainsRecoverySymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} recovery-suite symbol(s) with prefix '{s}'.\n",
            .{ production.recovery_symbols, recovery_symbol_prefix },
        ),
        error.ProductionContainsVerificationOrchestrationSymbols => std.debug.print(
            "Kernel role check failed: production ELF contains {d} verification-orchestration symbol(s).\n",
            .{production.verification_orchestration_symbols},
        ),
        error.ProductionContainsVerificationSignatures => std.debug.print(
            "Kernel role check failed: production ELF contains {d} verification-only workload signature(s).\n",
            .{production.verification_only_signatures},
        ),
        error.VerificationMissingRuntimeProofSymbols => std.debug.print(
            "Kernel role check failed: verification ELF contains no runtime-negative-proof symbols with prefix '{s}'.\n",
            .{runtime_proof_symbol_prefix},
        ),
        error.VerificationMissingBootedEvidenceSymbols => std.debug.print(
            "Kernel role check failed: verification ELF contains no booted-evidence proof symbols with prefix '{s}'.\n",
            .{booted_evidence_symbol_prefix},
        ),
        error.VerificationMissingExpectedSignatures => std.debug.print(
            "Kernel role check failed: verification ELF contains only {d} of {d} required verification-only workload signatures.\n",
            .{ verification.verification_only_signatures, verification_only_signatures.len },
        ),
        error.VerificationWritableLoadNotLarger => std.debug.print(
            "Kernel role check failed: verification writable load state ({d} bytes) is smaller than production ({d} bytes).\n",
            .{ verification.writable_load_size, production.writable_load_size },
        ),
        error.VerificationWritableLoadDeltaTooSmall => std.debug.print(
            "Kernel role check failed: verification writable load state exceeds production by only {d} bytes; at least {d} bytes are required.\n",
            .{ verification.writable_load_size - production.writable_load_size, minimum_verification_writable_load_delta },
        ),
    }
    std.process.exit(1);
}

test "role validation accepts isolated proof evidence and seven MiB writable allocation delta" {
    const production = Analysis{
        .data_size = 1024,
        .writable_load_size = 2048,
        .symbol_count = 10,
        .runtime_proof_symbols = 0,
        .booted_evidence_symbols = 0,
        .demo_symbols = 0,
        .benchmark_symbols = 0,
        .recovery_symbols = 0,
        .verification_orchestration_symbols = 0,
        .verification_only_signatures = 0,
    };
    const verification = Analysis{
        .data_size = production.data_size + minimum_verification_writable_load_delta,
        .writable_load_size = production.writable_load_size + minimum_verification_writable_load_delta,
        .symbol_count = 20,
        .runtime_proof_symbols = 4,
        .booted_evidence_symbols = 1,
        .demo_symbols = 0,
        .benchmark_symbols = 0,
        .recovery_symbols = 0,
        .verification_orchestration_symbols = 1,
        .verification_only_signatures = verification_only_signatures.len,
    };
    try validateRoles(production, verification);
}

test "role validation rejects leaked and undersized proof kernels" {
    const clean = Analysis{
        .data_size = 4096,
        .writable_load_size = 8192,
        .symbol_count = 1,
        .runtime_proof_symbols = 0,
        .booted_evidence_symbols = 0,
        .demo_symbols = 0,
        .benchmark_symbols = 0,
        .recovery_symbols = 0,
        .verification_orchestration_symbols = 0,
        .verification_only_signatures = 0,
    };
    var leaked = clean;
    leaked.runtime_proof_symbols = 1;
    try std.testing.expectError(
        error.ProductionContainsRuntimeProofSymbols,
        validateRoles(leaked, clean),
    );

    var leaked_demo = clean;
    leaked_demo.demo_symbols = 1;
    try std.testing.expectError(
        error.ProductionContainsDemoSymbols,
        validateRoles(leaked_demo, clean),
    );

    var oversized = clean;
    oversized.writable_load_size = maximum_production_writable_load_size + 1;
    try std.testing.expectError(
        error.ProductionWritableLoadTooLarge,
        validateRoles(oversized, clean),
    );

    var leaked_signature = clean;
    leaked_signature.verification_only_signatures = 1;
    try std.testing.expectError(
        error.ProductionContainsVerificationSignatures,
        validateRoles(leaked_signature, clean),
    );

    var leaked_orchestration = clean;
    leaked_orchestration.verification_orchestration_symbols = 1;
    try std.testing.expectError(
        error.ProductionContainsVerificationOrchestrationSymbols,
        validateRoles(leaked_orchestration, clean),
    );

    var verification = clean;
    verification.runtime_proof_symbols = 1;
    verification.booted_evidence_symbols = 1;
    verification.verification_only_signatures = verification_only_signatures.len;
    verification.writable_load_size += minimum_verification_writable_load_delta - 1;
    try std.testing.expectError(
        error.VerificationWritableLoadDeltaTooSmall,
        validateRoles(clean, verification),
    );
}

test "CLI parsing requires exact role-specific userspace artifact counts" {
    var args = [_][]const u8{"artifact"} ** expected_cli_arg_count;
    args[0] = "check-kernel-roles";
    args[1] = "production-kernel.elf";
    args[2] = "verification-kernel.elf";
    args[3] = production_userspace_marker;
    const verification_marker_index = 4 + production_userspace_count;
    args[verification_marker_index] = verification_userspace_marker;

    const parsed = try parseCliInputs(&args);
    try std.testing.expectEqual(production_userspace_count, parsed.production_userspace_paths.len);
    try std.testing.expectEqual(verification_only_userspace_count, parsed.verification_userspace_paths.len);
    try std.testing.expectEqualStrings("production-kernel.elf", parsed.production_kernel_path);
    try std.testing.expectEqualStrings("verification-kernel.elf", parsed.verification_kernel_path);

    try std.testing.expectError(error.InvalidArgumentCount, parseCliInputs(args[0 .. args.len - 1]));
    var extra_args = [_][]const u8{"artifact"} ** (expected_cli_arg_count + 1);
    try std.testing.expectError(error.InvalidArgumentCount, parseCliInputs(&extra_args));

    args[3] = verification_userspace_marker;
    try std.testing.expectError(error.MissingProductionUserspaceMarker, parseCliInputs(&args));
    args[3] = production_userspace_marker;
    args[verification_marker_index] = production_userspace_marker;
    try std.testing.expectError(error.MissingVerificationUserspaceMarker, parseCliInputs(&args));
}

test "userspace role validation rejects renamed identities and dormant MMU proof code" {
    const clean = UserspaceAnalysis{
        .verification_only_signatures = 0,
        .verification_identity_mask = 0,
        .mmu_probe_machine_code_sentinels = 0,
    };
    try validateProductionUserspaceArtifact("/tmp/userspace-notes.elf", clean);

    var leaked_signature = clean;
    leaked_signature.verification_only_signatures = 1;
    try std.testing.expectError(
        error.ProductionContainsVerificationSignature,
        validateProductionUserspaceArtifact("/tmp/userspace-notes.elf", leaked_signature),
    );

    var leaked_identity = clean;
    leaked_identity.verification_identity_mask = 1;
    try std.testing.expectError(
        error.ProductionContainsVerificationSignature,
        validateProductionUserspaceArtifact("/tmp/userspace-renamed.elf", leaked_identity),
    );

    var leaked_machine_code = clean;
    leaked_machine_code.mmu_probe_machine_code_sentinels = 1;
    try std.testing.expectError(
        error.ProductionContainsMmuProbeMachineCode,
        validateProductionUserspaceArtifact("/tmp/userspace-notes.elf", leaked_machine_code),
    );
    try std.testing.expectError(
        error.ProductionUsesVerificationArtifactName,
        validateProductionUserspaceArtifact("/tmp/userspace-mmu-isolation-proof.elf", clean),
    );

    const distinct = [_][]const u8{
        "/tmp/a/userspace-notes.elf",
        "/tmp/b/userspace-viewer.elf",
    };
    try validateDistinctProductionUserspaceArtifacts(&distinct);
    const duplicate = [_][]const u8{
        "/tmp/a/userspace-notes.elf",
        "/tmp/b/userspace-notes.elf",
    };
    try std.testing.expectError(
        error.DuplicateProductionUserspaceArtifact,
        validateDistinctProductionUserspaceArtifacts(&duplicate),
    );
}

test "verification userspace validation requires exact identities and MMU positive control" {
    const notes_analysis = UserspaceAnalysis{
        .verification_only_signatures = 1,
        .verification_identity_mask = 1,
        .mmu_probe_machine_code_sentinels = 0,
    };
    try validateVerificationUserspaceArtifact(
        "/tmp/userspace-notes-daily.elf",
        0,
        notes_analysis,
    );

    var unexpected_probe = notes_analysis;
    unexpected_probe.mmu_probe_machine_code_sentinels = 1;
    try std.testing.expectError(
        error.VerificationArtifactContainsUnexpectedMmuProbeMachineCode,
        validateVerificationUserspaceArtifact("/tmp/userspace-notes-daily.elf", 0, unexpected_probe),
    );
    try std.testing.expectError(
        error.VerificationArtifactNameMismatch,
        validateVerificationUserspaceArtifact("/tmp/renamed.elf", 0, notes_analysis),
    );

    const proof_identity_mask = @as(u8, 1) << @intCast(mmu_proof_identity_index);
    const proof_analysis = UserspaceAnalysis{
        .verification_only_signatures = 2,
        .verification_identity_mask = proof_identity_mask,
        .mmu_probe_machine_code_sentinels = mmu_probe_machine_code_sentinel_count,
    };
    try validateVerificationUserspaceArtifact(
        "/tmp/userspace-mmu-isolation-proof.elf",
        mmu_proof_identity_index,
        proof_analysis,
    );

    var wrong_identity = proof_analysis;
    wrong_identity.verification_identity_mask |= 1;
    try std.testing.expectError(
        error.VerificationIdentityMismatch,
        validateVerificationUserspaceArtifact(
            "/tmp/userspace-mmu-isolation-proof.elf",
            mmu_proof_identity_index,
            wrong_identity,
        ),
    );
    var missing_sentinel = proof_analysis;
    missing_sentinel.mmu_probe_machine_code_sentinels -= 1;
    try std.testing.expectError(
        error.MmuProofMissingMachineCodeSentinels,
        validateVerificationUserspaceArtifact(
            "/tmp/userspace-mmu-isolation-proof.elf",
            mmu_proof_identity_index,
            missing_sentinel,
        ),
    );
}

test "userspace ELF analysis scans loaded identities and executable probe sentinels" {
    var storage = [_]u8{0} ** 2048;
    const bytes = buildTestElf(&storage);

    const non_executable = try analyzeUserspaceElf(bytes);
    try std.testing.expectEqual(verification_only_signatures.len, non_executable.verification_only_signatures);
    try std.testing.expectEqual(@as(u8, 0x1f), non_executable.verification_identity_mask);
    try std.testing.expectEqual(@as(usize, 0), non_executable.mmu_probe_machine_code_sentinels);

    var sentinel_offset = testSymbolTableOffset();
    @memcpy(
        storage[sentinel_offset..][0..mmu_probe_role_tag_machine_code.len],
        &mmu_probe_role_tag_machine_code,
    );
    sentinel_offset += mmu_probe_role_tag_machine_code.len;
    @memcpy(
        storage[sentinel_offset..][0..mmu_probe_foreign_address_machine_code.len],
        &mmu_probe_foreign_address_machine_code,
    );
    sentinel_offset += mmu_probe_foreign_address_machine_code.len;
    @memcpy(
        storage[sentinel_offset..][0..mmu_probe_fault_code_imm32_machine_code.len],
        &mmu_probe_fault_code_imm32_machine_code,
    );
    const fault_code_offset = sentinel_offset;
    writeU32(&storage, elf_header_size + 24, 4 | pf_execute);
    const executable = try analyzeUserspaceElf(bytes);
    try std.testing.expectEqual(
        mmu_probe_machine_code_sentinel_count,
        executable.mmu_probe_machine_code_sentinels,
    );

    @memset(
        storage[fault_code_offset..][0..mmu_probe_fault_code_imm32_machine_code.len],
        0,
    );
    @memcpy(
        storage[fault_code_offset..][0..mmu_probe_fault_code_push_imm8_machine_code.len],
        &mmu_probe_fault_code_push_imm8_machine_code,
    );
    const compact_fault_code = try analyzeUserspaceElf(bytes);
    try std.testing.expectEqual(
        mmu_probe_machine_code_sentinel_count,
        compact_fault_code.mmu_probe_machine_code_sentinels,
    );

    writeU32(&storage, elf_header_size + 24, 4);
    const executable_flag_removed = try analyzeUserspaceElf(bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        executable_flag_removed.mmu_probe_machine_code_sentinels,
    );
}

test "ELF parser reads loaded state, defined symbols, and workload signatures" {
    var storage = [_]u8{0} ** 2048;
    const bytes = buildTestElf(&storage);
    const analysis = try analyzeElf(bytes);
    try std.testing.expectEqual(@as(u64, 16), analysis.data_size);
    try std.testing.expectEqual(@as(u64, 48), analysis.writable_load_size);
    try std.testing.expectEqual(@as(usize, 3), analysis.symbol_count);
    try std.testing.expectEqual(@as(usize, 1), analysis.runtime_proof_symbols);
    try std.testing.expectEqual(@as(usize, 1), analysis.booted_evidence_symbols);
    try std.testing.expectEqual(@as(usize, 0), analysis.demo_symbols);
    try std.testing.expectEqual(@as(usize, 0), analysis.benchmark_symbols);
    try std.testing.expectEqual(@as(usize, 0), analysis.recovery_symbols);
    try std.testing.expectEqual(verification_only_signatures.len, analysis.verification_only_signatures);

    const first_signature_offset = std.mem.indexOf(u8, bytes, verification_only_signatures[0]).?;
    writeU32(&storage, elf_header_size + 16, first_signature_offset);
    writeU32(&storage, elf_header_size + 20, first_signature_offset);
    const unloaded_signature_analysis = try analyzeElf(bytes);
    try std.testing.expectEqual(@as(usize, 0), unloaded_signature_analysis.verification_only_signatures);
    writeU32(&storage, elf_header_size + 16, bytes.len);
    writeU32(&storage, elf_header_size + 20, bytes.len);

    const first_symbol_offset = testSymbolTableOffset() + symbol_size;
    writeU16(&storage, first_symbol_offset + 14, shn_undef);
    const undefined_analysis = try analyzeElf(bytes);
    try std.testing.expectEqual(@as(usize, 0), undefined_analysis.runtime_proof_symbols);
    writeU16(&storage, first_symbol_offset + 14, 2);

    const section_table_offset = elf_header_size + 2 * program_header_size;
    const data_section_offset = section_table_offset + 2 * section_header_size;
    writeU32(&storage, data_section_offset + 8, 0);
    try std.testing.expectError(error.InvalidDataSection, analyzeElf(bytes));
    writeU32(&storage, data_section_offset + 8, shf_write | shf_alloc);

    const writable_program_offset = elf_header_size + program_header_size;
    writeU32(&storage, writable_program_offset + 24, 4);
    try std.testing.expectError(error.MissingWritableLoadSegment, analyzeElf(bytes));
    writeU32(&storage, writable_program_offset + 24, 4 | pf_write);

    storage[ei_class] = 2;
    try std.testing.expectError(error.UnsupportedElfClass, analyzeElf(bytes));

    storage[ei_class] = elf_class_32;
    storage[ei_data] = 2;
    try std.testing.expectError(error.UnsupportedElfEndian, analyzeElf(bytes));

    storage[ei_data] = elf_data_little_endian;
    writeU16(&storage, 42, 16);
    try std.testing.expectError(error.InvalidProgramHeaderSize, analyzeElf(bytes));
    writeU16(&storage, 42, program_header_size);

    const symbol_section_offset = section_table_offset + 5 * section_header_size;
    writeU32(&storage, symbol_section_offset + 36, 8);
    try std.testing.expectError(error.InvalidSymbolTable, analyzeElf(bytes));
}

fn buildTestElf(storage: []u8) []u8 {
    @memset(storage, 0);
    const program_count: u16 = 2;
    const program_table_offset: u32 = elf_header_size;
    const section_count: u16 = 6;
    const section_table_offset: u32 = program_table_offset + program_count * program_header_size;
    const section_names = "\x00.shstrtab\x00.data\x00.bss\x00.strtab\x00.symtab\x00";
    const symbol_names = "\x00native.session.proofs.runtime_negative_proofs.fixture\x00native.session.booted_evidence.runProduction\x00";
    const section_names_offset: u32 = section_table_offset + section_count * section_header_size;
    const data_offset: u32 = section_names_offset + section_names.len;
    const strings_offset: u32 = data_offset + 16;
    const symbols_offset: u32 = std.mem.alignForward(u32, strings_offset + symbol_names.len, 4);
    const signatures_offset: u32 = symbols_offset + 3 * @as(u32, symbol_size);
    var signature_blob_size: usize = 0;
    for (verification_only_signatures) |signature| signature_blob_size += signature.len + 1;
    const file_size: usize = @as(usize, signatures_offset) + signature_blob_size;

    @memcpy(storage[0..4], "\x7fELF");
    storage[ei_class] = elf_class_32;
    storage[ei_data] = elf_data_little_endian;
    storage[ei_version] = elf_current_version;
    writeU32(storage, 20, elf_current_version);
    writeU32(storage, 28, program_table_offset);
    writeU32(storage, 32, section_table_offset);
    writeU16(storage, 40, elf_header_size);
    writeU16(storage, 42, program_header_size);
    writeU16(storage, 44, program_count);
    writeU16(storage, 46, section_header_size);
    writeU16(storage, 48, section_count);
    writeU16(storage, 50, 1);

    writeSection(storage, section_table_offset + section_header_size, .{
        .name_offset = 1,
        .section_type = sht_strtab,
        .flags = 0,
        .address = 0,
        .offset = section_names_offset,
        .size = section_names.len,
        .link = 0,
        .info = 0,
        .alignment = 1,
        .entry_size = 0,
    });
    writeSection(storage, section_table_offset + 2 * section_header_size, .{
        .name_offset = 11,
        .section_type = sht_progbits,
        .flags = shf_write | shf_alloc,
        .address = 0x2000,
        .offset = data_offset,
        .size = 16,
        .link = 0,
        .info = 0,
        .alignment = 4,
        .entry_size = 0,
    });
    writeSection(storage, section_table_offset + 3 * section_header_size, .{
        .name_offset = 17,
        .section_type = sht_nobits,
        .flags = shf_write | shf_alloc,
        .address = 0x2010,
        .offset = 0,
        .size = 32,
        .link = 0,
        .info = 0,
        .alignment = 4,
        .entry_size = 0,
    });
    writeSection(storage, section_table_offset + 4 * section_header_size, .{
        .name_offset = 22,
        .section_type = sht_strtab,
        .flags = 0,
        .address = 0,
        .offset = strings_offset,
        .size = symbol_names.len,
        .link = 0,
        .info = 0,
        .alignment = 1,
        .entry_size = 0,
    });
    writeSection(storage, section_table_offset + 5 * section_header_size, .{
        .name_offset = 30,
        .section_type = sht_symtab,
        .flags = 0,
        .address = 0,
        .offset = symbols_offset,
        .size = 3 * symbol_size,
        .link = 4,
        .info = 1,
        .alignment = 4,
        .entry_size = symbol_size,
    });

    @memcpy(storage[section_names_offset..][0..section_names.len], section_names);
    @memcpy(storage[strings_offset..][0..symbol_names.len], symbol_names);
    writeSymbol(storage, symbols_offset + symbol_size, 1, 2);
    const booted_name_offset = 1 + "native.session.proofs.runtime_negative_proofs.fixture".len + 1;
    writeSymbol(storage, symbols_offset + 2 * symbol_size, booted_name_offset, 2);

    var signature_offset: usize = signatures_offset;
    for (verification_only_signatures) |signature| {
        @memcpy(storage[signature_offset..][0..signature.len], signature);
        signature_offset += signature.len + 1;
    }

    writeProgramHeader(storage, program_table_offset, .{
        .segment_type = pt_load,
        .offset = 0,
        .virtual_address = 0,
        .file_size = @intCast(file_size),
        .memory_size = @intCast(file_size),
        .flags = 4,
        .alignment = 1,
    });
    writeProgramHeader(storage, program_table_offset + program_header_size, .{
        .segment_type = pt_load,
        .offset = data_offset,
        .virtual_address = 0x2000,
        .file_size = 16,
        .memory_size = 48,
        .flags = 4 | pf_write,
        .alignment = 1,
    });
    return storage[0..file_size];
}

fn testSymbolTableOffset() usize {
    const program_count: u32 = 2;
    const section_count: u32 = 6;
    const section_names = "\x00.shstrtab\x00.data\x00.bss\x00.strtab\x00.symtab\x00";
    const symbol_names = "\x00native.session.proofs.runtime_negative_proofs.fixture\x00native.session.booted_evidence.runProduction\x00";
    const section_names_offset: u32 = elf_header_size +
        program_count * program_header_size +
        section_count * section_header_size;
    const data_offset: u32 = section_names_offset + section_names.len;
    const strings_offset: u32 = data_offset + 16;
    return @intCast(std.mem.alignForward(u32, strings_offset + symbol_names.len, 4));
}

fn writeProgramHeader(bytes: []u8, offset: anytype, program: ProgramHeader) void {
    const start: usize = @intCast(offset);
    writeU32(bytes, start, program.segment_type);
    writeU32(bytes, start + 4, program.offset);
    writeU32(bytes, start + 8, program.virtual_address);
    writeU32(bytes, start + 16, program.file_size);
    writeU32(bytes, start + 20, program.memory_size);
    writeU32(bytes, start + 24, program.flags);
    writeU32(bytes, start + 28, program.alignment);
}

fn writeSection(bytes: []u8, offset: anytype, section: Section) void {
    const start: usize = @intCast(offset);
    writeU32(bytes, start, section.name_offset);
    writeU32(bytes, start + 4, section.section_type);
    writeU32(bytes, start + 8, section.flags);
    writeU32(bytes, start + 12, section.address);
    writeU32(bytes, start + 16, section.offset);
    writeU32(bytes, start + 20, section.size);
    writeU32(bytes, start + 24, section.link);
    writeU32(bytes, start + 28, section.info);
    writeU32(bytes, start + 32, section.alignment);
    writeU32(bytes, start + 36, section.entry_size);
}

fn writeSymbol(bytes: []u8, offset: anytype, name_offset: anytype, section_index: u16) void {
    const start: usize = @intCast(offset);
    writeU32(bytes, start, name_offset);
    writeU16(bytes, start + 14, section_index);
}

fn writeU16(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(value), .little);
}

fn writeU32(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], @intCast(value), .little);
}
