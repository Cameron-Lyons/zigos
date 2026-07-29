const std = @import("std");

const max_input_bytes: usize = 16 * 1024 * 1024;

const Diagnostics = struct {
    items: std.ArrayList([]const u8) = .empty,

    fn add(
        self: *Diagnostics,
        allocator: std.mem.Allocator,
        comptime format: []const u8,
        args: anytype,
    ) !void {
        try self.items.append(allocator, try std.fmt.allocPrint(allocator, format, args));
    }
};

const Threshold = struct {
    name: []const u8,
    max_cycles: u64,
    line: usize,
};

const Baseline = struct {
    name: []const u8,
    cycles_hundredths: u64,
    allowed_percent: u64,
    line: usize,
};

const QualityGate = struct {
    name: []const u8,
    minimum: ?u64,
    maximum: ?u64,
    line: usize,
};

fn Table(comptime Entry: type) type {
    return struct {
        entries: std.ArrayList(Entry) = .empty,
        by_name: std.StringHashMap(usize),

        fn init(allocator: std.mem.Allocator) @This() {
            return .{ .by_name = std.StringHashMap(usize).init(allocator) };
        }
    };
}

const Result = struct {
    name: []const u8,
    iterations: u64,
    cycles: u64,
    cycles_per_op_hundredths: u64,
    checksum: u64,
    line: usize,
};

const QualityResult = struct {
    name: []const u8,
    value: u64,
    cycles: u64,
    line: usize,
};

const QualitySummary = struct {
    gates: u64,
    total_cycles: u64,
};

const Accelerator = enum {
    kvm,
    tcg,
};

const Summary = struct {
    benchmarks: u64,
    quality_gates: u64,
    quality_cycles: u64,
    total_cycles: u64,
};

const Log = struct {
    results: Table(Result),
    quality_results: Table(QualityResult),
    quality_summary: ?QualitySummary = null,
    summary: ?Summary = null,
    accelerator: ?Accelerator = null,
    accelerator_markers: usize = 0,
    start_markers: usize = 0,
    pass_markers: usize = 0,

    fn init(allocator: std.mem.Allocator) Log {
        return .{
            .results = Table(Result).init(allocator),
            .quality_results = Table(QualityResult).init(allocator),
        };
    }
};

const Analysis = struct {
    diagnostics: Diagnostics = .{},
    thresholds: Table(Threshold),
    baselines: Table(Baseline),
    quality_gates: Table(QualityGate),
    log: Log,

    fn init(allocator: std.mem.Allocator) Analysis {
        return .{
            .thresholds = Table(Threshold).init(allocator),
            .baselines = Table(Baseline).init(allocator),
            .quality_gates = Table(QualityGate).init(allocator),
            .log = Log.init(allocator),
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 7 or !std.mem.eql(u8, args[1], "check")) {
        std.debug.print(
            "usage: {s} check <log> <thresholds> <baselines> <quality-gates> <summary-output>\n",
            .{args[0]},
        );
        std.process.exit(2);
    }

    var analysis = Analysis.init(allocator);
    const log_source = readInput(allocator, io, args[2], "benchmark log", &analysis.diagnostics) catch "";
    const threshold_source = readInput(allocator, io, args[3], "threshold config", &analysis.diagnostics) catch "";
    const baseline_source = readInput(allocator, io, args[4], "baseline config", &analysis.diagnostics) catch "";
    const quality_source = readInput(allocator, io, args[5], "quality-gate config", &analysis.diagnostics) catch "";

    try analyzeSources(
        allocator,
        &analysis,
        threshold_source,
        baseline_source,
        quality_source,
        log_source,
    );

    const markdown = try renderMarkdown(allocator, &analysis);
    try writeSummary(io, args[6], markdown);

    if (analysis.diagnostics.items.items.len != 0) {
        for (analysis.diagnostics.items.items) |message| std.debug.print("{s}\n", .{message});
        std.process.exit(1);
    }

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    if (performanceGatesEnforced(&analysis.log)) {
        try stdout_writer.interface.print(
            "Kernel benchmark KVM performance and quality gates passed: {d} benchmarks and {d} quality gates.\n",
            .{ analysis.thresholds.entries.items.len, analysis.quality_gates.entries.items.len },
        );
    } else {
        try stdout_writer.interface.print(
            "Kernel benchmark functional and quality gates passed under {s}: {d} benchmarks and {d} quality gates; cycle ceilings were not enforced.\n",
            .{ acceleratorName(analysis.log.accelerator), analysis.thresholds.entries.items.len, analysis.quality_gates.entries.items.len },
        );
    }
    try stdout_writer.interface.flush();
}

fn readInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    label: []const u8,
    diagnostics: *Diagnostics,
) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_input_bytes)) catch |err| {
        try diagnostics.add(allocator, "Unable to read {s}: {s}", .{ label, @errorName(err) });
        return err;
    };
}

fn writeSummary(io: std.Io, path: []const u8, markdown: []const u8) !void {
    if (std.fs.path.dirname(path)) |directory| {
        if (directory.len != 0 and !std.fs.path.isAbsolute(directory)) {
            try std.Io.Dir.cwd().createDirPath(io, directory);
        }
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = markdown });
}

fn analyzeSources(
    allocator: std.mem.Allocator,
    analysis: *Analysis,
    threshold_source: []const u8,
    baseline_source: []const u8,
    quality_source: []const u8,
    log_source: []const u8,
) !void {
    try parseThresholds(allocator, &analysis.diagnostics, &analysis.thresholds, threshold_source);
    try parseBaselines(allocator, &analysis.diagnostics, &analysis.baselines, baseline_source);
    try parseQualityGates(allocator, &analysis.diagnostics, &analysis.quality_gates, quality_source);
    try parseLog(allocator, &analysis.diagnostics, &analysis.log, log_source);
    try validateAnalysis(allocator, analysis);
}

fn parseThresholds(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    table: *Table(Threshold),
    source: []const u8,
) !void {
    var line_iterator = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (line_iterator.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tokens: [3][]const u8 = undefined;
        const count = collectTokens(line, &tokens);
        if (count != 2) {
            try diagnostics.add(allocator, "Threshold config line {d} must contain exactly 2 columns", .{line_number});
            continue;
        }
        if (!validName(tokens[0])) {
            try diagnostics.add(allocator, "Threshold config line {d} has an invalid benchmark name", .{line_number});
            continue;
        }
        const maximum = parseUnsigned(tokens[1]) orelse {
            try diagnostics.add(allocator, "Threshold config line {d} has an invalid maximum", .{line_number});
            continue;
        };
        const gop = try table.by_name.getOrPut(tokens[0]);
        if (gop.found_existing) {
            const first_line = table.entries.items[gop.value_ptr.*].line;
            try diagnostics.add(
                allocator,
                "Duplicate threshold for {s} on lines {d} and {d}",
                .{ tokens[0], first_line, line_number },
            );
            continue;
        }
        gop.value_ptr.* = table.entries.items.len;
        try table.entries.append(allocator, .{ .name = tokens[0], .max_cycles = maximum, .line = line_number });
    }
    if (table.entries.items.len == 0) try diagnostics.add(allocator, "Threshold config has no entries", .{});
}

fn parseBaselines(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    table: *Table(Baseline),
    source: []const u8,
) !void {
    var line_iterator = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (line_iterator.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tokens: [4][]const u8 = undefined;
        const count = collectTokens(line, &tokens);
        if (count != 3) {
            try diagnostics.add(allocator, "Baseline config line {d} must contain exactly 3 columns", .{line_number});
            continue;
        }
        if (!validName(tokens[0])) {
            try diagnostics.add(allocator, "Baseline config line {d} has an invalid benchmark name", .{line_number});
            continue;
        }
        const baseline = parseFixedHundredths(tokens[1], false) orelse {
            try diagnostics.add(allocator, "Baseline config line {d} has an invalid fixed-point baseline", .{line_number});
            continue;
        };
        if (baseline == 0) {
            try diagnostics.add(allocator, "Baseline config line {d} must be greater than zero", .{line_number});
            continue;
        }
        const allowed_percent = parseUnsigned(tokens[2]) orelse {
            try diagnostics.add(allocator, "Baseline config line {d} has an invalid allowance", .{line_number});
            continue;
        };
        if (baselineLimit(baseline, allowed_percent) == null) {
            try diagnostics.add(allocator, "Baseline config line {d} overflows allowance calculation", .{line_number});
            continue;
        }
        const gop = try table.by_name.getOrPut(tokens[0]);
        if (gop.found_existing) {
            const first_line = table.entries.items[gop.value_ptr.*].line;
            try diagnostics.add(
                allocator,
                "Duplicate baseline for {s} on lines {d} and {d}",
                .{ tokens[0], first_line, line_number },
            );
            continue;
        }
        gop.value_ptr.* = table.entries.items.len;
        try table.entries.append(allocator, .{
            .name = tokens[0],
            .cycles_hundredths = baseline,
            .allowed_percent = allowed_percent,
            .line = line_number,
        });
    }
    if (table.entries.items.len == 0) try diagnostics.add(allocator, "Baseline config has no entries", .{});
}

fn parseQualityGates(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    table: *Table(QualityGate),
    source: []const u8,
) !void {
    var line_iterator = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (line_iterator.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tokens: [4][]const u8 = undefined;
        const count = collectTokens(line, &tokens);
        if (count != 3) {
            try diagnostics.add(allocator, "Quality-gate config line {d} must contain exactly 3 columns", .{line_number});
            continue;
        }
        if (!validName(tokens[0])) {
            try diagnostics.add(allocator, "Quality-gate config line {d} has an invalid gate name", .{line_number});
            continue;
        }
        const minimum = parseOptionalUnsigned(tokens[1]) orelse {
            try diagnostics.add(allocator, "Quality-gate config line {d} has an invalid minimum", .{line_number});
            continue;
        };
        const maximum = parseOptionalUnsigned(tokens[2]) orelse {
            try diagnostics.add(allocator, "Quality-gate config line {d} has an invalid maximum", .{line_number});
            continue;
        };
        if (minimum.value == null and maximum.value == null) {
            try diagnostics.add(allocator, "Quality-gate config line {d} must set at least one bound", .{line_number});
            continue;
        }
        if (minimum.value != null and maximum.value != null and minimum.value.? > maximum.value.?) {
            try diagnostics.add(allocator, "Quality-gate config line {d} has minimum greater than maximum", .{line_number});
            continue;
        }
        const gop = try table.by_name.getOrPut(tokens[0]);
        if (gop.found_existing) {
            const first_line = table.entries.items[gop.value_ptr.*].line;
            try diagnostics.add(
                allocator,
                "Duplicate quality gate for {s} on lines {d} and {d}",
                .{ tokens[0], first_line, line_number },
            );
            continue;
        }
        gop.value_ptr.* = table.entries.items.len;
        try table.entries.append(allocator, .{
            .name = tokens[0],
            .minimum = minimum.value,
            .maximum = maximum.value,
            .line = line_number,
        });
    }
    if (table.entries.items.len == 0) try diagnostics.add(allocator, "Quality-gate config has no entries", .{});
}

const OptionalUnsigned = struct { value: ?u64 };

fn parseOptionalUnsigned(text: []const u8) ?OptionalUnsigned {
    if (std.mem.eql(u8, text, "-")) return .{ .value = null };
    return .{ .value = parseUnsigned(text) orelse return null };
}

fn collectTokens(line: []const u8, output: [][]const u8) usize {
    var iterator = std.mem.tokenizeAny(u8, line, " \t");
    var count: usize = 0;
    while (iterator.next()) |token| {
        if (count < output.len) output[count] = token;
        count += 1;
    }
    return count;
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-') return false;
    }
    return true;
}

fn parseUnsigned(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(u64, text, 10) catch null;
}

fn parseFixedHundredths(text: []const u8, canonical: bool) ?u64 {
    const decimal_index = std.mem.indexOfScalar(u8, text, '.');
    const whole_text = if (decimal_index) |index| text[0..index] else text;
    const fraction_text = if (decimal_index) |index| text[index + 1 ..] else "";
    if (whole_text.len == 0) return null;
    if (canonical and fraction_text.len != 2) return null;
    if (!canonical and decimal_index != null and (fraction_text.len == 0 or fraction_text.len > 2)) return null;
    if (decimal_index == null and canonical) return null;
    if (std.mem.indexOfScalar(u8, fraction_text, '.') != null) return null;

    const whole = parseUnsigned(whole_text) orelse return null;
    const fraction = if (fraction_text.len == 0)
        0
    else if (fraction_text.len == 1)
        (parseUnsigned(fraction_text) orelse return null) * 10
    else
        parseUnsigned(fraction_text) orelse return null;
    const scaled_whole = std.math.mul(u64, whole, 100) catch return null;
    return std.math.add(u64, scaled_whole, fraction) catch null;
}

fn parseLog(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    source: []const u8,
) !void {
    var line_iterator = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (line_iterator.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (!std.mem.startsWith(u8, line, "BENCH:")) continue;

        if (std.mem.startsWith(u8, line, "BENCH:ENV:")) {
            try parseEnvironmentLine(allocator, diagnostics, log, line, line_number);
        } else if (std.mem.eql(u8, line, "BENCH:START")) {
            log.start_markers += 1;
        } else if (std.mem.eql(u8, line, "BENCH:PASS")) {
            log.pass_markers += 1;
        } else if (std.mem.startsWith(u8, line, "BENCH:RESULT:")) {
            try parseResultLine(allocator, diagnostics, log, line, line_number);
        } else if (std.mem.startsWith(u8, line, "BENCH:QUALITY:")) {
            try parseQualityLine(allocator, diagnostics, log, line, line_number);
        } else if (std.mem.startsWith(u8, line, "BENCH:QUALITY_SUMMARY:")) {
            try parseQualitySummaryLine(allocator, diagnostics, log, line, line_number);
        } else if (std.mem.startsWith(u8, line, "BENCH:SUMMARY:")) {
            try parseSummaryLine(allocator, diagnostics, log, line, line_number);
        } else {
            try diagnostics.add(allocator, "Unrecognized benchmark record on log line {d}", .{line_number});
        }
    }
}

fn parseEnvironmentLine(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    line: []const u8,
    line_number: usize,
) !void {
    log.accelerator_markers += 1;
    if (log.accelerator_markers > 1) {
        try diagnostics.add(allocator, "Duplicate benchmark accelerator record on log line {d}", .{line_number});
        return;
    }

    var fields: [4][]const u8 = undefined;
    if (splitFields(line, &fields) != 3 or
        !std.mem.eql(u8, fields[0], "BENCH") or
        !std.mem.eql(u8, fields[1], "ENV"))
    {
        return addMalformed(allocator, diagnostics, "benchmark environment", line_number);
    }
    const accelerator = fieldValue(fields[2], "accelerator") orelse
        return addMalformed(allocator, diagnostics, "benchmark environment", line_number);
    if (std.mem.eql(u8, accelerator, "kvm")) {
        log.accelerator = .kvm;
    } else if (std.mem.eql(u8, accelerator, "tcg")) {
        log.accelerator = .tcg;
    } else {
        try diagnostics.add(allocator, "Unsupported benchmark accelerator '{s}' on log line {d}", .{ accelerator, line_number });
    }
}

fn splitFields(line: []const u8, output: [][]const u8) usize {
    var iterator = std.mem.splitScalar(u8, line, ':');
    var count: usize = 0;
    while (iterator.next()) |field| {
        if (count < output.len) output[count] = field;
        count += 1;
    }
    return count;
}

fn fieldValue(field: []const u8, key: []const u8) ?[]const u8 {
    if (field.len <= key.len or field[key.len] != '=' or !std.mem.eql(u8, field[0..key.len], key)) return null;
    return field[key.len + 1 ..];
}

fn parseResultLine(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    line: []const u8,
    line_number: usize,
) !void {
    var fields: [8][]const u8 = undefined;
    if (splitFields(line, &fields) != 7 or
        !std.mem.eql(u8, fields[0], "BENCH") or
        !std.mem.eql(u8, fields[1], "RESULT") or
        !validName(fields[2]))
    {
        try diagnostics.add(allocator, "Malformed benchmark result on log line {d}", .{line_number});
        return;
    }
    const iterations = parseFieldUnsigned(fields[3], "iterations") orelse return addMalformed(allocator, diagnostics, "benchmark result", line_number);
    const cycles = parseFieldUnsigned(fields[4], "cycles") orelse return addMalformed(allocator, diagnostics, "benchmark result", line_number);
    const cycles_per_op_text = fieldValue(fields[5], "cycles_per_op") orelse return addMalformed(allocator, diagnostics, "benchmark result", line_number);
    const cycles_per_op = parseFixedHundredths(cycles_per_op_text, true) orelse return addMalformed(allocator, diagnostics, "benchmark result", line_number);
    const checksum = parseFieldUnsigned(fields[6], "checksum") orelse return addMalformed(allocator, diagnostics, "benchmark result", line_number);
    if (iterations == 0) {
        try diagnostics.add(allocator, "Benchmark result {s} has zero iterations on log line {d}", .{ fields[2], line_number });
        return;
    }
    const scaled_cycles = std.math.mul(u64, cycles, 100) catch {
        try diagnostics.add(allocator, "Benchmark result {s} overflows cycle scaling on log line {d}", .{ fields[2], line_number });
        return;
    };
    if (scaled_cycles / iterations != cycles_per_op) {
        try diagnostics.add(allocator, "Benchmark result {s} has inconsistent cycles_per_op on log line {d}", .{ fields[2], line_number });
    }

    const gop = try log.results.by_name.getOrPut(fields[2]);
    if (gop.found_existing) {
        const first_line = log.results.entries.items[gop.value_ptr.*].line;
        try diagnostics.add(
            allocator,
            "Duplicate benchmark result for {s} on log lines {d} and {d}",
            .{ fields[2], first_line, line_number },
        );
        return;
    }
    gop.value_ptr.* = log.results.entries.items.len;
    try log.results.entries.append(allocator, .{
        .name = fields[2],
        .iterations = iterations,
        .cycles = cycles,
        .cycles_per_op_hundredths = cycles_per_op,
        .checksum = checksum,
        .line = line_number,
    });
}

fn parseQualityLine(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    line: []const u8,
    line_number: usize,
) !void {
    var fields: [6][]const u8 = undefined;
    if (splitFields(line, &fields) != 5 or
        !std.mem.eql(u8, fields[0], "BENCH") or
        !std.mem.eql(u8, fields[1], "QUALITY") or
        !validName(fields[2]))
    {
        try diagnostics.add(allocator, "Malformed quality result on log line {d}", .{line_number});
        return;
    }
    const value = parseFieldUnsigned(fields[3], "value") orelse return addMalformed(allocator, diagnostics, "quality result", line_number);
    const cycles = parseFieldUnsigned(fields[4], "cycles") orelse return addMalformed(allocator, diagnostics, "quality result", line_number);
    const gop = try log.quality_results.by_name.getOrPut(fields[2]);
    if (gop.found_existing) {
        const first_line = log.quality_results.entries.items[gop.value_ptr.*].line;
        try diagnostics.add(
            allocator,
            "Duplicate quality result for {s} on log lines {d} and {d}",
            .{ fields[2], first_line, line_number },
        );
        return;
    }
    gop.value_ptr.* = log.quality_results.entries.items.len;
    try log.quality_results.entries.append(allocator, .{
        .name = fields[2],
        .value = value,
        .cycles = cycles,
        .line = line_number,
    });
}

fn parseQualitySummaryLine(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    line: []const u8,
    line_number: usize,
) !void {
    if (log.quality_summary != null) {
        try diagnostics.add(allocator, "Duplicate quality summary on log line {d}", .{line_number});
        return;
    }
    var fields: [5][]const u8 = undefined;
    if (splitFields(line, &fields) != 4 or
        !std.mem.eql(u8, fields[0], "BENCH") or
        !std.mem.eql(u8, fields[1], "QUALITY_SUMMARY"))
    {
        return addMalformed(allocator, diagnostics, "quality summary", line_number);
    }
    const gates = parseFieldUnsigned(fields[2], "gates") orelse return addMalformed(allocator, diagnostics, "quality summary", line_number);
    const total_cycles = parseFieldUnsigned(fields[3], "total_cycles") orelse return addMalformed(allocator, diagnostics, "quality summary", line_number);
    log.quality_summary = .{ .gates = gates, .total_cycles = total_cycles };
}

fn parseSummaryLine(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    log: *Log,
    line: []const u8,
    line_number: usize,
) !void {
    if (log.summary != null) {
        try diagnostics.add(allocator, "Duplicate benchmark summary on log line {d}", .{line_number});
        return;
    }
    var fields: [7][]const u8 = undefined;
    if (splitFields(line, &fields) != 6 or
        !std.mem.eql(u8, fields[0], "BENCH") or
        !std.mem.eql(u8, fields[1], "SUMMARY"))
    {
        return addMalformed(allocator, diagnostics, "benchmark summary", line_number);
    }
    const benchmarks = parseFieldUnsigned(fields[2], "benchmarks") orelse return addMalformed(allocator, diagnostics, "benchmark summary", line_number);
    const quality_gates = parseFieldUnsigned(fields[3], "quality_gates") orelse return addMalformed(allocator, diagnostics, "benchmark summary", line_number);
    const quality_cycles = parseFieldUnsigned(fields[4], "quality_cycles") orelse return addMalformed(allocator, diagnostics, "benchmark summary", line_number);
    const total_cycles = parseFieldUnsigned(fields[5], "total_cycles") orelse return addMalformed(allocator, diagnostics, "benchmark summary", line_number);
    log.summary = .{
        .benchmarks = benchmarks,
        .quality_gates = quality_gates,
        .quality_cycles = quality_cycles,
        .total_cycles = total_cycles,
    };
}

fn parseFieldUnsigned(field: []const u8, key: []const u8) ?u64 {
    return parseUnsigned(fieldValue(field, key) orelse return null);
}

fn addMalformed(
    allocator: std.mem.Allocator,
    diagnostics: *Diagnostics,
    kind: []const u8,
    line_number: usize,
) error{OutOfMemory}!void {
    try diagnostics.add(allocator, "Malformed {s} on log line {d}", .{ kind, line_number });
}

fn validateAnalysis(allocator: std.mem.Allocator, analysis: *Analysis) !void {
    const enforce_performance = performanceGatesEnforced(&analysis.log);
    for (analysis.thresholds.entries.items) |threshold| {
        if (!analysis.baselines.by_name.contains(threshold.name)) {
            try analysis.diagnostics.add(allocator, "Threshold {s} has no matching baseline", .{threshold.name});
        }
    }
    for (analysis.baselines.entries.items) |baseline| {
        if (!analysis.thresholds.by_name.contains(baseline.name)) {
            try analysis.diagnostics.add(allocator, "Baseline {s} has no matching threshold", .{baseline.name});
        }
    }

    for (analysis.log.results.entries.items) |result| {
        if (!analysis.thresholds.by_name.contains(result.name)) {
            try analysis.diagnostics.add(allocator, "Untracked benchmark result: {s}", .{result.name});
        }
    }
    for (analysis.thresholds.entries.items) |threshold| {
        const result = lookup(Result, &analysis.log.results, threshold.name) orelse {
            try analysis.diagnostics.add(allocator, "Missing benchmark result: {s}", .{threshold.name});
            continue;
        };
        const threshold_scaled = std.math.mul(u64, threshold.max_cycles, 100) catch {
            try analysis.diagnostics.add(allocator, "Threshold for {s} overflows fixed-point scaling", .{threshold.name});
            continue;
        };
        if (enforce_performance and result.cycles_per_op_hundredths > threshold_scaled) {
            try analysis.diagnostics.add(
                allocator,
                "Benchmark threshold failed for {s}: {d}.{d:0>2} > {d} cycles/op",
                .{
                    threshold.name,
                    result.cycles_per_op_hundredths / 100,
                    result.cycles_per_op_hundredths % 100,
                    threshold.max_cycles,
                },
            );
        }
        if (enforce_performance) {
            if (lookup(Baseline, &analysis.baselines, threshold.name)) |baseline| {
                if (!passesBaseline(result.cycles_per_op_hundredths, baseline)) {
                    try analysis.diagnostics.add(
                        allocator,
                        "Benchmark baseline regression for {s}: {d}.{d:0>2} exceeds {d}.{d:0>2} with {d}% allowance",
                        .{
                            threshold.name,
                            result.cycles_per_op_hundredths / 100,
                            result.cycles_per_op_hundredths % 100,
                            baseline.cycles_hundredths / 100,
                            baseline.cycles_hundredths % 100,
                            baseline.allowed_percent,
                        },
                    );
                }
            }
        }
    }

    for (analysis.log.quality_results.entries.items) |result| {
        if (!analysis.quality_gates.by_name.contains(result.name)) {
            try analysis.diagnostics.add(allocator, "Untracked quality result: {s}", .{result.name});
        }
    }
    for (analysis.quality_gates.entries.items) |gate| {
        const result = lookup(QualityResult, &analysis.log.quality_results, gate.name) orelse {
            try analysis.diagnostics.add(allocator, "Missing quality result: {s}", .{gate.name});
            continue;
        };
        if (gate.minimum) |minimum| {
            if (result.value < minimum) try analysis.diagnostics.add(
                allocator,
                "Quality gate failed for {s}: {d} < {d}",
                .{ gate.name, result.value, minimum },
            );
        }
        if (gate.maximum) |maximum| {
            if (result.value > maximum) try analysis.diagnostics.add(
                allocator,
                "Quality gate failed for {s}: {d} > {d}",
                .{ gate.name, result.value, maximum },
            );
        }
    }

    if (analysis.log.start_markers != 1) try analysis.diagnostics.add(
        allocator,
        "Benchmark log must contain exactly one BENCH:START marker; found {d}",
        .{analysis.log.start_markers},
    );
    if (analysis.log.pass_markers != 1) try analysis.diagnostics.add(
        allocator,
        "Benchmark log must contain exactly one BENCH:PASS marker; found {d}",
        .{analysis.log.pass_markers},
    );
    if (analysis.log.accelerator_markers != 1) try analysis.diagnostics.add(
        allocator,
        "Benchmark log must contain exactly one BENCH:ENV accelerator record; found {d}",
        .{analysis.log.accelerator_markers},
    );

    const benchmark_cycles = checkedCycleTotal(Result, analysis.log.results.entries.items);
    if (benchmark_cycles == null) try analysis.diagnostics.add(
        allocator,
        "Benchmark result cycle total overflows u64",
        .{},
    );
    const quality_cycles = checkedCycleTotal(QualityResult, analysis.log.quality_results.entries.items);
    if (quality_cycles == null) try analysis.diagnostics.add(
        allocator,
        "Quality result cycle total overflows u64",
        .{},
    );

    if (analysis.log.quality_summary) |summary| {
        if (summary.gates != analysis.log.quality_results.entries.items.len) try analysis.diagnostics.add(
            allocator,
            "Quality summary count does not match parsed quality results",
            .{},
        );
        if (quality_cycles) |total| {
            if (summary.total_cycles != total) try analysis.diagnostics.add(
                allocator,
                "Quality summary cycles do not match parsed quality results",
                .{},
            );
        }
    } else {
        try analysis.diagnostics.add(allocator, "Missing BENCH:QUALITY_SUMMARY record", .{});
    }

    if (analysis.log.summary) |summary| {
        if (summary.benchmarks != analysis.log.results.entries.items.len) try analysis.diagnostics.add(
            allocator,
            "Benchmark summary count does not match parsed benchmark results",
            .{},
        );
        if (summary.quality_gates != analysis.log.quality_results.entries.items.len) try analysis.diagnostics.add(
            allocator,
            "Benchmark summary quality count does not match parsed quality results",
            .{},
        );
        if (quality_cycles) |total| {
            if (summary.quality_cycles != total) try analysis.diagnostics.add(
                allocator,
                "Benchmark summary quality cycles do not match parsed quality results",
                .{},
            );
        }
        if (benchmark_cycles) |total| {
            if (summary.total_cycles != total) try analysis.diagnostics.add(
                allocator,
                "Benchmark summary cycles do not match parsed benchmark results",
                .{},
            );
        }
    } else {
        try analysis.diagnostics.add(allocator, "Missing BENCH:SUMMARY record", .{});
    }
}

fn performanceGatesEnforced(log: *const Log) bool {
    const accelerator = log.accelerator orelse return false;
    return accelerator == .kvm;
}

fn acceleratorName(accelerator: ?Accelerator) []const u8 {
    const value = accelerator orelse return "UNKNOWN";
    return @tagName(value);
}

fn lookup(comptime Entry: type, table: *const Table(Entry), name: []const u8) ?Entry {
    const index = table.by_name.get(name) orelse return null;
    return table.entries.items[index];
}

fn checkedCycleTotal(comptime Entry: type, entries: []const Entry) ?u64 {
    var total: u64 = 0;
    for (entries) |entry| total = std.math.add(u64, total, entry.cycles) catch return null;
    return total;
}

fn passesBaseline(actual_hundredths: u64, baseline: Baseline) bool {
    const limit = baselineLimit(baseline.cycles_hundredths, baseline.allowed_percent) orelse return false;
    return @as(u128, actual_hundredths) * 100 <= limit;
}

fn baselineLimit(cycles_hundredths: u64, allowed_percent: u64) ?u128 {
    const multiplier = std.math.add(u128, @as(u128, allowed_percent), 100) catch return null;
    return std.math.mul(u128, @as(u128, cycles_hundredths), multiplier) catch null;
}

fn renderMarkdown(allocator: std.mem.Allocator, analysis: *const Analysis) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    const overall = if (analysis.diagnostics.items.items.len == 0) "PASS" else "FAIL";

    try writer.writeAll("## Kernel Benchmark Summary\n\n");
    try writer.print("- Overall status: `{s}`\n", .{overall});
    try writer.print("- Accelerator: `{s}`\n", .{acceleratorName(analysis.log.accelerator)});
    if (analysis.log.accelerator) |accelerator| {
        if (accelerator == .kvm) {
            try writer.writeAll("- Cycle ceilings: `ENFORCED`\n");
        } else {
            try writer.writeAll("- Cycle ceilings: `NOT ENFORCED` (software-emulation functional run)\n");
        }
    } else {
        try writer.writeAll("- Cycle ceilings: `UNAVAILABLE`\n");
    }
    if (analysis.log.summary) |summary| {
        try writer.print("- Benchmarks reported: `{d}`\n", .{summary.benchmarks});
        try writer.print("- Quality gates reported: `{d}`\n", .{summary.quality_gates});
        try writer.print("- Benchmark suite cycles: `{d}`\n", .{summary.total_cycles});
    }
    try writer.writeAll("\n| Benchmark | Iterations | Cycles/op | Threshold | Baseline | Status |\n");
    try writer.writeAll("| --- | ---: | ---: | ---: | ---: | --- |\n");
    for (analysis.thresholds.entries.items) |threshold| {
        const baseline = lookup(Baseline, &analysis.baselines, threshold.name);
        const result = lookup(Result, &analysis.log.results, threshold.name);
        if (result) |entry| {
            const threshold_scaled = std.math.mul(u64, threshold.max_cycles, 100) catch std.math.maxInt(u64);
            const row_passes = entry.cycles_per_op_hundredths <= threshold_scaled and
                (baseline == null or passesBaseline(entry.cycles_per_op_hundredths, baseline.?));
            try writer.print(
                "| `{s}` | {d} | {d}.{d:0>2} | <= {d} | ",
                .{
                    threshold.name,
                    entry.iterations,
                    entry.cycles_per_op_hundredths / 100,
                    entry.cycles_per_op_hundredths % 100,
                    threshold.max_cycles,
                },
            );
            if (baseline) |configured| {
                try writer.print(
                    "{d}.{d:0>2} (+{d}%)",
                    .{ configured.cycles_hundredths / 100, configured.cycles_hundredths % 100, configured.allowed_percent },
                );
            } else {
                try writer.writeAll("--");
            }
            const row_status = if (!performanceGatesEnforced(&analysis.log))
                "NOT ENFORCED"
            else if (row_passes)
                "PASS"
            else
                "FAIL";
            try writer.print(" | {s} |\n", .{row_status});
        } else {
            try writer.print("| `{s}` | -- | -- | <= {d} | -- | MISSING |\n", .{ threshold.name, threshold.max_cycles });
        }
    }

    try writer.writeAll("\n| Quality gate | Value | Minimum | Maximum | Status |\n");
    try writer.writeAll("| --- | ---: | ---: | ---: | --- |\n");
    for (analysis.quality_gates.entries.items) |gate| {
        if (lookup(QualityResult, &analysis.log.quality_results, gate.name)) |entry| {
            const row_passes = (gate.minimum == null or entry.value >= gate.minimum.?) and
                (gate.maximum == null or entry.value <= gate.maximum.?);
            try writer.print("| `{s}` | {d} | ", .{ gate.name, entry.value });
            if (gate.minimum) |minimum| try writer.print("{d}", .{minimum}) else try writer.writeAll("--");
            try writer.writeAll(" | ");
            if (gate.maximum) |maximum| try writer.print("{d}", .{maximum}) else try writer.writeAll("--");
            try writer.print(" | {s} |\n", .{if (row_passes) "PASS" else "FAIL"});
        } else {
            try writer.print("| `{s}` | -- | -- | -- | MISSING |\n", .{gate.name});
        }
    }

    if (analysis.diagnostics.items.items.len != 0) {
        try writer.writeAll("\n### Validation failures\n\n");
        for (analysis.diagnostics.items.items) |message| try writer.print("- {s}\n", .{message});
    }
    return output.toOwnedSlice();
}

const valid_thresholds = "bench.case 10\n";
const valid_baselines = "bench.case 10.00 0\n";
const valid_quality_gates = "gate.case 1 1\n";
const valid_log_without_environment =
    \\BOOT:START
    \\BENCH:START
    \\BENCH:RESULT:bench.case:iterations=100:cycles=1000:cycles_per_op=10.00:checksum=7
    \\BENCH:QUALITY:gate.case:value=1:cycles=5
    \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
    \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=1000
    \\BENCH:PASS
;
const valid_log = "BENCH:ENV:accelerator=kvm\n" ++ valid_log_without_environment;

fn analyzeFixture(
    allocator: std.mem.Allocator,
    thresholds: []const u8,
    baselines: []const u8,
    quality_gates: []const u8,
    log_source: []const u8,
) !Analysis {
    var analysis = Analysis.init(allocator);
    try analyzeSources(allocator, &analysis, thresholds, baselines, quality_gates, log_source);
    return analysis;
}

fn diagnosticsContain(analysis: *const Analysis, needle: []const u8) bool {
    for (analysis.diagnostics.items.items) |message| {
        if (std.mem.indexOf(u8, message, needle) != null) return true;
    }
    return false;
}

test "accepts a complete internally consistent benchmark report" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, valid_log);
    try std.testing.expectEqual(@as(usize, 0), analysis.diagnostics.items.items.len);
}

test "accepts CRLF config and final lines without newline" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(
        arena.allocator(),
        "# threshold\r\nbench.case 10",
        "bench.case 10.00 0\r\n",
        "gate.case 1 1",
        valid_log,
    );
    try std.testing.expectEqual(@as(usize, 0), analysis.diagnostics.items.items.len);
}

test "rejects duplicate results even when the final result passes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const duplicate_log = valid_log ++
        "\nBENCH:RESULT:bench.case:iterations=100:cycles=1000:cycles_per_op=10.00:checksum=7\n";
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, duplicate_log);
    try std.testing.expect(diagnosticsContain(&analysis, "Duplicate benchmark result"));
}

test "rejects non-numeric and extra-column config values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(
        arena.allocator(),
        "bench.case NaN trailing\n",
        valid_baselines,
        valid_quality_gates,
        valid_log,
    );
    try std.testing.expect(diagnosticsContain(&analysis, "exactly 2 columns"));
}

test "rejects forged cycles per operation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const forged_log =
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=1000:cycles_per_op=9.99:checksum=7
        \\BENCH:QUALITY:gate.case:value=1:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=1000
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, forged_log);
    try std.testing.expect(diagnosticsContain(&analysis, "inconsistent cycles_per_op"));
}

test "rejects mismatched summary totals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const bad_summary_log =
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=1000:cycles_per_op=10.00:checksum=7
        \\BENCH:QUALITY:gate.case:value=1:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=4
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=4:total_cycles=999
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, bad_summary_log);
    try std.testing.expect(diagnosticsContain(&analysis, "summary cycles"));
}

test "enforces threshold baseline and quality boundaries with integer math" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const over_log =
        \\BENCH:ENV:accelerator=kvm
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=1001:cycles_per_op=10.01:checksum=7
        \\BENCH:QUALITY:gate.case:value=2:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=1001
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, over_log);
    try std.testing.expect(diagnosticsContain(&analysis, "Benchmark threshold failed"));
    try std.testing.expect(diagnosticsContain(&analysis, "Benchmark baseline regression"));
    try std.testing.expect(diagnosticsContain(&analysis, "Quality gate failed"));
}

test "software emulation skips cycle ceilings but retains quality gates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const tcg_log =
        \\BENCH:ENV:accelerator=tcg
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=100000:cycles_per_op=1000.00:checksum=7
        \\BENCH:QUALITY:gate.case:value=1:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=100000
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, tcg_log);
    try std.testing.expectEqual(@as(usize, 0), analysis.diagnostics.items.items.len);
    const markdown = try renderMarkdown(arena.allocator(), &analysis);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "Cycle ceilings: `NOT ENFORCED`") != null);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "| NOT ENFORCED |") != null);
}

test "software emulation still enforces structural and quality gates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const bad_tcg_log =
        \\BENCH:ENV:accelerator=tcg
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=100000:cycles_per_op=1000.00:checksum=7
        \\BENCH:QUALITY:gate.case:value=2:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=100000
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, bad_tcg_log);
    try std.testing.expect(diagnosticsContain(&analysis, "Quality gate failed"));
    try std.testing.expect(!diagnosticsContain(&analysis, "Benchmark threshold failed"));
    try std.testing.expect(!diagnosticsContain(&analysis, "Benchmark baseline regression"));
}

test "requires one supported accelerator record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const missing = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, valid_log_without_environment);
    try std.testing.expect(diagnosticsContain(&missing, "exactly one BENCH:ENV accelerator record"));

    const duplicate = try analyzeFixture(
        arena.allocator(),
        valid_thresholds,
        valid_baselines,
        valid_quality_gates,
        valid_log ++ "\nBENCH:ENV:accelerator=kvm\n",
    );
    try std.testing.expect(diagnosticsContain(&duplicate, "Duplicate benchmark accelerator record"));

    const unsupported_log = "BENCH:ENV:accelerator=hvf\n" ++ valid_log_without_environment;
    const unsupported = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, unsupported_log);
    try std.testing.expect(diagnosticsContain(&unsupported, "Unsupported benchmark accelerator"));
}

test "rejects duplicate and nonsensical quality-gate configuration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(
        arena.allocator(),
        valid_thresholds,
        valid_baselines,
        "gate.case - -\ngate.case 2 1\n",
        valid_log,
    );
    try std.testing.expect(diagnosticsContain(&analysis, "must set at least one bound"));
    try std.testing.expect(diagnosticsContain(&analysis, "minimum greater than maximum"));
}

test "rejects baseline allowance multiplication overflow in every optimization mode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(
        arena.allocator(),
        valid_thresholds,
        "bench.case 184467440737095516.15 18446744073709551615\n",
        valid_quality_gates,
        valid_log,
    );
    try std.testing.expect(diagnosticsContain(&analysis, "overflows allowance calculation"));
}

test "rejects duplicate config entries and mismatched benchmark sets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(
        arena.allocator(),
        "bench.case 10\nbench.case 11\n",
        "bench.case 10.00 0\nother.case 1.00 0\n",
        valid_quality_gates,
        valid_log,
    );
    try std.testing.expect(diagnosticsContain(&analysis, "Duplicate threshold"));
    try std.testing.expect(diagnosticsContain(&analysis, "no matching threshold"));
}

test "rejects malformed record shapes and duplicate summaries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const malformed_log =
        \\BENCH:START
        \\BENCH:RESULT:bench.case:iterations=100:cycles=1000:cycles_per_op=10:checksum=7
        \\BENCH:QUALITY:gate.case:value=1:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=0:quality_gates=1:quality_cycles=5:total_cycles=0
        \\BENCH:SUMMARY:benchmarks=0:quality_gates=1:quality_cycles=5:total_cycles=0
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, malformed_log);
    try std.testing.expect(diagnosticsContain(&analysis, "Malformed benchmark result"));
    try std.testing.expect(diagnosticsContain(&analysis, "Duplicate benchmark summary"));
}

test "rejects missing configured records and untracked log records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const untracked_log =
        \\BENCH:START
        \\BENCH:RESULT:other.case:iterations=100:cycles=1000:cycles_per_op=10.00:checksum=7
        \\BENCH:QUALITY:other.gate:value=1:cycles=5
        \\BENCH:QUALITY_SUMMARY:gates=1:total_cycles=5
        \\BENCH:SUMMARY:benchmarks=1:quality_gates=1:quality_cycles=5:total_cycles=1000
        \\BENCH:PASS
    ;
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, untracked_log);
    try std.testing.expect(diagnosticsContain(&analysis, "Untracked benchmark result"));
    try std.testing.expect(diagnosticsContain(&analysis, "Missing benchmark result"));
    try std.testing.expect(diagnosticsContain(&analysis, "Untracked quality result"));
    try std.testing.expect(diagnosticsContain(&analysis, "Missing quality result"));
}

test "renders incomplete input as a deterministic failure summary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const analysis = try analyzeFixture(arena.allocator(), valid_thresholds, valid_baselines, valid_quality_gates, "");
    const markdown = try renderMarkdown(arena.allocator(), &analysis);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "Overall status: `FAIL`") != null);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "| `bench.case` | -- | -- | <= 10 | -- | MISSING |") != null);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "Missing BENCH:SUMMARY record") != null);
}

test "rejects aggregate overflow for benchmark and quality cycle totals" {
    const per_record_cycles = std.math.maxInt(u64) / 100;
    var results: [101]Result = undefined;
    for (&results) |*result| result.* = .{
        .name = "bench.case",
        .iterations = 1,
        .cycles = per_record_cycles,
        .cycles_per_op_hundredths = 0,
        .checksum = 0,
        .line = 1,
    };
    var quality_results: [101]QualityResult = undefined;
    for (&quality_results) |*result| result.* = .{
        .name = "gate.case",
        .value = 1,
        .cycles = per_record_cycles,
        .line = 1,
    };

    try std.testing.expectEqual(@as(?u64, null), checkedCycleTotal(Result, &results));
    try std.testing.expectEqual(@as(?u64, null), checkedCycleTotal(QualityResult, &quality_results));
}
