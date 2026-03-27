const std = @import("std");

pub const MAX_COMMAND_LENGTH = 256;
pub const MAX_ARGS = 16;
pub const MAX_PIPE_STAGES = 8;
pub const MAX_TOKENS = 32;

pub const TokenizationError = error{
    UnterminatedQuote,
    UnterminatedSubstitution,
    TrailingEscape,
    TooManyTokens,
    TokenTooLong,
    CommandSubstitutionFailed,
};

const TokenCharClass = enum(u4) {
    other,
    whitespace,
    single_quote,
    double_quote,
    backslash,
    dollar,
    pipe,
    stdin_redirect,
    stdout_redirect,
    background,
    glob,
};

const CharFlag = struct {
    const var_char: u8 = 1 << 0;
    const wildcard: u8 = 1 << 1;
};

const token_char_classes = initTokenCharClasses();
const char_flags = initCharFlags();

fn initTokenCharClasses() [256]TokenCharClass {
    var table = [_]TokenCharClass{.other} ** 256;
    table[' '] = .whitespace;
    table['\t'] = .whitespace;
    table['\n'] = .whitespace;
    table['\r'] = .whitespace;
    table['\''] = .single_quote;
    table['"'] = .double_quote;
    table['\\'] = .backslash;
    table['$'] = .dollar;
    table['|'] = .pipe;
    table['<'] = .stdin_redirect;
    table['>'] = .stdout_redirect;
    table['&'] = .background;
    table['*'] = .glob;
    table['?'] = .glob;
    return table;
}

fn initCharFlags() [256]u8 {
    var table = [_]u8{0} ** 256;

    var ch: u16 = '0';
    while (ch <= '9') : (ch += 1) {
        table[@as(usize, ch)] |= CharFlag.var_char;
    }

    ch = 'A';
    while (ch <= 'Z') : (ch += 1) {
        table[@as(usize, ch)] |= CharFlag.var_char;
    }

    ch = 'a';
    while (ch <= 'z') : (ch += 1) {
        table[@as(usize, ch)] |= CharFlag.var_char;
    }

    table['_'] |= CharFlag.var_char;
    table['*'] |= CharFlag.wildcard;
    table['?'] |= CharFlag.wildcard;
    return table;
}

fn tokenCharClass(char: u8) TokenCharClass {
    return token_char_classes[@as(usize, char)];
}

fn charHasFlag(char: u8, flag: u8) bool {
    return (char_flags[@as(usize, char)] & flag) != 0;
}

pub const TokenKind = enum {
    word,
    pipe,
    stdin_redirect,
    stdout_redirect,
    append_stdout_redirect,
    background,
};

pub const CommandToken = struct {
    text: [*:0]const u8,
    len: usize,
    kind: TokenKind,
    has_glob: bool,

    pub fn slice(self: CommandToken) []const u8 {
        return tokenSlice(self);
    }
};

pub const CommandCaptureError = error{
    CommandFailed,
    NoSpaceLeft,
};

pub const ExpansionHooks = struct {
    context: ?*anyopaque = null,
    getVarFn: ?*const fn (?*anyopaque, []const u8) ?[]const u8 = null,
    captureCommandFn: ?*const fn (?*anyopaque, []const u8, []u8) CommandCaptureError!usize = null,
};

pub const PipelineConfigError = error{
    EmptyStage,
    MissingPath,
    TooManyStages,
    ArgumentTooLong,
    UnsupportedBuiltin,
    UnsupportedRedirection,
    AmbiguousRedirect,
    UnsupportedBackground,
    OpenFailed,
    PipeFailed,
    DupFailed,
    CloseFailed,
};

pub const ParsedStage = struct {
    args: [MAX_ARGS][*:0]const u8 = undefined,
    arg_glob: [MAX_ARGS]bool = [_]bool{false} ** MAX_ARGS,
    arg_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS,
    arg_count: usize = 0,
    stdin_path: ?[*:0]const u8 = null,
    stdin_glob: bool = false,
    stdin_path_storage: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
    stdout_path: ?[*:0]const u8 = null,
    stdout_glob: bool = false,
    stdout_path_storage: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
    append_stdout: bool = false,
};

pub const ParsedPipeline = struct {
    stages: [MAX_PIPE_STAGES]ParsedStage = [_]ParsedStage{ParsedStage{}} ** MAX_PIPE_STAGES,
    stage_count: usize = 0,
};

pub fn tokenizeCommandLine(
    input: []const u8,
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    out_tokens: *[MAX_TOKENS]CommandToken,
    hooks: ExpansionHooks,
    allow_command_substitution: bool,
) TokenizationError!usize {
    var token_count: usize = 0;
    var token_len: usize = 0;
    var token_active = false;
    var token_has_glob = false;
    var in_single_quote = false;
    var in_double_quote = false;
    var escaping = false;

    var idx: usize = 0;
    while (idx < input.len) : (idx += 1) {
        const char = input[idx];
        const char_class = tokenCharClass(char);

        if (escaping) {
            try appendTokenChar(storage, token_count, &token_len, char);
            token_active = true;
            escaping = false;
            continue;
        }

        if (in_single_quote) {
            if (char_class == .single_quote) {
                in_single_quote = false;
            } else {
                try appendTokenChar(storage, token_count, &token_len, char);
            }
            token_active = true;
            continue;
        }

        if (in_double_quote) {
            switch (char_class) {
                .double_quote => {
                    in_double_quote = false;
                },
                .backslash => {
                    escaping = true;
                },
                .dollar => {
                    try expandShellSubstitution(
                        input,
                        &idx,
                        storage,
                        token_count,
                        &token_len,
                        &token_has_glob,
                        hooks,
                        allow_command_substitution,
                        true,
                    );
                },
                else => {
                    try appendTokenChar(storage, token_count, &token_len, char);
                },
            }
            token_active = true;
            continue;
        }

        if (char_class == .whitespace) {
            if (token_active) {
                try finishWordToken(storage, out_tokens, &token_count, &token_len, &token_active, &token_has_glob);
            }
            continue;
        }

        switch (char_class) {
            .single_quote => {
                in_single_quote = true;
                token_active = true;
            },
            .double_quote => {
                in_double_quote = true;
                token_active = true;
            },
            .backslash => {
                escaping = true;
                token_active = true;
            },
            .dollar => {
                try expandShellSubstitution(
                    input,
                    &idx,
                    storage,
                    token_count,
                    &token_len,
                    &token_has_glob,
                    hooks,
                    allow_command_substitution,
                    false,
                );
                token_active = true;
            },
            .pipe, .stdin_redirect, .stdout_redirect, .background => {
                if (token_active) {
                    try finishWordToken(storage, out_tokens, &token_count, &token_len, &token_active, &token_has_glob);
                }

                const operator_len: usize = if (char_class == .stdout_redirect and idx + 1 < input.len and input[idx + 1] == '>') 2 else 1;
                try addOperatorToken(
                    storage,
                    out_tokens,
                    &token_count,
                    if (operator_len == 2) .append_stdout_redirect else switch (char_class) {
                        .pipe => .pipe,
                        .stdin_redirect => .stdin_redirect,
                        .stdout_redirect => .stdout_redirect,
                        .background => .background,
                        else => unreachable,
                    },
                    if (operator_len == 2) ">>" else input[idx .. idx + 1],
                );
                if (operator_len == 2) idx += 1;
            },
            .glob => {
                try appendTokenChar(storage, token_count, &token_len, char);
                token_active = true;
                token_has_glob = true;
            },
            else => {
                try appendTokenChar(storage, token_count, &token_len, char);
                token_active = true;
            },
        }
    }

    if (escaping) return error.TrailingEscape;
    if (in_single_quote or in_double_quote) return error.UnterminatedQuote;
    if (token_active) {
        try finishWordToken(storage, out_tokens, &token_count, &token_len, &token_active, &token_has_glob);
    }

    return token_count;
}

pub fn tokenSlice(token: CommandToken) []const u8 {
    return sliceFromCStr(token.text);
}

pub fn containsShellOperators(tokens: []const CommandToken) bool {
    for (tokens) |token| {
        if (token.kind != .word) return true;
    }
    return false;
}

pub fn isBackgroundRequest(tokens: []const CommandToken) bool {
    return tokens.len > 0 and tokens[tokens.len - 1].kind == .background;
}

pub fn isValidBackgroundPlacement(tokens: []const CommandToken) bool {
    var idx: usize = 0;
    while (idx < tokens.len) : (idx += 1) {
        if (tokens[idx].kind == .background and idx != tokens.len - 1) {
            return false;
        }
    }
    return true;
}

pub fn parsePipelineInto(tokens: []const CommandToken, result: *ParsedPipeline) PipelineConfigError!void {
    result.* = ParsedPipeline{};
    result.stage_count = 1;

    var stage_idx: usize = 0;
    var token_idx: usize = 0;
    while (token_idx < tokens.len) : (token_idx += 1) {
        const token = tokens[token_idx];
        var stage = &result.stages[stage_idx];

        switch (token.kind) {
            .pipe => {
                if (stage.arg_count == 0) return error.EmptyStage;
                if (stage_idx + 1 >= MAX_PIPE_STAGES) return error.TooManyStages;
                stage_idx += 1;
                result.stage_count = stage_idx + 1;
            },
            .stdin_redirect => {
                if (token_idx + 1 >= tokens.len or tokens[token_idx + 1].kind != .word) return error.MissingPath;
                if (stage_idx != 0 or stage.stdin_path != null) return error.UnsupportedRedirection;
                token_idx += 1;
                const path_token = tokens[token_idx];
                try copyIntoStageBuffer(&stage.stdin_path_storage, tokenSlice(path_token));
                stage.stdin_path = @ptrCast(&stage.stdin_path_storage[0]);
                stage.stdin_glob = path_token.has_glob;
            },
            .stdout_redirect, .append_stdout_redirect => {
                if (token_idx + 1 >= tokens.len or tokens[token_idx + 1].kind != .word) return error.MissingPath;
                if (stage.stdout_path != null) return error.UnsupportedRedirection;
                token_idx += 1;
                const path_token = tokens[token_idx];
                try copyIntoStageBuffer(&stage.stdout_path_storage, tokenSlice(path_token));
                stage.stdout_path = @ptrCast(&stage.stdout_path_storage[0]);
                stage.stdout_glob = path_token.has_glob;
                stage.append_stdout = token.kind == .append_stdout_redirect;
            },
            .word => {
                if (stage.arg_count >= MAX_ARGS) return error.ArgumentTooLong;
                try copyIntoStageBuffer(&stage.arg_storage[stage.arg_count], tokenSlice(token));
                stage.args[stage.arg_count] = @ptrCast(&stage.arg_storage[stage.arg_count][0]);
                stage.arg_glob[stage.arg_count] = token.has_glob;
                stage.arg_count += 1;
            },
            .background => return error.UnsupportedBackground,
        }
    }

    for (result.stages[0..result.stage_count]) |stage| {
        if (stage.arg_count == 0) return error.EmptyStage;
    }

    if (result.stage_count > 1) {
        if (result.stages[0].stdout_path != null) return error.UnsupportedRedirection;
        var idx: usize = 1;
        while (idx < result.stage_count) : (idx += 1) {
            const stage = result.stages[idx];
            if (idx < result.stage_count - 1 and stage.stdout_path != null) return error.UnsupportedRedirection;
            if (stage.stdin_path != null) return error.UnsupportedRedirection;
        }
    }
}

pub fn parsePipeline(tokens: []const CommandToken) PipelineConfigError!ParsedPipeline {
    var result = ParsedPipeline{};
    try parsePipelineInto(tokens, &result);
    return result;
}

fn appendTokenChar(
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    token_index: usize,
    token_len: *usize,
    char: u8,
) TokenizationError!void {
    if (token_index >= MAX_TOKENS) return error.TooManyTokens;
    if (token_len.* + 1 >= MAX_COMMAND_LENGTH) return error.TokenTooLong;
    storage[token_index][token_len.*] = char;
    token_len.* += 1;
}

fn appendTokenText(
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    token_index: usize,
    token_len: *usize,
    text: []const u8,
) TokenizationError!void {
    for (text) |char| {
        try appendTokenChar(storage, token_index, token_len, char);
    }
}

fn expandShellSubstitution(
    input: []const u8,
    idx: *usize,
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    token_index: usize,
    token_len: *usize,
    token_has_glob: *bool,
    hooks: ExpansionHooks,
    allow_command_substitution: bool,
    quoted: bool,
) TokenizationError!void {
    if (idx.* + 1 >= input.len) {
        try appendTokenChar(storage, token_index, token_len, '$');
        return;
    }

    if (input[idx.* + 1] == '(') {
        if (!allow_command_substitution) return error.CommandSubstitutionFailed;
        const sub_slice = parseCommandSubstitution(input, idx) catch return error.UnterminatedSubstitution;
        const capture_command = hooks.captureCommandFn orelse return error.CommandSubstitutionFailed;
        var output_buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
        const output_len = capture_command(hooks.context, sub_slice, &output_buffer) catch return error.CommandSubstitutionFailed;
        try appendTokenText(storage, token_index, token_len, output_buffer[0..output_len]);
        if (!quoted and containsWildcardChars(output_buffer[0..output_len])) {
            token_has_glob.* = true;
        }
        return;
    }

    const maybe_var = parseVariableReference(input, idx);
    if (maybe_var == null) {
        try appendTokenChar(storage, token_index, token_len, '$');
        return;
    }

    const get_var = hooks.getVarFn orelse return;
    if (get_var(hooks.context, maybe_var.?)) |value| {
        try appendTokenText(storage, token_index, token_len, value);
        if (!quoted and containsWildcardChars(value)) {
            token_has_glob.* = true;
        }
    }
}

fn parseVariableReference(input: []const u8, idx: *usize) ?[]const u8 {
    const next = idx.* + 1;
    if (next >= input.len) return null;

    if (input[next] == '{') {
        var end = next + 1;
        while (end < input.len and input[end] != '}') : (end += 1) {}
        if (end >= input.len) return null;
        idx.* = end;
        return input[next + 1 .. end];
    }

    var end = next;
    while (end < input.len and isVarChar(input[end])) : (end += 1) {}
    if (end == next) return null;
    idx.* = end - 1;
    return input[next..end];
}

fn parseCommandSubstitution(input: []const u8, idx: *usize) error{Unterminated}![]const u8 {
    var depth: usize = 1;
    var cursor = idx.* + 2;
    var in_single_quote = false;
    var in_double_quote = false;
    var escaping = false;

    while (cursor < input.len) : (cursor += 1) {
        const char = input[cursor];
        const char_class = tokenCharClass(char);

        if (escaping) {
            escaping = false;
            continue;
        }

        if (in_single_quote) {
            if (char_class == .single_quote) in_single_quote = false;
            continue;
        }

        if (in_double_quote) {
            switch (char_class) {
                .double_quote => in_double_quote = false,
                .backslash => escaping = true,
                else => {},
            }
            continue;
        }

        switch (char_class) {
            .single_quote => in_single_quote = true,
            .double_quote => in_double_quote = true,
            .backslash => escaping = true,
            else => switch (char) {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if (depth == 0) {
                        const sub = input[idx.* + 2 .. cursor];
                        idx.* = cursor;
                        return sub;
                    }
                },
                else => {},
            },
        }
    }

    return error.Unterminated;
}

fn finishWordToken(
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    out_tokens: *[MAX_TOKENS]CommandToken,
    token_count: *usize,
    token_len: *usize,
    token_active: *bool,
    token_has_glob: *bool,
) TokenizationError!void {
    if (token_count.* >= MAX_TOKENS) return error.TooManyTokens;
    storage[token_count.*][token_len.*] = 0;
    out_tokens[token_count.*] = .{
        .text = @ptrCast(&storage[token_count.*][0]),
        .len = token_len.*,
        .kind = .word,
        .has_glob = token_has_glob.*,
    };
    token_count.* += 1;
    token_len.* = 0;
    token_active.* = false;
    token_has_glob.* = false;
}

fn addOperatorToken(
    storage: *[MAX_TOKENS][MAX_COMMAND_LENGTH]u8,
    out_tokens: *[MAX_TOKENS]CommandToken,
    token_count: *usize,
    kind: TokenKind,
    text: []const u8,
) TokenizationError!void {
    if (token_count.* >= MAX_TOKENS) return error.TooManyTokens;
    if (text.len + 1 >= MAX_COMMAND_LENGTH) return error.TokenTooLong;
    @memcpy(storage[token_count.*][0..text.len], text);
    storage[token_count.*][text.len] = 0;
    out_tokens[token_count.*] = .{
        .text = @ptrCast(&storage[token_count.*][0]),
        .len = text.len,
        .kind = kind,
        .has_glob = false,
    };
    token_count.* += 1;
}

fn copyIntoStageBuffer(buffer: *[MAX_COMMAND_LENGTH]u8, text: []const u8) PipelineConfigError!void {
    if (text.len >= buffer.len) return error.ArgumentTooLong;
    @memset(buffer, 0);
    @memcpy(buffer[0..text.len], text);
}

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}

fn containsWildcardChars(text: []const u8) bool {
    for (text) |char| {
        if (charHasFlag(char, CharFlag.wildcard)) return true;
    }
    return false;
}

fn isVarChar(char: u8) bool {
    return charHasFlag(char, CharFlag.var_char);
}

const TestHooks = struct {
    fn getVar(_: ?*anyopaque, name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "USER")) return "root";
        if (std.mem.eql(u8, name, "GLOB")) return "*.zig";
        return null;
    }

    fn captureCommand(_: ?*anyopaque, line: []const u8, output: []u8) CommandCaptureError!usize {
        if (std.mem.eql(u8, line, "printf hi")) {
            @memcpy(output[0..2], "hi");
            return 2;
        }
        if (std.mem.eql(u8, line, "printf *.zig")) {
            @memcpy(output[0..5], "*.zig");
            return 5;
        }
        return error.CommandFailed;
    }
};

const TestRng = struct {
    state: u64,

    fn next(self: *TestRng) u64 {
        self.state = self.state *% 6364136223846793005 +% 1;
        return self.state;
    }

    fn choose(self: *TestRng, limit: usize) usize {
        if (limit == 0) return 0;
        return @intCast(self.next() % limit);
    }
};

fn randomCommand(rng: *TestRng, buffer: []u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t'\"\\$()|<>*&?._/-";
    const len = rng.choose(buffer.len + 1);
    for (buffer[0..len]) |*byte| {
        byte.* = alphabet[rng.choose(alphabet.len)];
    }
    return buffer[0..len];
}

test "tokenize handles quotes variables and substitutions" {
    var storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;

    const hooks = ExpansionHooks{
        .getVarFn = TestHooks.getVar,
        .captureCommandFn = TestHooks.captureCommand,
    };

    const token_count = try tokenizeCommandLine(
        "echo \"$USER\" $(printf hi) '*.txt' $GLOB",
        &storage,
        &tokens,
        hooks,
        true,
    );

    try std.testing.expectEqual(@as(usize, 5), token_count);
    try std.testing.expectEqualStrings("echo", tokenSlice(tokens[0]));
    try std.testing.expectEqualStrings("root", tokenSlice(tokens[1]));
    try std.testing.expectEqualStrings("hi", tokenSlice(tokens[2]));
    try std.testing.expectEqualStrings("*.txt", tokenSlice(tokens[3]));
    try std.testing.expectEqualStrings("*.zig", tokenSlice(tokens[4]));
    try std.testing.expect(!tokens[1].has_glob);
    try std.testing.expect(!tokens[2].has_glob);
    try std.testing.expect(tokens[4].has_glob);
}

test "tokenize rejects unterminated substitution" {
    var storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;

    try std.testing.expectError(
        error.UnterminatedSubstitution,
        tokenizeCommandLine("echo $(printf hi", &storage, &tokens, .{}, true),
    );
}

test "background helper validates final placement" {
    var storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;

    const token_count = try tokenizeCommandLine("sleep 1 &", &storage, &tokens, .{}, true);
    try std.testing.expect(isBackgroundRequest(tokens[0..token_count]));
    try std.testing.expect(isValidBackgroundPlacement(tokens[0..token_count]));

    const invalid_count = try tokenizeCommandLine("sleep & 1", &storage, &tokens, .{}, true);
    try std.testing.expect(!isValidBackgroundPlacement(tokens[0..invalid_count]));
}

test "parsePipeline tracks redirects and rejects invalid intermediate redirects" {
    var storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;

    const token_count = try tokenizeCommandLine("cat < in.txt | grep zig | wc > out.txt", &storage, &tokens, .{}, true);
    const pipeline = try parsePipeline(tokens[0..token_count]);
    try std.testing.expectEqual(@as(usize, 3), pipeline.stage_count);
    try std.testing.expectEqualStrings("cat", tokenSlice(.{
        .text = pipeline.stages[0].args[0],
        .len = 3,
        .kind = .word,
        .has_glob = false,
    }));
    try std.testing.expectEqualStrings("in.txt", sliceFromCStr(pipeline.stages[0].stdin_path.?));
    try std.testing.expectEqualStrings("out.txt", sliceFromCStr(pipeline.stages[2].stdout_path.?));

    const invalid_count = try tokenizeCommandLine("cat | grep zig > tmp | wc", &storage, &tokens, .{}, true);
    try std.testing.expectError(error.UnsupportedRedirection, parsePipeline(tokens[0..invalid_count]));
}

test "tokenize randomized command corpus stays within parser invariants" {
    var rng = TestRng{ .state = 0x1234_5678_9ABC_DEF0 };
    var input_buf: [MAX_COMMAND_LENGTH]u8 = undefined;
    var storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = undefined;
    var tokens: [MAX_TOKENS]CommandToken = undefined;

    const hooks = ExpansionHooks{
        .getVarFn = TestHooks.getVar,
        .captureCommandFn = TestHooks.captureCommand,
    };

    for (0..1024) |_| {
        const input = randomCommand(&rng, &input_buf);
        const token_count = tokenizeCommandLine(input, &storage, &tokens, hooks, true) catch continue;

        try std.testing.expect(token_count <= MAX_TOKENS);
        for (tokens[0..token_count]) |token| {
            try std.testing.expect(token.len < MAX_COMMAND_LENGTH);
            try std.testing.expect(token.text[token.len] == 0);
        }

        if (parsePipeline(tokens[0..token_count])) |pipeline| {
            try std.testing.expect(pipeline.stage_count <= MAX_PIPE_STAGES);
        } else |_| {}
    }
}
