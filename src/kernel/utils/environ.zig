const console = @import("console.zig");
const panic_utils = @import("panic.zig");

const MAX_ENV_VARS = 64;
const MAX_VAR_NAME_LEN = 64;
const MAX_VAR_VALUE_LEN = 256;

pub const MAX_EXPORT_ENTRIES = MAX_ENV_VARS;
pub const MAX_EXPORT_ENTRY_LEN = MAX_VAR_NAME_LEN + 1 + MAX_VAR_VALUE_LEN;

pub const EnvVar = struct {
    name: [MAX_VAR_NAME_LEN]u8,
    value: [MAX_VAR_VALUE_LEN]u8,
    name_len: usize,
    value_len: usize,
};

// SAFETY: entries are initialized on demand via setenv; env_count tracks valid entries
var env_vars: [MAX_ENV_VARS]EnvVar = undefined;
var env_count: usize = 0;
var initialized: bool = false;

pub fn init() void {
    if (initialized) return;

    env_count = 0;
    for (&env_vars) |*var_entry| {
        var_entry.name = [_]u8{0} ** MAX_VAR_NAME_LEN;
        var_entry.value = [_]u8{0} ** MAX_VAR_VALUE_LEN;
        var_entry.name_len = 0;
        var_entry.value_len = 0;
    }

    initialized = true;

    setDefaultVar("PATH", "/bin:/usr/bin:/mnt/bin");
    setDefaultVar("HOME", "/home/user");
    setDefaultVar("SHELL", "/bin/sh");
    setDefaultVar("USER", "root");
    setDefaultVar("TERM", "vga");
}

fn setDefaultVar(comptime name: []const u8, comptime value: []const u8) void {
    setVar(name, value) catch |err| panic_utils.panic(
        "Default environment variable violates invariant: {s}={s}: {s}",
        .{ name, value, @errorName(err) },
    );
}

pub fn setVar(name: []const u8, value: []const u8) !void {
    if (!initialized) init();

    if (name.len == 0 or name.len >= MAX_VAR_NAME_LEN) {
        return error.InvalidName;
    }

    if (value.len >= MAX_VAR_VALUE_LEN) {
        return error.ValueTooLong;
    }

    var i: usize = 0;
    while (i < env_count) : (i += 1) {
        if (env_vars[i].name_len == name.len) {
            var match = true;
            var j: usize = 0;
            while (j < name.len) : (j += 1) {
                if (env_vars[i].name[j] != name[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                @memcpy(env_vars[i].value[0..value.len], value);
                env_vars[i].value_len = value.len;
                env_vars[i].value[value.len] = 0;
                return;
            }
        }
    }

    if (env_count >= MAX_ENV_VARS) {
        return error.TooManyVars;
    }

    @memcpy(env_vars[env_count].name[0..name.len], name);
    env_vars[env_count].name[name.len] = 0;
    env_vars[env_count].name_len = name.len;

    @memcpy(env_vars[env_count].value[0..value.len], value);
    env_vars[env_count].value[value.len] = 0;
    env_vars[env_count].value_len = value.len;

    env_count += 1;
}

pub fn getVar(name: []const u8) ?[]const u8 {
    if (!initialized) init();

    var i: usize = 0;
    while (i < env_count) : (i += 1) {
        if (env_vars[i].name_len == name.len) {
            var match = true;
            var j: usize = 0;
            while (j < name.len) : (j += 1) {
                if (env_vars[i].name[j] != name[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return env_vars[i].value[0..env_vars[i].value_len];
            }
        }
    }

    return null;
}

pub fn unsetVar(name: []const u8) void {
    if (!initialized) return;

    var i: usize = 0;
    while (i < env_count) : (i += 1) {
        if (env_vars[i].name_len == name.len) {
            var match = true;
            var j: usize = 0;
            while (j < name.len) : (j += 1) {
                if (env_vars[i].name[j] != name[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                var k = i;
                while (k < env_count - 1) : (k += 1) {
                    env_vars[k] = env_vars[k + 1];
                }
                env_count -= 1;
                return;
            }
        }
    }
}

pub fn printAll() void {
    if (!initialized) init();

    var i: usize = 0;
    while (i < env_count) : (i += 1) {
        var j: usize = 0;
        while (j < env_vars[i].name_len) : (j += 1) {
            console.putChar(env_vars[i].name[j]);
        }
        console.putChar('=');
        j = 0;
        while (j < env_vars[i].value_len) : (j += 1) {
            console.putChar(env_vars[i].value[j]);
        }
        console.putChar('\n');
    }
}

pub fn exportEntries(storage: *[MAX_EXPORT_ENTRIES][MAX_EXPORT_ENTRY_LEN]u8, lengths: *[MAX_EXPORT_ENTRIES]usize) usize {
    if (!initialized) init();

    var count: usize = 0;
    while (count < env_count and count < storage.len) : (count += 1) {
        @memset(&storage[count], 0);
        @memcpy(storage[count][0..env_vars[count].name_len], env_vars[count].name[0..env_vars[count].name_len]);
        storage[count][env_vars[count].name_len] = '=';
        @memcpy(
            storage[count][env_vars[count].name_len + 1 .. env_vars[count].name_len + 1 + env_vars[count].value_len],
            env_vars[count].value[0..env_vars[count].value_len],
        );
        lengths[count] = env_vars[count].name_len + 1 + env_vars[count].value_len;
    }

    return count;
}

pub fn expandVar(input: []const u8, output: []u8) usize {
    if (!initialized) init();

    var in_idx: usize = 0;
    var out_idx: usize = 0;

    while (in_idx < input.len and out_idx < output.len) {
        if (input[in_idx] == '$' and in_idx + 1 < input.len) {
            var var_start = in_idx + 1;
            var var_end = var_start;

            if (input[var_start] == '{') {
                var_start += 1;
                var_end = var_start;
                while (var_end < input.len and input[var_end] != '}') : (var_end += 1) {}

                if (var_end < input.len) {
                    const var_name = input[var_start..var_end];
                    if (getVar(var_name)) |value| {
                        for (value) |c| {
                            if (out_idx < output.len) {
                                output[out_idx] = c;
                                out_idx += 1;
                            }
                        }
                    }
                    in_idx = var_end + 1;
                } else {
                    output[out_idx] = input[in_idx];
                    out_idx += 1;
                    in_idx += 1;
                }
            } else {
                while (var_end < input.len and isVarChar(input[var_end])) : (var_end += 1) {}

                if (var_end > var_start) {
                    const var_name = input[var_start..var_end];
                    if (getVar(var_name)) |value| {
                        for (value) |c| {
                            if (out_idx < output.len) {
                                output[out_idx] = c;
                                out_idx += 1;
                            }
                        }
                    }
                    in_idx = var_end;
                } else {
                    output[out_idx] = input[in_idx];
                    out_idx += 1;
                    in_idx += 1;
                }
            }
        } else {
            output[out_idx] = input[in_idx];
            out_idx += 1;
            in_idx += 1;
        }
    }

    return out_idx;
}

fn isVarChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '_';
}
