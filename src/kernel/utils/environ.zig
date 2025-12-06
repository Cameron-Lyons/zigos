const std = @import("std");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

const MAX_ENV_VARS = 64;
const MAX_VAR_NAME_LEN = 64;
const MAX_VAR_VALUE_LEN = 256;

pub const EnvVar = struct {
    name: [MAX_VAR_NAME_LEN]u8,
    value: [MAX_VAR_VALUE_LEN]u8,
    name_len: usize,
    value_len: usize,
};

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


    setVar("PATH", "/bin:/usr/bin") catch {};
    setVar("HOME", "/home/user") catch {};
    setVar("SHELL", "/bin/sh") catch {};
    setVar("USER", "root") catch {};
    setVar("TERM", "vga") catch {};

    initialized = true;
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
            vga.put_char(env_vars[i].name[j]);
        }
        vga.put_char('=');
        j = 0;
        while (j < env_vars[i].value_len) : (j += 1) {
            vga.put_char(env_vars[i].value[j]);
        }
        vga.put_char('\n');
    }
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