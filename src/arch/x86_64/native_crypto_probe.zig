const std = @import("std");
const x86 = @import("x86");
const model = @import("xstate_roundtrip_model");
const checksum = @import("volume_checksum");

const SERIAL_BASE: u16 = 0x3F8;
const SERIAL_LINE_STATUS: u16 = SERIAL_BASE + 5;
const SERIAL_TRANSMIT_EMPTY: u8 = 1 << 5;
const QEMU_EXIT_PORT: u16 = 0xF4;
const QEMU_SUCCESS: u32 = 0x10;
const QEMU_FAILURE: u32 = 0x11;

extern fn zigos_xstate_host_roundtrip(*const [3]model.Image, *[3]model.Image) callconv(.c) void;

comptime {
    if (!std.crypto.core.aes.has_hardware_support)
        @compileError("native crypto proof requires the hardware AES implementation");
}

pub fn panic(_: []const u8, _: ?*std.lang.StackTrace, _: ?usize) noreturn {
    fail("panic");
}

pub export fn native_crypto_probe_main() callconv(.c) noreturn {
    serialInit();
    if (!checkInitialFpControls()) fail("INITIAL_FP_CONTROLS");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:INITIAL_FP_CONTROLS:PASS\n");
    if (!checkAvx2()) fail("AVX2");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:AVX2:PASS\n");
    if (!checkAes()) fail("AES128");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:AES128:PASS\n");
    if (!checkSha256()) fail("SHA256");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:SHA256:PASS\n");
    if (!checkGhash()) fail("GHASH");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:GHASH:PASS\n");
    if (!checkChecksum()) fail("CHECKSUM_XXH64");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:CHECKSUM_XXH64:PASS\n");

    var inputs: [3]model.Image = undefined;
    var outputs: [3]model.Image = undefined;
    for (&inputs, &outputs, 0..) |*input, *output, owner| {
        model.initialize(input, owner);
        model.initializeCanary(output);
    }
    zigos_xstate_host_roundtrip(&inputs, &outputs);
    if (!model.verify(&inputs, &outputs)) fail("XSTATE");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:XSTATE_X87_XMM_YMM_128:PASS\n");
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:PASS\n");
    // Retain the entry marker for tools that also inspect long-mode readiness.
    serialWrite("ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:READY\n");
    exitQemu(QEMU_SUCCESS);
}

noinline fn checkInitialFpControls() bool {
    var x87_control: u16 = undefined;
    var mxcsr: u32 = undefined;
    asm volatile ("fnstcw %[control]"
        : [control] "=m" (x87_control),
    );
    asm volatile ("stmxcsr %[control]"
        : [control] "=m" (mxcsr),
    );
    return x87_control == 0x037f and mxcsr == 0x1f80;
}

noinline fn checkAvx2() bool {
    const result = asm volatile ("vpmulld %[right], %[left], %[result]"
        : [result] "=x" (-> @Vector(8, u32)),
        : [left] "x" (@as(@Vector(8, u32), .{ 1, 2, 3, 4, 5, 6, 7, 8 })),
          [right] "x" (@as(@Vector(8, u32), .{ 9, 10, 11, 12, 13, 14, 15, 16 })),
    );
    return @reduce(.And, result == @as(@Vector(8, u32), .{ 9, 20, 33, 48, 65, 84, 105, 128 }));
}

noinline fn checkChecksum() bool {
    // This 80-byte known answer crosses two complete XXH64 stripes and a tail.
    var input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".*;
    std.mem.doNotOptimizeAway(&input);
    return checksum.checksumBytes(&input) == 0xe04a477f19ee145d;
}

noinline fn checkAes() bool {
    var key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var input = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    std.mem.doNotOptimizeAway(&key);
    std.mem.doNotOptimizeAway(&input);
    var output: [16]u8 = undefined;
    const context = std.crypto.core.aes.Aes128.initEnc(key);
    context.encrypt(&output, &input);
    return std.mem.eql(u8, &output, "\x69\xC4\xE0\xD8\x6A\x7B\x04\x30\xD8\xCD\xB7\x80\x70\xB4\xC5\x5A");
}

noinline fn checkSha256() bool {
    var input: [3]u8 = "abc".*;
    std.mem.doNotOptimizeAway(&input);
    var output: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &output, .{});
    return std.mem.eql(u8, &output, "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00\x15\xAD");
}

noinline fn checkGhash() bool {
    var key: [16]u8 = @splat(0x42);
    var input: [256]u8 = @splat(0x69);
    std.mem.doNotOptimizeAway(&key);
    std.mem.doNotOptimizeAway(&input);
    var output: [16]u8 = undefined;
    var context = std.crypto.onetimeauth.Ghash.init(&key);
    context.update(&input);
    context.final(&output);
    return std.mem.eql(u8, &output, "\x88\x92\x95\xFA\x74\x6E\x8B\x17\x4B\xF4\xEC\x80\xA6\x5D\xEA\x41");
}

fn serialInit() void {
    x86.outb(SERIAL_BASE + 1, 0x00);
    x86.outb(SERIAL_BASE + 3, 0x80);
    x86.outb(SERIAL_BASE, 0x03);
    x86.outb(SERIAL_BASE + 1, 0x00);
    x86.outb(SERIAL_BASE + 3, 0x03);
    x86.outb(SERIAL_BASE + 2, 0xC7);
    x86.outb(SERIAL_BASE + 4, 0x0B);
}

fn serialWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        while ((x86.inb(SERIAL_LINE_STATUS) & SERIAL_TRANSMIT_EMPTY) == 0) {
            asm volatile ("pause");
        }
        x86.outb(SERIAL_BASE, byte);
    }
}

fn fail(reason: []const u8) noreturn {
    serialWrite("ZIGOS:ARCH:X86_64:NATIVE_CRYPTO:FAIL ");
    serialWrite(reason);
    serialWrite("\nZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:FAIL\n");
    exitQemu(QEMU_FAILURE);
}

fn exitQemu(status: u32) noreturn {
    x86.outl(QEMU_EXIT_PORT, status);
    while (true) x86.hlt();
}
