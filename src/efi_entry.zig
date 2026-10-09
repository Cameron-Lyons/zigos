// Keep the EFI loader and the kernel's pure address contract in one module.
pub const main = @import("boot/efi_stub.zig").main;
