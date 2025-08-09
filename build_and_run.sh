mkdir -p build

echo "Assembling boot code..."
nasm -f elf64 src/boot/boot.asm -o build/boot.o

echo "Building kernel..."
zig build

echo "Linking kernel..."
ld -n -T src/arch/x86_64/linker.ld -o build/kernel.elf build/boot.o zig-out/bin/kernel.elf

echo "Running OS in QEMU..."
qemu-system-x86_64 -kernel build/kernel.elf -m 128M -no-reboot -no-shutdown
