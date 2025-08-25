mkdir -p build

echo "Building kernel..."
zig build kernel

echo "Copying kernel..."
cp zig-out/bin/kernel.elf build/kernel.elf

echo "Running OS in QEMU..."
qemu-system-x86_64 -kernel build/kernel.elf -m 512M -no-reboot -no-shutdown -device e1000,netdev=net0 -netdev user,id=net0
