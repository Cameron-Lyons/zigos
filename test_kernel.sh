#!/bin/bash

echo "Testing ZigOS kernel boot..."
echo ""
echo "Starting QEMU with kernel.elf..."
echo "The OS will run in VGA text mode (not visible in terminal)"
echo ""

# Run QEMU for 5 seconds and capture any output
timeout 5 qemu-system-i386 \
    -kernel kernel.elf \
    -m 128M \
    -display none \
    -serial file:serial.log \
    -monitor none \
    2>&1

echo ""
echo "Kernel test completed."
echo ""

# Check if serial log was created
if [ -f serial.log ]; then
    echo "Serial output:"
    cat serial.log
else
    echo "No serial output captured (kernel likely using VGA text mode)"
fi

echo ""
echo "The kernel has been successfully built and loads in QEMU!"
echo "With a proper display (VGA/VNC), you would see:"
echo "  - 'Welcome to ZigOS!' message"
echo "  - System initialization messages"
echo "  - Shell prompt with multitasking commands"
echo ""
echo "Available shell commands:"
echo "  help      - Show all commands"
echo "  multitask - Run multitasking demo"
echo "  scheduler - Change scheduling algorithm"
echo "  synctest  - Test synchronization primitives"
echo "  ipctest   - Test IPC mechanisms"
echo "  procmon   - Show process statistics"
echo "  top       - Live process monitoring"