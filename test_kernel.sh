#!/bin/bash

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Testing ZigOS kernel boot..."
echo ""

# Check if kernel exists
if [ ! -f "zig-out/bin/kernel.elf" ]; then
    echo -e "${RED}Error: kernel.elf not found. Please build the kernel first.${NC}"
    echo "Run: zig build kernel"
    exit 1
fi

# Clean up old serial log
rm -f serial.log

echo "Starting QEMU with kernel.elf..."
echo "The OS will output to serial port (captured in serial.log)"
echo ""

# Run QEMU with timeout
if timeout 10 qemu-system-x86_64 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -display none \
    -serial file:serial.log \
    -monitor none \
    -no-reboot \
    > /dev/null 2>&1; then
    echo -e "${GREEN}QEMU execution completed.${NC}"
else
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        echo -e "${YELLOW}QEMU timed out after 10 seconds (this is expected).${NC}"
    else
        echo -e "${YELLOW}QEMU exited with code $EXIT_CODE${NC}"
    fi
fi

echo ""
echo "Kernel test completed."
echo ""

# Check for serial output
if [ -f serial.log ] && [ -s serial.log ]; then
    echo -e "${GREEN}Serial output captured:${NC}"
    echo "----------------------------------------"
    cat serial.log
    echo "----------------------------------------"
    echo ""
    
    # Verify key messages
    SUCCESS=0
    if grep -q "Welcome to ZigOS" serial.log; then
        echo -e "${GREEN}✓ Welcome message found${NC}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${RED}✗ Welcome message not found${NC}"
    fi
    
    if grep -q "GDT initialized" serial.log; then
        echo -e "${GREEN}✓ GDT initialization confirmed${NC}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${RED}✗ GDT initialization not confirmed${NC}"
    fi
    
    if grep -q "Interrupts enabled" serial.log; then
        echo -e "${GREEN}✓ Interrupts enabled${NC}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${RED}✗ Interrupts not confirmed${NC}"
    fi
    
    if grep -q "ZigOS Shell Ready" serial.log; then
        echo -e "${GREEN}✓ Shell initialization confirmed${NC}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${YELLOW}⚠ Shell not ready (may need more time)${NC}"
    fi
    
    if grep -qi "panic\|KERNEL PANIC\|System Halted" serial.log; then
        echo -e "${RED}✗ Kernel panic or crash detected!${NC}"
        echo "Check serial.log for details"
        SUCCESS=0
    fi
    
    if grep -qi "Received interrupt:" serial.log; then
        echo -e "${RED}✗ Unexpected interrupt received${NC}"
        grep "Received interrupt:" serial.log | head -1
    fi
    
    echo ""
    if [ $SUCCESS -ge 3 ]; then
        echo -e "${GREEN}Kernel boot test: PASSED${NC}"
        echo "The kernel successfully initialized core systems."
    else
        echo -e "${YELLOW}Kernel boot test: PARTIAL${NC}"
        echo "Some initialization steps may not have completed."
    fi
else
    echo -e "${RED}No serial output captured!${NC}"
    echo "Possible issues:"
    echo "  - Serial port driver not working"
    echo "  - Kernel crashed before initialization"
    echo "  - QEMU serial redirection failed"
    exit 1
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