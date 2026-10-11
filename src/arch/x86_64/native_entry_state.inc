#ifndef ZIGOS_NATIVE_ENTRY_STATE_INC
#define ZIGOS_NATIVE_ENTRY_STATE_INC
/* GS names the current CPU's 128-byte native entry state. The companion
 * Zig module checks every field, mode bit and slot boundary against this ABI. */
#define CPU_KERNEL_STACK_TOP 0
#define CPU_USER_STACK_POINTER 8
#define CPU_KERNEL_PORT 16
#define CPU_ACTIVE_TASK_ID 24
#define CPU_NATIVE_ENTRY_MODES 32
#define CPU_USERSPACE_XSTATE 40
#define CPU_KERNEL_XSTATE 48
#define CPU_RESUME_RSP 56
#define CPU_RESUME_RIP 64
#define CPU_RESUME_REQUESTED 72
#define CPU_STATE_BYTES 128
#define CPU_STATE_ALIGNMENT 128
#define CPU_ENTRY_PKU 1
#define CPU_ENTRY_FRED 2
#define CPU_ENTRY_READY 4
#endif
