# Architecture

The repository is organized around stable subsystem boundaries rather than large catch-all files.

## Layout

- `build/`: build graph helpers split by concern.
- `scripts/`: shell entrypoints used by `zig build` for rootfs creation, QEMU-backed tests, and ISO generation.
- `src/kernel/boot/`: boot entrypoint, staged initialization, and boot-profile runners.
- `src/kernel/process/syscall/`: syscall ABI, init, dispatch, and per-domain handlers.
- `src/kernel/shell/`: REPL/session/runtime/launcher code plus parser modules and builtins.
- `src/kernel/fs/vfs/` and `src/kernel/fs/fat32/`: extracted support code for the VFS and FAT32 implementations.
- `user/bin/`: userspace programs grouped by source category and still installed flat into `/bin`.

## Boundaries

- `src/main.zig` should stay a thin top-level export surface.
- `src/kernel/boot/entry.zig` owns boot sequencing and profile selection.
- `src/kernel/boot/init/*.zig` should only contain staged initialization, not profile-specific behavior.
- `src/kernel/boot/profiles/*.zig` should orchestrate a boot mode, not redefine shared initialization.
- `src/kernel/process/syscall/dispatch.zig` is the syscall entry surface; per-domain syscall files own behavior.
- `src/kernel/shell/parser/` owns tokenization, expansion, and pipeline parsing. Shell runtime code should consume parser APIs rather than duplicate parsing logic.
- `src/kernel/fs/vfs.zig` and `src/kernel/fs/fat32.zig` should keep delegating helper logic into their subdirectories as the split continues.

## Userland Source Groups

- `user/bin/core/`: simple core utilities and shell-facing commands.
- `user/bin/fs/`: filesystem and mount-management tools.
- `user/bin/session/`: init, login, getty, and terminal-session utilities.
- `user/bin/system/`: process, host, and network-oriented tools.
- `user/bin/text/`: text-processing utilities.

## Import Rules

- Prefer importing the extracted module directly instead of a deprecated compatibility wrapper.
- Keep build-time paths in `build/programs.zig` and benchmark source-path strings aligned with the actual tree.
- When splitting a large file, leave a facade only long enough to migrate imports, then delete it.
