const std = @import("std");

pub const BootProfile = enum {
    dev,
    ci_smoke,
    test_vm,
    benchmark,
    smp_stress,
    userland_smoke,
};

const KernelArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
    output_path: []const u8,
};

const UserProgramArtifact = struct {
    install_step: *std.Build.Step,
    emitted_bin: std.Build.LazyPath,
    output_path: []const u8,
};

const UserProgramSpec = struct {
    name: []const u8,
    root_source: []const u8,
};

const headless_qemu_runner = "scripts/run-headless-qemu.sh";
const rootfs_image_path = "build/disk.img";

const user_program_specs = [_]UserProgramSpec{
    .{ .name = "hello", .root_source = "user/bin/hello.zig" },
    .{ .name = "echo", .root_source = "user/bin/echo.zig" },
    .{ .name = "env", .root_source = "user/bin/env.zig" },
    .{ .name = "which", .root_source = "user/bin/which.zig" },
    .{ .name = "head", .root_source = "user/bin/head.zig" },
    .{ .name = "tail", .root_source = "user/bin/tail.zig" },
    .{ .name = "sort", .root_source = "user/bin/sort.zig" },
    .{ .name = "uniq", .root_source = "user/bin/uniq.zig" },
    .{ .name = "true", .root_source = "user/bin/true.zig" },
    .{ .name = "false", .root_source = "user/bin/false.zig" },
    .{ .name = "test", .root_source = "user/bin/test.zig" },
    .{ .name = "hexdump", .root_source = "user/bin/hexdump.zig" },
    .{ .name = "wc", .root_source = "user/bin/wc.zig" },
    .{ .name = "ps", .root_source = "user/bin/ps.zig" },
    .{ .name = "ping", .root_source = "user/bin/ping.zig" },
    .{ .name = "whoami", .root_source = "user/bin/whoami.zig" },
    .{ .name = "id", .root_source = "user/bin/id.zig" },
    .{ .name = "date", .root_source = "user/bin/date.zig" },
    .{ .name = "hostname", .root_source = "user/bin/hostname.zig" },
    .{ .name = "uname", .root_source = "user/bin/uname.zig" },
    .{ .name = "cat", .root_source = "user/bin/cat.zig" },
    .{ .name = "cp", .root_source = "user/bin/cp.zig" },
    .{ .name = "mv", .root_source = "user/bin/mv.zig" },
    .{ .name = "grep", .root_source = "user/bin/grep.zig" },
    .{ .name = "kill", .root_source = "user/bin/kill.zig" },
    .{ .name = "ls", .root_source = "user/bin/ls.zig" },
    .{ .name = "pwd", .root_source = "user/bin/pwd.zig" },
    .{ .name = "mkdir", .root_source = "user/bin/mkdir.zig" },
    .{ .name = "rm", .root_source = "user/bin/rm.zig" },
    .{ .name = "sleep", .root_source = "user/bin/sleep.zig" },
    .{ .name = "touch", .root_source = "user/bin/touch.zig" },
    .{ .name = "tty", .root_source = "user/bin/tty.zig" },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});
    const host_target = b.resolveTargetQuery(.{});
    const benchmark_optimize: std.builtin.OptimizeMode = if (optimize == .Debug) .ReleaseFast else optimize;

    var user_programs: [user_program_specs.len]UserProgramArtifact = undefined;
    inline for (user_program_specs, 0..) |spec, i| {
        user_programs[i] = addUserProgram(b, target, optimize, spec.name, spec.root_source);
    }
    const motd_install = b.addInstallFileWithDir(b.path("user/rootfs/etc/motd"), .{ .custom = "user/rootfs/etc" }, "motd");
    const user_assets_module = createUserAssetsModule(b, target, optimize, user_program_specs[0..], user_programs[0..]);

    const dev_kernel = addKernelArtifact(b, target, optimize, "kernel.elf", .dev, user_assets_module);
    const ci_smoke_kernel = addKernelArtifact(b, target, optimize, "kernel-ci-smoke.elf", .ci_smoke, user_assets_module);
    const vm_test_kernel = addKernelArtifact(b, target, optimize, "kernel-test-vm.elf", .test_vm, user_assets_module);
    const benchmark_kernel = addKernelArtifact(b, target, optimize, "kernel-benchmark.elf", .benchmark, user_assets_module);
    const smp_stress_kernel = addKernelArtifact(b, target, optimize, "kernel-smp-stress.elf", .smp_stress, user_assets_module);
    const userland_smoke_kernel = addKernelArtifact(b, target, optimize, "kernel-userland-smoke.elf", .userland_smoke, user_assets_module);

    inline for (&.{ dev_kernel, ci_smoke_kernel, vm_test_kernel, benchmark_kernel, smp_stress_kernel, userland_smoke_kernel }) |artifact| {
        dependOnUserPrograms(&artifact.compile_step.step, user_programs[0..], &motd_install.step);
    }

    const kernel_step = b.step("kernel", "Build the development kernel");
    kernel_step.dependOn(dev_kernel.install_step);

    const ci_kernel_step = b.step("kernel-ci-smoke", "Build the CI smoke test kernel");
    ci_kernel_step.dependOn(ci_smoke_kernel.install_step);

    const vm_kernel_step = b.step("kernel-test-vm", "Build the VM test kernel");
    vm_kernel_step.dependOn(vm_test_kernel.install_step);

    const benchmark_kernel_step = b.step("kernel-bench", "Build the kernel benchmark profile");
    benchmark_kernel_step.dependOn(benchmark_kernel.install_step);

    const smp_stress_kernel_step = b.step("kernel-smp-stress", "Build the SMP stress kernel profile");
    smp_stress_kernel_step.dependOn(smp_stress_kernel.install_step);

    const userland_smoke_kernel_step = b.step("kernel-userland-smoke", "Build the userland smoke-test kernel");
    userland_smoke_kernel_step.dependOn(userland_smoke_kernel.install_step);

    const userland_step = b.step("userland", "Build the staged user programs");
    dependOnUserPrograms(userland_step, user_programs[0..], &motd_install.step);

    const rootfs_cmd = b.addSystemCommand(&.{
        "sh",                                                              "-c",
        buildRootfsScript(b, user_program_specs[0..], user_programs[0..]),
    });
    dependOnUserPrograms(&rootfs_cmd.step, user_programs[0..], &motd_install.step);

    const rootfs_step = b.step("rootfs", "Build the FAT disk image for user programs");
    rootfs_step.dependOn(&rootfs_cmd.step);

    const qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        dev_kernel.output_path,
        "-m",
        "256M",
        "-cpu",
        "qemu64",
        "-smp",
        "2",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "e1000,netdev=net0",
        "-netdev",
        "user,id=net0,dhcpstart=10.0.2.15",
        "-device",
        "AC97",
        "-drive",
        "file=" ++ rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    qemu_cmd.step.dependOn(dev_kernel.install_step);
    qemu_cmd.step.dependOn(&rootfs_cmd.step);

    const run_step = b.step("run", "Run the development kernel in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    const ci_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        ci_smoke_kernel.output_path,
        "128M",
        "stdio",
    });
    ci_qemu_cmd.step.dependOn(ci_smoke_kernel.install_step);

    const run_ci_step = b.step("run-ci-smoke", "Run the CI smoke kernel in QEMU");
    run_ci_step.dependOn(&ci_qemu_cmd.step);

    const vm_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        vm_test_kernel.output_path,
        "128M",
        "stdio",
    });
    vm_qemu_cmd.step.dependOn(vm_test_kernel.install_step);

    const run_vm_step = b.step("run-test-vm", "Run the VM test kernel in QEMU");
    run_vm_step.dependOn(&vm_qemu_cmd.step);

    const benchmark_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        benchmark_kernel.output_path,
        "128M",
        "stdio",
    });
    benchmark_qemu_cmd.step.dependOn(benchmark_kernel.install_step);

    const run_benchmark_step = b.step("run-kernel-bench", "Run the kernel benchmark profile in QEMU");
    run_benchmark_step.dependOn(&benchmark_qemu_cmd.step);

    const run_smp_stress_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\QEMU_EXTRA_ARGS="-cpu qemu64 -smp 2" bash scripts/run-headless-qemu.sh "zig-out/bin/kernel-smp-stress.elf" "256M" "stdio"
    });
    run_smp_stress_cmd.step.dependOn(smp_stress_kernel.install_step);

    const run_smp_stress_step = b.step("run-smp-stress", "Run the SMP stress kernel profile in QEMU");
    run_smp_stress_step.dependOn(&run_smp_stress_cmd.step);

    const run_userland_smoke_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        userland_smoke_kernel.output_path,
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-drive",
        "file=" ++ rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    run_userland_smoke_cmd.step.dependOn(userland_smoke_kernel.install_step);
    run_userland_smoke_cmd.step.dependOn(&rootfs_cmd.step);

    const run_userland_smoke_step = b.step("run-userland-smoke", "Run the userland smoke kernel in QEMU");
    run_userland_smoke_step.dependOn(&run_userland_smoke_cmd.step);

    const userland_smoke_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\LOG_PATH="build/userland-smoke.log"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mdir >/dev/null 2>&1; then
        \\  echo "mdir not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "$LOG_PATH"
        \\mdir -i "build/disk.img" ::/bin > "build/userland-smoke-rootfs.txt"
        \\USERLAND_SMOKE_SECONDS="${USERLAND_SMOKE_SECONDS:-20}"
        \\$QEMU_BIN -kernel "zig-out/bin/kernel-userland-smoke.elf" -m 128M -display none -serial file:"$LOG_PATH" -monitor none -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 -drive file="build/disk.img",if=ide,format=raw,id=disk0 >/dev/null 2>&1 &
        \\QEMU_PID=$!
        \\TIMED_OUT=0
        \\ELAPSED=0
        \\while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
        \\  if [ "$ELAPSED" -ge "$USERLAND_SMOKE_SECONDS" ]; then
        \\    TIMED_OUT=1
        \\    kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
        \\    sleep 1
        \\    kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
        \\    break
        \\  fi
        \\  sleep 1
        \\  ELAPSED=$((ELAPSED + 1))
        \\done
        \\wait "$QEMU_PID" >/dev/null 2>&1 || true
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "Userland smoke test failed: no serial output captured" >&2
        \\  exit 1
        \\fi
        \\if ! grep -Fq "echo" "build/userland-smoke-rootfs.txt"; then
        \\  echo "Userland smoke test failed: rootfs image is missing /bin/echo" >&2
        \\  cat "build/userland-smoke-rootfs.txt" >&2
        \\  exit 1
        \\fi
        \\if [ "$TIMED_OUT" -eq 1 ] && ! grep -Fq "USERLAND:PASS" "$LOG_PATH"; then
        \\  echo "Userland smoke test failed: QEMU timed out after ${USERLAND_SMOKE_SECONDS}s before USERLAND:PASS" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\for marker in "BOOT:START" "BOOT:PROFILE:userland_smoke" "Disk root mounted at /" "BOOT:SHELL_READY" "USERLAND:HELLO" "USERLAND:ECHO" "USERLAND:ENV" "USERLAND:CMDSUB" "USERLAND:QUOTED" "USERLAND:ESCAPED" "USERLAND:GLOB" "USERLAND:UNAME" "USERLAND:LS" "USERLAND:CAT" "USERLAND:ENV_STANDALONE" "USERLAND:ENV_BIN" "USERLAND:WHICH" "USERLAND:HEAD" "USERLAND:TAIL" "USERLAND:WC" "USERLAND:SORT" "USERLAND:UNIQ" "USERLAND:HEXDUMP" "USERLAND:TEST" "USERLAND:TRUE" "USERLAND:CP" "USERLAND:MV" "USERLAND:GREP" "USERLAND:PS" "USERLAND:PING" "USERLAND:WHOAMI" "USERLAND:ID" "USERLAND:DATE" "USERLAND:HOSTNAME" "USERLAND:PIPE_OK" "USERLAND:REDIRECT_WRITE" "USERLAND:REDIRECT_READ" "USERLAND:BG_START" "USERLAND:JOBS_RUNNING" "USERLAND:JOBS_STOPPED" "USERLAND:BG_RESUME" "USERLAND:JOBS_RESUMED" "user:root home:/home/user" "shell-ZigOS" "USERLAND QUOTED" "USERLAND ESCAPED" "/bin/cat /bin/cp /bin/ls" "Welcome to ZigOS userspace smoke test." "PATH=/bin:/usr/bin:/mnt/bin" "00000000" "uid=1000(user) gid=1000(users) euid=1000 egid=1000" "zigos" "USERLAND:PIPE" "USERLAND:REDIRECT" "[1] Running /bin/sleep 3" "[1] Stopped /bin/sleep 3" "USERLAND:PASS"; do
        \\  if ! grep -Fq "$marker" "$LOG_PATH"; then
        \\    echo "Userland smoke test failed: missing marker '$marker'" >&2
        \\    cat "$LOG_PATH" >&2
        \\    exit 1
        \\  fi
        \\done
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted|USERLAND:FAIL" "$LOG_PATH"; then
        \\  echo "Userland smoke test failed: panic or failure marker found" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\echo "Userland smoke test passed. Log: $LOG_PATH"
    });
    userland_smoke_test_cmd.step.dependOn(userland_smoke_kernel.install_step);
    userland_smoke_test_cmd.step.dependOn(&rootfs_cmd.step);

    const userland_smoke_test_step = b.step("userland-smoke-test", "Run the automated userland smoke test");
    userland_smoke_test_step.dependOn(&userland_smoke_test_cmd.step);

    const kernel_benchmark_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\LOG_PATH="build/kernel-benchmark.log"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "$LOG_PATH"
        \\QEMU_BIN="$QEMU_BIN" bash scripts/run-headless-qemu.sh "zig-out/bin/kernel-benchmark.elf" "128M" "file:$LOG_PATH"
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "Kernel benchmark test failed: no serial output captured" >&2
        \\  exit 1
        \\fi
        \\for marker in "BOOT:START" "BOOT:PROFILE:benchmark" "BOOT:CORE_READY" "BENCH:START" "BENCH:RESULT:shell.tokenize.expansions" "BENCH:RESULT:shell.pipeline.commandline" "BENCH:RESULT:shell.glob.match_matrix" "BENCH:RESULT:syscall.at.resolve_matrix" "BENCH:RESULT:vfs.fd.freelist_churn" "BENCH:RESULT:tcp.checksum.dual_stack" "BENCH:RESULT:tcp.options.roundtrip" "BENCH:RESULT:ipc.semops.batch" "BENCH:SUMMARY" "BENCH:PASS"; do
        \\  if ! grep -Fq "$marker" "$LOG_PATH"; then
        \\    echo "Kernel benchmark test failed: missing marker '$marker'" >&2
        \\    cat "$LOG_PATH" >&2
        \\    exit 1
        \\  fi
        \\done
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted|BENCH:FAIL" "$LOG_PATH"; then
        \\  echo "Kernel benchmark test failed: panic or benchmark failure marker found" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\bash scripts/check-kernel-benchmark-thresholds.sh "$LOG_PATH"
        \\bash scripts/check-kernel-benchmark-baseline.sh "$LOG_PATH"
        \\echo "Kernel benchmark run passed. Log: $LOG_PATH"
    });
    kernel_benchmark_test_cmd.step.dependOn(benchmark_kernel.install_step);

    const kernel_benchmark_test_step = b.step("kernel-bench-test", "Run the automated kernel benchmark profile in QEMU");
    kernel_benchmark_test_step.dependOn(&kernel_benchmark_test_cmd.step);

    const smp_stress_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\LOG_PATH="build/smp-stress.log"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "$LOG_PATH"
        \\SMP_STRESS_SECONDS="${SMP_STRESS_SECONDS:-15}"
        \\QEMU_BIN="$QEMU_BIN" QEMU_EXTRA_ARGS="-cpu qemu64 -smp 2" bash scripts/run-headless-qemu.sh "zig-out/bin/kernel-smp-stress.elf" "256M" "file:$LOG_PATH" >/dev/null 2>&1 &
        \\QEMU_PID=$!
        \\sleep "$SMP_STRESS_SECONDS"
        \\if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
        \\  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
        \\  sleep 1
        \\  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
        \\  echo "SMP stress test failed: QEMU timed out" >&2
        \\  exit 1
        \\fi
        \\wait "$QEMU_PID"
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "SMP stress test failed: no serial output captured" >&2
        \\  exit 1
        \\fi
        \\for marker in "BOOT:START" "BOOT:PROFILE:smp_stress" "BOOT:CORE_READY" "SMP:START" "SMP:ACTIVE_CPUS:" "SMP:TASKS_CREATED" "SMP:TASKS_DONE" "SMP:STATS:" "SMP:PASS"; do
        \\  if ! grep -Fq "$marker" "$LOG_PATH"; then
        \\    echo "SMP stress test failed: missing marker '$marker'" >&2
        \\    cat "$LOG_PATH" >&2
        \\    exit 1
        \\  fi
        \\done
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted|SMP:FAIL|SMP:TIMEOUT" "$LOG_PATH"; then
        \\  echo "SMP stress test failed: panic or failure marker found" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\echo "SMP stress test passed. Log: $LOG_PATH"
    });
    smp_stress_test_cmd.step.dependOn(smp_stress_kernel.install_step);

    const smp_stress_test_step = b.step("smp-stress-test", "Run the automated SMP scheduler stress profile in QEMU");
    smp_stress_test_step.dependOn(&smp_stress_test_cmd.step);

    const host_tests_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\mkdir -p build/zig-cache-tests build/zig-global-cache-tests
        \\export ZIG_LOCAL_CACHE_DIR="build/zig-cache-tests"
        \\export ZIG_GLOBAL_CACHE_DIR="build/zig-global-cache-tests"
        \\for test_file in \
        \\  src/kernel/process/syscall/at_semantics.zig \
        \\  src/kernel/process/syscall/syscall_semantics.zig \
        \\  src/kernel/process/syscall/path_semantics.zig \
        \\  src/kernel/fs/fd_freelist.zig \
        \\  src/kernel/shell/parser.zig \
        \\  src/kernel/shell/glob.zig \
        \\  src/kernel/shell/jobs.zig \
        \\  src/kernel/process/scheduler_policy.zig \
        \\  src/kernel/net/tcp/protocol.zig \
        \\  src/kernel/process/syscall/ipc_semantics.zig
        \\do
        \\  zig test "$test_file"
        \\done
    });
    const host_tests_step = b.step("host-tests", "Run host-side unit tests for extracted pure logic");
    host_tests_step.dependOn(&host_tests_cmd.step);

    const benchmark_module = createHostModule(b, host_target, benchmark_optimize, "src/benchmarks/main.zig");
    benchmark_module.addImport("at_semantics", createHostModule(b, host_target, benchmark_optimize, "src/kernel/process/syscall/at_semantics.zig"));
    benchmark_module.addImport("fd_freelist", createHostModule(b, host_target, benchmark_optimize, "src/kernel/fs/fd_freelist.zig"));
    benchmark_module.addImport("ipc_semantics", createHostModule(b, host_target, benchmark_optimize, "src/kernel/process/syscall/ipc_semantics.zig"));
    benchmark_module.addImport("shell_support", createHostModule(b, host_target, benchmark_optimize, "src/kernel/shell/bench_support.zig"));
    benchmark_module.addImport("tcp_protocol", createHostModule(b, host_target, benchmark_optimize, "src/kernel/net/tcp/protocol.zig"));

    const benchmark_exe = b.addExecutable(.{
        .name = "host-benchmarks",
        .root_module = benchmark_module,
    });
    const benchmark_run = b.addRunArtifact(benchmark_exe);
    if (b.args) |args| {
        benchmark_run.addArgs(args);
    }

    const benchmark_step = b.step("bench", "Run host-side benchmarks for extracted kernel logic");
    benchmark_step.dependOn(&benchmark_run.step);

    const iso_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\GRUB_MKRESCUE="${GRUB_MKRESCUE:-}"
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  for cmd in grub-mkrescue i686-elf-grub-mkrescue x86_64-elf-grub-mkrescue; do
        \\    if command -v "$cmd" >/dev/null 2>&1; then
        \\      GRUB_MKRESCUE="$cmd"
        \\      break
        \\    fi
        \\  done
        \\fi
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  echo "No GRUB mkrescue command found. Set GRUB_MKRESCUE or install GRUB tools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v xorriso >/dev/null 2>&1; then
        \\  echo "xorriso not found. Install xorriso." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mformat >/dev/null 2>&1; then
        \\  echo "mformat not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build/iso/boot/grub
        \\cp zig-out/bin/kernel.elf build/iso/boot/
        \\cp src/boot/grub.cfg build/iso/boot/grub/
        \\"$GRUB_MKRESCUE" -o build/os.iso build/iso
    });
    iso_cmd.step.dependOn(dev_kernel.install_step);

    const iso_step = b.step("iso", "Build bootable ISO (requires GRUB mkrescue, xorriso, and mtools)");
    iso_step.dependOn(&iso_cmd.step);

    const boot_test_iso_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\GRUB_MKRESCUE="${GRUB_MKRESCUE:-}"
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  for cmd in grub-mkrescue i686-elf-grub-mkrescue x86_64-elf-grub-mkrescue; do
        \\    if command -v "$cmd" >/dev/null 2>&1; then
        \\      GRUB_MKRESCUE="$cmd"
        \\      break
        \\    fi
        \\  done
        \\fi
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  echo "No GRUB mkrescue command found. Set GRUB_MKRESCUE or install GRUB tools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v xorriso >/dev/null 2>&1; then
        \\  echo "xorriso not found. Install xorriso." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mformat >/dev/null 2>&1; then
        \\  echo "mformat not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\rm -rf build/boot-test-iso
        \\mkdir -p build/boot-test-iso/boot/grub
        \\cp zig-out/bin/kernel-ci-smoke.elf build/boot-test-iso/boot/kernel.elf
        \\cp src/boot/grub.cfg build/boot-test-iso/boot/grub/
        \\"$GRUB_MKRESCUE" -o build/boot-test.iso build/boot-test-iso
    });
    boot_test_iso_cmd.step.dependOn(ci_smoke_kernel.install_step);

    const boot_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\BOOT_TEST_SECONDS="${BOOT_TEST_SECONDS:-12}"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\LOG_PATH="build/boot-test-serial.log"
        \\rm -f "$LOG_PATH"
        \\"$QEMU_BIN" \
        \\  -cdrom build/boot-test.iso \
        \\  -boot d \
        \\  -m 256M \
        \\  -display none \
        \\  -serial file:"$LOG_PATH" \
        \\  -monitor none \
        \\  -no-reboot \
        \\  -no-shutdown \
        \\  >/dev/null 2>&1 &
        \\QEMU_PID=$!
        \\sleep "$BOOT_TEST_SECONDS"
        \\if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
        \\  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
        \\  sleep 1
        \\  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
        \\fi
        \\wait "$QEMU_PID" >/dev/null 2>&1 || true
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "Boot test failed: no serial output at $LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "Welcome to ZigOS" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'Welcome to ZigOS'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "A minimal operating system written in Zig" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'A minimal operating system written in Zig'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "Initializing GDT" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'Initializing GDT'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\WELCOME_LINE="$(grep -n "Welcome to ZigOS" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\MINIMAL_LINE="$(grep -n "A minimal operating system written in Zig" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\GDT_LINE="$(grep -n "Initializing GDT" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\if [ "$MINIMAL_LINE" -le "$WELCOME_LINE" ] || [ "$GDT_LINE" -le "$MINIMAL_LINE" ]; then
        \\  echo "Boot test failed: boot markers are out of order" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted" "$LOG_PATH"; then
        \\  echo "Boot test failed: panic marker found in boot log" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\echo "Boot test passed. Log: $LOG_PATH"
    });
    boot_test_cmd.step.dependOn(&boot_test_iso_cmd.step);

    const boot_test_step = b.step("boot-test", "Build a CI-smoke ISO and verify headless boot markers in QEMU");
    boot_test_step.dependOn(&boot_test_cmd.step);
}

fn addKernelArtifact(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    boot_profile: BootProfile,
    user_assets_module: *std.Build.Module,
) KernelArtifact {
    const options = b.addOptions();
    options.addOption(BootProfile, "boot_profile", boot_profile);

    const kernel_module = b.addModule(b.fmt("kernel-{s}", .{@tagName(boot_profile)}), .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    kernel_module.addOptions("build_options", options);
    kernel_module.addImport("user_assets", user_assets_module);
    kernel_module.addAssemblyFile(b.path("src/boot/boot64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt32.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupts.s"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush.S"));
    kernel_module.addAssemblyFile(b.path("src/arch/x86/syscall6.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/process/context_switch.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/smp/ap_trampoline.S"));

    const kernel = b.addExecutable(.{
        .name = name,
        .root_module = kernel_module,
    });
    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    const install = b.addInstallArtifact(kernel, .{});
    return .{
        .compile_step = kernel,
        .install_step = &install.step,
        .output_path = b.fmt("zig-out/bin/{s}", .{name}),
    };
}

fn createHostModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    root_source: []const u8,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
    });
}

fn dependOnUserPrograms(step: *std.Build.Step, programs: []const UserProgramArtifact, motd_step: *std.Build.Step) void {
    for (programs) |program| {
        step.dependOn(program.install_step);
    }
    step.dependOn(motd_step);
}

fn buildRootfsScript(b: *std.Build, specs: []const UserProgramSpec, programs: []const UserProgramArtifact) []const u8 {
    std.debug.assert(specs.len == programs.len);

    var script = std.ArrayList(u8).empty;
    script.appendSlice(b.allocator,
        \\set -eu
        \\if ! command -v mkfs.fat >/dev/null 2>&1; then
        \\  echo "mkfs.fat not found. Install dosfstools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mmd >/dev/null 2>&1; then
        \\  echo "mmd not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mcopy >/dev/null 2>&1; then
        \\  echo "mcopy not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "build/disk.img"
        \\truncate -s 64M "build/disk.img"
        \\mkfs.fat -F 32 "build/disk.img" >/dev/null
        \\mmd -i "build/disk.img" ::/etc
        \\mmd -i "build/disk.img" ::/bin
        \\mmd -i "build/disk.img" ::/tmp
        \\mmd -i "build/disk.img" ::/dev
        \\mmd -i "build/disk.img" ::/usr
        \\mmd -i "build/disk.img" ::/usr/bin
        \\
    ) catch @panic("failed to build rootfs script");

    for (specs, 0..) |spec, i| {
        script.print(b.allocator, "mcopy -i \"{s}\" \"{s}\" ::/bin/{s}\n", .{
            rootfs_image_path,
            programs[i].output_path,
            spec.name,
        }) catch @panic("failed to append rootfs copy command");
    }

    script.appendSlice(b.allocator,
        \\mcopy -i "build/disk.img" "zig-out/user/rootfs/etc/motd" ::/etc/motd
    ) catch @panic("failed to finish rootfs script");

    return script.toOwnedSlice(b.allocator) catch @panic("failed to allocate rootfs script");
}

fn createUserAssetsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    specs: []const UserProgramSpec,
    programs: []const UserProgramArtifact,
) *std.Build.Module {
    std.debug.assert(specs.len == programs.len);

    const write_files = b.addWriteFiles();
    for (specs, 0..) |spec, i| {
        _ = write_files.addCopyFile(programs[i].emitted_bin, b.fmt("assets/{s}", .{spec.name}));
    }
    _ = write_files.addCopyFile(b.path("user/rootfs/etc/motd"), "assets/motd");

    var source = std.ArrayList(u8).empty;
    source.appendSlice(b.allocator,
        \\pub const ProgramAsset = struct {
        \\    name: []const u8,
        \\    data: []const u8,
        \\};
        \\
        \\pub const programs = [_]ProgramAsset{
    ) catch @panic("failed to start user assets source");

    for (specs) |spec| {
        source.print(b.allocator, "    .{{ .name = \"{s}\", .data = @embedFile(\"assets/{s}\") }},\n", .{
            spec.name,
            spec.name,
        }) catch @panic("failed to append user asset");
    }

    source.appendSlice(b.allocator,
        \\};
        \\
        \\pub const motd = @embedFile("assets/motd");
    ) catch @panic("failed to finish user assets source");

    const assets_source = write_files.add("user_assets.zig", source.toOwnedSlice(b.allocator) catch @panic("failed to allocate user assets source"));

    return b.createModule(.{
        .root_source_file = assets_source,
        .target = target,
        .optimize = optimize,
    });
}

fn addUserProgram(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root_source: []const u8,
) UserProgramArtifact {
    _ = optimize;
    const user_optimize: std.builtin.OptimizeMode = .ReleaseSmall;

    const abi_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/process/syscall/abi.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const syscall_module = b.createModule(.{
        .root_source_file = b.path("user/lib/syscall.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    syscall_module.addImport("abi", abi_module);

    const runtime_module = b.createModule(.{
        .root_source_file = b.path("user/lib/runtime.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    runtime_module.addImport("syscall", syscall_module);

    const cstr_module = b.createModule(.{
        .root_source_file = b.path("user/lib/cstr.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const stdio_module = b.createModule(.{
        .root_source_file = b.path("user/lib/stdio.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    stdio_module.addImport("syscall", syscall_module);

    const cli_module = b.createModule(.{
        .root_source_file = b.path("user/lib/cli.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    cli_module.addImport("stdio", stdio_module);

    const fsutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/fsutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    fsutil_module.addImport("syscall", syscall_module);

    const processutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/processutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    processutil_module.addImport("cstr", cstr_module);
    processutil_module.addImport("syscall", syscall_module);

    const envutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/envutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    envutil_module.addImport("cstr", cstr_module);

    const shell_registry_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/shell/registry.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const user_module = b.addModule(b.fmt("user-{s}", .{name}), .{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = user_optimize,
    });
    user_module.addImport("cstr", cstr_module);
    user_module.addImport("cli", cli_module);
    user_module.addImport("envutil", envutil_module);
    user_module.addImport("fsutil", fsutil_module);
    user_module.addImport("processutil", processutil_module);
    user_module.addImport("runtime", runtime_module);
    user_module.addImport("shell_registry", shell_registry_module);
    user_module.addImport("syscall", syscall_module);
    user_module.addImport("stdio", stdio_module);

    user_module.addAssemblyFile(b.path("user/crt0.S"));

    const program = b.addExecutable(.{
        .name = name,
        .root_module = user_module,
    });
    program.setLinkerScript(b.path("user/linker.ld"));

    const install = b.addInstallArtifact(program, .{
        .dest_dir = .{ .override = .{ .custom = "user/bin" } },
        .dest_sub_path = name,
    });

    return .{
        .install_step = &install.step,
        .emitted_bin = program.getEmittedBin(),
        .output_path = b.fmt("zig-out/user/bin/{s}", .{name}),
    };
}
