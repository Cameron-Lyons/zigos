# Kernel benchmarks

Run `./scripts/zig.sh build -Doptimize=ReleaseFast benchmark`. The checker
requires complete results and quality checks under every accelerator. KVM
also enforces cycle ceilings and baseline regression limits; TCG timing is
informational. Baselines use the slowest of three consecutive KVM runs.

The secret-store cases fill and reset a bounded 16-record store in batches.
Each operation imports one record, lends and describes a handle, then either
exports into a caller-owned buffer or verifies raw-export denial. Half the
records are exportable. Buffers are erased after use.

- `software_import_handle_export` uses resident software secrets.
- `sealed_import_handle_export` uses the explicit verification provider,
  including authenticated encryption, metadata binding, ciphertext hashing,
  and recovery of exportable records. It measures the store and envelope code;
  TPM command latency is outside this microbenchmark. The TPM guest test
  exercises the real adapter and persisted recovery.

These replace the old mixed case whose hardware provider only produced a
digest. Its cycle budget did not cover recoverable encrypted objects.

The new baselines were captured on 2026-09-26 with the pinned Zig 0.16.0
ReleaseFast build and KVM. All values are cycles per complete operation:

| Workload | Run 1 | Run 2 | Run 3 | Baseline | Ceiling |
| --- | ---: | ---: | ---: | ---: | ---: |
| Software | 139.62 | 136.55 | 132.75 | 139.62 | 300 |
| Sealed | 5288.63 | 5353.70 | 5313.16 | 5353.70 | 8000 |

The standard 50% regression allowance applies to both baselines. Other
workloads retain their existing baselines and ceilings.

`./scripts/zig.sh build ipc-ring-benchmark` measures an eight-slot ring with
88-byte payloads on the host. `single_receive` sends and receives one record;
`split_receive` sends, peeks, pops, and copies the same record. Both use the
current validation code, so this is a comparison of receive strategies, not a
historical kernel baseline. `full_queue` measures rejection while all eight
slots remain occupied. Each result is the median of five 200,000-iteration
samples after warmup. These host timings are informational; the QEMU kernel
benchmark remains the integration gate.

The text-layout case locates, moves, and relocates the caret in a full 512-byte
document. It varies hard breaks, widths of 20 and 120 columns, wrap affinity,
movement direction, and one-row versus 23-row page steps. Its checksum includes
the resulting byte offset, row, and affinity; invalid caret results fail the run.
