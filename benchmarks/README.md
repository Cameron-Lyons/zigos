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
