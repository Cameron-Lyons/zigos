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

`./scripts/zig.sh build text-scanout-benchmark` measures 1280×720 text scanout
using ordinary host RAM. `full_redraw` alternates every cell's glyph;
`single_cell` changes one glyph; `pool_only` moves unchanged combining
graphemes within the frame's byte pool. Each result is the median of five
samples after warmup. The target checks exact damage: all cells, one cell,
and zero cells respectively. Each damaged cell writes 240 pixels. Host timings
exclude device memory latency and supplement the QEMU and hardware display
proofs. The tool also runs without `--check-damage` for comparison with an
earlier implementation that redraws cells when pool offsets change.

`./scripts/zig.sh build id-index-benchmark` measures 512-bucket ID tables with
sequential keys, keys differing only in their high generation bits, misses
after every home bucket has been occupied and emptied, and repeated insertion
and deletion. It reports resident table bytes, lookup checksums, and the median
of five samples. The tool imports only the public ID-index functions so it can
also measure an earlier core implementation. Deletion now shifts affected
probe-chain entries; both lookup and deletion remain bounded by capacity.

`./scripts/zig.sh build endpoint-readiness-benchmark` compares the original
owner scan with maintained nonempty-queue counts in the same build. Owners
hold 1, 8, 32, or 63 endpoints. Cases check empty queues, a pending message in
the last visited endpoint, and send/drain with readiness checks. Both paths pay
the current send/drain accounting cost, making the scan comparison conservative.
Each result is the median of five 200,000-iteration samples; unexpected
readiness or message results fail the run.

`./scripts/zig.sh build text-layout-benchmark` compares caret location followed
by a second row scan with one visible-window pass over 512-byte ASCII and
Unicode documents. Cases place the caret at the head, middle, and end. Before
timing, every case verifies identical caret locations, first visible rows,
and row contents. Both paths run in the same ReleaseFast build and report the
median of five samples. These host benchmarks supplement booted validation.

The text-layout case locates, moves, and relocates the caret in a full 512-byte
document. It varies hard breaks, widths of 20 and 120 columns, wrap affinity,
movement direction, and one-row versus 23-row page steps. Its checksum includes
the resulting byte offset, row, and affinity; invalid caret results fail the run.
