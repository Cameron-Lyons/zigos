# Kernel benchmarks

Run `zig build -Doptimize=fast benchmark`. The checker
requires complete results and quality checks under every accelerator. KVM
also enforces cycle ceilings and baseline regression limits; TCG timing is
informational. Baselines use the slowest of three consecutive KVM runs.
Capture stops after 300 seconds; set `ZIGOS_BENCHMARK_SECONDS` to a positive
integer to change that limit. A timeout fails the run and retains its serial log.

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

`zig build ipc-ring-benchmark` measures an eight-slot ring with
the native `x86_64_v3+aes+pclmul+sha` CPU floor and the host OS/ABI;
Apple Silicon executes it through Rosetta. `single_receive` sends and receives
one 88-byte record; `split_receive` sends, peeks, pops, and copies the same record. Both use the
current validation code, so this is a comparison of receive strategies, not a
historical kernel baseline. `full_queue` measures rejection while all eight
slots remain occupied. Each result is the median of five 200,000-iteration
samples after warmup. These host timings are informational; the QEMU kernel
benchmark remains the integration gate.

The same executable also compares the previous endpoint enqueue strategy,
which stages a zero-padded full record, with checked direct payload enqueue for
0, 1, 17, and 88-byte messages. Both validate the ring and received bytes; both
exclude the syscall's required user-memory snapshot. Direct enqueue removes
the intermediate 88-byte payload, handles overlap before clearing unused
bytes, and publishes the head after the complete slot write. Repeated hosted
x86-64 runs on this Apple Silicon host through Rosetta improved all four sizes.
One `zig build ipc-ring-benchmark` run produced the following send/receive
medians, including the shared correctness check:

| Payload bytes | Staged record (ns) | Direct payload (ns) |
| --- | ---: | ---: |
| 0 | 44.72 | 36.70 |
| 1 | 47.24 | 41.26 |
| 17 | 53.35 | 44.71 |
| 88 | 62.79 | 60.76 |

The short-message benefit was 13–18%; the full-length benefit was small and
does not establish a stable gain.

A native aarch64 host build instead regressed: staged/direct medians were
20.85/40.44, 20.55/40.52, 21.26/43.34, and 23.36/42.69 ns respectively. This
optimization is specific to the selected code-generation target; these
measurements do not establish native x86 hardware or kernel throughput.

To reproduce the host-architecture comparison separately:

```sh
zig build-exe -O ReleaseFast --dep ipc_ring \
  -Mroot=tools/benchmark_ipc_ring.zig \
  -Mipc_ring=src/native/kernel_api/ipc_ring.zig \
  -femit-bin=build/benchmark-ipc-ring-host
build/benchmark-ipc-ring-host
```

`zig build response-preflight-benchmark` compares the previous declared-span
validation followed by required-prefix validation with the current single
declared-span admission. It calls the actual preflight API, with equal explicit
inlining of both admission bodies, and keeps final-publication revalidation in
the production path. One, four, and eight ordered load regions and a terminal
stack cover exact and oversized declarations. Status checks cover valid, short,
low, overflowing, and zero-required outputs; every pair checks its checksum.
Seven 500,000-iteration samples alternate strategy order. The hosted native
x86-64 floor under Rosetta, Zig 0.17.0 `fast`, measured on 2026-10-09:

| Layout, 32-byte declaration | Previous | Single validation |
| --- | ---: | ---: |
| One load region | 8.76 ns | 5.62 ns |
| Four load regions | 14.33 ns | 8.68 ns |
| Eight load regions | 22.24 ns | 12.53 ns |
| Terminal stack | 4.94 ns | 3.86 ns |

64-byte declarations showed the same direction. These timings cover hosted
admission only: physical page preparation is excluded equally, and no complete
syscall or hardware latency improvement is claimed.

`zig build text-scanout-benchmark` measures 1280×720 text scanout
using ordinary host RAM. `full_redraw` alternates every cell's glyph;
`single_cell` changes one glyph; `pool_only` moves unchanged combining
graphemes within the frame's byte pool. Each result is the median of five
samples after warmup. The target checks exact damage: all cells, one cell,
and zero cells respectively. Each damaged cell writes 240 pixels. Host timings
exclude device memory latency and supplement the QEMU and hardware display
proofs. The tool also runs without `--check-damage` for comparison with an
earlier implementation that redraws cells when pool offsets change.

`zig build id-index-benchmark` measures 512-bucket ID tables with
sequential keys, keys differing only in their high generation bits, misses
after every home bucket has been occupied and emptied, and repeated insertion
and deletion. It reports resident table bytes, lookup checksums, and the median
of five samples. The tool imports only the public ID-index functions so it can
also measure an earlier core implementation. Deletion now shifts affected
probe-chain entries; both lookup and deletion remain bounded by capacity.

`zig build endpoint-readiness-benchmark` compares the original
owner scan with maintained nonempty-queue counts in the same build. Owners
hold 1, 8, 32, or 63 endpoints. Cases check empty queues, a pending message in
the last visited endpoint, and send/drain with readiness checks. Both paths pay
the current send/drain accounting cost, making the scan comparison conservative.
Each result is the median of five 200,000-iteration samples; unexpected
readiness or message results fail the run.

`zig build text-layout-benchmark` compares caret location followed
by a second row scan with one visible-window pass over 512-byte ASCII and
Unicode documents. Cases place the caret at the head, middle, and end. Before
timing, every case verifies identical caret locations, first visible rows,
and row contents. Both paths run in the same `fast` build and report the
median of five paired samples with alternating strategy order. Timed window
checksums must match. These host benchmarks supplement booted validation.

The target also compares frozen original Unicode boundary loops with the current
next, previous and ceiling helpers. Use
`zig build text-layout-benchmark -Dtext-boundaries-only=true` to run this section
alone. Three 512-byte documents cover ASCII, CRLF and mixed Unicode. Point cases
cycle eight offsets near the head, middle and end; inclusive byte sweeps and
chained left/right traces report nanoseconds per actual helper call. Separate
ceiling rows measure the zero/end shortcuts, and dedicated Unicode rows select
only offsets that require the iterator fallback. Both methods use identical
mutable-text, offset and result barriers. Every byte, oversized offset and chain
step is compared before timing; five alternating paired samples must have equal
checksums and call counts. These measurements concern the helpers, including
barrier overhead, and do not measure complete editor events.

On 2026-10-09, Zig 0.17.0 `fast` measurements on an idle Apple Silicon host
produced the following medians. The AMD64 comparison uses the same harness
compiled for `x86_64_v3+aes+pclmul+sha` and executed through macOS Rosetta.
All 51 pairs on each target had identical call counts and checksums, also
matching across targets. Values are original iterator → current helper in
nanoseconds per call.

| Chained cursor trace | Native Apple Silicon | AMD64 through Rosetta |
| --- | ---: | ---: |
| ASCII right | 1072.57 → 1.61 | 1449.77 → 2.53 |
| ASCII left | 1076.74 → 1.52 | 1422.12 → 1.95 |
| CRLF ASCII right | 1077.27 → 20.80 | 1452.63 → 28.69 |
| CRLF ASCII left | 1089.74 → 21.03 | 1444.74 → 28.05 |
| Mixed Unicode right | 3295.40 → 1302.81 | 2972.41 → 1228.41 |
| Mixed Unicode left | 3263.31 → 1451.56 | 2977.53 → 1368.87 |

Guaranteed Unicode fallback rows changed by −0.20% to +1.19% on native Apple
Silicon and −0.43% to +1.31% through Rosetta. The shortest ASCII paths approach
the shared barrier and loop overhead. These results do not establish complete
editor-event latency or performance on native AMD64 hardware. To reproduce the
AMD64 comparison on macOS, compile both modules with the same explicit target
and optimization settings, then run the resulting executable:

```sh
zig build-exe -O ReleaseFast -target x86_64-macos \
  -mcpu x86_64_v3+aes+pclmul+sha --dep text_layout \
  -Mroot=tools/benchmark_text_layout.zig \
  -O ReleaseFast -target x86_64-macos -mcpu x86_64_v3+aes+pclmul+sha \
  -Mtext_layout=src/text_layout_benchmark.zig \
  -femit-bin=/tmp/zigos-text-boundaries-amd64
/tmp/zigos-text-boundaries-amd64 --boundaries-only
```

The same host target also pairs the original Notes vertical navigation scans
with iterator reuse, checking identical caret offsets, wrap affinity, preferred
columns, and grapheme boundaries before timing. Cases cover both directions,
one-row and five-row steps, initial and retained columns, and all three caret
positions. Five 20,000-iteration samples alternate method order and check matching
checksums. On 2026-10-09, using the same Zig 0.17.0 `fast` build on an Apple
Silicon host, middle-of-document downward row movement changed from 341.10 to
116.08 ns for ASCII and 9732.43 to 3683.02 ns for Unicode with initial columns;
retained columns changed from 231.78 to 116.66 ns and 6495.60 to 3183.63 ns.
Upward movement still traverses preceding rows: 47 of 48 pairs were faster in
that run, with retained-column Unicode Up at the document end 3.2% slower.
These hosted results are informational, not kernel latency thresholds.

The text-layout case locates, moves, and relocates the caret in a full 512-byte
document. It varies hard breaks, widths of 20 and 120 columns, wrap affinity,
movement direction, and one-row versus 23-row page steps. Its checksum includes
the resulting byte offset, row, and affinity; invalid caret results fail the run.

`zig build heap-allocator-benchmark` uses a 16 MiB host arena.
It measures small-allocation reuse, successful and exhausted searches through
1024 separated free blocks, and batches of 512 eight-KiB allocations freed in
a permutation. The batch checks live payload bytes before release and exercises
allocation-start lookup and adjacent-span coalescing. Results report the median
of five samples and allocator array metadata, excluding scalar globals.
The same tool can import an earlier `heap_benchmark.zig` for comparison.

The large-span cases hold 1,024 separated eight-KiB holes behind live guards
and reserve one 32-KiB candidate. `large_fragmented_fit` frees that candidate
and times allocation, its exact-address check and two endpoint payload writes;
the two clock reads remain included. Restoring the holes and freeing the
candidate occur outside each measured interval. `large_fragmented_exhausted`
keeps the candidate live and measures steady failed 32-KiB requests. Both
cases check the live guards after timing.

The allocator retains eight exact magazine sizes through four KiB. Shared free
lists now use twenty additional floor-log2 size ranges and a 32-bit nonempty
bitmap, allowing larger requests to skip smaller and empty ranges. The starting
range still checks each span's exact length; larger allocations keep their
granule-aligned requested size rather than rounding to the range boundary.

Matched measurements on 2026-10-09 compiled the previous and current allocator
with the same final harness and Zig 0.17.0 `fast` settings in both modules.
The following ranges span three paired runs of their five-sample medians,
executing `x86_64_v3+aes+pclmul+sha` macOS binaries through Rosetta:

| Workload | Previous (ns/iteration) | Current (ns/iteration) |
| --- | ---: | ---: |
| `hot_reuse` | 20.42–20.84 | 20.51–20.74 |
| `fragmented_fit` | 20.35–20.42 | 20.35–20.38 |
| `fragmented_exhausted` | 30.40–30.42 | 30.48–31.38 |
| `page_batches` | 19930.23–22187.50 | 21268.75–21559.38 |
| `cached_pressure` | 412.04–417.35 | 429.73–431.56 |
| `large_fragmented_fit` | 2997.50–3041.44 | 37.61–38.05 |
| `large_fragmented_exhausted` | 2982.08–3058.83 | 26.27–26.33 |

All seven checksums matched in every pair. Large fragmented searches improved
substantially, while hot reuse was essentially unchanged. Page batches were
6.7% and 8.2% slower in two pairs and 4.1% faster in the third; cached pressure
was 3.0–4.6% slower in all three. Array metadata grew from 102,418 to 102,456
bytes, with another four scalar bytes for the bitmap. These results show the
large-search benefit and its common-workload costs; they do not establish a
general allocation-throughput gain, hardware latency or a kernel threshold.

The same paired native aarch64 host builds measured large fits at
2694.80–2719.72 versus 28.02–29.22 ns and exhausted searches at
2725.08–2774.79 versus 17.85–18.94 ns. ARM page batches were slower in all three
pairs, by 2.6–41.8%, and other common workloads varied substantially. The cause
of that variation was not measured.

`zig build scheduler-wake-benchmark` measures repeated event wakes through
the real scheduler and task runtime, with one task and all 128 task slots.
`coalesced` keeps tasks ready; `reactivated` parks each task before its next
wake, including the park operation in the timing. Fixtures and exact checks
for ready queues, task incarnations, CPU budgets, wake counts, and deadlines
run outside the timed interval. A balanced 16,384-iteration warmup precedes
nine 2,000,000-iteration samples, with monotonic ticks across warmup and every
sample. Results report median `ns/wake` for coalesced wakes and
`ns/park+wake` for reactivation, using Zig 0.17.0 `fast`. The target runs hosted
x86-64 code; Apple Silicon hosts require Rosetta.

Matched before/after measurements on 2026-10-09 used the same compiler and
x86-64 macOS host execution under Rosetta. Resolving steady-state wakes
through their cached, generation-checked task handles removed a task-ID
index probe. Stale handles still refresh through the index. All four result
checksums matched; these timings are informational and do not establish
hardware wake latency or a kernel regression threshold. These earlier measurements
precede the balanced warmup and monotonic sample-clock correction; recapture both
revisions with the current harness before comparing new timings with this table.

| Workload | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| One task, coalesced | 16.42 ns | 13.18 ns | 19.7% |
| 128 tasks, coalesced | 18.75 ns | 15.12 ns | 19.4% |
| One task, reactivated | 24.77 ns | 20.45 ns | 17.4% |
| 128 tasks, reactivated | 28.63 ns | 23.77 ns | 17.0% |

`zig build storage-checksum-benchmark` compares the previous FNV-1a corruption
checksum with root-v6 seed-zero XXH64 in the same native host `fast` build.
Each case warms the exact input, checks every repeated result, and reports the
median of five samples over at least 32 MiB or 100 hashes. The buffers cover a
small record, one volume block, and one complete inactive checkpoint region.
On 2026-10-09, Zig 0.17.0 on an Apple Silicon host measured:

| Buffer | FNV-1a | XXH64 | Speedup |
| --- | ---: | ---: | ---: |
| 128 bytes | 117.51 ns | 10.92 ns | 10.8× |
| 4096 bytes | 5407.35 ns | 326.14 ns | 16.6× |
| 389120 bytes | 518364.58 ns | 28140.41 ns | 18.4× |

A second same-build comparison using the OS's x86-64-v3 plus AES/PCLMUL/SHA
target under Rosetta measured 110.72/13.45 ns, 5248.72/244.06 ns, and
500822.09/21732.92 ns for FNV-1a/XXH64 at the same buffer sizes. Reproduce this
hosted target with:

```sh
zig run -O ReleaseFast -target x86_64-macos -mcpu=x86_64_v3+aes+pclmul+sha \
  --dep volume_checksum -Mroot=tools/benchmark_storage_checksum.zig \
  -O ReleaseFast -target x86_64-macos -mcpu=x86_64_v3+aes+pclmul+sha \
  -Mvolume_checksum=src/native/storage/volume/checksum.zig
```

These timings cover only checksumming, not complete storage operations or device
latency. XXH64 detects accidental corruption; content addresses and metadata
authentication continue to use SHA-256 and signatures. The new root format
rejects earlier formats on load and save rather than migrating stored data.
Fixed known answers, unaligned slices, stripe boundaries, mutation checks, and
the x86-64 QEMU known answer cover the portable checksum contract.

`zig build storage-quota-benchmark` compares the previous separate count and
maximum-entry scans with one pass over each workspace/snapshot arena. Both paths
use the real Store/Directory layouts and identical persistability predicates;
the current path calls the production quota function. Changing entry counts
checks exact usage before timing and prevents constant-input elimination.
Seven alternating-order samples each evaluate 1,000,000 states. A Zig 0.17.0
`fast` build on Apple Silicon on 2026-10-09 measured:

| State | Previous | Single pass |
| --- | ---: | ---: |
| Empty | 18.01 ns | 9.35 ns |
| Sparse | 17.99 ns | 9.23 ns |
| Full | 35.60 ns | 19.93 ns |
| Malformed | 31.57 ns | 17.55 ns |

Checksums matched. These hosted timings include the shared changing-entry
fixture writes and supplement the persistence and quota policy regressions;
they do not measure complete saves or device latency.

`zig build workspace-index-benchmark` measures 192 path buckets
and 96 object buckets with 64 live entries. Cases cover hits, empty misses after
every home bucket has been occupied and retired, and steady insertion/deletion.
Every replacement checks both indexes and rejects retained old entries. The
tables remain 288 bytes together; deletion closes affected probe chains.
The tool accepts either the old or new object-removal signature to support
comparison against the parent implementation.

`zig build object-chunks-benchmark` compares prefix traversal with
positioned cursors in the same executable. Both paths verify the immutable
manifest and copy 181-byte transport ranges; one-time verification is warmed
equally before timing. It reconstructs two-page, fourteen-page, and maximum
28-page payloads in forward, reverse, and retransmission order, checks exact
payload bytes, and reports page visits and median time per payload. Positioned
cursors remove prefix visits while retaining full manifest verification.
Their setup can cost more for a range wholly within the first page, where
there are no prefix visits to eliminate.

The same tool first compares frozen cleared scratch with the current public
object-address and Merkle-root functions. Both retain the same SHA-256 framing,
tree ordering and odd-leaf duplication, check complete digests before timing,
and check repeated-result checksums in five alternating-order samples. Empty,
partial, odd-chunk and full 28-page inputs are included. On 2026-10-09, the
native Apple Silicon host `fast` build measured:

| Operation | Input | Cleared scratch | Live-prefix scratch |
| --- | --- | ---: | ---: |
| Payload address | Empty | 137.86 ns | 113.44 ns |
| Payload address | 1 byte | 241.14 ns | 183.13 ns |
| Payload address | 4096 bytes | 2124.70 ns | 2068.69 ns |
| Payload address | 114688 bytes | 57873.68 ns | 57812.66 ns |
| Merkle root | 1 reference | 100.10 ns | 68.38 ns |
| Merkle root | 28 references | 4033.95 ns | 3996.11 ns |

The full-payload timing difference is within noise. These hosted measurements
do not establish native hardware hashing or storage latency. Actual native-floor
compiler and linked-kernel inspection confirms removal of the 952-byte reference
and 896-byte Merkle scratch clears, while persistent chunk-index tails still
receive canonical zeros. Fixed independent digest and poisoned-tail tests cover
the initialization contract. The hosted x86-64-v3 plus SHA executable cannot
run this SHA workload under the available Rosetta runtime; the production floor
remains unchanged. To run only hash comparisons on the native host:

```sh
zig run -O ReleaseFast --dep object_chunks \
  -Mroot=tools/benchmark_object_chunks.zig \
  -O ReleaseFast --dep binary_cursor \
  -Mobject_chunks=src/object_chunk_benchmark.zig \
  -O ReleaseFast -Mbinary_cursor=src/native/core/binary_cursor.zig -- --hashes-only
```

`zig build surface-text-benchmark` compares the previous separate
UTF-8 and cursor/anchor boundary checks with combined canonical validation in
the same executable. Full 512-byte ASCII and Unicode documents place collapsed
and selected cursors at the head, middle, and end. Both paths retain metadata,
wrap-affinity, save-state, and zero-tail checks. Each case checks acceptance and
reports the median of five paired samples with alternating strategy order.
Host timings exclude syscall copying and
supplement ingress and Unicode conformance tests.

## Successful syscall dispatch

`zig build syscall-dispatch-benchmark` measures the actual hosted scalar
Surface, trusted port and Kernel for successful time, capability, resource and
accounting queries, endpoint send/receive pairs with 0, 17 and 88-byte
payloads, capability mint/MOVE/revoke cycles and shared-memory map/unmap pairs.
Two live nonzero tasks hold attached task-scoped grants and explicit
user-memory mappings. Setup, full output validation and negative authority and
pointer controls run outside the timed samples. Runtime input barriers preserve
normal admission; timed status, byte-count, output and checksum checks remain
included, along with loop overhead. Endpoint timings include payload staging.

Each workload runs seven samples after warmup: 100,000 iterations normally,
and 50,000 for shared-memory mapping to stay inside its bounded virtual aperture.
Compact and
explicit detailed dispatch alternate order; their checksums must agree. Endpoint
rows report both the whole send/receive pair and its mean cost per dispatch;
they do not isolate send from receive. The detailed success path includes
diagnostic initialization, but failure diagnostic construction is not measured.
Use `-- --seed=0x1e22b6d03db41815` to reproduce the default runtime seed.

On 2026-10-11, Zig 0.17.0 `fast`, the selected AMD64 CPU floor executed through
Rosetta on Apple Silicon. Three balanced process runs per version compared the
same frozen harness before and after routing lookup reuse, direct sealed-slot
receive and conditional capability staging. Medians of the three process
medians, in nanoseconds per complete compact send/receive pair:

| Payload bytes | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| 0 | 251.24 | 234.04 | 6.85% |
| 17 | 290.74 | 275.60 | 5.21% |
| 88 | 363.12 | 345.64 | 4.81% |

All 882 raw samples in the final three-version comparison had matching
per-workload, per-strategy checksums and dispatch counts. Compact query controls
remained within 0.71% of their baseline medians; no query improvement is claimed.
Separate alternating runs checked each routing and direct-receive change.

These are local dispatcher measurements, including host memory copying and
translation overhead. They exclude privilege entry/return, native user-page
preparation, scheduler launch and hardware timing. The fixture uses one load
region per task, two endpoints, no attached gift in timed traffic and no table
pressure. It ranks the measured hosted workloads only. The old native fast-entry fixture
returns unavailable before port publication; its timing cannot substitute for
successful native syscall latency. The QEMU kernel benchmark and integration
checks remain required validation gates.


The additional `endpoint_prefilled_pair_*` cases move complete source payload
initialization outside clocks. Each nonempty timed pair poisons the receiving
buffer's first and last bytes and requires both to be restored by the actual
receive. Correlation, ticks and caller still vary; full payload validation and
all original dynamic payload cases remain. Timings include the two canary
writes/checks and the actual syscall staging copies. The same expanded harness
was compiled against preserved pre-optimization sources and optimized sources;
three alternating process pairs produced these compact medians:

| Prefilled payload bytes | Before (ns/pair) | After (ns/pair) | Reduction |
| --- | ---: | ---: | ---: |
| 0 | 251.64 | 234.29 | 6.89% |
| 17 | 285.61 | 270.59 | 5.26% |
| 88 | 287.87 | 270.08 | 6.18% |

All 840 raw samples matched checksums and dispatch counts across versions and
strategies. In the optimized run, the regenerated 88-byte pair cost about 347 ns
and its prefilled counterpart about 270 ns: that difference includes source
byte generation and the different canary checks, so it is not a copy-only
measurement. Prefilled 17 and 88-byte results are close; no stable ordering
between them is claimed. Further copy or request-admission changes need a
separate measured comparison with the existing ownership and error-order rules.

The next comparison adds successful `capability_mint_revoke_pair`,
`capability_mint_move_revoke_cycle` and `shared_memory_map_unmap_pair` workloads.
Capability cycles mint fresh runtime-selected targets, optionally MOVE authority
to the other live task, then authenticate public self-revocation. Checks cover
new handles, scoped ownership, source removal and final revocation. Shared-memory
cycles map and unmap a real 4 KiB object with fresh response canaries; each
strategy/sample owns a fresh fixture initialized outside clocks. No trusted
cleanup or virtual-cursor reset occurs inside timed loops. The mapping fixture
measures hosted metadata mutations and excludes native page-table registration.

The capability cycles were the slowest measured operations. Single-entry mint
now uses capacity-sized temporary plan, reservation and output storage through
the existing transaction algorithm. Audit-trace computation borrows the record
and combines wrapping FNV multiplications only for proven zero suffix bytes;
the canonical 107-byte stream and trace identity remain exact. Paired transaction
tests preserve admission error order and rollback; an independent byte-stream
oracle checks integer boundaries, randomized records and explicit trace overrides.

On 2026-10-11, the same Zig/AMD64/Rosetta setup and frozen 13-workload harness
produced these medians from three alternating baseline/optimized process pairs.
Times cover the entire successful operation cycle, including timed validation
and loop overhead; they do not isolate individual mint, MOVE or revoke latency.

| Cycle | Compact before (ns) | Compact after (ns) | Reduction | Detailed before (ns) | Detailed after (ns) | Reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Mint → revoke | 716.08 | 698.61 | 2.44% | 775.40 | 761.16 | 1.84% |
| Mint → MOVE → revoke | 1503.42 | 1415.92 | 5.82% | 1597.33 | 1510.61 | 5.43% |
| Shared-memory map → unmap | 189.79 | 190.11 | −0.17% | 242.61 | 242.68 | −0.03% |

All 1,092 raw samples across the six processes matched per-workload,
per-strategy checksums and actual dispatch counts. Query and endpoint controls
remained within 1.61% of baseline medians. A consolidated shared-mapping candidate
regressed by 3.48% in a separate matched comparison and was discarded; the
accepted mapping implementation is unchanged. Small control differences and
the shared-mapping results do not establish a performance change. These results
remain local dispatcher measurements and exclude native privilege entry/return.
