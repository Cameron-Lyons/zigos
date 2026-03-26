#!/usr/bin/env bash
set -eu

mkdir -p build/zig-cache-tests build/zig-global-cache-tests
export ZIG_LOCAL_CACHE_DIR="build/zig-cache-tests"
export ZIG_GLOBAL_CACHE_DIR="build/zig-global-cache-tests"

python3 - <<'INNER' > build/host-test-targets.txt
from pathlib import Path

root = Path('/home/cameronl/zigos')
search_roots = [
    root / 'src/kernel/process/syscall',
    root / 'src/kernel/fs',
    root / 'src/kernel/shell',
    root / 'src/kernel/process',
    root / 'src/kernel/net/tcp',
]

seen: set[Path] = set()
targets: list[str] = []
for base in search_roots:
    for path in sorted(base.rglob('*.zig')):
        if path in seen:
            continue
        try:
            text = path.read_text()
        except Exception:
            continue
        if 'test "' not in text:
            continue
        seen.add(path)
        targets.append(str(path.relative_to(root)))

for target in targets:
    print(target)
INNER

if [ ! -s build/host-test-targets.txt ]; then
  echo "Host test discovery failed: no inline test targets found" >&2
  exit 1
fi

while IFS= read -r test_file; do
  zig test "$test_file"
done < build/host-test-targets.txt
