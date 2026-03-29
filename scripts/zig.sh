#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
REQUIRED_ZIG_VERSION="${REQUIRED_ZIG_VERSION:-$(awk '$1 == "zig" { print $2; exit }' "$ROOT_DIR/.tool-versions")}"

: "${ZIG_LOCAL_CACHE_DIR:=${ROOT_DIR}/build/zig-cache}"
: "${ZIG_GLOBAL_CACHE_DIR:=${ROOT_DIR}/build/zig-global-cache}"
export ZIG_LOCAL_CACHE_DIR
export ZIG_GLOBAL_CACHE_DIR
mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

candidate_matches() {
  local candidate="$1"
  [ -x "$candidate" ] || return 1
  [ "$("$candidate" version 2>/dev/null || true)" = "$REQUIRED_ZIG_VERSION" ]
}

if [ -n "${ZIG_BIN:-}" ]; then
  exec "$ZIG_BIN" "$@"
fi

if have_cmd zig && [ "$(zig version 2>/dev/null || true)" = "$REQUIRED_ZIG_VERSION" ]; then
  exec zig "$@"
fi

if have_cmd mise && mise where "zig@${REQUIRED_ZIG_VERSION}" >/dev/null 2>&1; then
  exec mise exec "zig@${REQUIRED_ZIG_VERSION}" -- zig "$@"
fi

for candidate in \
  "$ROOT_DIR/.zig/zig" \
  "$ROOT_DIR/tools/zig/zig" \
  "$ROOT_DIR/build/zig-x86_64-linux-${REQUIRED_ZIG_VERSION}/zig"
do
  if candidate_matches "$candidate"; then
    exec "$candidate" "$@"
  fi
done

cat >&2 <<EOF
Zigos requires Zig ${REQUIRED_ZIG_VERSION}.
Use ./scripts/zig.sh for repo commands after doing one of the following:
  - install Zig ${REQUIRED_ZIG_VERSION} and make it your active \`zig\`
  - install it through \`mise\`
  - set ZIG_BIN=/absolute/path/to/zig
EOF
exit 1
