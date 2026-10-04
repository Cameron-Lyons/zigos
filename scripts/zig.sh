#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
REQUIRED_ZIG_VERSION="${REQUIRED_ZIG_VERSION:-$(awk '$1 == "zig" { print $2; exit }' "$ROOT_DIR/.tool-versions")}"

# Environment observations in build.zig do not invalidate Zig's configure
# cache. Make the reproducible-media timestamp an explicit build option.
if [ "${1:-}" = build ] && [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  have_epoch_option=false
  for zig_arg in "$@"; do
    case "$zig_arg" in
      -Dsource-date-epoch | -Dsource-date-epoch=*) have_epoch_option=true ;;
      --) break ;;
    esac
  done
  if ! "$have_epoch_option"; then
    zig_build_args=()
    epoch_added=false
    for zig_arg in "$@"; do
      if [ "$zig_arg" = -- ] && ! "$epoch_added"; then
        zig_build_args+=("-Dsource-date-epoch=$SOURCE_DATE_EPOCH")
        epoch_added=true
      fi
      zig_build_args+=("$zig_arg")
    done
    if ! "$epoch_added"; then
      zig_build_args+=("-Dsource-date-epoch=$SOURCE_DATE_EPOCH")
    fi
    set -- "${zig_build_args[@]}"
  fi
fi

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
