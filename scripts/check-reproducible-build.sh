#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-build/release-security}"
OUTPUT_PATH="$ROOT_DIR/$OUTPUT_DIR"
WORK_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-repro.XXXXXX")"

cleanup() {
  rm -rf -- "$WORK_PARENT"
}
trap cleanup EXIT

mkdir -p "$OUTPUT_PATH"

json_escape() {
  sed 's/\\/\\\\/g; s/"/\\"/g' <<<"$1"
}

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

copy_workspace() {
  local dest="${1:?destination required}"
  mkdir -p "$dest"
  git -C "$ROOT_DIR" ls-files --cached --others --exclude-standard -z |
    while IFS= read -r -d '' path; do
      mkdir -p "$dest/$(dirname "$path")"
      cp -p "$ROOT_DIR/$path" "$dest/$path"
    done
}

write_digest_manifest() {
  local tree="${1:?tree required}"
  local manifest="${2:?manifest required}"
  local files=()

  if [ -f "$tree/zig-out/bin/kernel-zigos-native.elf" ]; then
    files+=("zig-out/bin/kernel-zigos-native.elf")
  fi
  if [ -f "$tree/zig-out/bin/zigos-sign" ]; then
    files+=("zig-out/bin/zigos-sign")
  fi
  if [ -f "$tree/zig-out/bin/zigos-verify-release" ]; then
    files+=("zig-out/bin/zigos-verify-release")
  fi
  if [ -f "$tree/build/os.iso" ]; then
    files+=("build/os.iso")
  fi
  if [ -d "$tree/zig-out/bin" ]; then
    while IFS= read -r -d '' file; do
      files+=("${file#"$tree"/}")
    done < <(find "$tree/zig-out/bin" -type f -print0)
  fi

  if [ "${#files[@]}" -eq 0 ]; then
    echo "No reproducible build artifacts found in $tree" >&2
    return 1
  fi

  sorted_files="$(mktemp "${TMPDIR:-/tmp}/zigos-repro-files.XXXXXX")"
  printf '%s\n' "${files[@]}" | LC_ALL=C sort -u > "$sorted_files"
  files=()
  while IFS= read -r file; do
    files+=("$file")
  done < "$sorted_files"
  rm -f -- "$sorted_files"
  : > "$manifest"
  for file in "${files[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$tree/$file")" "$file" >> "$manifest"
  done
}

build_copy() {
  local tree="${1:?tree required}"
  (
    cd "$tree"
    ./scripts/zig.sh build iso signing-cli verify-release-cli
  )
}

first_tree="$WORK_PARENT/first"
second_tree="$WORK_PARENT/second"
copy_workspace "$first_tree"
copy_workspace "$second_tree"

build_copy "$first_tree"
build_copy "$second_tree"

first_manifest="$WORK_PARENT/first.sha256"
second_manifest="$WORK_PARENT/second.sha256"
write_digest_manifest "$first_tree" "$first_manifest"
write_digest_manifest "$second_tree" "$second_manifest"

created_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
commit_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf 'NOASSERTION')"
zig_version="$("$ROOT_DIR/scripts/zig.sh" version 2>/dev/null || printf 'unknown')"

if ! cmp -s "$first_manifest" "$second_manifest"; then
  diff -u "$first_manifest" "$second_manifest" >&2 || true
  cat > "$OUTPUT_PATH/reproducible-build.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "commit": "$(json_escape "$commit_sha")",
  "zig_version": "$(json_escape "$zig_version")",
  "status": "failed"
}
EOF
  exit 1
fi

cp "$first_manifest" "$OUTPUT_PATH/reproducible-artifact-digests.sha256"
cat > "$OUTPUT_PATH/reproducible-build.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "commit": "$(json_escape "$commit_sha")",
  "zig_version": "$(json_escape "$zig_version")",
  "status": "passed",
  "comparison": "two independent tracked-workspace builds produced identical release artifact digests",
  "digest_manifest": "$OUTPUT_DIR/reproducible-artifact-digests.sha256"
}
EOF

printf 'Reproducible build OK: compared two independent release builds\n'
