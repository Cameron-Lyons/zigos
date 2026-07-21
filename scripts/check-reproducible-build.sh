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

REQUIRED_RELEASE_ARTIFACTS=(
  "zig-out/bin/kernel-zigos-native.elf"
  "zig-out/bin/zigos-sign"
  "zig-out/bin/zigos-verify-release"
  "build/os.iso"
  "spec/production_readiness.json"
  "spec/release_security/release_artifacts.json"
  "spec/release_security/release_keyring.json"
  "spec/release_security/revoked_release_keys.json"
  "spec/release_security/fuzz_corpus.json"
  "spec/release_security/memory_safety_inventory.json"
  "spec/release_security/threat_model.json"
  "spec/release_security/crash_dump_redaction.json"
  "spec/release_security/vulnerability_disclosure.json"
)

PRODUCTION_USERSPACE_ARTIFACTS=(
  "zig-out/bin/userspace-session-manager.elf"
  "zig-out/bin/userspace-permission-review.elf"
  "zig-out/bin/userspace-service-registry.elf"
  "zig-out/bin/userspace-workspace-storage.elf"
  "zig-out/bin/userspace-viewer.elf"
  "zig-out/bin/userspace-notes.elf"
  "zig-out/bin/userspace-sync.elf"
  "zig-out/bin/userspace-capture.elf"
  "zig-out/bin/userspace-policy-mediation.elf"
  "zig-out/bin/userspace-network-stack.elf"
  "zig-out/bin/userspace-storage-object.elf"
  "zig-out/bin/userspace-storage-driver.elf"
  "zig-out/bin/userspace-package-service.elf"
  "zig-out/bin/userspace-compositor.elf"
  "zig-out/bin/userspace-indexing-search.elf"
  "zig-out/bin/userspace-personal-context.elf"
  "zig-out/bin/userspace-sync-service.elf"
  "zig-out/bin/userspace-media-print.elf"
  "zig-out/bin/userspace-attention-broker.elf"
  "zig-out/bin/userspace-task-lifecycle.elf"
  "zig-out/bin/userspace-sensitive-capture.elf"
  "zig-out/bin/userspace-secure-pasteboard.elf"
  "zig-out/bin/userspace-object-resilience.elf"
  "zig-out/bin/userspace-secret-vault.elf"
)

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

is_forbidden_release_artifact() {
  local relative_path="${1:?artifact path required}"
  case "$relative_path" in
    build/os-verification.iso | \
      zig-out/bin/kernel-zigos-native-verification.elf | \
      zig-out/bin/kernel-zigos-native-tampered-*.elf | \
      zig-out/bin/kernel-zigos-native-rollback-slot-failure.elf | \
      zig-out/bin/kernel-zigos-native-storage-durability.elf | \
      zig-out/bin/kernel-recovery.elf | \
      zig-out/bin/kernel-benchmark.elf | \
      zig-out/bin/userspace-transport-probe.elf | \
      zig-out/bin/userspace-termination-probe.elf | \
      zig-out/bin/userspace-service-client.elf | \
      zig-out/bin/userspace-mmu-isolation-proof.elf | \
      zig-out/bin/userspace-notes-daily.elf)
      return 0
      ;;
  esac
  return 1
}

is_explicit_release_artifact() {
  local relative_path="${1:?artifact path required}"
  local allowed_path
  for allowed_path in "${REQUIRED_RELEASE_ARTIFACTS[@]}" "${PRODUCTION_USERSPACE_ARTIFACTS[@]}"; do
    if [ "$relative_path" = "$allowed_path" ]; then
      return 0
    fi
  done
  return 1
}

is_allowed_release_artifact() {
  local relative_path="${1:?artifact path required}"
  ! is_forbidden_release_artifact "$relative_path" || return 1
  is_explicit_release_artifact "$relative_path"
}

copy_workspace() {
  local dest="${1:?destination required}"
  mkdir -p "$dest"
  jj -R "$ROOT_DIR" file list -r @ -T 'path ++ "\n"' |
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      mkdir -p "$dest/$(dirname "$path")"
      cp -p "$ROOT_DIR/$path" "$dest/$path"
    done
}

write_digest_manifest() {
  local tree="${1:?tree required}"
  local manifest="${2:?manifest required}"
  local files=()
  local relative_path

  for relative_path in "${REQUIRED_RELEASE_ARTIFACTS[@]}"; do
    if [ ! -f "$tree/$relative_path" ]; then
      printf 'Missing required reproducible production artifact in %s: %s\n' "$tree" "$relative_path" >&2
      return 1
    fi
    files+=("$relative_path")
  done
  for relative_path in "${PRODUCTION_USERSPACE_ARTIFACTS[@]}"; do
    if [ ! -f "$tree/$relative_path" ]; then
      printf 'Missing required reproducible production userspace artifact in %s: %s\n' "$tree" "$relative_path" >&2
      return 1
    fi
    files+=("$relative_path")
  done

  sorted_files="$(mktemp "${TMPDIR:-/tmp}/zigos-repro-files.XXXXXX")"
  printf '%s\n' "${files[@]}" | LC_ALL=C sort -u > "$sorted_files"
  files=()
  while IFS= read -r file; do
    if ! is_allowed_release_artifact "$file"; then
      printf 'Reproducible build manifest contains an artifact outside the production release allowlist: %s\n' "$file" >&2
      return 1
    fi
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
    ./scripts/zig.sh build -Doptimize=ReleaseFast iso signing-cli verify-release-cli
  )
}

if ! command -v jj >/dev/null 2>&1; then
  printf 'Jujutsu (jj) is required to record reproducible-build source provenance.\n' >&2
  exit 1
fi

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
repo_vcs="jj"
repo_url="$(jj -R "$ROOT_DIR" git remote list 2>/dev/null | awk '$1 == "origin" { print $2; found = 1; exit } END { exit found ? 0 : 1 }' || printf 'NOASSERTION')"
repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"')"
commit_sha="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"')"
dirty_count="$(jj -R "$ROOT_DIR" diff -r @ --name-only | wc -l | tr -d ' ')"
zig_version="$("$ROOT_DIR/scripts/zig.sh" version 2>/dev/null || printf 'unknown')"

if ! cmp -s "$first_manifest" "$second_manifest"; then
  diff -u "$first_manifest" "$second_manifest" >&2 || true
  cat > "$OUTPUT_PATH/reproducible-build.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "repo_vcs": "$repo_vcs",
  "repository": "$(json_escape "$repo_url")",
  "repo_change_id": "$(json_escape "$repo_change_id")",
  "commit": "$(json_escape "$commit_sha")",
  "dirty_workspace_file_count": $dirty_count,
  "zig_version": "$(json_escape "$zig_version")",
  "optimize_mode": "ReleaseFast",
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
  "repo_vcs": "$repo_vcs",
  "repository": "$(json_escape "$repo_url")",
  "repo_change_id": "$(json_escape "$repo_change_id")",
  "commit": "$(json_escape "$commit_sha")",
  "dirty_workspace_file_count": $dirty_count,
  "zig_version": "$(json_escape "$zig_version")",
  "optimize_mode": "ReleaseFast",
  "status": "passed",
  "comparison": "two independent tracked-workspace builds produced identical release artifact digests",
  "digest_manifest": "$OUTPUT_DIR/reproducible-artifact-digests.sha256"
}
EOF

printf 'Reproducible build OK: compared two independent release builds\n'
