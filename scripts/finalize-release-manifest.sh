#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-build/release-security}"
ARTIFACT_ROOT_INPUT="${2:-$ROOT_DIR}"
MANIFEST_PAYLOAD_TYPE="application/vnd.zigos.release-manifest.v1+json"

is_safe_relative_dir() {
  local candidate="${1:-}"
  local segment
  local segments=()
  [[ "$candidate" == build/* ]] && [[ "$candidate" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  IFS='/' read -r -a segments <<< "$candidate"
  for segment in "${segments[@]}"; do
    [ -n "$segment" ] && [ "$segment" != "." ] && [ "$segment" != ".." ] || return 1
  done
}

is_safe_relative_dir "$OUTPUT_DIR" || {
  printf 'Release output directory must be a safe relative path: %s\n' "$OUTPUT_DIR" >&2
  exit 2
}
OUTPUT_PATH="$ROOT_DIR/$OUTPUT_DIR"
ARTIFACT_ROOT="$(realpath "$ARTIFACT_ROOT_INPUT")"

fail_finalization() {
  printf 'release manifest finalization failed: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

file_size_bytes() {
  local file="${1:?file required}"
  wc -c < "$file" | tr -d ' '
}

base64_no_wrap() {
  base64 | tr -d '\n'
}

base64_decode() {
  if base64 --help 2>&1 | grep -q -- '--decode'; then
    base64 --decode
  else
    base64 -D
  fi
}

is_sha256_hex() {
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

is_positive_integer() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

is_base64_text() {
  local value="${1:-}"
  [ -n "$value" ] || return 1
  [[ "$value" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
  [ $(( ${#value} % 4 )) -eq 0 ]
}

is_allowed_evidence_name() {
  local candidate="${1:?evidence name required}"
  local expected
  for expected in "${RELEASE_EVIDENCE_NAMES[@]}"; do
    [ "$candidate" = "$expected" ] && return 0
  done
  return 1
}

require_contained_regular_file() {
  local root="${1:?root required}"
  local relative_path="${2:?relative path required}"
  local candidate="$root/$relative_path"
  local resolved
  [ -f "$candidate" ] || fail_finalization "missing required file: $relative_path"
  [ ! -L "$candidate" ] || fail_finalization "symbolic links are not permitted: $relative_path"
  resolved="$(realpath "$candidate")"
  case "$resolved" in
    "$root"/*) ;;
    *) fail_finalization "file resolves outside its trusted root: $relative_path" ;;
  esac
}

REQUIRED_RELEASE_TARGETS=(
  "build/os.iso"
  "spec/production_readiness.json"
  "spec/release_security/crash_dump_redaction.json"
  "spec/release_security/fuzz_corpus.json"
  "spec/release_security/memory_safety_inventory.json"
  "spec/release_security/release_artifacts.json"
  "spec/release_security/threat_model.json"
  "spec/release_security/vulnerability_disclosure.json"
  "zig-out/bin/kernel-zigos-native.elf"
  "zig-out/bin/userspace-attention-broker.elf"
  "zig-out/bin/userspace-capture.elf"
  "zig-out/bin/userspace-compositor.elf"
  "zig-out/bin/userspace-indexing-search.elf"
  "zig-out/bin/userspace-media-print.elf"
  "zig-out/bin/userspace-network-stack.elf"
  "zig-out/bin/userspace-notes.elf"
  "zig-out/bin/userspace-object-resilience.elf"
  "zig-out/bin/userspace-package-service.elf"
  "zig-out/bin/userspace-permission-review.elf"
  "zig-out/bin/userspace-personal-context.elf"
  "zig-out/bin/userspace-policy-mediation.elf"
  "zig-out/bin/userspace-secret-vault.elf"
  "zig-out/bin/userspace-secure-pasteboard.elf"
  "zig-out/bin/userspace-sensitive-capture.elf"
  "zig-out/bin/userspace-service-registry.elf"
  "zig-out/bin/userspace-session-manager.elf"
  "zig-out/bin/userspace-storage-driver.elf"
  "zig-out/bin/userspace-storage-object.elf"
  "zig-out/bin/userspace-sync-service.elf"
  "zig-out/bin/userspace-sync.elf"
  "zig-out/bin/userspace-task-lifecycle.elf"
  "zig-out/bin/userspace-viewer.elf"
  "zig-out/bin/userspace-workspace-storage.elf"
)

RELEASE_EVIDENCE_NAMES=(
  "artifact-digests.sha256"
  "artifact-measurements.json"
  "customer-verification-policy.json"
  "provenance.dsse.intoto.jsonl"
  "provenance.intoto.jsonl"
  "release-trust-policy.dsse.json"
  "reproducible-artifact-digests.sha256"
  "reproducible-build.json"
  "root-metadata.json"
  "sbom.spdx.json"
)

[ "${#REQUIRED_RELEASE_TARGETS[@]}" -eq 33 ] ||
  fail_finalization "release target catalog must contain exactly 33 paths"
[ "${#RELEASE_EVIDENCE_NAMES[@]}" -eq 10 ] ||
  fail_finalization "release evidence catalog must contain exactly 10 names"
target_unique_count="$(printf '%s\n' "${REQUIRED_RELEASE_TARGETS[@]}" | sort -u | wc -l | tr -d ' ')"
evidence_unique_count="$(printf '%s\n' "${RELEASE_EVIDENCE_NAMES[@]}" | sort -u | wc -l | tr -d ' ')"
[ "$target_unique_count" -eq "${#REQUIRED_RELEASE_TARGETS[@]}" ] ||
  fail_finalization "release target catalog contains a duplicate path"
[ "$evidence_unique_count" -eq "${#RELEASE_EVIDENCE_NAMES[@]}" ] ||
  fail_finalization "release evidence catalog contains a duplicate name"

[ ! -L "$ROOT_DIR/build" ] || fail_finalization "repository build directory must not be a symbolic link"
[ "$(realpath "$ROOT_DIR/build")" = "$ROOT_DIR/build" ] ||
  fail_finalization "repository build directory resolves outside the workspace"
[ -d "$OUTPUT_PATH" ] || fail_finalization "release evidence directory does not exist: $OUTPUT_PATH"
case "$(realpath "$OUTPUT_PATH")" in
  "$ROOT_DIR/build"/*) ;;
  *) fail_finalization "release evidence directory resolves outside the repository build directory" ;;
esac

lock_dir="${OUTPUT_PATH}.finalize.lock"
if ! mkdir -m 0700 -- "$lock_dir"; then
  fail_finalization "another finalizer is active or a stale ceremony lock exists: $lock_dir"
fi
work_dir=""
cleanup() {
  if [ -n "$work_dir" ]; then
    rm -rf -- "$work_dir"
  fi
  rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
work_dir="$(mktemp -d "$ROOT_DIR/build/.release-finalize.XXXXXX")"

command -v jq >/dev/null 2>&1 || fail_finalization "jq is required"
[ -n "${ZIGOS_RELEASE_TRUST_ROOT:-}" ] || fail_finalization "ZIGOS_RELEASE_TRUST_ROOT is required"
[ -n "${ZIGOS_RELEASE_TRUST_ROOT_SHA256:-}" ] || fail_finalization "ZIGOS_RELEASE_TRUST_ROOT_SHA256 is required"
is_sha256_hex "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" ||
  fail_finalization "ZIGOS_RELEASE_TRUST_ROOT_SHA256 must be lowercase SHA-256"
[ -n "${ZIGOS_RELEASE_TRUST_POLICY:-}" ] || fail_finalization "ZIGOS_RELEASE_TRUST_POLICY is required"
[ -n "${ZIGOS_RELEASE_TRUST_STATE:-}" ] || fail_finalization "ZIGOS_RELEASE_TRUST_STATE is required"
[ -n "${ZIGOS_RELEASE_VERIFIER:-}" ] || fail_finalization "ZIGOS_RELEASE_VERIFIER is required"
[ -n "${ZIGOS_RELEASE_VERIFIER_SHA256:-}" ] || fail_finalization "ZIGOS_RELEASE_VERIFIER_SHA256 is required"
is_sha256_hex "$ZIGOS_RELEASE_VERIFIER_SHA256" ||
  fail_finalization "ZIGOS_RELEASE_VERIFIER_SHA256 must be lowercase SHA-256"
case "$ZIGOS_RELEASE_TRUST_ROOT" in
  /*) ;;
  *) fail_finalization "ZIGOS_RELEASE_TRUST_ROOT must be an absolute, independently provisioned path" ;;
esac
case "$ZIGOS_RELEASE_TRUST_POLICY" in
  /*) ;;
  *) fail_finalization "ZIGOS_RELEASE_TRUST_POLICY must be an absolute, independently provisioned path" ;;
esac
case "$ZIGOS_RELEASE_TRUST_STATE" in
  /*) ;;
  *) fail_finalization "ZIGOS_RELEASE_TRUST_STATE must be an absolute persistent path" ;;
esac
case "$ZIGOS_RELEASE_VERIFIER" in
  /*) ;;
  *) fail_finalization "ZIGOS_RELEASE_VERIFIER must be an absolute, independently provisioned path" ;;
esac
[ -n "${ZIGOS_RELEASE_SIGNING_KEY_ID:-}" ] || fail_finalization "ZIGOS_RELEASE_SIGNING_KEY_ID is required"
is_sha256_hex "$ZIGOS_RELEASE_SIGNING_KEY_ID" ||
  fail_finalization "ZIGOS_RELEASE_SIGNING_KEY_ID must be a lowercase SHA-256 key id"
[ -n "${ZIGOS_RELEASE_DSSE_SIGN_COMMAND:-}" ] || fail_finalization "ZIGOS_RELEASE_DSSE_SIGN_COMMAND is required"
[ "${ZIGOS_RELEASE_HARDWARE_BACKED:-}" = "true" ] || fail_finalization "ZIGOS_RELEASE_HARDWARE_BACKED=true is required"
is_positive_integer "${ZIGOS_RELEASE_SEQUENCE:-}" || fail_finalization "ZIGOS_RELEASE_SEQUENCE must be a positive integer"
is_positive_integer "${ZIGOS_RELEASE_EXPIRES_AT:-}" || fail_finalization "ZIGOS_RELEASE_EXPIRES_AT must be a positive Unix timestamp"

[ -f "$ZIGOS_RELEASE_VERIFIER" ] && [ -x "$ZIGOS_RELEASE_VERIFIER" ] && [ ! -L "$ZIGOS_RELEASE_VERIFIER" ] ||
  fail_finalization "release verifier must be an executable regular file, not a symlink"
canonical_release_verifier="$(realpath "$ZIGOS_RELEASE_VERIFIER")"
case "$canonical_release_verifier" in
  "$ARTIFACT_ROOT" | "$ARTIFACT_ROOT"/*)
    fail_finalization "release verifier must be provisioned independently of the candidate artifact tree"
    ;;
esac
release_verifier="$work_dir/pinned-release-verifier"
cp "$ZIGOS_RELEASE_VERIFIER" "$release_verifier"
chmod 0500 "$release_verifier"
[ "$(sha256_file "$release_verifier")" = "$ZIGOS_RELEASE_VERIFIER_SHA256" ] ||
  fail_finalization "release verifier copy does not match its independently pinned SHA-256"
[ -f "$ZIGOS_RELEASE_TRUST_ROOT" ] || fail_finalization "trusted root metadata file is missing"
[ -f "$ZIGOS_RELEASE_TRUST_POLICY" ] || fail_finalization "signed trust policy file is missing"

rm -f -- "$OUTPUT_PATH/release-manifest.dsse.json"

cmp -s "$ZIGOS_RELEASE_TRUST_ROOT" "$OUTPUT_PATH/root-metadata.json" ||
  fail_finalization "bundled root metadata differs from the independently supplied root"
cmp -s "$ZIGOS_RELEASE_TRUST_POLICY" "$OUTPUT_PATH/release-trust-policy.dsse.json" ||
  fail_finalization "bundled trust policy differs from the authenticated external policy"
[ "$(sha256_file "$OUTPUT_PATH/root-metadata.json")" = "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" ] ||
  fail_finalization "bundled root metadata does not match the pinned digest"

"$release_verifier" trust-info \
  --trusted-root "$ZIGOS_RELEASE_TRUST_ROOT" \
  --trusted-root-sha256 "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" \
  --policy "$OUTPUT_PATH/release-trust-policy.dsse.json" \
  --release-key-id "$ZIGOS_RELEASE_SIGNING_KEY_ID"

for target in "${REQUIRED_RELEASE_TARGETS[@]}"; do
  require_contained_regular_file "$ARTIFACT_ROOT" "$target"
done
for evidence in "${RELEASE_EVIDENCE_NAMES[@]}"; do
  require_contained_regular_file "$OUTPUT_PATH" "$evidence"
done

while IFS= read -r -d '' evidence_path; do
  evidence_name="${evidence_path##*/}"
  is_allowed_evidence_name "$evidence_name" ||
    fail_finalization "unexpected file in exact release evidence directory: $evidence_name"
done < <(find "$OUTPUT_PATH" -mindepth 1 -maxdepth 1 -print0)

cmp -s "$OUTPUT_PATH/artifact-digests.sha256" "$OUTPUT_PATH/reproducible-artifact-digests.sha256" ||
  fail_finalization "primary and independently reproduced target digest manifests differ"

policy_payload_b64="$(jq -er --arg payload_type 'application/vnd.zigos.release-trust-policy.v1+json' \
  'select(.payloadType == $payload_type) | .payload | select(type == "string" and length > 0)' \
  "$OUTPUT_PATH/release-trust-policy.dsse.json")"
printf '%s' "$policy_payload_b64" | base64_decode > "$work_dir/policy.json" ||
  fail_finalization "authenticated trust policy payload is not valid base64"
policy_version="$(jq -er '.policyVersion | select(type == "number" and . > 0 and floor == .)' "$work_dir/policy.json")"
profile_id="$(jq -er '.artifactProfile.profileId | select(type == "string" and length > 0)' "$work_dir/policy.json")"
policy_expires_at="$(jq -er '.expiresAt | select(type == "number" and . > 0 and floor == .)' "$work_dir/policy.json")"
release_key_not_after="$(jq -er --arg key_id "$ZIGOS_RELEASE_SIGNING_KEY_ID" \
  '.releaseKeys[] | select(.keyId == $key_id and .status == "active") | .notAfter | select(type == "number" and . > 0 and floor == .)' \
  "$work_dir/policy.json")"
if [ "$ZIGOS_RELEASE_EXPIRES_AT" -gt "$policy_expires_at" ] ||
   [ "$ZIGOS_RELEASE_EXPIRES_AT" -gt "$release_key_not_after" ]; then
  fail_finalization "manifest expiry exceeds the authenticated policy or release-key window"
fi

reproducible="$OUTPUT_PATH/reproducible-build.json"
jq -e 'select(.status == "passed" and .repo_vcs == "jj" and .dirty_workspace_file_count == 0 and .optimize_mode == "ReleaseFast")' \
  "$reproducible" >/dev/null || fail_finalization "reproducible-build evidence is not a clean ReleaseFast Jujutsu build"
repository="$(jq -er '.repository | select(type == "string" and length > 0)' "$reproducible")"
change_id="$(jq -er '.repo_change_id | select(type == "string" and length > 0)' "$reproducible")"
commit_id="$(jq -er '.commit | select(type == "string" and length > 0)' "$reproducible")"
zig_version="$(jq -er '.zig_version | select(type == "string" and length > 0)' "$reproducible")"
optimize_mode="$(jq -er '.optimize_mode | select(type == "string" and length > 0)' "$reproducible")"

: > "$work_dir/targets.tsv"
for target in "${REQUIRED_RELEASE_TARGETS[@]}"; do
  printf '%s\t%s\t%s\n' \
    "$target" \
    "$(sha256_file "$ARTIFACT_ROOT/$target")" \
    "$(file_size_bytes "$ARTIFACT_ROOT/$target")" >> "$work_dir/targets.tsv"
done
jq -Rn '[inputs | split("\t") | {path: .[0], sha256: .[1], sizeBytes: (.[2] | tonumber)}]' \
  < "$work_dir/targets.tsv" > "$work_dir/targets.json"

: > "$work_dir/evidence.tsv"
for evidence in "${RELEASE_EVIDENCE_NAMES[@]}"; do
  printf '%s\t%s\t%s\n' \
    "$evidence" \
    "$(sha256_file "$OUTPUT_PATH/$evidence")" \
    "$(file_size_bytes "$OUTPUT_PATH/$evidence")" >> "$work_dir/evidence.tsv"
done
jq -Rn '[inputs | split("\t") | {path: .[0], sha256: .[1], sizeBytes: (.[2] | tonumber)}]' \
  < "$work_dir/evidence.tsv" > "$work_dir/evidence.json"

issued_at="$(date -u '+%s')"
if [ "$ZIGOS_RELEASE_EXPIRES_AT" -le "$issued_at" ]; then
  fail_finalization "ZIGOS_RELEASE_EXPIRES_AT must be later than the current trusted wall clock"
fi

jq -cnS \
  --argjson policyVersion "$policy_version" \
  --arg profileId "$profile_id" \
  --argjson releaseSequence "$ZIGOS_RELEASE_SEQUENCE" \
  --argjson issuedAt "$issued_at" \
  --argjson expiresAt "$ZIGOS_RELEASE_EXPIRES_AT" \
  --arg repository "$repository" \
  --arg changeId "$change_id" \
  --arg commitId "$commit_id" \
  --arg zigVersion "$zig_version" \
  --arg optimizeMode "$optimize_mode" \
  --slurpfile targets "$work_dir/targets.json" \
  --slurpfile evidence "$work_dir/evidence.json" \
  '{
    policyVersion: $policyVersion,
    profileId: $profileId,
    releaseSequence: $releaseSequence,
    issuedAt: $issuedAt,
    expiresAt: $expiresAt,
    source: {
      repository: $repository,
      changeId: $changeId,
      commitId: $commitId
    },
    build: {
      zigVersion: $zigVersion,
      target: "x86-freestanding-none",
      optimizeMode: $optimizeMode,
      builderId: "zigos-local-release-security-gate"
    },
    targets: $targets[0],
    evidence: $evidence[0]
  }' > "$work_dir/manifest.json"

manifest_payload="$(<"$work_dir/manifest.json")"
manifest_signature="$({
  printf 'DSSEv1 %d %s %d ' "${#MANIFEST_PAYLOAD_TYPE}" "$MANIFEST_PAYLOAD_TYPE" "${#manifest_payload}"
  printf '%s' "$manifest_payload"
} | bash -c "$ZIGOS_RELEASE_DSSE_SIGN_COMMAND" | tr -d '\n')"
is_base64_text "$manifest_signature" ||
  fail_finalization "ZIGOS_RELEASE_DSSE_SIGN_COMMAND produced malformed manifest signature base64"
manifest_payload_b64="$(printf '%s' "$manifest_payload" | base64_no_wrap)"

jq -cn \
  --arg payloadType "$MANIFEST_PAYLOAD_TYPE" \
  --arg payload "$manifest_payload_b64" \
  --arg keyid "$ZIGOS_RELEASE_SIGNING_KEY_ID" \
  --arg sig "$manifest_signature" \
  '{payloadType: $payloadType, payload: $payload, signatures: [{keyid: $keyid, sig: $sig}]}' \
  > "$work_dir/release-manifest.dsse.json"

candidate_bundle="$work_dir/candidate-bundle"
mkdir -p "$candidate_bundle"
for evidence in "${RELEASE_EVIDENCE_NAMES[@]}"; do
  cp "$OUTPUT_PATH/$evidence" "$candidate_bundle/$evidence"
done
cp "$work_dir/release-manifest.dsse.json" "$candidate_bundle/release-manifest.dsse.json"

"$release_verifier" verify-candidate \
  --bundle "$candidate_bundle" \
  --artifacts "$ARTIFACT_ROOT" \
  --trusted-root "$ZIGOS_RELEASE_TRUST_ROOT" \
  --trusted-root-sha256 "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" \
  --trust-state "$ZIGOS_RELEASE_TRUST_STATE"

mv -f -- "$work_dir/release-manifest.dsse.json" "$OUTPUT_PATH/release-manifest.dsse.json"

if ! "$release_verifier" verify \
  --bundle "$OUTPUT_PATH" \
  --artifacts "$ARTIFACT_ROOT" \
  --trusted-root "$ZIGOS_RELEASE_TRUST_ROOT" \
  --trusted-root-sha256 "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" \
  --trust-state "$ZIGOS_RELEASE_TRUST_STATE"; then
  rm -f -- "$OUTPUT_PATH/release-manifest.dsse.json"
  fail_finalization "published bundle failed final verification; publication marker withdrawn"
fi

printf 'Authenticated exact release manifest finalized at %s\n' "$OUTPUT_DIR/release-manifest.dsse.json"
