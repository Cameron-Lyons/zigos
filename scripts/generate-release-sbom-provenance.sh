#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-build/release-security}"
RELEASE_OPTIMIZE_MODE="${2:-ReleaseFast}"

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

if [ "$RELEASE_OPTIMIZE_MODE" != "ReleaseFast" ]; then
  printf 'Release generation requires optimize mode ReleaseFast, got %s\n' "$RELEASE_OPTIMIZE_MODE" >&2
  exit 2
fi

[ ! -L "$ROOT_DIR/build" ] || {
  printf 'Repository build directory must not be a symbolic link.\n' >&2
  exit 2
}
mkdir -p "$ROOT_DIR/build"
[ "$(realpath "$ROOT_DIR/build")" = "$ROOT_DIR/build" ] || {
  printf 'Repository build directory resolves outside the workspace.\n' >&2
  exit 2
}
mkdir -p "$OUTPUT_PATH"
case "$(realpath "$OUTPUT_PATH")" in
  "$ROOT_DIR/build"/*) ;;
  *)
    printf 'Release output directory resolves outside the repository build directory.\n' >&2
    exit 2
    ;;
esac

GENERATOR_EVIDENCE_NAMES=(
  "artifact-digests.sha256"
  "artifact-measurements.json"
  "customer-verification-policy.json"
  "provenance.dsse.intoto.jsonl"
  "provenance.intoto.jsonl"
  "release-trust-policy.dsse.json"
  "root-metadata.json"
  "sbom.spdx.json"
)

# Withhold the publication marker before touching any evidence. Remove only the
# files owned by this generator so a failed invocation cannot leave a stale mix
# that a manually invoked finalizer could publish.
rm -f -- "$OUTPUT_PATH/release-manifest.dsse.json"
for evidence_name in "${GENERATOR_EVIDENCE_NAMES[@]}"; do
  rm -f -- "$OUTPUT_PATH/$evidence_name"
done

# Build every owned evidence file in a same-filesystem staging directory. The
# final renames replace hostile leaf symlinks or hard links instead of following
# them, while the absent manifest keeps a partially published set untrusted.
WORK_PATH="$(mktemp -d "$OUTPUT_PATH/.generate.XXXXXX")"
cleanup_generation() {
  rm -rf -- "$WORK_PATH"
}
trap cleanup_generation EXIT

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

file_size_bytes() {
  local file="${1:?file required}"
  wc -c < "$file" | tr -d ' '
}

base64_no_wrap() {
  base64 | tr -d '\n'
}

is_sha256_hex() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

dsse_payload_type="application/vnd.in-toto+json"

fail_release_generation() {
  printf 'release SBOM/provenance generation failed: %s\n' "$*" >&2
  exit 1
}

is_base64_text() {
  local value="${1:-}"
  [ -n "$value" ] || return 1
  [[ "$value" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
  [ $(( ${#value} % 4 )) -eq 0 ] || return 1
}

require_dsse_signature_b64() {
  local source_label="${1:?signature source required}"
  local signature_b64="${2:?signature required}"
  if ! is_base64_text "$signature_b64"; then
    fail_release_generation "$source_label produced malformed DSSE signature; expected non-empty standard base64"
  fi
  printf '%s' "$signature_b64"
}

validate_dsse_signing_environment() {
  [ "${ZIGOS_RELEASE_HARDWARE_BACKED:-}" = "true" ] ||
    fail_release_generation "ZIGOS_RELEASE_HARDWARE_BACKED=true is required"
  [ -n "${ZIGOS_RELEASE_DSSE_SIGN_COMMAND:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_DSSE_SIGN_COMMAND is required"
  [ -n "${ZIGOS_RELEASE_SIGNING_KEY_ID:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_SIGNING_KEY_ID is required"
  is_sha256_hex "$ZIGOS_RELEASE_SIGNING_KEY_ID" ||
    fail_release_generation "ZIGOS_RELEASE_SIGNING_KEY_ID must be a lowercase SHA-256 key id"
  [ -n "${ZIGOS_RELEASE_TRUST_ROOT:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_TRUST_ROOT is required"
  [ -n "${ZIGOS_RELEASE_TRUST_ROOT_SHA256:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_TRUST_ROOT_SHA256 is required"
  is_sha256_hex "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" ||
    fail_release_generation "ZIGOS_RELEASE_TRUST_ROOT_SHA256 must be lowercase SHA-256"
  [ -n "${ZIGOS_RELEASE_TRUST_POLICY:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_TRUST_POLICY is required"
  [ -n "${ZIGOS_RELEASE_VERIFIER:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_VERIFIER is required"
  [ -n "${ZIGOS_RELEASE_VERIFIER_SHA256:-}" ] ||
    fail_release_generation "ZIGOS_RELEASE_VERIFIER_SHA256 is required"
  is_sha256_hex "$ZIGOS_RELEASE_VERIFIER_SHA256" ||
    fail_release_generation "ZIGOS_RELEASE_VERIFIER_SHA256 must be lowercase SHA-256"

  case "$ZIGOS_RELEASE_TRUST_ROOT" in
    /*) ;;
    *) fail_release_generation "ZIGOS_RELEASE_TRUST_ROOT must be an absolute, independently provisioned path" ;;
  esac
  case "$ZIGOS_RELEASE_TRUST_POLICY" in
    /*) ;;
    *) fail_release_generation "ZIGOS_RELEASE_TRUST_POLICY must be an absolute, independently provisioned path" ;;
  esac
  case "$ZIGOS_RELEASE_VERIFIER" in
    /*) ;;
    *) fail_release_generation "ZIGOS_RELEASE_VERIFIER must be an absolute, independently provisioned path" ;;
  esac
  [ -f "$ZIGOS_RELEASE_TRUST_ROOT" ] ||
    fail_release_generation "trusted root metadata file is missing"
  [ -f "$ZIGOS_RELEASE_TRUST_POLICY" ] ||
    fail_release_generation "signed trust policy file is missing"
  [ -f "$ZIGOS_RELEASE_VERIFIER" ] && [ -x "$ZIGOS_RELEASE_VERIFIER" ] && [ ! -L "$ZIGOS_RELEASE_VERIFIER" ] ||
    fail_release_generation "release verifier must be an executable regular file, not a symlink"
  canonical_release_verifier="$(realpath "$ZIGOS_RELEASE_VERIFIER")"
  case "$canonical_release_verifier" in
    "$ROOT_DIR" | "$ROOT_DIR"/*)
      fail_release_generation "release verifier must be provisioned independently of the candidate artifact tree"
      ;;
  esac
}

sign_dsse_statement() {
  local statement="${1:?statement required}"
  local signature_b64
  signature_b64="$({
    printf 'DSSEv1 %d %s %d ' "${#dsse_payload_type}" "$dsse_payload_type" "${#statement}"
    printf '%s' "$statement"
  } | bash -c "$ZIGOS_RELEASE_DSSE_SIGN_COMMAND" | tr -d '\n')"
  require_dsse_signature_b64 "ZIGOS_RELEASE_DSSE_SIGN_COMMAND" "$signature_b64"
}

validate_dsse_signing_environment

release_verifier="$WORK_PATH/pinned-release-verifier"
cp "$ZIGOS_RELEASE_VERIFIER" "$release_verifier"
chmod 0500 "$release_verifier"
[ "$(sha256_file "$release_verifier")" = "$ZIGOS_RELEASE_VERIFIER_SHA256" ] ||
  fail_release_generation "release verifier copy does not match its independently pinned SHA-256"
"$release_verifier" trust-info \
  --trusted-root "$ZIGOS_RELEASE_TRUST_ROOT" \
  --trusted-root-sha256 "$ZIGOS_RELEASE_TRUST_ROOT_SHA256" \
  --policy "$ZIGOS_RELEASE_TRUST_POLICY" \
  --release-key-id "$ZIGOS_RELEASE_SIGNING_KEY_ID"

cp "$ZIGOS_RELEASE_TRUST_ROOT" "$WORK_PATH/root-metadata.json"
cp "$ZIGOS_RELEASE_TRUST_POLICY" "$WORK_PATH/release-trust-policy.dsse.json"

artifact_files=()

REQUIRED_RELEASE_ARTIFACTS=(
  "build/os.iso"
  "spec/production_readiness.json"
  "spec/release_security/crash_dump_redaction.json"
  "spec/release_security/fuzz_corpus.json"
  "spec/release_security/memory_safety_inventory.json"
  "spec/release_security/release_artifacts.json"
  "spec/release_security/threat_model.json"
  "spec/release_security/vulnerability_disclosure.json"
  "zig-out/bin/kernel-zigos-native.elf"
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

require_artifact_path() {
  local relative_path="${1:?artifact path required}"
  local absolute_path="$ROOT_DIR/$relative_path"
  if [ ! -f "$absolute_path" ]; then
    printf 'missing required release artifact: %s\n' "$relative_path" >&2
    return 1
  fi
  add_artifact_path "$relative_path"
}

add_artifact_path() {
  local relative_path="${1:?artifact path required}"
  local absolute_path="$ROOT_DIR/$relative_path"
  if ! is_allowed_release_artifact "$relative_path"; then
    fail_release_generation "artifact is outside the production release allowlist: $relative_path"
  fi
  if [ -f "$absolute_path" ]; then
    artifact_files+=("$relative_path")
  fi
}

collect_production_userspace_artifacts() {
  local relative_path
  local missing_artifacts=0
  for relative_path in "${PRODUCTION_USERSPACE_ARTIFACTS[@]}"; do
    require_artifact_path "$relative_path" || missing_artifacts=1
  done
  return "$missing_artifacts"
}

missing_required_artifacts=0
for required_artifact in "${REQUIRED_RELEASE_ARTIFACTS[@]}"; do
  require_artifact_path "$required_artifact" || missing_required_artifacts=1
done
collect_production_userspace_artifacts || missing_required_artifacts=1
if [ "$missing_required_artifacts" -ne 0 ]; then
  printf 'Build the production ISO, kernel, policy manifests, and userspace images before generating SBOM/provenance; provision release trust and the verifier independently.\n' >&2
  exit 1
fi

if [ "${#REQUIRED_RELEASE_ARTIFACTS[@]}" -ne 9 ] ||
   [ "${#PRODUCTION_USERSPACE_ARTIFACTS[@]}" -ne 24 ] ||
   [ "${#artifact_files[@]}" -ne 33 ]; then
  fail_release_generation "production release catalog must contain exactly 9 fixed targets and 24 userspace targets"
fi

if [ "${#artifact_files[@]}" -eq 0 ]; then
  echo "No release artifacts were found. Build iso and userspace-production-images before generating SBOM/provenance." >&2
  exit 1
fi

sorted_artifacts="$(mktemp "${TMPDIR:-/tmp}/zigos-release-artifacts.XXXXXX")"
printf '%s\n' "${artifact_files[@]}" | LC_ALL=C sort -u > "$sorted_artifacts"
artifact_files=()
while IFS= read -r file; do
  if ! is_allowed_release_artifact "$file"; then
    fail_release_generation "selected artifact is outside the production release allowlist: $file"
  fi
  artifact_files+=("$file")
done < "$sorted_artifacts"
rm -f -- "$sorted_artifacts"
if [ "${#artifact_files[@]}" -ne 33 ]; then
  fail_release_generation "production release catalog contains a duplicate or missing target"
fi

digests_path="$WORK_PATH/artifact-digests.sha256"
measurements_path="$WORK_PATH/artifact-measurements.json"
: > "$digests_path"
for file in "${artifact_files[@]}"; do
  printf '%s  %s\n' "$(sha256_file "$ROOT_DIR/$file")" "$file" >> "$digests_path"
done

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "measurement_algorithm": "sha256",\n'
  printf '  "artifacts": [\n'
  first=1
  for file in "${artifact_files[@]}"; do
    digest="$(sha256_file "$ROOT_DIR/$file")"
    size_bytes="$(file_size_bytes "$ROOT_DIR/$file")"
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {"path": "%s", "sha256": "%s", "size_bytes": %s}' "$(json_escape "$file")" "$digest" "$size_bytes"
  done
  printf '\n  ]\n'
  printf '}\n'
} > "$measurements_path"

if ! command -v jj >/dev/null 2>&1; then
  printf 'Jujutsu (jj) is required to generate release source provenance.\n' >&2
  exit 1
fi

repo_vcs="jj"
repo_url="$(jj -R "$ROOT_DIR" git remote list 2>/dev/null | awk '$1 == "origin" { print $2; found = 1; exit } END { exit found ? 0 : 1 }' || printf 'NOASSERTION')"
repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"')"
commit_sha="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"')"
dirty_count="$(jj -R "$ROOT_DIR" diff -r @ --name-only | wc -l | tr -d ' ')"
zig_version="$("$ROOT_DIR/scripts/zig.sh" version 2>/dev/null || printf 'unknown')"
created_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

sbom_path="$WORK_PATH/sbom.spdx.json"
{
  printf '{\n'
  printf '  "spdxVersion": "SPDX-2.3",\n'
  printf '  "dataLicense": "CC0-1.0",\n'
  printf '  "SPDXID": "SPDXRef-DOCUMENT",\n'
  printf '  "name": "zigos-release-sbom",\n'
  printf '  "documentNamespace": "https://github.com/Cameron-Lyons/zigos/release-security/%s",\n' "$(json_escape "$commit_sha")"
  printf '  "creationInfo": {\n'
  printf '    "created": "%s",\n' "$created_utc"
  printf '    "creators": ["Tool: scripts/generate-release-sbom-provenance.sh", "Organization: Zigos release security gate"]\n'
  printf '  },\n'
  printf '  "packages": [\n'
  printf '    {\n'
  printf '      "name": "zigos",\n'
  printf '      "SPDXID": "SPDXRef-Package-zigos",\n'
  printf '      "downloadLocation": "%s",\n' "$(json_escape "$repo_url")"
  printf '      "versionInfo": "%s",\n' "$(json_escape "$commit_sha")"
  printf '      "filesAnalyzed": true,\n'
  printf '      "supplier": "Organization: Zigos release security gate"\n'
  printf '    }\n'
  printf '  ],\n'
  printf '  "files": [\n'
  first=1
  for file in "${artifact_files[@]}"; do
    digest="$(sha256_file "$ROOT_DIR/$file")"
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {\n'
    printf '      "fileName": "%s",\n' "$(json_escape "$file")"
    printf '      "SPDXID": "SPDXRef-File-%s",\n' "$(printf '%s' "$file" | tr -c 'A-Za-z0-9' '-')"
    printf '      "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}],\n' "$digest"
    printf '      "licenseConcluded": "NOASSERTION",\n'
    printf '      "copyrightText": "NOASSERTION"\n'
    printf '    }'
  done
  printf '\n  ]\n'
  printf '}\n'
} > "$sbom_path"

provenance_path="$WORK_PATH/provenance.intoto.jsonl"
dsse_provenance_path="$WORK_PATH/provenance.dsse.intoto.jsonl"
: > "$provenance_path"
: > "$dsse_provenance_path"
release_key_id="$ZIGOS_RELEASE_SIGNING_KEY_ID"
for file in "${artifact_files[@]}"; do
  digest="$(sha256_file "$ROOT_DIR/$file")"
  escaped_file="$(json_escape "$file")"
  statement="{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"$escaped_file\",\"digest\":{\"sha256\":\"$digest\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"buildType\":\"https://github.com/Cameron-Lyons/zigos/release-security-gate\",\"externalParameters\":{\"repository\":\"$(json_escape "$repo_url")\",\"sourceControl\":\"$repo_vcs\",\"changeId\":\"$(json_escape "$repo_change_id")\",\"commit\":\"$(json_escape "$commit_sha")\",\"zigVersion\":\"$(json_escape "$zig_version")\",\"optimizeMode\":\"$RELEASE_OPTIMIZE_MODE\"}},\"runDetails\":{\"builder\":{\"id\":\"zigos-local-release-security-gate\"},\"metadata\":{\"invocationId\":\"$created_utc\",\"startedOn\":\"$created_utc\",\"dirtyWorkspaceFileCount\":$dirty_count}}}}"
  printf '%s\n' "$statement" >> "$provenance_path"
  payload_b64="$(printf '%s' "$statement" | base64_no_wrap)"
  release_signature_b64="$(sign_dsse_statement "$statement")"
  cat >> "$dsse_provenance_path" <<EOF
{"payloadType":"$dsse_payload_type","payload":"$payload_b64","signatures":[{"keyid":"$(json_escape "$release_key_id")","sig":"$release_signature_b64"}]}
EOF
done

cat > "$WORK_PATH/customer-verification-policy.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "release_manifest": "$OUTPUT_DIR/release-manifest.dsse.json",
  "trusted_root_evidence": "$OUTPUT_DIR/root-metadata.json",
  "signed_trust_policy": "$OUTPUT_DIR/release-trust-policy.dsse.json",
  "trusted_root_bootstrap": "supply root metadata and its lowercase SHA-256 digest independently of the release bundle",
  "verifier_bootstrap": "supply zigos-verify-release and its lowercase SHA-256 digest independently of the release bundle and artifact tree",
  "rollback_state": "persist outside both the release bundle and artifact root",
  "automatic_root_rotation_supported": false,
  "artifact_digest_manifest": "$OUTPUT_DIR/artifact-digests.sha256",
  "artifact_measurements": "$OUTPUT_DIR/artifact-measurements.json",
  "spdx_sbom": "$OUTPUT_DIR/sbom.spdx.json",
  "provenance_statements": "$OUTPUT_DIR/provenance.intoto.jsonl",
  "dsse_provenance": "$OUTPUT_DIR/provenance.dsse.intoto.jsonl",
  "reproducible_build_evidence": "$OUTPUT_DIR/reproducible-build.json",
  "reproducible_artifact_digests": "$OUTPUT_DIR/reproducible-artifact-digests.sha256",
  "required_predicate_type": "https://slsa.dev/provenance/v1",
  "required_payload_type": "application/vnd.in-toto+json",
  "required_manifest_payload_type": "application/vnd.zigos.release-manifest.v1+json",
  "required_trust_policy_payload_type": "application/vnd.zigos.release-trust-policy.v1+json",
  "require_hardware_backed_release_key": true,
  "exact_target_count": 33,
  "exact_evidence_count": 10,
  "verification_steps": [
    "Copy the independently obtained zigos-verify-release executable into private staging, compare that exact copy with its independently distributed SHA-256 pin, and execute only the matched copy.",
    "Obtain root metadata and its SHA-256 digest independently; the bundled root-metadata.json is consistency evidence and never a trust bootstrap.",
    "Before first-use acceptance, require policyVersion to meet root minimumPolicyVersion and releaseSequence to meet the authenticated policy minimumReleaseSequence.",
    "Authenticate release-trust-policy.dsse.json with the pinned root threshold before parsing its payload; reject unknown, invalid, and duplicate signer ids.",
    "Authenticate release-manifest.dsse.json with currently active, unrevoked delegated release keys before parsing its payload.",
    "Require the authenticated policy and manifest to contain exactly 33 production targets and 10 evidence files; the signed manifest is the sole digest authority.",
    "Hash and size-check all targets and hash all evidence before parsing any evidence; treat artifact-digests.sha256 only as a consistency projection.",
    "Verify every DSSE signature in provenance.dsse.intoto.jsonl against the authenticated delegated policy; signatures cover the DSSE v1 pre-authentication encoding.",
    "Verify each decoded in-toto Statement has predicateType https://slsa.dev/provenance/v1, exactly one subject per signed DSSE envelope, and subject digests matching the authenticated release manifest.",
    "Require zigos-verify-release to fail closed unless each signed SLSA statement records buildDefinition.buildType=https://github.com/Cameron-Lyons/zigos/release-security-gate, runDetails.builder.id=zigos-local-release-security-gate, sourceControl=jj, the Jujutsu changeId, the commit id, repository, and Zig version used to generate the release, and runDetails.metadata records dirtyWorkspaceFileCount=0.",
    "Require every active release key notBefore/notAfter window to cover the signed SLSA runDetails.metadata.startedOn date.",
    "Compare artifact-measurements.json size and digest measurements against downloaded artifacts, requiring exact one-entry-per-artifact coverage without duplicates.",
    "Compare reproducible-build.json and reproducible-artifact-digests.sha256 against the complete release digest manifest, including fail-closed repo_vcs=jj, repository, Jujutsu change ID, commit id, Zig version, dirty_workspace_file_count=0 evidence, and equality with the signed SLSA source identity.",
    "Persist root, authenticated policy payload, release sequence, authenticated manifest payload, and trusted-time state outside the downloaded bundle; reject rollback, equivocation, clock rollback, and implicit root changes.",
    "Run zigos-verify-release verify with explicit --bundle, --artifacts, --trusted-root, --trusted-root-sha256, and --trust-state arguments before trusting a downloaded release.",
    "Reject required post-quantum rollout unless zigos-verify-release supports and verifies the policy-required production algorithm from a validated provider."
  ]
}
EOF

cat > "$WORK_PATH/vulnerability-disclosure-dry-run.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "primary_private_intake": "https://github.com/Cameron-Lyons/zigos/security/advisories/new",
  "backup_private_intake": "security@zigos.dev",
  "steps": [
    "private-report-created",
    "maintainer-acknowledged",
    "severity-triaged",
    "cwe-recorded",
    "advisory-drafted",
    "fix-or-not-exploitable-decision-recorded"
  ],
  "status": "dry-run-recorded"
}
EOF

disclosure_audit_path="$ROOT_DIR/build/release-audit"
[ ! -L "$disclosure_audit_path" ] ||
  fail_release_generation "release audit directory must not be a symbolic link"
mkdir -p "$disclosure_audit_path"
case "$(realpath "$disclosure_audit_path")" in
  "$ROOT_DIR/build"/*) ;;
  *) fail_release_generation "release audit directory resolves outside the repository build directory" ;;
esac

for evidence_name in "${GENERATOR_EVIDENCE_NAMES[@]}"; do
  [ -f "$WORK_PATH/$evidence_name" ] && [ ! -L "$WORK_PATH/$evidence_name" ] ||
    fail_release_generation "generator did not stage required evidence: $evidence_name"
  mv -f -- "$WORK_PATH/$evidence_name" "$OUTPUT_PATH/$evidence_name"
done
mv -f -- \
  "$WORK_PATH/vulnerability-disclosure-dry-run.json" \
  "$disclosure_audit_path/vulnerability-disclosure-dry-run.json"

printf 'Authenticated release evidence generated under %s\n' "$OUTPUT_DIR"
