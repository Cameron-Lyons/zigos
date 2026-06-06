#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-build/release-security}"
OUTPUT_PATH="$ROOT_DIR/$OUTPUT_DIR"

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

base64_no_wrap() {
  base64 | tr -d '\n'
}

artifact_files=()

add_artifact_path() {
  local relative_path="${1:?artifact path required}"
  local absolute_path="$ROOT_DIR/$relative_path"
  if [ -f "$absolute_path" ]; then
    artifact_files+=("$relative_path")
    return
  fi
  if [ -d "$absolute_path" ]; then
    while IFS= read -r -d '' file; do
      artifact_files+=("${file#"$ROOT_DIR"/}")
    done < <(find "$absolute_path" -type f -print0)
  fi
}

add_artifact_path "zig-out/bin/kernel-zigos-native.elf"
add_artifact_path "zig-out/bin/zigos-sign"
add_artifact_path "build/os.iso"
add_artifact_path "zig-out/bin"
add_artifact_path "spec/production_readiness.json"
add_artifact_path "spec/release_security/release_artifacts.json"
add_artifact_path "spec/release_security/release_keyring.json"
add_artifact_path "spec/release_security/revoked_release_keys.json"
add_artifact_path "spec/release_security/fuzz_corpus.json"
add_artifact_path "spec/release_security/memory_safety_inventory.json"
add_artifact_path "spec/release_security/threat_model.json"
add_artifact_path "spec/release_security/crash_dump_redaction.json"
add_artifact_path "spec/release_security/vulnerability_disclosure.json"

if [ "${#artifact_files[@]}" -eq 0 ]; then
  echo "No release artifacts were found. Build iso, signing-cli, and userspace-images before generating SBOM/provenance." >&2
  exit 1
fi

sorted_artifacts="$(mktemp "${TMPDIR:-/tmp}/zigos-release-artifacts.XXXXXX")"
printf '%s\n' "${artifact_files[@]}" | LC_ALL=C sort -u > "$sorted_artifacts"
artifact_files=()
while IFS= read -r file; do
  artifact_files+=("$file")
done < "$sorted_artifacts"
rm -f -- "$sorted_artifacts"

digests_path="$OUTPUT_PATH/artifact-digests.sha256"
: > "$digests_path"
for file in "${artifact_files[@]}"; do
  printf '%s  %s\n' "$(sha256_file "$ROOT_DIR/$file")" "$file" >> "$digests_path"
done

repo_url="$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || printf 'NOASSERTION')"
commit_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf 'NOASSERTION')"
dirty_count="$(git -C "$ROOT_DIR" status --short 2>/dev/null | wc -l | tr -d ' ')"
zig_version="$("$ROOT_DIR/scripts/zig.sh" version 2>/dev/null || printf 'unknown')"
created_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

sbom_path="$OUTPUT_PATH/sbom.spdx.json"
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

provenance_path="$OUTPUT_PATH/provenance.intoto.jsonl"
dsse_provenance_path="$OUTPUT_PATH/provenance.dsse.intoto.jsonl"
: > "$provenance_path"
: > "$dsse_provenance_path"
release_key_id="${ZIGOS_RELEASE_SIGNING_KEY_ID:-zigos-release-signing-required}"
release_signature_b64="${ZIGOS_RELEASE_DSSE_SIGNATURE_B64:-$(printf '%s' 'UNSIGNED_LOCAL_PREVIEW_REQUIRES_HARDWARE_RELEASE_SIGNING' | base64_no_wrap)}"
for file in "${artifact_files[@]}"; do
  digest="$(sha256_file "$ROOT_DIR/$file")"
  escaped_file="$(json_escape "$file")"
  statement="{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"$escaped_file\",\"digest\":{\"sha256\":\"$digest\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"buildType\":\"https://github.com/Cameron-Lyons/zigos/release-security-gate\",\"externalParameters\":{\"repository\":\"$(json_escape "$repo_url")\",\"commit\":\"$(json_escape "$commit_sha")\",\"zigVersion\":\"$(json_escape "$zig_version")\"}},\"runDetails\":{\"builder\":{\"id\":\"zigos-local-release-security-gate\"},\"metadata\":{\"invocationId\":\"$created_utc\",\"startedOn\":\"$created_utc\",\"dirtyWorkspaceFileCount\":$dirty_count}}}}"
  printf '%s\n' "$statement" >> "$provenance_path"
  payload_b64="$(printf '%s' "$statement" | base64_no_wrap)"
  cat >> "$dsse_provenance_path" <<EOF
{"payloadType":"application/vnd.in-toto+json","payload":"$payload_b64","signatures":[{"keyid":"$(json_escape "$release_key_id")","sig":"$release_signature_b64"}]}
EOF
done

public_release_allowed=false
release_key_status="required-not-configured"
release_public_key="${ZIGOS_RELEASE_SIGNING_PUBLIC_KEY:-TBD}"
release_custody="${ZIGOS_RELEASE_SIGNING_CUSTODY:-hardware-or-kms-required}"
release_generation="${ZIGOS_RELEASE_SIGNING_GENERATION:-1}"
release_not_before="${ZIGOS_RELEASE_SIGNING_NOT_BEFORE:-TBD}"
release_not_after="${ZIGOS_RELEASE_SIGNING_NOT_AFTER:-TBD}"
if [ "${ZIGOS_RELEASE_HARDWARE_BACKED:-}" = "true" ] && [ -n "${ZIGOS_RELEASE_DSSE_SIGNATURE_B64:-}" ]; then
  public_release_allowed=true
  release_key_status="active"
fi

cat > "$OUTPUT_PATH/release-keyring.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "public_release_allowed": $public_release_allowed,
  "required_provider_boundary": "offline HSM or cloud KMS release signing provider",
  "keys": [
    {
      "key_id": "$(json_escape "$release_key_id")",
      "status": "$release_key_status",
      "algorithm": "ed25519",
      "custody": "$(json_escape "$release_custody")",
      "hardware_backed": true,
      "generation": $release_generation,
      "not_before": "$(json_escape "$release_not_before")",
      "not_after": "$(json_escape "$release_not_after")",
      "public_key": "$(json_escape "$release_public_key")",
      "rotation_policy": "new release key generation before not_after or immediately after suspected exposure",
      "revocation_source": "$OUTPUT_DIR/revoked-release-keys.json"
    }
  ],
  "preview_profiles": [
    {
      "profile": "ed25519+ml-dsa65",
      "status": "preview-only",
      "release_allowed": false,
      "fips_204_status": "not a production FIPS 204 ML-DSA implementation"
    }
  ]
}
EOF

cp "$ROOT_DIR/spec/release_security/revoked_release_keys.json" "$OUTPUT_PATH/revoked-release-keys.json"

cat > "$OUTPUT_PATH/customer-verification-policy.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$created_utc",
  "artifact_digest_manifest": "$OUTPUT_DIR/artifact-digests.sha256",
  "spdx_sbom": "$OUTPUT_DIR/sbom.spdx.json",
  "provenance_statements": "$OUTPUT_DIR/provenance.intoto.jsonl",
  "dsse_provenance": "$OUTPUT_DIR/provenance.dsse.intoto.jsonl",
  "release_keyring": "$OUTPUT_DIR/release-keyring.json",
  "revoked_release_keys": "$OUTPUT_DIR/revoked-release-keys.json",
  "reproducible_build_evidence": "$OUTPUT_DIR/reproducible-build.json",
  "required_predicate_type": "https://slsa.dev/provenance/v1",
  "required_payload_type": "application/vnd.in-toto+json",
  "require_hardware_backed_release_key": true,
  "reject_unsigned_local_preview": true,
  "verification_steps": [
    "Compare each downloaded artifact SHA-256 digest with artifact-digests.sha256.",
    "Verify every DSSE signature in provenance.dsse.intoto.jsonl against release-keyring.json before parsing payloads.",
    "Reject signatures from key ids or generations listed in revoked-release-keys.json.",
    "Verify each decoded in-toto Statement has predicateType https://slsa.dev/provenance/v1 and subject digests matching artifact-digests.sha256.",
    "Compare reproducible-build.json and reproducible-artifact-digests.sha256 against the release digest manifest.",
    "Reject ed25519+ml-dsa65 as a production FIPS 204 signal; it is preview-only until replaced by a validated ML-DSA provider."
  ]
}
EOF

cat > "$OUTPUT_PATH/vulnerability-disclosure-dry-run.json" <<EOF
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

printf 'Release SBOM/provenance generated under %s\n' "$OUTPUT_DIR"
