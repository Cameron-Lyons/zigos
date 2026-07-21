#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 7 ]; then
  printf 'usage: scripts/verify-release-bundle.sh VERIFIER VERIFIER_SHA256 BUNDLE ARTIFACT_ROOT TRUSTED_ROOT ROOT_SHA256 TRUST_STATE\n' >&2
  exit 2
fi

VERIFIER="$1"
VERIFIER_SHA256="$2"
BUNDLE_INPUT="$3"
ARTIFACT_ROOT_INPUT="$4"
TRUSTED_ROOT="$5"
ROOT_SHA256="$6"
TRUST_STATE="$7"

fail() {
  printf 'pinned release verification failed: %s\n' "$*" >&2
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

is_sha256_hex() {
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

case "$VERIFIER" in
  /*) ;;
  *) fail "verifier path must be absolute" ;;
esac
case "$TRUSTED_ROOT" in
  /*) ;;
  *) fail "trusted root path must be absolute" ;;
esac
case "$TRUST_STATE" in
  /*) ;;
  *) fail "trust state path must be absolute" ;;
esac
is_sha256_hex "$VERIFIER_SHA256" || fail "verifier pin must be lowercase SHA-256"
is_sha256_hex "$ROOT_SHA256" || fail "root pin must be lowercase SHA-256"
if [ ! -f "$VERIFIER" ] || [ ! -x "$VERIFIER" ] || [ -L "$VERIFIER" ]; then
  fail "verifier must be an executable regular file, not a symlink"
fi
[ -f "$TRUSTED_ROOT" ] || fail "trusted root is missing"
[ -d "$BUNDLE_INPUT" ] || fail "bundle directory is missing"
[ -d "$ARTIFACT_ROOT_INPUT" ] || fail "artifact root is missing"

verifier_canonical="$(realpath "$VERIFIER")"
bundle_canonical="$(realpath "$BUNDLE_INPUT")"
artifacts_canonical="$(realpath "$ARTIFACT_ROOT_INPUT")"
case "$verifier_canonical" in
  "$bundle_canonical" | "$bundle_canonical"/* | "$artifacts_canonical" | "$artifacts_canonical"/*)
    fail "verifier must be provisioned independently of the bundle and artifact tree"
    ;;
esac

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/zigos-pinned-verifier.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

pinned_verifier="$work_dir/zigos-verify-release"
cp "$VERIFIER" "$pinned_verifier"
chmod 0500 "$pinned_verifier"
[ "$(sha256_file "$pinned_verifier")" = "$VERIFIER_SHA256" ] ||
  fail "verifier copy does not match its independently supplied pin"

"$pinned_verifier" verify \
  --bundle "$bundle_canonical" \
  --artifacts "$artifacts_canonical" \
  --trusted-root "$TRUSTED_ROOT" \
  --trusted-root-sha256 "$ROOT_SHA256" \
  --trust-state "$TRUST_STATE"
