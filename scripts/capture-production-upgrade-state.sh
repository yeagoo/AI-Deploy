#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY_DIR="${OPSCTL_PRODUCTION_REGISTRY:-/srv/server-registry}"
STATE_DIR="${OPSCTL_PRODUCTION_STATE:-/var/lib/opsctl}"
OUTPUT_ROOT="${OPSCTL_UPGRADE_BACKUP_ROOT:-/var/backups/opsctl-upgrades}"
OLD_DEB="${OPSCTL_PREVIOUS_DEB:-$ROOT_DIR/target/release-dist/v0.1.0/opsctl_0.1.0_arm64.deb}"
CANDIDATE_DEB="${OPSCTL_CANDIDATE_DEB:-$ROOT_DIR/target/release-dist/v0.6.0/opsctl_0.6.0_arm64.deb}"
EXECUTE=0
ZSTD_LEVEL="${OPSCTL_UPGRADE_ZSTD_LEVEL:-1}"

usage() {
  echo "usage: $0 [--registry DIR] [--state DIR] [--output-root DIR] [--old-deb FILE] [--candidate-deb FILE] [--execute]" >&2
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY_DIR="${2:?missing --registry value}"; shift 2 ;;
    --state) STATE_DIR="${2:?missing --state value}"; shift 2 ;;
    --output-root) OUTPUT_ROOT="${2:?missing --output-root value}"; shift 2 ;;
    --old-deb) OLD_DEB="${2:?missing --old-deb value}"; shift 2 ;;
    --candidate-deb) CANDIDATE_DEB="${2:?missing --candidate-deb value}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "unknown argument: $1" ;;
  esac
done

for command in tar zstd sha256sum jq realpath find sort stat dpkg-query dpkg-deb; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

safe_source_dir() {
  local path="$1"
  [ "${path#/}" != "$path" ] || fail "source path must be absolute: $path"
  [ "$path" != "/" ] || fail "source path cannot be /"
  [ -d "$path" ] || fail "source directory is missing: $path"
  [ ! -L "$path" ] || fail "source directory cannot be a symlink: $path"
}

safe_source_dir "$REGISTRY_DIR"
safe_source_dir "$STATE_DIR"
if [ ! -f "$OLD_DEB" ] || [ -L "$OLD_DEB" ]; then
  fail "old Debian package is unsafe or missing"
fi
if [ ! -f "$CANDIDATE_DEB" ] || [ -L "$CANDIDATE_DEB" ]; then
  fail "candidate Debian package is unsafe or missing"
fi
dpkg-deb --info "$OLD_DEB" >/dev/null
dpkg-deb --info "$CANDIDATE_DEB" >/dev/null

REGISTRY_DIR="$(realpath -e "$REGISTRY_DIR")"
STATE_DIR="$(realpath -e "$STATE_DIR")"
OLD_DEB="$(realpath -e "$OLD_DEB")"
CANDIDATE_DEB="$(realpath -e "$CANDIDATE_DEB")"
if [ -e "$OUTPUT_ROOT" ] && [ -L "$OUTPUT_ROOT" ]; then
  fail "output root cannot be a symlink"
fi
OUTPUT_ROOT="$(realpath -m "$OUTPUT_ROOT")"
case "$OUTPUT_ROOT/" in
  "$REGISTRY_DIR/"*|"$STATE_DIR/"*) fail "output root cannot be inside a source tree" ;;
esac
case "$REGISTRY_DIR/" in "$OUTPUT_ROOT/"*) fail "registry cannot be inside output root" ;; esac
case "$STATE_DIR/" in "$OUTPUT_ROOT/"*) fail "state cannot be inside output root" ;; esac

if [ "$(id -u)" -ne 0 ] && { [ ! -r "$REGISTRY_DIR" ] || [ ! -r "$STATE_DIR" ]; }; then
  fail "execute this command through sudo to read protected production data"
fi

reject_ambiguous_names() {
  local source="$1"
  if find "$source" -xdev \( -name $'*\n*' -o -name $'*\t*' \) -print -quit | grep -q .; then
    fail "source contains a tab or newline in a path: $source"
  fi
}

validate_symlinks() {
  local source="$1" link target resolved
  while IFS= read -r -d '' link; do
    target="$(readlink -- "$link")"
    case "$target" in *$'\n'*|*$'\t'*) fail "symlink target contains a tab or newline: $link" ;; esac
    if [[ "$target" = /* ]]; then
      resolved="$(realpath -m -- "$target")"
    else
      resolved="$(realpath -m -- "$(dirname "$link")/$target")"
    fi
    case "$resolved" in
      "$source"|"$source/"*) ;;
      *) external_symlinks=$((external_symlinks + 1)) ;;
    esac
  done < <(find "$source" -xdev -type l -print0)
}

tree_fingerprint() {
  local source="$1"
  find "$source" -xdev -printf '%y\t%P\t%s\t%T@\t%l\n' \
    | LC_ALL=C sort \
    | sha256sum \
    | awk '{print $1}'
}

tree_count() {
  find "$1" -xdev -printf '.' | wc -c | tr -d ' '
}

archive_tree() {
  local source="$1" output="$2"
  tar --acls --xattrs --selinux --numeric-owner --one-file-system --sort=name \
    -C "$source" -cf - . \
    | zstd -q -T0 -"$ZSTD_LEVEL" -o "$output"
  chmod 0400 "$output"
}

archive_installed_package() {
  local output="$1" list_file="$2" path
  : > "$list_file"
  while IFS= read -r path; do
    path="${path#/}"
    if [ -n "$path" ] && { [ -f "/$path" ] || [ -L "/$path" ]; }; then
      printf '%s\0' "$path" >> "$list_file"
    fi
  done < <(dpkg -L opsctl)
  while IFS= read -r -d '' path; do
    printf '%s\0' "${path#/}" >> "$list_file"
  done < <(find /var/lib/dpkg/info -maxdepth 1 -type f -name 'opsctl.*' -print0)
  tar -C / --null --files-from "$list_file" --acls --xattrs --selinux --numeric-owner \
    --sort=name -cf - \
    | zstd -q -T0 -"$ZSTD_LEVEL" -o "$output"
  chmod 0400 "$output"
}

registry_bytes="$(du -sb "$REGISTRY_DIR" | awk '{print $1}')"
state_bytes="$(du -sb "$STATE_DIR" | awk '{print $1}')"
old_version="$(dpkg-deb -f "$OLD_DEB" Version)"
candidate_version="$(dpkg-deb -f "$CANDIDATE_DEB" Version)"
installed_version="$(dpkg-query -W -f='${Version}' opsctl 2>/dev/null || true)"

cat <<EOF
production upgrade snapshot plan
  registry=$REGISTRY_DIR ($registry_bytes bytes)
  state=$STATE_DIR ($state_bytes bytes)
  installed_version=${installed_version:-unknown}
  old_package_version=$old_version
  candidate_version=$candidate_version
  output_root=$OUTPUT_ROOT
  execute=$EXECUTE
EOF

[ "$EXECUTE" -eq 1 ] || exit 0
[ "$old_version" = "0.1.0" ] || fail "old package must be version 0.1.0"
[ "$candidate_version" = "0.6.0" ] || fail "candidate package must be version 0.6.0"
[ "$installed_version" = "0.1.0" ] || fail "installed opsctl version must be 0.1.0"
if pgrep -x opsctl >/dev/null 2>&1; then
  fail "an opsctl process is running; retry in a quiet maintenance window"
fi

reject_ambiguous_names "$REGISTRY_DIR"
reject_ambiguous_names "$STATE_DIR"
external_symlinks=0
validate_symlinks "$REGISTRY_DIR"
validate_symlinks "$STATE_DIR"

mkdir -p "$OUTPUT_ROOT"
chmod 0700 "$OUTPUT_ROOT"

umask 077
work_dir="$(mktemp -d "$OUTPUT_ROOT/.snapshot.XXXXXX")"
cleanup() {
  if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT

registry_before="$(tree_fingerprint "$REGISTRY_DIR")"
state_before="$(tree_fingerprint "$STATE_DIR")"
registry_count="$(tree_count "$REGISTRY_DIR")"
state_count="$(tree_count "$STATE_DIR")"

archive_tree "$REGISTRY_DIR" "$work_dir/registry.tar.zst"
archive_tree "$STATE_DIR" "$work_dir/state.tar.zst"
archive_installed_package "$work_dir/installed-package.tar.zst" "$work_dir/package-files.list0"
rm -f "$work_dir/package-files.list0"
install -m 0400 "$OLD_DEB" "$work_dir/input-0.1.0.deb"
install -m 0400 "$CANDIDATE_DEB" "$work_dir/input-0.6.0.deb"

registry_after="$(tree_fingerprint "$REGISTRY_DIR")"
state_after="$(tree_fingerprint "$STATE_DIR")"
if [ "$registry_before" != "$registry_after" ] || [ "$state_before" != "$state_after" ]; then
  fail "production registry/state changed during capture; no snapshot was published"
fi
if pgrep -x opsctl >/dev/null 2>&1; then
  fail "an opsctl process started during capture; no snapshot was published"
fi

installed_binary_sha256="$(sha256sum /usr/bin/opsctl | awk '{print $1}')"
registry_archive_sha256="$(sha256sum "$work_dir/registry.tar.zst" | awk '{print $1}')"
state_archive_sha256="$(sha256sum "$work_dir/state.tar.zst" | awk '{print $1}')"
installed_archive_sha256="$(sha256sum "$work_dir/installed-package.tar.zst" | awk '{print $1}')"
old_deb_sha256="$(sha256sum "$work_dir/input-0.1.0.deb" | awk '{print $1}')"
candidate_deb_sha256="$(sha256sum "$work_dir/input-0.6.0.deb" | awk '{print $1}')"
candidate_provenance="local_unverified_input"
candidate_manifest="$(dirname "$CANDIDATE_DEB")/RELEASE_MANIFEST.json"
if [ -f "$candidate_manifest" ] && [ ! -L "$candidate_manifest" ]; then
  expected_candidate_sha="$(jq -r --arg name "$(basename "$CANDIDATE_DEB")" '.artifacts[]? | select(.name == $name) | .sha256' "$candidate_manifest" | head -n 1)"
  manifest_version="$(jq -r '.version // empty' "$candidate_manifest")"
  manifest_quality="$(jq -r '.quality // empty' "$candidate_manifest")"
  if [ "$manifest_version" = "$candidate_version" ] \
    && [ "$manifest_quality" = "passed" ] \
    && [ "$expected_candidate_sha" = "$candidate_deb_sha256" ]; then
    candidate_provenance="release_manifest_verified"
  fi
fi
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg created_at "$created_at" \
  --arg registry "$REGISTRY_DIR" \
  --arg state "$STATE_DIR" \
  --arg installed_version "$installed_version" \
  --arg old_version "$old_version" \
  --arg candidate_version "$candidate_version" \
  --arg installed_binary_sha256 "$installed_binary_sha256" \
  --arg registry_fingerprint "$registry_before" \
  --arg state_fingerprint "$state_before" \
  --arg registry_archive_sha256 "$registry_archive_sha256" \
  --arg state_archive_sha256 "$state_archive_sha256" \
  --arg installed_archive_sha256 "$installed_archive_sha256" \
  --arg old_deb_sha256 "$old_deb_sha256" \
  --arg candidate_deb_sha256 "$candidate_deb_sha256" \
  --arg candidate_provenance "$candidate_provenance" \
  --argjson external_symlinks "$external_symlinks" \
  --argjson registry_entries "$registry_count" \
  --argjson state_entries "$state_count" \
  '{schema_version:"opsctl.production_upgrade_snapshot.v1",created_at:$created_at,status:"captured",consistent:true,sensitive:true,encryption:"none_root_only",sources:{registry:$registry,state:$state},versions:{installed:$installed_version,rollback_package:$old_version,candidate:$candidate_version},installed_binary_sha256:$installed_binary_sha256,symlinks:{dereferenced:false,external_targets:$external_symlinks},trees:{registry:{entries:$registry_entries,fingerprint:$registry_fingerprint,archive:"registry.tar.zst",sha256:$registry_archive_sha256},state:{entries:$state_entries,fingerprint:$state_fingerprint,archive:"state.tar.zst",sha256:$state_archive_sha256}},package_inputs:{installed_payload:{archive:"installed-package.tar.zst",sha256:$installed_archive_sha256},rollback_deb:{archive:"input-0.1.0.deb",sha256:$old_deb_sha256,provenance:"local_unverified_input"},candidate_deb:{archive:"input-0.6.0.deb",sha256:$candidate_deb_sha256,provenance:$candidate_provenance}},limitations:["archive encryption is not configured; filesystem access is root-only","service environment files under /etc/opsctl are not included","symlinks are preserved as links and are never dereferenced","live package and services were not changed"]}' \
  > "$work_dir/manifest.json"
chmod 0400 "$work_dir/manifest.json"

(
  cd "$work_dir"
  sha256sum registry.tar.zst state.tar.zst installed-package.tar.zst \
    input-0.1.0.deb input-0.6.0.deb manifest.json > SHA256SUMS
)
chmod 0400 "$work_dir/SHA256SUMS"
sync -f "$work_dir"
snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)-$$"
final_dir="$OUTPUT_ROOT/$snapshot_name"
[ ! -e "$final_dir" ] || fail "snapshot destination already exists"
mv "$work_dir" "$final_dir"
work_dir=""
chmod 0700 "$final_dir"
trap - EXIT
echo "$final_dir"
