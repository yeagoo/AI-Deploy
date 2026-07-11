#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${OPSCTL_RELEASE_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)}"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
TARGETS="${OPSCTL_RELEASE_TARGETS:-$HOST_TARGET}"
OUT_DIR="${OPSCTL_RELEASE_OUT:-$ROOT_DIR/target/release-dist/v$VERSION}"
SKIP_QUALITY="${OPSCTL_RELEASE_SKIP_QUALITY:-0}"
BUILD_TOOL="${OPSCTL_RELEASE_BUILD_TOOL:-cargo}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

target_to_deb_arch() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "amd64" ;;
    aarch64-unknown-linux-gnu) echo "arm64" ;;
    armv7-unknown-linux-gnueabihf) echo "armhf" ;;
    *) echo "unsupported" ;;
  esac
}

require_command cargo
require_command rustc
require_command sha256sum
require_command dpkg-deb
if [ "$BUILD_TOOL" = "cross" ]; then
  require_command cross
elif [ "$BUILD_TOOL" != "cargo" ]; then
  echo "unsupported OPSCTL_RELEASE_BUILD_TOOL=$BUILD_TOOL; expected cargo or cross" >&2
  exit 1
fi

if [ "$SKIP_QUALITY" != "1" ]; then
  if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is required unless OPSCTL_RELEASE_SKIP_QUALITY=1" >&2
    exit 1
  fi
  if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "cargo-deny is required unless OPSCTL_RELEASE_SKIP_QUALITY=1" >&2
    exit 1
  fi
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
  cargo audit
  cargo deny check
fi

rm -rf "$OUT_DIR"
install -d -m 0755 "$OUT_DIR"
install -m 0644 CHANGELOG.md "$OUT_DIR/CHANGELOG.md"

for target in $TARGETS; do
  if [ "$BUILD_TOOL" = "cargo" ] && command -v rustup >/dev/null 2>&1; then
    rustup target add "$target" >/dev/null
  fi
  "$BUILD_TOOL" build --release --target "$target"
  bin_path="$ROOT_DIR/target/$target/release/opsctl"
  artifact_bin="$OUT_DIR/opsctl-$VERSION-$target"
  install -m 0755 "$bin_path" "$artifact_bin"

  deb_arch="$(target_to_deb_arch "$target")"
  if [ "$deb_arch" != "unsupported" ]; then
    deb_path="$(OPSCTL_BIN_SRC="$bin_path" OPSCTL_DEB_ARCH="$deb_arch" OPSCTL_DEB_VERSION="$VERSION" scripts/build-deb.sh | tail -n 1)"
    cp "$deb_path" "$OUT_DIR/"
  else
    echo "skipping deb package for unsupported target mapping: $target" >&2
  fi
done

(
  cd "$OUT_DIR"
  sha256sum -- * > SHA256SUMS
  {
    printf '{\n'
    printf '  "schema_version": "opsctl.release_manifest.v1",\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "build_tool": "%s",\n' "$BUILD_TOOL"
    printf '  "quality": "%s",\n' "$(if [ "$SKIP_QUALITY" = "1" ]; then echo "skipped"; else echo "passed"; fi)"
    printf '  "artifacts": [\n'
    first=1
    while IFS= read -r line; do
      checksum="${line%% *}"
      artifact="${line#*  }"
      [ "$artifact" = "SHA256SUMS" ] && continue
      if [ "$first" = "0" ]; then
        printf ',\n'
      fi
      first=0
      size="$(wc -c < "$artifact" | tr -d ' ')"
      printf '    {"name": "%s", "sha256": "%s", "size": %s}' "$artifact" "$checksum" "$size"
    done < SHA256SUMS
    printf '\n  ]\n'
    printf '}\n'
  } > RELEASE_MANIFEST.json
  sha256sum RELEASE_MANIFEST.json >> SHA256SUMS
)

cat > "$OUT_DIR/RELEASE_NOTES.md" <<EOF
# opsctl v$VERSION

Generated on $(date -u +%Y-%m-%dT%H:%M:%SZ).

## Highlights

$(awk -v version="$VERSION" '$0 ~ "^## " version " " { emit=1; next } emit && /^## / { exit } emit { print }' CHANGELOG.md)

## Artifacts

$(find "$OUT_DIR" -maxdepth 1 -type f ! -name RELEASE_NOTES.md ! -name SHA256SUMS -printf '- %f\n' | sort)

## Verification

Use:

\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`

Quality gates were $(if [ "$SKIP_QUALITY" = "1" ]; then echo "skipped by OPSCTL_RELEASE_SKIP_QUALITY=1"; else echo "run before packaging"; fi).

Build tool: $BUILD_TOOL.
EOF

echo "$OUT_DIR"
