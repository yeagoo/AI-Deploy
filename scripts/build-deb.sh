#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${OPSCTL_DEB_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)}"
ARCH="${OPSCTL_DEB_ARCH:-$(dpkg --print-architecture)}"
PKG_DIR="$ROOT_DIR/target/debian/opsctl_${VERSION}_${ARCH}"
OUT_DIR="$ROOT_DIR/target/debian"
if [ -n "${OPSCTL_BIN_SRC:-}" ]; then
  BIN_SRC="$OPSCTL_BIN_SRC"
else
  cargo build --release
  BIN_SRC="$ROOT_DIR/target/release/opsctl"
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to build a Debian package" >&2
  exit 1
fi

if [ ! -x "$BIN_SRC" ]; then
  echo "opsctl binary is missing or not executable: $BIN_SRC" >&2
  exit 1
fi

rm -rf "$PKG_DIR"
install -d -m 0755 "$PKG_DIR/DEBIAN"
install -d -m 0755 "$PKG_DIR/usr/bin"
install -d -m 0755 "$PKG_DIR/usr/share/doc/opsctl"
install -d -m 0755 "$PKG_DIR/usr/share/opsctl"
install -d -m 0755 "$PKG_DIR/usr/share/opsctl/scripts"
install -d -m 0755 "$PKG_DIR/usr/lib/systemd/system"

install -m 0755 "$BIN_SRC" "$PKG_DIR/usr/bin/opsctl"
install -m 0644 README.md docs/DEBIAN_INSTALL.md docs/MANAGED_PROJECTS.md docs/PRODUCTION_DELIVERY_HANDOFF.md docs/SECURITY.md "$PKG_DIR/usr/share/doc/opsctl/"
cp -R examples/server-registry "$PKG_DIR/usr/share/opsctl/examples-server-registry"
cp -R schemas "$PKG_DIR/usr/share/opsctl/schemas"
cp -R templates "$PKG_DIR/usr/share/opsctl/templates"
install -m 0755 scripts/install-sudoers.sh "$PKG_DIR/usr/share/opsctl/scripts/"
install -m 0755 scripts/production-onboarding-check.sh "$PKG_DIR/usr/share/opsctl/scripts/"
install -m 0644 packaging/systemd/*.service "$PKG_DIR/usr/lib/systemd/system/"
install -m 0644 packaging/systemd/*.timer "$PKG_DIR/usr/lib/systemd/system/"

sed \
  -e "s/@VERSION@/$VERSION/g" \
  -e "s/@ARCH@/$ARCH/g" \
  packaging/debian/control.in > "$PKG_DIR/DEBIAN/control"
install -m 0755 packaging/debian/postinst "$PKG_DIR/DEBIAN/postinst"

install -d -m 0755 "$OUT_DIR"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$OUT_DIR"

echo "$OUT_DIR/opsctl_${VERSION}_${ARCH}.deb"
