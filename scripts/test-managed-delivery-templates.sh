#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRIDGE="$ROOT_DIR/templates/opsctl-git-push-deliver.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_OPSCTL="$TMP_DIR/opsctl"
CAPTURE="$TMP_DIR/argv"
cat >"$FAKE_OPSCTL" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$OPSCTL_TEST_CAPTURE"
EOF
chmod 0755 "$FAKE_OPSCTL"

export OPSCTL_BIN="$FAKE_OPSCTL"
export OPSCTL_TEST_CAPTURE="$CAPTURE"
export OPSCTL_REGISTRY="$TMP_DIR/registry"
export OPSCTL_STATE_DIR="$TMP_DIR/state"
export OPSCTL_DELIVERY_PROJECT_ROOT="$TMP_DIR/project"
export OPSCTL_DELIVERY_SERVICE_ID="example"
export OPSCTL_DELIVERY_RUNTIME_USER="deploy"
export OPSCTL_DELIVERY_BRANCH="main"
export OPSCTL_DELIVERY_PORT="3000"
export OPSCTL_DELIVERY_DOMAIN="example.com"
export OPSCTL_DELIVERY_ENV_FILE="$TMP_DIR/example.env"
commit="0123456789abcdef0123456789abcdef01234567"

assert_line() {
  if ! grep -Fqx -- "$1" "$CAPTURE"; then
    echo "missing expected bridge argument: $1" >&2
    exit 1
  fi
}

OPSCTL_DELIVERY_MODE=execute "$BRIDGE" "$commit" main
assert_line "--execute"
assert_line "$commit"
assert_line "$OPSCTL_DELIVERY_PROJECT_ROOT"
assert_line "$OPSCTL_DELIVERY_ENV_FILE"

OPSCTL_DELIVERY_MODE=dry-run "$BRIDGE" "$commit" main
assert_line "--dry-run"
if grep -Fqx -- "--execute" "$CAPTURE"; then
  echo "dry-run bridge invocation unexpectedly contained --execute" >&2
  exit 1
fi

rm -f "$CAPTURE"
if OPSCTL_DELIVERY_MODE=invalid "$BRIDGE" "$commit" main >/dev/null 2>&1; then
  echo "invalid delivery mode was accepted" >&2
  exit 1
fi
test ! -e "$CAPTURE"

if OPSCTL_DELIVERY_MODE=execute "$BRIDGE" "$commit" release >/dev/null 2>&1; then
  echo "unauthorized branch was accepted" >&2
  exit 1
fi
test ! -e "$CAPTURE"

if OPSCTL_DELIVERY_MODE=execute OPSCTL_DELIVERY_PORT=70000 "$BRIDGE" "$commit" main >/dev/null 2>&1; then
  echo "out-of-range port was accepted" >&2
  exit 1
fi
test ! -e "$CAPTURE"

if OPSCTL_DELIVERY_MODE=execute OPSCTL_DELIVERY_ENV_FILE=relative.env "$BRIDGE" "$commit" main >/dev/null 2>&1; then
  echo "relative environment path was accepted" >&2
  exit 1
fi
test ! -e "$CAPTURE"

if OPSCTL_DELIVERY_MODE=execute "$BRIDGE" "ABCDEF0123456789abcdef0123456789abcdef01" main >/dev/null 2>&1; then
  echo "non-canonical commit was accepted" >&2
  exit 1
fi
test ! -e "$CAPTURE"

echo "PASS: managed delivery bridge validates mode, branch, commit, port, and absolute paths"
