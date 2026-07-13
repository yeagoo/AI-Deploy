#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

expected="${1:-}"
cargo_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
lock_version="$(awk '
  /^\[\[package\]\]$/ { package = ""; next }
  /^name = "opsctl"$/ { package = "opsctl"; next }
  package == "opsctl" && /^version = "/ {
    value = $0
    sub(/^version = "/, "", value)
    sub(/"$/, "", value)
    print value
    exit
  }
' Cargo.lock)"

if [[ ! "$cargo_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Cargo.toml contains an invalid release version" >&2
  exit 1
fi
if [ -z "$lock_version" ] || [ "$lock_version" != "$cargo_version" ]; then
  echo "Cargo.toml and Cargo.lock release versions do not match" >&2
  exit 1
fi
if ! grep -Fq "## $cargo_version -" CHANGELOG.md; then
  echo "CHANGELOG.md has no entry for $cargo_version" >&2
  exit 1
fi

if [ -n "$expected" ]; then
  expected="${expected#v}"
  if [ "$expected" != "$cargo_version" ]; then
    echo "requested release identity does not match the source version" >&2
    exit 1
  fi
fi

if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  github_tag="${GITHUB_REF_NAME:-}"
  if [ "$github_tag" != "v$cargo_version" ]; then
    echo "GitHub tag does not match the source version" >&2
    exit 1
  fi
fi

printf '%s\n' "$cargo_version"
