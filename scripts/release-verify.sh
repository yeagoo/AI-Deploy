#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/release-verify.sh <release-dir>" >&2
  exit 2
fi

input_dir="$1"

if [ ! -d "$input_dir" ]; then
  echo "release directory does not exist: $input_dir" >&2
  exit 1
fi

release_dir="$(cd "$input_dir" && pwd)"

cd "$release_dir"

if [ ! -f SHA256SUMS ]; then
  echo "missing SHA256SUMS" >&2
  exit 1
fi

if [ ! -f RELEASE_MANIFEST.json ]; then
  echo "missing RELEASE_MANIFEST.json" >&2
  exit 1
fi

sha256sum -c SHA256SUMS

python3 - "$release_dir" <<'PY'
import json
import pathlib
import sys

release_dir = pathlib.Path(sys.argv[1])
manifest = json.loads((release_dir / "RELEASE_MANIFEST.json").read_text())
if manifest.get("schema_version") != "opsctl.release_manifest.v1":
    raise SystemExit("unexpected release manifest schema_version")
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("release manifest has no artifacts")
for artifact in artifacts:
    name = artifact.get("name")
    checksum = artifact.get("sha256")
    size = artifact.get("size")
    if not isinstance(name, str) or "/" in name or name in {"", ".", ".."}:
        raise SystemExit(f"unsafe artifact name in release manifest: {name!r}")
    if not isinstance(checksum, str) or len(checksum) != 64:
        raise SystemExit(f"invalid checksum for {name!r}")
    if not isinstance(size, int) or size <= 0:
        raise SystemExit(f"invalid size for {name!r}")
    if not (release_dir / name).is_file():
        raise SystemExit(f"artifact listed in manifest is missing: {name}")
PY

echo "release verification passed: $release_dir"
