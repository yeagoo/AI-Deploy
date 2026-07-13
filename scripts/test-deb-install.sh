#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APPLY="${OPSCTL_DEB_TEST_APPLY:-0}"
IMAGE="${OPSCTL_DEB_TEST_IMAGE:-debian:13}"
PLATFORM="${OPSCTL_DEB_TEST_PLATFORM:-}"
DEB_PATH="${OPSCTL_DEB_PATH:-}"
PREVIOUS_DEB="${OPSCTL_PREVIOUS_DEB:-}"

if [ -z "$DEB_PATH" ]; then
  DEB_PATH="$(find "$ROOT_DIR/target/debian" -maxdepth 1 -type f -name 'opsctl_*.deb' 2>/dev/null | sort | tail -n 1 || true)"
fi

if [ -z "$DEB_PATH" ] || [ ! -f "$DEB_PATH" ]; then
  DEB_PATH="$(scripts/build-deb.sh | tail -n 1)"
fi
EXPECTED_VERSION="${OPSCTL_EXPECTED_VERSION:-$(dpkg-deb -f "$DEB_PATH" Version)}"
PREVIOUS_VERSION=""
if [ -n "$PREVIOUS_DEB" ] && [ -f "$PREVIOUS_DEB" ]; then
  PREVIOUS_VERSION="${OPSCTL_PREVIOUS_VERSION:-$(dpkg-deb -f "$PREVIOUS_DEB" Version)}"
fi

if [ "$APPLY" != "1" ]; then
  cat <<EOF
Debian package install test is disabled by default.

Set OPSCTL_DEB_TEST_APPLY=1 to run an install/upgrade/remove smoke in Docker.

Current settings:
  image=$IMAGE
  platform=${PLATFORM:-default}
  deb=$DEB_PATH
  previous_deb=${PREVIOUS_DEB:-none}
  expected_version=$EXPECTED_VERSION
  previous_version=${PREVIOUS_VERSION:-none}
EOF
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the Debian package install test" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker daemon access is required for the Debian package install test" >&2
  exit 1
fi

docker_args=(run --rm)
if [ -n "$PLATFORM" ]; then
  docker_args+=(--platform "$PLATFORM")
fi
docker_args+=(-v "$DEB_PATH:/tmp/opsctl.deb:ro")
docker_args+=(-e "OPSCTL_EXPECTED_VERSION=$EXPECTED_VERSION")
if [ -n "$PREVIOUS_DEB" ]; then
  if [ ! -f "$PREVIOUS_DEB" ]; then
    echo "OPSCTL_PREVIOUS_DEB does not exist: $PREVIOUS_DEB" >&2
    exit 1
  fi
  docker_args+=(-v "$PREVIOUS_DEB:/tmp/opsctl-previous.deb:ro")
  docker_args+=(-e "OPSCTL_PREVIOUS_VERSION=$PREVIOUS_VERSION")
fi
# This script is intentionally expanded only inside the container.
# shellcheck disable=SC2016
docker_args+=("$IMAGE" bash -euxo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates adduser sudo

if [ -f /tmp/opsctl-previous.deb ]; then
  dpkg -i /tmp/opsctl-previous.deb
  test -x /usr/bin/opsctl
  /usr/bin/opsctl --version | grep -q "opsctl $OPSCTL_PREVIOUS_VERSION"
fi

dpkg -i /tmp/opsctl.deb
test -x /usr/bin/opsctl
/usr/bin/opsctl --version | grep -q "opsctl $OPSCTL_EXPECTED_VERSION"
id opsctl
getent group opsctl
test -f /usr/lib/systemd/system/opsctl-install-check.service
test -f /usr/lib/systemd/system/opsctl-install-check.timer
test -f /usr/lib/systemd/system/opsctl-backup-run@.service
test -f /usr/lib/systemd/system/opsctl-backup-run@.timer
test -f /usr/lib/systemd/system/opsctl-backup-check@.service
test -f /usr/lib/systemd/system/opsctl-backup-check@.timer
test -f /usr/lib/systemd/system/opsctl-restore-drill@.service
test -f /usr/lib/systemd/system/opsctl-restore-drill@.timer
test -f /usr/lib/systemd/system/opsctl-volume-protect-campaign@.service
test -f /usr/lib/systemd/system/opsctl-volume-protect-campaign@.timer
test -f /usr/lib/systemd/system/opsctl-evidence-verify.service
test -f /usr/lib/systemd/system/opsctl-evidence-verify.timer
test -f /usr/lib/systemd/system/opsctl-evidence-checkpoint@.service
test -f /usr/lib/systemd/system/opsctl-evidence-checkpoint@.timer
test -f /usr/lib/systemd/system/opsctl-recovery-lab@.service
test -f /usr/lib/systemd/system/opsctl-recovery-lab@.timer
test -f /usr/share/opsctl/templates/sudoers.opsctl.example
test -x /usr/share/opsctl/templates/opsctl-git-push-deliver.sh
test -f /usr/share/opsctl/templates/opsctl-delivery.env.example
test -f /usr/share/doc/opsctl/PRODUCTION_DELIVERY_HANDOFF.md
test -f /usr/share/opsctl/scripts/install-sudoers.sh
test -f /usr/share/opsctl/scripts/production-onboarding-check.sh
bash -n /usr/share/opsctl/scripts/production-onboarding-check.sh
if dpkg --compare-versions "$OPSCTL_EXPECTED_VERSION" ge 0.6.1; then
  grep -q "Environment=OPSCTL_LOCK_WAIT_SECONDS=21600" /usr/lib/systemd/system/opsctl-backup-run@.service
  grep -q "FixedRandomDelay=true" /usr/lib/systemd/system/opsctl-backup-run@.timer
fi

test "$(stat -c "%a" /srv/server-registry)" = "2750"
test "$(stat -c "%G" /srv/server-registry)" = "opsctl"
test "$(stat -c "%a" /var/lib/opsctl)" = "700"
test "$(stat -c "%U:%G" /var/lib/opsctl)" = "opsctl:opsctl"
test "$(stat -c "%U:%G" /var/lib/opsctl/opsctl.db)" = "opsctl:opsctl"
test "$(stat -c "%U:%G" /var/lib/opsctl/audit.log)" = "opsctl:opsctl"
test "$(stat -c "%a" /var/lib/opsctl/restore-drills)" = "700"
test "$(stat -c "%U:%G" /var/lib/opsctl/restore-drills)" = "opsctl:opsctl"
test "$(stat -c "%a" /var/lib/opsctl/volume-protect-restores)" = "700"
test "$(stat -c "%U:%G" /var/lib/opsctl/volume-protect-restores)" = "opsctl:opsctl"
test -d /etc/opsctl
printf "registry-preserved\n" >/srv/server-registry/history/package-upgrade-sentinel
printf "state-preserved\n" >/var/lib/opsctl/package-upgrade-sentinel
runuser -u opsctl -- /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json >/tmp/install-check.json
grep -q "\"ok\":true" /tmp/install-check.json
chown root:root /var/lib/opsctl/audit.log
mkdir -p /var/lib/opsctl/restore-drills/ownership-sentinel
touch /var/lib/opsctl/restore-drills/ownership-sentinel/restored-file
chown root:root /var/lib/opsctl/restore-drills/ownership-sentinel/restored-file

cp /usr/share/opsctl/templates/sudoers.opsctl.example /tmp/opsctl-sudoers
chmod 0440 /tmp/opsctl-sudoers
/usr/bin/opsctl helper sudoers-check --path /tmp/opsctl-sudoers --json >/tmp/sudoers-check.json
grep -q "\"ok\":true" /tmp/sudoers-check.json
visudo -cf /tmp/opsctl-sudoers

if [ -f /tmp/opsctl-previous.deb ]; then
  dpkg -i --force-downgrade /tmp/opsctl-previous.deb
  /usr/bin/opsctl --version | grep -q "opsctl $OPSCTL_PREVIOUS_VERSION"
  grep -q "registry-preserved" /srv/server-registry/history/package-upgrade-sentinel
  grep -q "state-preserved" /var/lib/opsctl/package-upgrade-sentinel
  dpkg-deb -c /tmp/opsctl-previous.deb >/tmp/opsctl-previous-files
  if grep -q "\./usr/lib/systemd/system/opsctl-evidence-verify.timer" /tmp/opsctl-previous-files; then
    test -f /usr/lib/systemd/system/opsctl-evidence-verify.timer
  else
    test ! -e /usr/lib/systemd/system/opsctl-evidence-verify.timer
  fi

  dpkg -i /tmp/opsctl.deb
  /usr/bin/opsctl --version | grep -q "opsctl $OPSCTL_EXPECTED_VERSION"
  grep -q "registry-preserved" /srv/server-registry/history/package-upgrade-sentinel
  grep -q "state-preserved" /var/lib/opsctl/package-upgrade-sentinel
fi

dpkg -i /tmp/opsctl.deb
test "$(stat -c "%U:%G" /var/lib/opsctl/package-upgrade-sentinel)" = "opsctl:opsctl"
test "$(stat -c "%U:%G" /var/lib/opsctl/audit.log)" = "opsctl:opsctl"
test "$(stat -c "%U:%G" /var/lib/opsctl/restore-drills/ownership-sentinel/restored-file)" = "root:root"
runuser -u opsctl -- /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json >/tmp/install-check-after-upgrade.json
grep -q "\"ok\":true" /tmp/install-check-after-upgrade.json

dpkg -r opsctl
test ! -e /usr/bin/opsctl
test -d /srv/server-registry
test -d /var/lib/opsctl
grep -q "registry-preserved" /srv/server-registry/history/package-upgrade-sentinel
grep -q "state-preserved" /var/lib/opsctl/package-upgrade-sentinel
')

docker "${docker_args[@]}"
if [ -n "$PREVIOUS_VERSION" ]; then
  echo "PASS: Debian package install, $PREVIOUS_VERSION -> $EXPECTED_VERSION upgrade, rollback, re-upgrade, and remove smoke"
else
  echo "PASS: Debian package install, reinstall, and remove smoke for $EXPECTED_VERSION"
fi
