# opsctl production defaults for interactive AI/operator shells.
# This file intentionally contains no secrets.
export OPSCTL_REGISTRY="${OPSCTL_REGISTRY:-/srv/server-registry}"
export OPSCTL_STATE_DIR="${OPSCTL_STATE_DIR:-/var/lib/opsctl}"
export OPSCTL_BACKUP_ENV_FILE="${OPSCTL_BACKUP_ENV_FILE:-/etc/opsctl/restic.env}"

case ":$PATH:" in
  *:/home/ivmm/.bun/bin:*) ;;
  *) PATH="/home/ivmm/.bun/bin:$PATH" ;;
esac
export PATH
