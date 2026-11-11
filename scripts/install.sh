#!/usr/bin/env bash
# Installs PathGuard from a build directory.
#   cmake -S . -B build && cmake --build build -j && sudo scripts/install.sh
# Existing configuration, hash lists and rules in /etc/pathguard are kept.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build}
PREFIX=${PREFIX:-/usr/local}
ETC=/etc/pathguard

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -x $BUILD/pathguardd && -x $BUILD/pathguardctl ]] || { echo "build first (missing $BUILD/pathguardd)" >&2; exit 1; }

install -d -m 0755 "$PREFIX/sbin"
install -m 0755 "$BUILD/pathguardd" "$PREFIX/sbin/pathguardd"
install -m 0755 "$BUILD/pathguardctl" "$PREFIX/sbin/pathguardctl"

getent group pathguard-admin >/dev/null || groupadd --system pathguard-admin
id pathguard >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin --user-group pathguard

install -d -m 0755 "$ETC" "$ETC/rules"
keep() { [[ -e $2 ]] && echo "kept existing $2" || install -m 0644 "$1" "$2"; }
keep "$ROOT/config/pathguard.conf" "$ETC/pathguard.conf"
keep "$ROOT/config/blocklist.sha256" "$ETC/blocklist.sha256"
keep "$ROOT/config/allowlist.sha256" "$ETC/allowlist.sha256"
for r in "$ROOT"/rules/*.yar; do keep "$r" "$ETC/rules/$(basename "$r")"; done

install -d -m 0700 /var/lib/pathguard /var/lib/pathguard/quarantine
install -d -m 0750 /var/log/pathguard

sed "s#@PREFIX@#$PREFIX#g" "$ROOT/packaging/pathguard.service" > /etc/systemd/system/pathguard.service
chmod 0644 /etc/systemd/system/pathguard.service
systemctl daemon-reload

echo
echo "installed. Checking configuration:"
"$PREFIX/sbin/pathguardd" --check --config "$ETC/pathguard.conf" || true
cat <<EOF

next steps:
  1. set watch_path in $ETC/pathguard.conf to a dedicated filesystem
     (for testing: sudo $ROOT/tests/vm/setup_testfs.sh  ->  /mnt/pg-test)
  2. sudo systemctl enable --now pathguard
  3. sudo pathguardctl status
  (optional) sudo usermod -aG pathguard-admin <user>   # read-only status access
EOF
