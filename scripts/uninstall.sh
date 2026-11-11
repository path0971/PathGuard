#!/usr/bin/env bash
# Removes PathGuard. By default configuration, logs and the quarantine are
# kept (quarantined files are never deleted implicitly). --purge removes them.
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
PURGE=0
[[ ${1:-} == --purge ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

systemctl disable --now pathguard 2>/dev/null || true
rm -f /etc/systemd/system/pathguard.service
systemctl daemon-reload
rm -f "$PREFIX/sbin/pathguardd" "$PREFIX/sbin/pathguardctl"

if [[ $PURGE -eq 1 ]]; then
    n=$(find /var/lib/pathguard/quarantine -name '*.bin' 2>/dev/null | wc -l)
    [[ $n -gt 0 ]] && echo "purging $n quarantined file(s)"
    rm -rf /etc/pathguard /var/lib/pathguard /var/log/pathguard /run/pathguard
    id pathguard >/dev/null 2>&1 && userdel pathguard
    getent group pathguard-admin >/dev/null && groupdel pathguard-admin
    echo "PathGuard removed (purged)"
else
    echo "PathGuard removed; kept /etc/pathguard, /var/log/pathguard, /var/lib/pathguard (use --purge to delete)"
fi
