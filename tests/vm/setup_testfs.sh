#!/usr/bin/env bash
# Creates (or removes with --remove) a dedicated loop-mounted ext4 filesystem
# used as the protected scope in the tests.
set -euo pipefail

IMG=${IMG:-/var/tmp/pg-test.img}
MNT=${MNT:-/mnt/pg-test}
SIZE=${SIZE:-1G}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if [[ ${1:-} == --remove ]]; then
    mountpoint -q "$MNT" && umount "$MNT"
    rm -f "$IMG"
    echo "removed $MNT and $IMG"
    exit 0
fi

if mountpoint -q "$MNT"; then
    echo "$MNT is already mounted"
    exit 0
fi
[[ -e $IMG ]] || { truncate -s "$SIZE" "$IMG"; mkfs.ext4 -q -F "$IMG"; }
mkdir -p "$MNT"
mount -o loop "$IMG" "$MNT"
chmod 1777 "$MNT"
echo "mounted $IMG on $MNT ($(findmnt -no FSTYPE "$MNT"))"
