#!/usr/bin/env bash
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$1"
mkdir -p "$out"
out="$(realpath "$out")"
k="$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -name '*-generic' -printf '%f\n' | sort -V | tail -1)"
test -n "$k"
sudo install -m 0644 "/boot/vmlinuz-$k" "$out/vmlinuz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{bin,dev,proc,sys,modules}
cp /bin/busybox "$work/bin/busybox"
ln -s busybox "$work/bin/sh"
install -m 0755 "$here/init" "$work/init"
gcc -O2 -Wall -Wextra -static "$here/observe.c" -o "$work/bin/observe"
declare -A seen=()
n=0
for mod in xhci_pci usbhid hid_generic evdev; do
    deps="$(modprobe -S "$k" --show-depends "$mod")"
    while read -r op file rest; do
        [[ "$op" == insmod ]] || continue
        [[ -z "${seen[$file]:-}" ]] || continue
        seen["$file"]=1
        n=$((n+1))
        target="$(printf '%s/modules/%03d.ko' "$work" "$n")"
        case "$file" in
            *.zst) zstd -q -d -c "$file" > "$target";;
            *.xz) xz -dc "$file" > "$target";;
            *.gz) gzip -dc "$file" > "$target";;
            *.ko) cp "$file" "$target";;
            *) echo "Unexpected module suffix" >&2; exit 1;;
        esac
    done <<< "$deps"
done
(cd "$work"; find . -print0 | sort -z | cpio --null -o --format=newc --quiet | gzip -n > "$out/initramfs.cpio.gz")
printf '%s\n' "$k" > "$out/kernel-version.txt"
echo "Guest kernel: $k; copied module dependencies: $n"
