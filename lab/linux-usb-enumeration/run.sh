#!/usr/bin/env bash
# Standalone virtual-device experiment; no physical hardware or USB/IP claim.
set -euo pipefail
export LC_ALL=C
out=${1:?usage: bash run.sh NEW_OUTPUT_DIRECTORY}
mkdir "$out"
out=$(realpath "$out")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
mkdir -p "$root"/{bin,dev,proc,sys,modules}
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*-generic' -type f | sort -V | tail -1)
test -n "$kernel"
kver=${kernel##*/vmlinuz-}
test -d "/lib/modules/$kver"
cp /bin/busybox "$root/bin/busybox"
for cmd in sh mount insmod cat sleep readlink reboot; do ln -s busybox "$root/bin/$cmd"; done
# Build a minimal initramfs with the distro kernel's exact module dependencies.
for mod in xhci_pci usbhid hid_generic; do
  modprobe --show-depends -S "$kver" "$mod"
done | awk '$1=="insmod" && !seen[$2]++ {print $2}' > "$work/module-paths"
n=0
while IFS= read -r module; do
  n=$((n+1))
  dest=$(printf '%s/modules/%04d.ko' "$root" "$n")
  case "$module" in
    *.zst) zstd -dc "$module" > "$dest";;
    *.xz) xz -dc "$module" > "$dest";;
    *.gz) gzip -dc "$module" > "$dest";;
    *.ko) cp "$module" "$dest";;
    *) exit 1;;
  esac
done < "$work/module-paths"
cat > "$root/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
for f in /modules/*.ko; do
  [ -f "$f" ] || continue
  insmod "$f"
done
check() {
  keyboard=0
  tablet=0
  for d in /sys/bus/usb/devices/*; do
    [ -f "$d/product" ] || continue
    product=$(cat "$d/product")
    case "$product" in
      'QEMU USB Keyboard'|'QEMU USB Tablet')
        for i in "$d":*; do
          [ -L "$i/driver" ] || continue
          driver=$(readlink "$i/driver")
          case "$driver" in */usbhid) ;; *) continue;; esac
          echo "GUEST_USB_DEVICE product=$product vid=$(cat "$d/idVendor") pid=$(cat "$d/idProduct") driver=usbhid"
          case "$product" in
            'QEMU USB Keyboard') keyboard=1;;
            'QEMU USB Tablet') tablet=1;;
          esac
        done;;
    esac
  done
  [ "$keyboard" = 1 ] && [ "$tablet" = 1 ]
}
i=0
while [ "$i" -lt 20 ]; do
  if check; then
    echo GUEST_USB_ENUMERATION_AND_HID_BINDING=PASS
    reboot -f
    exit 0
  fi
  i=$((i+1))
  sleep 1
done
echo GUEST_USB_ENUMERATION_AND_HID_BINDING=FAIL
reboot -f
GUEST
chmod 755 "$root/init"
(cd "$root"; find . -print0 | cpio --null -o --format=newc --quiet | gzip -n) > "$work/initramfs.gz"
{
  printf 'guest kernel=%s\n' "$kver"
  qemu-system-x86_64 --version
  sha256sum "$kernel" "$work/initramfs.gz"
} > "$out/runtime.txt"
timeout 180s qemu-system-x86_64 -machine q35,accel=tcg -m 768 -smp 2 \
  -nodefaults -display none -monitor none -serial stdio -no-reboot \
  -kernel "$kernel" -initrd "$work/initramfs.gz" \
  -append 'console=ttyS0 rdinit=/init panic=1' \
  -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0 \
  > "$out/guest.log" 2>&1
grep -Fx 'GUEST_USB_ENUMERATION_AND_HID_BINDING=PASS' <(tr -d '\r' < "$out/guest.log")
! grep -q 'GUEST_USB_ENUMERATION_AND_HID_BINDING=FAIL' "$out/guest.log"
(cd "$out"; sha256sum guest.log runtime.txt > SHA256SUMS)
