# Linux guest USB enumeration experiment

This standalone pre-release experiment boots a real distribution Linux kernel with a minimal BusyBox initramfs under QEMU TCG. It checks that both emulated USB HID devices enumerate in guest sysfs and bind to the guest usbhid interface driver. This is enumeration/binding only: no event delivery, USB/IP, ownership transfer, physical hardware or production claim.

On a disposable x86-64 Ubuntu 24.04 machine:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-system-x86 busybox-static cpio kmod zstd xz-utils linux-image-generic
sudo chmod a+r /boot/vmlinuz-*-generic
bash lab/linux-usb-enumeration/run.sh /tmp/linux-usb-evidence-new
(cd /tmp/linux-usb-evidence-new && sha256sum -c SHA256SUMS)
```

The output directory must be new. The test uses no guest network or host USB passthrough. It records the actual selected kernel and QEMU version and hashes; distribution package versions are not pinned for cross-run bitwise reproducibility. A failure or timeout does not qualify the experiment. No kernel or initramfs is redistributed by CI.
