# Linux guest dual-HID evaluation

Reproduce on Ubuntu 24.04 using the public distro packages:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends linux-image-generic qemu-system-x86 busybox-static cpio gcc libc6-dev kmod zstd xz-utils
bash lab/linux-usb-demo/build.sh ./linux-demo-build
python3 -I lab/linux-usb-demo/run.py ./linux-demo-build ./linux-demo-evidence
(cd linux-demo-evidence && sha256sum -c SHA256SUMS)
```

The local build creates a Linux kernel/initramfs boot workset with a tiny guest evdev observer. QEMU TCG boots the kernel, guest sysfs identifies both virtual USB devices and confirms their usbhid interface drivers, and host QMP injects KEY_A down/up. The guest must independently observe the ordered events. The harness saves the actual guest VGA framebuffer and runtime receipt. No networking, external devices or private credentials. Only observations and screenshot are uploaded; rebuild locally using distribution packages rather than redistributing upstream binaries. This is a native-device evaluation, not USB/IP, protected guest enrollment, production authorization or physical USB qualification.
Tablet input events are not tested. Keyboard evdev key-down/up remains required.
