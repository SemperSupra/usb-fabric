# QEMU USB device demonstrator

A standalone bootable x86 fixture for evaluating QEMU's virtual USB controller and device hotplug through QMP. It is not a USB/IP exporter, guest USB driver or production USB Fabric runtime.

## Reproduce on Ubuntu 24.04

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends qemu-system-x86 nasm
python3 lab/qemu-usb-demo/run.py ./demo-output
(cd demo-output && sha256sum -c SHA256SUMS)
```

The harness builds a 1 MiB raw BIOS disk from the included assembly, boots it with QEMU TCG (no KVM required), waits for the guest's debug-port boot marker, observes the virtual keyboard, adds and removes a virtual USB tablet using QMP, verifies the keyboard remains, and captures the actual VGA framebuffer as PNG. All VM state is temporary; no guest or host networking is configured. The guest is deliberately a minimal firmware-level fixture; device enumeration is host-side, not evidence of guest USB event handling.

Evaluation bundle: raw disk, assembly source, actual screenshot, structured runtime receipt, boot marker and SHA-256 checksums. The evaluation workflow installs upstream QEMU/NASM from Ubuntu, does not package them, uses no private credentials, and runs on a standard public hosted runner. This is an R&D evaluation artifact, not a licensed production release.
