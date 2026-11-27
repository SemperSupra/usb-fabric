#!/usr/bin/env python3
"""Boot a local distro Linux kernel and capture real USB HID evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

helper_path = Path(__file__).resolve().parents[1] / 'qemu-usb-demo' / 'run.py'
spec = importlib.util.spec_from_file_location('qemu_fixture', helper_path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def main(build, out):
    build = build.resolve()
    out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='linux-usb-') as tmp:
        root = Path(tmp)
        serial = root / 'serial.txt'
        sock = root / 'qmp.sock'
        with (root / 'stderr').open('wb') as err:
            vm = subprocess.Popen([
                'qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', '512M',
                '-kernel', str(build / 'vmlinuz'), '-initrd', str(build / 'initramfs.cpio.gz'),
                '-append', 'console=tty0 console=ttyS0 quiet loglevel=3 panic=1 rdinit=/init',
                '-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0,id=demo-keyboard',
                '-display', 'none', '-monitor', 'none', '-serial', f'file:{serial}', '-nic', 'none',
                '-qmp', f'unix:{sock},server=on,wait=off', '-no-reboot'],
                stdout=subprocess.DEVNULL, stderr=err)
            qmp = None
            def wait_marker(marker, seconds=90):
                return helper.wait_for(lambda: serial.exists() and marker in serial.read_bytes(), marker.decode(), seconds)
            try:
                helper.wait_for(sock.exists, 'QMP socket missing')
                qmp = helper.QMP(sock)
                wait_marker(b'GUEST_USB_KEYBOARD_ENUMERATED=PASS')
                wait_marker(b'GUEST_EVDEV_READY')
                helper.require('keyboard' in qmp.usb().lower(), 'host keyboard missing')
                key = {'type': 'qcode', 'data': 'a'}
                qmp.call('input-send-event', events=[{'type':'key','data':{'down':True,'key':key}}])
                wait_marker(b'GUEST_EVDEV_KEY_A_DOWN=PASS', 20)
                qmp.call('input-send-event', events=[{'type':'key','data':{'down':False,'key':key}}])
                wait_marker(b'GUEST_EVDEV_KEY_A_UP=PASS', 20)
                wait_marker(b'GUEST_OBSERVER_EXIT', 10)
                ppm = root / 'screen.ppm'
                qmp.call('screendump', filename=str(ppm))
                dims = helper.png_from_ppm(ppm, out / 'linux-guest.png')
                # Preserve only intended guest observations, not host paths or raw boot logs.
                lines = serial.read_text(errors='replace').splitlines()
                markers = [s for s in lines if s.startswith(('USB ', 'GUEST_'))]
                (out / 'guest-observations.txt').write_text('\n'.join(markers)+'\n')
                receipt = {'scope': 'Native QEMU USB keyboard; real Linux guest sysfs and evdev, no USB/IP claim',
                           'qemu': qmp.call('query-version'),
                           'kernel': (build/'kernel-version.txt').read_text().strip(),
                           'kernel_sha256': hashlib.sha256((build/'vmlinuz').read_bytes()).hexdigest(),
                           'usb_enumerated': True, 'evdev_key_a_down': True, 'evdev_key_a_up': True,
                           'framebuffer': dims, 'guest_observations': markers}
                (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
                print(json.dumps(receipt, indent=2))
                qmp.call('quit')
                vm.wait(timeout=10)
            except Exception:
                if serial.exists():
                    print('Guest serial tail:', serial.read_text(errors='replace')[-5000:])
                raise
            finally:
                if qmp:
                    qmp.close()
                if vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait(timeout=5)
    names=sorted(p.name for p in out.iterdir())
    (out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256((out/n).read_bytes()).hexdigest()}  {n}\n' for n in names))
    print('LINUX_USB_EVDEV_DEMO=PASS')


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('build',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    main(a.build,a.output)
