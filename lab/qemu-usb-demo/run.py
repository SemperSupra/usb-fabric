#!/usr/bin/env python3
"""Run a bootable fixture and inspect actual QEMU virtual USB devices."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import zlib


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.f = self.sock.makefile('rwb')
        greeting = json.loads(self.f.readline())
        require('QMP' in greeting, 'QMP greeting missing')
        self.seq = 0
        self.call('qmp_capabilities')

    def call(self, command, **arguments):
        self.seq += 1
        req = {'execute': command, 'id': self.seq}
        if arguments:
            req['arguments'] = arguments
        self.f.write(json.dumps(req).encode() + b'\n')
        self.f.flush()
        while True:
            line = self.f.readline()
            require(line, 'QMP closed')
            msg = json.loads(line)
            if msg.get('id') != self.seq:
                continue
            require('error' not in msg, 'QMP rejected ' + command + ': ' + str(msg.get('error')))
            return msg['return']

    def usb(self):
        return self.call('human-monitor-command', **{'command-line': 'info usb'})

    def close(self):
        self.f.close()
        self.sock.close()


def wait_for(fn, reason, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(0.2)
    raise RuntimeError(reason)


def png_from_ppm(src, dst):
    # QEMU P6 screendump format, converted losslessly using the standard library.
    raw = src.read_bytes()
    match = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255[\r\n ]', raw)
    require(match, 'invalid QEMU PPM')
    w, h = map(int, match.groups())
    pixels = raw[match.end():]
    require(0 < w <= 4096 and 0 < h <= 4096 and len(pixels) == w*h*3, 'invalid raster length')
    require(len(set(pixels)) > 1, 'blank frame')
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    rows = b''.join(b'\0' + pixels[i:i+w*3] for i in range(0, len(pixels), w*3))
    dst.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w,h,8,2,0,0,0)) +
                    chunk(b'IDAT', zlib.compress(rows,9)) + chunk(b'IEND', b''))
    return [w, h]


def run(out):
    out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('boot.asm')
    image = out / 'usb-fabric-demo.img'
    boot = out / 'boot.bin'
    subprocess.run(['nasm','-f','bin',str(source),'-o',str(boot)],check=True,timeout=15)
    raw = boot.read_bytes()
    require(len(raw)==512 and raw[-2:]==b'\x55\xaa', 'bad boot signature')
    image.write_bytes(raw + bytes(1024*1024-512))
    boot.unlink()
    shutil.copyfile(source, out/'boot.asm')
    with tempfile.TemporaryDirectory(prefix='usb-demo-') as tmp:
        root = Path(tmp)
        qmp_path = root/'qmp.sock'
        debug = root/'debug.log'
        with (root/'qemu.stderr').open('wb') as err:
            vm = subprocess.Popen(['qemu-system-x86_64','-machine','q35,accel=tcg','-m','64M',
                '-drive',f'file={image.resolve()},format=raw,if=ide,snapshot=on',
                '-boot','order=c','-device','qemu-xhci,id=xhci',
                '-device','usb-kbd,bus=xhci.0,id=demo-keyboard',
                '-display','none','-monitor','none','-serial','none','-nic','none',
                '-qmp',f'unix:{qmp_path},server=on,wait=off',
                '-debugcon',f'file:{debug}','-no-reboot'],
                stdout=subprocess.DEVNULL,stderr=err)
            qmp = None
            try:
                wait_for(lambda: qmp_path.exists() or (vm.poll() is not None and False),'QMP socket missing')
                qmp = QMP(qmp_path)
                wait_for(lambda: debug.exists() and b'USB_DEMO_BOOT_READY' in debug.read_bytes(),
                         'guest boot marker missing',30)
                status = qmp.call('query-status')
                require(status.get('running') is True,'guest not running')
                before = qmp.usb()
                require('keyboard' in before.lower() and 'tablet' not in before.lower(), 'initial USB inventory')
                qmp.call('device_add',driver='usb-tablet',id='demo-tablet',bus='xhci.0')
                added = wait_for(lambda: (s if 'tablet' in (s:=qmp.usb()).lower() else None),'tablet not observed')
                require('keyboard' in added.lower(),'keyboard lost')
                qmp.call('device_del',id='demo-tablet')
                removed = wait_for(lambda: (s if 'tablet' not in (s:=qmp.usb()).lower() else None),'tablet removal not observed')
                require('keyboard' in removed.lower(),'keyboard lost after removal')
                ppm = root/'screen.ppm'
                qmp.call('screendump',filename=str(ppm))
                dimensions = png_from_ppm(ppm,out/'qemu-guest.png')
                receipt = {'scope':'QEMU TCG BIOS boot and host-side USB device add/remove; no guest USB stack or USB/IP qualification',
                           'qemu':qmp.call('query-version'),'boot_marker':True,'running':True,
                           'keyboard_preserved':True,'tablet_add_observed':True,'tablet_remove_observed':True,
                           'usb_before':before,'usb_added':added,'usb_after':removed,'screen_pixels':dimensions}
                (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
                (out/'boot-observation.txt').write_text('USB_DEMO_BOOT_READY\n')
                print(json.dumps(receipt,indent=2))
                qmp.call('quit')
                vm.wait(timeout=10)
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
    names = sorted(p.name for p in out.iterdir())
    (out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256((out/n).read_bytes()).hexdigest()}  {n}\n' for n in names))
    print('QEMU_DEVICE_DEMO=PASS')


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('output',type=Path)
    run(p.parse_args().output)
