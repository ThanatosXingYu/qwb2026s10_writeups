#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELFStudy 主求解脚本（对应题解第 3、4 节）。

流程：
  1. 从文件偏移 0x7396 取 0x330 字节密文，按加载期 stub 的链式 XOR 还原
     校验函数（与 extract.py 完全相同的算法）；
  2. 从明文 blob 的 0x7686 处读 6 个 QWORD：
         W[0] = C0 ^ C1,  W[1] = C2 ^ C3
         target = (C4, C5)                # 0x76a6 / 0x76ae 两条 cmp 的立即数
  3. 按 i = 2..31 扩展 W[i] = rol64(W[i-1]+W[i-2],13) ^ ror64(W[i-2],7) ^ i*delta；
  4. 30 轮 Feistel 逆推：新状态 (r8,r9) 由旧状态 (r9, r8 ^ G(r9,W[i])) 得到，
     因此 r8,r9 = r9 ^ G(r8,W[i]), r8（i 从 31 递减到 2）；
  5. 去掉白化：word0 = r8 ^ W[0]，word1 = r9 ^ W[1]，小端拼成 16 字节，
     即 flag{} 内 32 个 hex 字符；
  6. 正向回代，确认末态与 target 完全一致后才输出。

用法：
    python solve.py                      # 默认读取同目录 ./elfstudy
    python solve.py --elf elfstudy --blob-out checker.bin
"""

import argparse
import struct
import sys

# ---- 题解「静态提取校验函数」与 PoC 的固定偏移 -------------------------------------------
BLOB_OFF = 0x7396          # 加密校验函数起点（第 2 个 LOAD 段尾页缝隙）
BLOB_END = 0x76C6          # 0x7396 + 0x330，之后是 .rela.plt 的副本
BLOB_SIZE = BLOB_END - BLOB_OFF
LAST_WORD = BLOB_SIZE // 4 - 1           # 0xcb，stub 的 loop 初值
K_OFF = 0x7686             # 四对异或常量
TAR_OFF = 0x76A6           # 两个 64 位比较目标

M64 = (1 << 64) - 1
DELTA = 0x9E3779B97F4A7C15

# 解密后 blob 中 0x7686 起的 6 个 QWORD（题解「密钥与目标常量」）
EXPECTED_QWORDS = [
    0xD868187917BB2795,
    0xC7CEA69E35F49213,
    0x939EC78E9D68B6EB,
    0xC562921852331BB3,
    0x4FB335A84FA7D2D7,
    0x02A183E3B4F4F49F,
]


# ---- 链式 XOR 解密（与 extract.py 同算法，保证可独立运行） ---------------
def chained_xor_decrypt(blob):
    """key = 0；i 从 0xcb 递减到 1：P[i] = C[i] ^ key，key += P[i]（32 位）。"""
    if len(blob) % 4 != 0:
        raise ValueError("blob 长度必须是 4 的倍数")
    words = list(struct.unpack("<%dI" % (len(blob) // 4), blob))
    key = 0
    for i in range(LAST_WORD, 0, -1):
        plain = (words[i] ^ key) & 0xFFFFFFFF
        words[i] = plain
        key = (key + plain) & 0xFFFFFFFF
    return struct.pack("<%dI" % len(words), *words)


# ---- 轮函数与密钥扩展 ----------------------------------------------------
def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64


def ror(x, n):
    n %= 64
    return ((x >> n) | (x << (64 - n))) & M64


def expand_key(w0, w1):
    """W[i] = rol64(W[i-1] + W[i-2], 13) ^ ror64(W[i-2], 7) ^ (i * delta)。"""
    w = [w0, w1]
    for i in range(2, 32):
        w.append((rol((w[i - 1] + w[i - 2]) & M64, 13)
                  ^ ror(w[i - 2], 7)
                  ^ ((i * DELTA) & M64)) & M64)
    return w


def g(x, k):
    """G(x,k) = (rol64(x+k,13) ^ rol64(x,29)) + rol64(x,47)。"""
    return ((rol((x + k) & M64, 13) ^ rol(x, 29)) + rol(x, 47)) & M64


def feistel_forward(w0, w1, w):
    r8, r9 = w0 ^ w[0], w1 ^ w[1]
    for i in range(2, 32):
        r8, r9 = r9, (r8 ^ g(r9, w[i])) & M64
    return r8, r9


def feistel_inverse(t0, t1, w):
    """从第 30 轮输出倒推白化前的 (w0, w1)。"""
    r8, r9 = t0, t1
    for i in range(31, 1, -1):
        r8, r9 = (r9 ^ g(r8, w[i])) & M64, r8
    return r8 ^ w[0], r9 ^ w[1]


def load_blob(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < BLOB_END:
        raise SystemExit("[!] %s 只有 0x%x 字节，至少需要 0x%x"
                         % (path, len(data), BLOB_END))
    plain = chained_xor_decrypt(data[BLOB_OFF:BLOB_END])
    # 健全性检查：0x7396 处仍是 90 90 90 90，0x739a 是 endbr64
    if plain[:4] != b"\x90\x90\x90\x90":
        raise SystemExit("[!] 解密后 0x7396 不是 90 90 90 90，算法或偏移有误")
    if plain[4:8] != b"\xf3\x0f\x1e\xfa":
        raise SystemExit("[!] 解密后 0x739a 不是 endbr64，算法或偏移有误")
    return plain


def main():
    ap = argparse.ArgumentParser(
        description="ELFStudy: 解密加载期校验函数并逆推 flag")
    ap.add_argument("--elf", default="./elfstudy",
                    help="附件 elfstudy 路径（默认 ./elfstudy）")
    ap.add_argument("--blob-out", default=None,
                    help="可选：把解密后的 0x330 字节写到该文件，便于 objdump")
    args = ap.parse_args()

    plain = load_blob(args.elf)
    if args.blob_out:
        with open(args.blob_out, "wb") as f:
            f.write(plain)
        print("[+] 解密 blob -> %s" % args.blob_out)

    q = list(struct.unpack_from("<6Q", plain, K_OFF - BLOB_OFF))
    labels = ["0x7686", "0x768e", "0x7696", "0x769e", "0x76a6", "0x76ae"]
    for off, val, exp in zip(labels, q, EXPECTED_QWORDS):
        flag = "" if val == exp else "   <-- 与题解记录不一致"
        print("[+] %s = 0x%016x%s" % (off, val, flag))
    if q != EXPECTED_QWORDS:
        print("[!] 警告：blob 常量与题解记录不同，请确认是否为同一附件",
              file=sys.stderr)

    w0k, w1k = q[0] ^ q[1], q[2] ^ q[3]
    t0, t1 = q[4], q[5]
    print("[+] W[0] = 0x%016x (0x7686 ^ 0x768e)" % w0k)
    print("[+] W[1] = 0x%016x (0x7696 ^ 0x769e)" % w1k)
    print("[+] target = (0x%016x, 0x%016x)" % (t0, t1))

    w = expand_key(w0k, w1k)
    a, b = feistel_inverse(t0, t1, w)

    # 正向回代：任何移位方向 / 轮序 / delta 错误都会让末态变成随机值
    f0, f1 = feistel_forward(a, b, w)
    if (f0, f1) != (t0, t1):
        raise SystemExit("[!] 回代失败：末态 (0x%016x, 0x%016x) != target"
                         % (f0, f1))

    data = a.to_bytes(8, "little") + b.to_bytes(8, "little")
    print("[+] word0 = 0x%016x, word1 = 0x%016x" % (a, b))
    print("[+] 回代校验通过")
    print("flag{%s}" % data.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
