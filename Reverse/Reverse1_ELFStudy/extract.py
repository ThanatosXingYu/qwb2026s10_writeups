#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELFStudy 静态提取器。

按题解「静态提取校验函数」的链式 XOR 算法，把藏在第 2 个 LOAD 段尾页缝隙里
(文件偏移 0x7396, 长度 0x330) 的加密校验函数就地解密，落到独立文件，
供 solve.py 直接读取常量，或给 objdump 反汇编使用：

    python extract.py --elf elfstudy --out checker.bin
    objdump -D -b binary -m i386:x86-64 checker.bin | less

解密算法（对应加载期 stub 0x7325 的循环体）：

    key = 0
    for i = 0xcb downto 1:          # 32 位字，地址 0x7396 + i*4
        P[i] = C[i] ^ key
        key = (key + P[i]) & 0xffffffff
    P[0] = C[0]                     # 索引 0 未被 stub 改写（恒为 90 90 90 90）

stub 从高地址往低地址处理，加密密钥就是“上一轮已经解出的明文”，
所以必须严格倒序解密；索引 0 保持原样。
"""

import argparse
import struct
import sys

BLOB_OFF = 0x7396          # 加密校验函数起始（第 2 个 LOAD 段尾页缝隙）
BLOB_END = 0x76C6          # 0x7396 + 0x330，其后是 .rela.plt 的副本
BLOB_SIZE = BLOB_END - BLOB_OFF          # 0x330
STUB_OFF = 0x7325          # 运行期拼装解密 stub 的位置（静态全 0）
LAST_WORD = BLOB_SIZE // 4 - 1           # 0xcb
K_OFF = 0x7686             # 四对异或常量（W[0]/W[1] 的来源）
TAR_OFF = 0x76A6           # 两个 64 位比较目标


def chained_xor_decrypt(blob: bytes) -> bytes:
    """题解 PoC 中的链式 XOR 解密，原地语义，返回等长明文。"""
    if len(blob) % 4 != 0:
        raise ValueError("blob 长度必须是 4 的倍数")
    words = list(struct.unpack("<%dI" % (len(blob) // 4), blob))
    key = 0
    for i in range(LAST_WORD, 0, -1):          # 0xcb -> 1
        plain = (words[i] ^ key) & 0xFFFFFFFF
        words[i] = plain
        key = (key + plain) & 0xFFFFFFFF
    # words[0] 不变（stub 的 loop 在 ecx==1 之后退出，索引 0 从未被访问）
    return struct.pack("<%dI" % len(words), *words)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ELFStudy: 解密 0x7396 处 0x330 字节的校验函数")
    ap.add_argument("--elf", required=True, help="附件 elfstudy 路径")
    ap.add_argument("--out", default="checker.bin",
                    help="解密后 blob 的输出路径（默认 checker.bin）")
    args = ap.parse_args()

    with open(args.elf, "rb") as f:
        data = f.read()
    if len(data) < BLOB_END:
        print("[!] 文件太短：0x%x 字节，至少需要 0x%x" % (len(data), BLOB_END),
              file=sys.stderr)
        return 1

    blob = data[BLOB_OFF:BLOB_END]
    plain = chained_xor_decrypt(blob)

    # 健全性检查：索引 0 的四个字节在明文里仍是 90 90 90 90，
    # 其后紧跟 endbr64 (f3 0f 1e fa)，与题解记录的运行期内存一致。
    if plain[:4] != b"\x90\x90\x90\x90":
        print("[!] 前 4 字节不是 90 90 90 90，解密失败", file=sys.stderr)
        return 1
    if plain[4:8] != b"\xf3\x0f\x1e\xfa":
        print("[!] 0x739a 处不是 endbr64，解密失败", file=sys.stderr)
        return 1

    with open(args.out, "wb") as f:
        f.write(plain)

    k = struct.unpack_from("<6Q", plain, K_OFF - BLOB_OFF)
    print("[+] 密文区间 : 0x%04x - 0x%04x (%d 字节)" % (BLOB_OFF, BLOB_END, BLOB_SIZE))
    print("[+] 解密 stub : 0x%04x（静态为 0，运行期被拼装）" % STUB_OFF)
    print("[+] 校验入口 : 0x%04x (endbr64 位于 0x739a)" % (BLOB_OFF + 4))
    print("[+] 输出文件 : %s" % args.out)
    print("[+] 0x%04x / 0x%04x 处的 6 个 QWORD（小端）:" % (K_OFF, K_OFF + 0x20))
    for i, v in enumerate(k):
        print("      0x%04x = 0x%016x" % (K_OFF + 8 * i, v))
    print("[+] W[0] = 0x%016x  (0x7686 ^ 0x768e)" % (k[0] ^ k[1]))
    print("[+] W[1] = 0x%016x  (0x7696 ^ 0x769e)" % (k[2] ^ k[3]))
    print("[+] 比较目标 = (0x%016x, 0x%016x)" % (k[4], k[5]))
    print("[*] 反汇编: objdump -D -b binary -m i386:x86-64 %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
