#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""license 常量还原脚本（对应题解「还原浮点编码的常量」一节）。

初始化代码没有直接复制 S-box 和目标值，而是反复调用 0x402747：
读单精度浮点 -> asin -> 乘 256 -> round -> 取低 8 位。浮点数组虚拟地址
0x50d8a0，对应文件偏移 0x10d8a0，第 i 个 float 位于 0x10d8a0 + 4*i：

    sbox   = decode(0x12a, 256)    # 256 字节置换，逆表 inv_sbox 用于下半段
    target = decode(0x22a, 24)     # 24 字节比较目标（GF(2) 混合后的 M·Y）

本脚本只负责这一步（这一步是纯静态、可脚本化的）；后续的单步解密轨迹
提取与 24×24 矩阵求逆依赖原 ELF 的隐藏指令，见同目录 README.md。

用法：
    python extract_consts.py                     # 默认 ./license
    python extract_consts.py --elf license --json consts.json
"""

import argparse
import json
import math
import struct
import sys

FLOAT_BASE_VA = 0x50D8A0       # 浮点常量表虚拟地址
FLOAT_BASE_OFF = 0x10D8A0      # 对应的文件偏移
SBOX_IDX = 0x12A               # S-box 在表中的下标（个数 256）
SBOX_LEN = 256
TARGET_IDX = 0x22A             # 24 字节目标值在表中的下标
TARGET_LEN = 24

# 题解记录的目标值，用于自检
EXPECTED_TARGET = "082f54e63c2997605d0679ba143a49d07dcdba76266c79d0"


def decode_float_byte(raw, index):
    """0x402747 的等价实现：round(asin(f) * 256) & 0xff。"""
    x = struct.unpack_from("<f", raw, FLOAT_BASE_OFF + 4 * index)[0]
    return int(round(math.asin(x) * 256)) & 0xFF


def decode(raw, start, count):
    return bytes(decode_float_byte(raw, start + i) for i in range(count))


def main():
    ap = argparse.ArgumentParser(
        description="license: 从 0x50d8a0 浮点表还原 S-box 与 24 字节目标")
    ap.add_argument("--elf", default="./license",
                    help="附件 license 路径（默认 ./license）")
    ap.add_argument("--json", default=None,
                    help="可选：把 sbox / inv_sbox / target 写成 JSON，便于 C 程序使用")
    args = ap.parse_args()

    raw = open(args.elf, "rb").read()
    need = FLOAT_BASE_OFF + 4 * (max(SBOX_IDX + SBOX_LEN, TARGET_IDX + TARGET_LEN))
    if len(raw) < need:
        raise SystemExit("[!] %s 只有 0x%x 字节，至少需要 0x%x"
                         % (args.elf, len(raw), need))

    sbox = decode(raw, SBOX_IDX, SBOX_LEN)
    target = decode(raw, TARGET_IDX, TARGET_LEN)

    if sorted(sbox) != list(range(256)):
        raise SystemExit("[!] 解出的 S-box 不是 256 字节置换，偏移或公式有误")
    if target.hex() != EXPECTED_TARGET:
        print("[!] 目标值与题解记录不同：", file=sys.stderr)
        print("    得到 %s" % target.hex(), file=sys.stderr)
        print("    期望 %s" % EXPECTED_TARGET, file=sys.stderr)
        return 1

    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i

    print("[+] 浮点表      : VA 0x%x / off 0x%x" % (FLOAT_BASE_VA, FLOAT_BASE_OFF))
    print("[+] sbox        : 0x%x, %d 字节，置换校验通过" % (SBOX_IDX, SBOX_LEN))
    print("[+] target      : 0x%x, %d 字节" % (TARGET_IDX, TARGET_LEN))
    print("    %s" % target.hex())
    print("[+] sbox[0x00..0x0f] = %s" % sbox[:16].hex())
    print("[+] inv_sbox[0x00..0x0f] = %s" % bytes(inv_sbox[:16]).hex())
    print("[*] 目标值对应 M·Y（M 为 24×24 二进制矩阵），"
          "题解「从输入相关的解密约束恢复后半段」反解得 Y =")
    print("    8721a19db336fdb91f3f6f5b9a2adcdc0b53034b6a8a0324")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"sbox": list(sbox), "inv_sbox": inv_sbox,
                       "target": target.hex()}, f, indent=2)
        print("[+] 写出 %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
