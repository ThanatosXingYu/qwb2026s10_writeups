#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QWB2026 Firmware 求解脚本（对应题解第 3 节）。

输入：qwb2026_firmware.tar.gz 解压出的 ota_package.bin
（fw_b.bin 里派生 keymat 需要 qemu + gdb 动态取值，见题解「从`fw_b.bin`提取keymat」一节，
 结果已作为常量固化，并用 fw_a 内置的 SM3 前缀做自检。）

流程与题解完全一致：
  1. keymat 自检：SM3(keymat)[:16] == 559a63419fb92be76c8fc4a23d8f62b8
  2. 恢复 0x3c 起三个分段描述符指向的 38 字节程序，SM3 必须等于
     OTA[0x1c:0x3c]；描述符布局需按附件枚举确认，因此先按
     (off, len) / (len, off) 两种解释做枚举，只接受“摘要精确命中”的组合，
     失败时退回题解「从OTA恢复vm_out8」抄录的程序常量（同样用头部摘要校验）。
  3. vm_out8 = 程序末尾连续 8 条 `01 XX` 立即数的字节（9f3e7c1a5b2d8460）
  4. P  = SM3("QWB2026::TWIN::DEVICE-A")[:16]
     A  = SM3(keymat || P || vm_out8)
     B  = SM3("twin-ctr" || A[:16])
     要求 SM3(B[:16])[:16] == cc6bc929b72471e6094c50776b65ff91
  5. OTA[0x86:0x8e] == "QWBPFLAG"，0x8e 处 LE u32 为密文长度，0x92 起密文
     用 SM4-CTR 解密：key = SM3(P)[:16]，初始计数块 = B[:16]
     （cryptography 的 CTR 语义：16 字节 nonce 即初始计数块，按大端加一）

SM4 为纯 Python 实现，不依赖 cryptography；`--selftest` 跑标准 KAT。

用法：
    python solve.py                                  # 默认 ./ota_package.bin
    python solve.py --ota ota_package.bin \
        --keymat dd97cb2de25cea1a8a9bc49b81abf9f4
    python solve.py --selftest                       # 只跑 SM4 已知答案测试
"""

import argparse
import hashlib
import struct
import sys

# ---- OTA 包固定布局（题解第 2、3 节） ---------------------------------
OTA_DIGEST_OFF = 0x1C          # 38 字节程序的 SM3 摘要（32 字节）
OTA_DESC_OFF = 0x3C            # 三个分段描述符
OTA_MARK_OFF = 0x86            # b"QWBPFLAG"
OTA_LEN_OFF = 0x8E             # 小端 u32 密文长度
OTA_CT_OFF = 0x92              # 密文起点
OTA_MARK = b"QWBPFLAG"
PROG_SIZE = 38

# 题解「从OTA恢复vm_out8」搬运后得到的 38 字节字节码程序
PROG_HEX = (
    "014101020281008201110281008203015a81418203019f013e"
    "017c011a015b012d0184016004"
)

# 题解「从`fw_b.bin`提取keymat」：fw_b.bin 0x10818 变换后的 32 字节，前 16 字节即 keymat
KEYMAT_HEX = "dd97cb2de25cea1a8a9bc49b81abf9f4"
KEYMAT_SM3_PREFIX = "559a63419fb92be76c8fc4a23d8f62b8"
# 题解「从OTA恢复vm_out8」：程序末尾八个立即数
VM_OUT8_HEX = "9f3e7c1a5b2d8460"

DEVICE_TAG = b"QWB2026::TWIN::DEVICE-A"
CTR_LABEL = b"twin-ctr"
CHAIN_TARGET = "cc6bc929b72471e6094c50776b65ff91"   # fw_a 内置校验值


def sm3(data):
    return hashlib.new("sm3", data).digest()


# =========================================================================
# SM4（GB/T 32907），纯 Python，用于 SM4-CTR
# =========================================================================
SBOX = bytes([
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
])
FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _tau(t):
    return (SBOX[(t >> 24) & 0xFF] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) \
        | (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]


def sm4_key_schedule(key):
    if len(key) != 16:
        raise ValueError("SM4 密钥必须是 16 字节")
    mk = struct.unpack(">4I", key)
    k = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        ck = sum(((4 * i + j) * 7 & 0xFF) << (24 - 8 * j) for j in range(4))
        t = _tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck)
        t ^= _rotl32(t, 13) ^ _rotl32(t, 23)
        k.append(k[i] ^ t)
        rk.append(k[i + 4])
    return rk


def sm4_encrypt_block(block, rk):
    if len(block) != 16:
        raise ValueError("SM4 分组必须是 16 字节")
    x = list(struct.unpack(">4I", block))
    for i in range(32):
        t = _tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])
        t ^= _rotl32(t, 2) ^ _rotl32(t, 10) ^ _rotl32(t, 18) ^ _rotl32(t, 24)
        x.append(x[i] ^ t)
    return struct.pack(">4I", x[35], x[34], x[33], x[32])


def sm4_ctr(key, nonce, data):
    """CTR：nonce 为 16 字节初始计数块，每处理一个分组按大端加一。"""
    if len(nonce) != 16:
        raise ValueError("SM4-CTR 初始计数块必须是 16 字节")
    rk = sm4_key_schedule(key)
    ctr = int.from_bytes(nonce, "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        ks = sm4_encrypt_block(ctr.to_bytes(16, "big"), rk)
        chunk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)


def sm4_selftest():
    """GB/T 32907 标准测试向量。"""
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    want = "681edf34d206965e86b3e94f536e4246"
    got = sm4_encrypt_block(pt, sm4_key_schedule(key)).hex()
    ok = got == want
    print("[%s] SM4 KAT: %s (期望 %s)" % ("+" if ok else "!", got, want))
    return ok


# =========================================================================
# OTA 解析
# =========================================================================
def recover_program_from_descriptors(ota, digest):
    """枚举 0x3c..0x86 内的 (off,len) 描述符表，只接受摘要精确命中的组合。

    描述符的确切字段顺序与步长未知，因此对 step ∈ {8,12,16} 与
    (off,len)/(len,off) 两种解释都试一遍；只有拼出的 38 字节程序 SM3
    与头部摘要完全一致才返回，绝不会接受“看起来合理”的猜测。
    """
    n = len(ota)
    for step in (8, 12, 16):
        for start in range(OTA_DESC_OFF, OTA_MARK_OFF - 3 * step + 1, 4):
            for swap in (False, True):
                segs = []
                ok = True
                for k in range(3):
                    base = start + k * step
                    x = int.from_bytes(ota[base:base + 4], "little")
                    y = int.from_bytes(ota[base + 4:base + 8], "little")
                    off, ln = (y, x) if swap else (x, y)
                    if ln == 0 or ln > 0x1000 or off + ln > n:
                        ok = False
                        break
                    segs.append(ota[off:off + ln])
                if not ok:
                    continue
                cand = b"".join(segs)
                if len(cand) == PROG_SIZE and sm3(cand) == digest:
                    return cand, start, step, swap
    return None


def extract_vm_out8(prog):
    """程序末尾 8 条 `01 XX` 立即数即输出字节，末字节 0x04 收尾。"""
    if len(prog) != PROG_SIZE or prog[-1] != 0x04:
        raise ValueError("程序长度或结尾 0x04 不符合题解记录")
    tail = prog[-17:-1]                       # 8 条 2 字节指令
    imm = []
    for i in range(0, 16, 2):
        if tail[i] != 0x01:
            raise ValueError("末尾第 %d 条不是 `01 XX` 形式" % (i // 2))
        imm.append(tail[i + 1])
    return bytes(imm)


def main():
    ap = argparse.ArgumentParser(
        description="QWB2026 Firmware: OTA key 派生与 SM4-CTR 解密")
    ap.add_argument("--ota", default="./ota_package.bin",
                    help="OTA 包路径（默认 ./ota_package.bin）")
    ap.add_argument("--keymat", default=KEYMAT_HEX,
                    help="16 字节 keymat 的 hex（默认 fw_b.bin 动态取到的值）")
    ap.add_argument("--vm-out8", default=None,
                    help="覆盖脚本从程序字节码里取出的 8 字节输出（hex）")
    ap.add_argument("--selftest", action="store_true",
                    help="只跑 SM4 标准测试向量后退出")
    args = ap.parse_args()

    if args.selftest:
        return 0 if sm4_selftest() else 1

    keymat = bytes.fromhex(args.keymat)
    if len(keymat) != 16:
        raise SystemExit("[!] keymat 必须是 16 字节（32 个 hex 字符）")

    ota = open(args.ota, "rb").read()
    if len(ota) < OTA_CT_OFF:
        raise SystemExit("[!] %s 太短：0x%x 字节" % (args.ota, len(ota)))
    print("[+] OTA: %s (%d 字节)" % (args.ota, len(ota)))

    # --- 1. keymat 自检（fw_a 第一组校验） ------------------------------
    got = sm3(keymat)[:16].hex()
    print("[+] SM3(keymat)[:16] = %s" % got)
    if got != KEYMAT_SM3_PREFIX:
        raise SystemExit("[!] keymat 自检失败，期望 %s" % KEYMAT_SM3_PREFIX)

    # --- 2. 38 字节程序 + 摘要校验（fw_a 第二组校验） -------------------
    digest = ota[OTA_DIGEST_OFF:OTA_DIGEST_OFF + 32]
    print("[+] OTA[0x1c:0x3c]   = %s" % digest.hex())
    rec = recover_program_from_descriptors(ota, digest)
    if rec:
        prog, start, step, swap = rec
        print("[+] 描述符表 @0x%x step=%d %s -> 拼出 %d 字节程序"
              % (start, step, "(len,off)" if swap else "(off,len)", len(prog)))
        if prog.hex() != PROG_HEX:
            print("[!] 拼接结果与题解抄录的字节码不同，以 OTA 内容为准")
    else:
        prog = bytes.fromhex(PROG_HEX)
        print("[+] 描述符枚举未命中，使用题解抄录的程序字节")
        if sm3(prog) != digest:
            raise SystemExit("[!] 程序 SM3 与 OTA 头部摘要不符，包可能有误")
    print("[+] 程序 = %s" % prog.hex())

    # --- 3. vm_out8 ----------------------------------------------------
    vm_out8 = extract_vm_out8(prog)
    if args.vm_out8:
        vm_out8 = bytes.fromhex(args.vm_out8)
    print("[+] vm_out8 = %s" % vm_out8.hex())
    if vm_out8.hex() != VM_OUT8_HEX:
        print("[!] 注意：vm_out8 与题解记录 %s 不同" % VM_OUT8_HEX)

    # --- 4. 派生 P / A / B（fw_a 第三组校验） ---------------------------
    p = sm3(DEVICE_TAG)[:16]
    a = sm3(keymat + p + vm_out8)
    b = sm3(CTR_LABEL + a[:16])
    print("[+] P  = SM3(\"QWB2026::TWIN::DEVICE-A\")[:16] = %s" % p.hex())
    print("[+] A  = SM3(keymat || P || vm_out8) = %s" % a.hex())
    print("[+] B  = SM3(\"twin-ctr\" || A[:16]) = %s" % b.hex())
    check = sm3(b[:16])[:16].hex()
    print("[+] SM3(B[:16])[:16] = %s" % check)
    if check != CHAIN_TARGET:
        raise SystemExit("[!] 派生链自检失败，期望 %s" % CHAIN_TARGET)

    # --- 5. 包尾密文 ---------------------------------------------------
    if ota[OTA_MARK_OFF:OTA_LEN_OFF] != OTA_MARK:
        raise SystemExit("[!] 0x86 处不是 QWBPFLAG 标记")
    length = int.from_bytes(ota[OTA_LEN_OFF:OTA_CT_OFF], "little")
    print("[+] 密文长度 = %d" % length)
    ct = ota[OTA_CT_OFF:OTA_CT_OFF + length]
    if len(ct) != length:
        raise SystemExit("[!] 密文被截断：只有 %d / %d 字节" % (len(ct), length))
    print("[+] 密文 = %s" % ct.hex())

    pt = sm4_ctr(sm3(p)[:16], b[:16], ct)
    print("[+] 明文 = %s" % pt.hex())
    try:
        text = pt.decode("ascii")
    except UnicodeDecodeError:
        raise SystemExit("[!] 明文不是 ASCII，派生参数或密文偏移有误")
    if not (text.startswith("flag{") and text.endswith("}")):
        print("[!] 明文格式不像 flag，请检查 vm_out8 字节序与密文起点")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
