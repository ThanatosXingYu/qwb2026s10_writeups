#!/bin/sh
# PWN13 CanonicoPWN —— guest 只有 busybox，没有 libc/编译器，必须静态链接。
# 用 musl.cc 交叉工具链或系统 musl-gcc：
#   musl-gcc -O2 -static -pthread -o poc poc.c
# 交叉编译示例：
#   x86_64-linux-musl-gcc -O2 -static -pthread -o poc exp.c
set -e

CC="${CC:-musl-gcc}"
OUT="${OUT:-poc}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "[-] 找不到 $CC，可设置 CC=x86_64-linux-musl-gcc 后再运行" >&2
    exit 1
fi

echo "[*] $CC -O2 -static -pthread -o $OUT exp.c"
"$CC" -O2 -static -pthread -o "$OUT" exp.c

if command -v strip >/dev/null 2>&1; then
    strip "$OUT" || true
fi

ls -l "$OUT"
echo "[+] 通过串口上传（base64+gzip，76 字符短行，每 26 行一个 here-doc）后执行："
echo "    chmod 777 /home/ctf && ./poc"
