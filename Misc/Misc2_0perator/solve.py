"""由屏幕二维码泄漏的 TOTP 密钥生成当前动态码。

用法:
    python solve.py [--secret ULPYXTUIZVJZQRJVWGM2MISRTLZGJTEF] [--digits 6] [--period 30]
"""
import argparse
import base64
import hashlib
import hmac
import struct
import time

SECRET = "ULPYXTUIZVJZQRJVWGM2MISRTLZGJTEF"


def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    key = base64.b32decode(secret, casefold=True)
    counter = struct.pack(">Q", int(time.time()) // period)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def main():
    parser = argparse.ArgumentParser(description="0perator TOTP generator")
    parser.add_argument("--secret", default=SECRET, help="Base32 TOTP 密钥")
    parser.add_argument("--digits", type=int, default=6, help="动态码位数")
    parser.add_argument("--period", type=int, default=30, help="时间步长（秒）")
    parser.add_argument("--count", type=int, default=1, help="输出当前及之后若干个动态码")
    args = parser.parse_args()

    for i in range(args.count):
        if i:
            time.sleep(args.period)
        print(totp(args.secret, args.digits, args.period))


if __name__ == "__main__":
    main()
