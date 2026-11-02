"""从自助机屏幕截图里解出绑定二维码的 otpauth 链接（含 TOTP 密钥）。

用法:
    python extract.py screen.png
"""
import argparse
import sys

import cv2


def main():
    parser = argparse.ArgumentParser(description="QR decoder for kiosk screenshot")
    parser.add_argument("image", help="VNC 画面截图路径")
    args = parser.parse_args()

    img = cv2.imread(args.image)
    if img is None:
        sys.exit(f"[-] cannot read {args.image}")

    text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not text:
        sys.exit("[-] no QR code found")
    print(text)
    # otpauth://totp/0perator:KIOSK-07?secret=ULPYXTUIZVJZQRJVWGM2MISRTLZGJTEF&issuer=0perator


if __name__ == "__main__":
    main()
