"""解密管理侧流量，重组 WebSocket 里的 RFB 帧，还原一帧 1024x768 RGB888 画面并求 MD5。

用法:
    python solve.py --manager manager.pcap --browser-keys browser.keys \
                    --internal internal.pcap --rdp-keys rdp.keys

流程:
    1. tshark 导出 websocket.payload / t124.userData 为 TSV；
    2. 只保留 frame >= 1939 且来自服务端端口的负载，按顺序拼接成 RFB 服务端字节流；
    3. 解析 ServerInit 得到宽高，再逐条处理 FramebufferUpdate 的矩形；
       Tight 编码支持 Fill(0x8)、JPEG(0x9) 与基本压缩 + Copy filter(0x0)，RLE 面保持原样；
    4. 对整帧原始 RGB888 字节求 MD5。
"""
import argparse
import hashlib
import subprocess

FIRST_FRAME = 1939      # 首个包含像素的完整更新所在的抓包帧号
SERVER_PORT = 5900      # 服务端 -> 客户端方向的源端口
TIGHT_ENCODING = 7
RAW_ENCODING = 0
# 无负载的伪编码（光标、桌面尺寸），遇到直接跳过
PSEUDO_ENCODINGS = {-239, -308, -223, -312, -313, -314, -240, -258}


def export(cap, keys, display, fields, out):
    cmd = ['tshark', '-nr', cap, '-o', 'tls.keylog_file:' + keys,
           '-Y', display, '-T', 'fields']
    for field in fields:
        cmd += ['-e', field]
    with open(out, 'wb') as fp:
        subprocess.run(cmd, stdout=fp, check=True)


def collect(tsv, min_frame=0, server_port=SERVER_PORT):
    stream = bytearray()
    with open(tsv, 'r', encoding='utf-8', errors='ignore') as fp:
        for line in fp:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 4 or not parts[3]:
                continue
            if int(parts[0]) < min_frame or int(parts[2]) != server_port:
                continue
            stream += bytes.fromhex(parts[3].replace(':', ''))
    return stream


def parse_server_init(stream):
    """跳过版本协商与安全类型，读出 ServerInit 的宽高。

    VNC 认证（安全类型 2）会多一个 4 字节 SecurityResult，None 认证则没有，
    这里对两种偏移各试一次，以宽高是否合理作为判定。
    """
    pos = stream.find(b'RFB 00')
    if pos < 0:
        raise SystemExit('[-] RFB version banner not found')
    pos += 12
    ntypes = stream[pos]
    pos += 1 + ntypes

    for offset in (pos + 4, pos):
        width = int.from_bytes(stream[offset:offset + 2], 'big')
        height = int.from_bytes(stream[offset + 2:offset + 4], 'big')
        if 0 < width <= 8192 and 0 < height <= 8192:
            return width, height
    raise SystemExit('[-] cannot locate ServerInit')


def read_compact(buf, pos):
    """Tight 紧凑长度：最多三个字节，每字节低 7 位，最高位表示续读。"""
    b = buf[pos]
    pos += 1
    length = b & 0x7F
    if b & 0x80:
        b = buf[pos]
        pos += 1
        length |= (b & 0x7F) << 7
        if b & 0x80:
            b = buf[pos]
            pos += 1
            length |= b << 14
    return length, pos


class Framebuffer:
    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.buf = bytearray(width * height * 3)

    def put(self, x, y, w, h, raw):
        for yy in range(h):
            base = ((y + yy) * self.width + x) * 3
            self.buf[base:base + w * 3] = raw[yy * w * 3:(yy + 1) * w * 3]

    def put_bgra(self, x, y, w, h, bgra):
        rgb = bytearray(w * h * 3)
        for i in range(w * h):
            b, g, r = bgra[4 * i], bgra[4 * i + 1], bgra[4 * i + 2]
            rgb[3 * i] = r
            rgb[3 * i + 1] = g
            rgb[3 * i + 2] = b
        self.put(x, y, w, h, bytes(rgb))


class TightDecoder:
    """Tight 编码：一个 zlib 流贯穿多个矩形，只在首次使用时初始化。"""

    def __init__(self):
        import zlib
        self._zlib = zlib
        self.stream = None

    def decompress(self, data):
        if self.stream is None:
            self.stream = self._zlib.decompressobj()
        return self.stream.decompress(data)


def decode_tight(stream, pos, dec, width, height, fb, x, y):
    """返回解码该 Tight 矩形后的新位置。"""
    length, pos = read_compact(stream, pos)
    end = pos + length
    control = stream[pos]
    pos += 1
    compression = control >> 4
    filter_id = control & 0x0F
    payload = bytes(stream[pos:end])

    if compression == 0x8:                          # Fill：整块同色
        b, g, r = payload[0], payload[1], payload[2]
        fb.put(x, y, width, height, bytes((r, g, b)) * (width * height))
        return end

    if compression == 0x9:                          # JPEG
        import cv2
        import numpy as np
        img = cv2.imdecode(np.frombuffer(payload, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise SystemExit('[-] jpeg rect decode failed')
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB).tobytes()
        fb.put(x, y, width, height, rgb)
        return end

    raw = dec.decompress(payload)
    if filter_id == 0:                              # Copy filter：32bpp 原始像素
        if len(raw) < width * height * 4:
            raise SystemExit(f'[-] tight rect too short: {len(raw)}')
        fb.put_bgra(x, y, width, height, raw[:width * height * 4])
    else:
        raise SystemExit(f'[-] unsupported tight filter {filter_id} '
                         f'(palette/gradient RLE need extra handling)')
    return end


def decode_updates(stream, fb):
    dec = TightDecoder()
    pos = 0
    rects = 0
    updates = 0
    while pos < len(stream):
        typ = stream[pos]
        if typ == 0:                                # FramebufferUpdate
            if pos + 4 > len(stream):
                break
            nrects = int.from_bytes(stream[pos + 2:pos + 4], 'big')
            pos += 4
            updates += 1
            for _ in range(nrects):
                if pos + 12 > len(stream):
                    return rects, updates
                x = int.from_bytes(stream[pos:pos + 2], 'big')
                y = int.from_bytes(stream[pos + 2:pos + 4], 'big')
                w = int.from_bytes(stream[pos + 4:pos + 6], 'big')
                h = int.from_bytes(stream[pos + 6:pos + 8], 'big')
                enc = int.from_bytes(stream[pos + 8:pos + 12], 'big', signed=True)
                pos += 12
                if enc == RAW_ENCODING:
                    size = w * h * 4
                    fb.put_bgra(x, y, w, h, bytes(stream[pos:pos + size]))
                    pos += size
                elif enc == TIGHT_ENCODING:
                    pos = decode_tight(stream, pos, dec, w, h, fb, x, y)
                elif enc in PSEUDO_ENCODINGS:
                    continue
                else:
                    raise SystemExit(f'[-] unsupported encoding {enc} at offset {pos - 12}')
                rects += 1
        elif typ == 1:                              # SetColourMapEntries
            n = int.from_bytes(stream[pos + 4:pos + 6], 'big')
            pos += 6 + n * 6
        elif typ == 2:                              # Bell
            pos += 1
        elif typ == 3:                              # ServerCutText
            n = int.from_bytes(stream[pos + 4:pos + 8], 'big')
            pos += 8 + n
        else:
            raise SystemExit(f'[-] unexpected message type {typ} at offset {pos}')
    return rects, updates


def main():
    parser = argparse.ArgumentParser(description='谍影重重7 - 控制台画面还原')
    parser.add_argument('--manager', default='manager.pcap')
    parser.add_argument('--browser-keys', default='browser.keys')
    parser.add_argument('--internal', default='internal.pcap')
    parser.add_argument('--rdp-keys', default='rdp.keys')
    parser.add_argument('--ws-tsv', default='websocket.tsv')
    parser.add_argument('--ch-tsv', default='channels.tsv')
    parser.add_argument('--png', default='framebuffer.png')
    parser.add_argument('--skip-rdp', action='store_true',
                        help='不导出 RDPDR 通道（未取得 rdp.keys 时使用）')
    args = parser.parse_args()

    export(args.manager, args.browser_keys,
           'tcp.stream==68 && websocket.payload',
           ['frame.number', 'frame.time_relative', 'tcp.srcport', 'websocket.payload'],
           args.ws_tsv)

    if not args.skip_rdp:
        export(args.internal, args.rdp_keys,
               't124.channelId==1004 && t124.userData',
               ['frame.number', 'ip.src', 't124.channelId', 't124.userData'],
               args.ch_tsv)

    full = collect(args.ws_tsv)
    width, height = parse_server_init(full)
    print(f'[*] server init: {width}x{height}')

    pixels = collect(args.ws_tsv, min_frame=FIRST_FRAME)
    print(f'[*] framebuffer stream bytes = {len(pixels)}')

    fb = Framebuffer(width, height)
    rects, updates = decode_updates(pixels, fb)
    digest = hashlib.md5(bytes(fb.buf)).hexdigest()
    print(f'[*] updates = {updates}, pixel rects = {rects}')
    print(f'[*] raw RGB888 MD5 = {digest}')

    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(bytes(fb.buf), np.uint8).reshape(height, width, 3)
        cv2.imwrite(args.png, cv2.cvtColor(arr, cv2.COLOR_RGB2BGR))
        print(f'[*] png -> {args.png}')
    except ImportError:
        with open('framebuffer.rgb', 'wb') as fp:
            fp.write(bytes(fb.buf))
        print('[*] opencv not installed, dumped framebuffer.rgb')


if __name__ == '__main__':
    main()
