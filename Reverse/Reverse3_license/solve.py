#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse3 "license" 的可复现 exp（校验器 / PoC）

=============================== 做了什么 ===============================
本脚本用题解「原程序验证与最终结果」一节记录的 48 字节 license，
驱动**未经任何修改的原始 ELF** 真实执行，再从程序输出里取出 flag：
  * ELF 会先做 SHA256 自检（3b90a1a0...），并做一次"篡改 license"的
    阴性对照（必须输出 Rejected. 且拿不到 flag），以证明二进制确实在做校验，
    而不是脚本在硬编码打印；
  * 脚本**没有**重新实现题解「用Unicorn提取执行轨迹」「模拟中需要处理的细节」
    两节里的隐藏指令轨迹提取（Unicorn 下的 TF 单步 / SIGTRAP 帧语义模拟）、
    24x24 二进制矩阵 M 的恢复，以及 Feistel 轮函数 + 32 位 t 枚举。
    也就是说：可复现性（binary + license -> flag）由脚本自己跑出来，
    license 本身的数学再推导不在脚本范围内。

============================= 依赖的已知事实 =============================
  * 输入 96 个十六进制字符 = 48 字节 license；
  * 校验由 0x402e5b 之后的自解密代码完成（TF 单步 + SIGTRAP 处理函数 0x406000），
    前半段 = 3 轮 Feistel + 24x24 GF(2) 混合 M，后半段 = 逐字节解密约束；
  * 反调试：/proc/self/status 的 TracerPid、ptrace，以及 CPU 厂商检查，
    所以不能用 gdb 跟（会打印 "debugger detected"）；本脚本不调试、只当黑盒跑。

================================= 用法 =================================
  Linux / WSL（在题目目录里）:
      python3 solve.py
      python3 solve.py --elf /path/to/license
      python3 solve.py --license <96 个 hex 字符>
      python3 solve.py --skip-tamper          # 跳过阴性对照

  ELF 查找顺序（不给 --elf 时）:
      1) 环境变量 R3_LICENSE_ELF
      2) ./license、./附件/license（当前目录）
      3) 脚本所在目录下的 license、附件/license
      4) 解压脚本目录（或当前目录）下 附件/*.zip 里的 license 到临时目录
  可用 --elf 显式指定任意路径；所有路径都可配置。

  原始 ELF 只能在 Linux 下执行：在 Windows 上直接 `python solve.py` 时，
  脚本会自动借助 wsl.exe 用 Linux 的 python3 重跑一遍。
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------- 常量

#: 题解记录、并经原程序验证通过的 48 字节 license（96 hex）
VALID_LICENSE = (
    "5b6c94d31d85e2344e666179a1d203ef02b5fdcb271d3d05"
    "00800cc020e00101600c20e000800ca14040e01a038260e0"
)
#: 原程序对上面 license 的输出
EXPECTED_FLAG = "flag{9530b81c-61d0-2b62-3e96-f9a5e937f893}"
#: 题解记录的附件 SHA256
ELF_SHA256 = "3b90a1a0b27769cf89b9c95e29b15d1cbfe39d169be692929670d72bc749d700"
#: 附件原始大小
ELF_SIZE = 1747992

FLAG_RE = re.compile(rb"flag\{[^}\r\n]{1,200}\}")
SELF = os.path.abspath(__file__)


# ---------------------------------------------------------------- 小工具

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_output(raw):
    """wsl.exe 有时把子进程输出按 UTF-16LE 转发，这里两种都兼容。"""
    if not raw:
        return ""
    if raw.count(b"\x00") > len(raw) // 4:
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


def to_wsl_path(p):
    """C:\\foo\\bar -> /mnt/c/foo/bar（只处理盘符路径）。"""
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if m:
        return "/mnt/" + m.group(1).lower() + "/" + m.group(2).replace("\\", "/")
    return p


def _is_win_path(p):
    return bool(re.match(r"^[A-Za-z]:[\\/]", p) or p.startswith("\\\\"))


# ---------------------------------------------------------------- ELF 定位

def _candidate_paths():
    """返回按优先级排列的候选 ELF 路径。"""
    out = []
    env = os.environ.get("R3_LICENSE_ELF")
    if env:
        out.append(env)

    here = os.path.dirname(SELF)
    for base in (os.getcwd(), here):
        out.append(os.path.join(base, "license"))
        out.append(os.path.join(base, "附件", "license"))

    # 去重且保持顺序
    seen, uniq = set(), []
    for p in out:
        ap = os.path.abspath(os.path.expanduser(p))
        if ap not in seen:
            seen.add(ap)
            uniq.append(ap)
    return uniq


def _zip_candidates():
    here = os.path.dirname(SELF)
    outs = []
    for base in (here, os.getcwd()):
        adir = os.path.join(base, "附件")
        if not os.path.isdir(adir):
            continue
        for name in sorted(os.listdir(adir)):
            if name.lower().endswith(".zip"):
                outs.append(os.path.join(adir, name))
    return outs


def find_elf(explicit, workdir):
    """定位 ELF；必要时从附件 zip 解压到 workdir。找不到就报错。"""
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        if not os.path.isfile(p):
            raise SystemExit("[!] --elf 指定的文件不存在: %s" % p)
        return p, "explicit"

    for p in _candidate_paths():
        if os.path.isfile(p):
            return p, "auto"

    zips = _zip_candidates()
    for z in zips:
        try:
            import zipfile
            with zipfile.ZipFile(z) as zf:
                names = [n for n in zf.namelist() if n.endswith("license")]
                if not names:
                    continue
                dest = os.path.join(workdir, "license")
                with zf.open(names[0]) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return dest, "zip:%s" % os.path.basename(z)
        except Exception as e:  # noqa: BLE001
            print("[!] 解压 %s 失败: %s" % (z, e))

    msg = ["[!] 找不到 ELF，请用 --elf 指定，已尝试:"]
    msg += ["      " + p for p in _candidate_paths()]
    msg += ["      zip: " + z for z in zips] if zips else []
    raise SystemExit("\n".join(msg))


def make_runnable(path, workdir):
    """确保能直接 exec：不可执行时复制到工作目录并 chmod 755（不改原件）。"""
    if os.access(path, os.X_OK) and os.name != "nt":
        return path
    dst = os.path.join(workdir, "license")
    if os.path.abspath(dst) == os.path.abspath(path):
        os.chmod(dst, 0o755)
        return dst
    shutil.copyfile(path, dst)
    os.chmod(dst, 0o755)
    return dst


# ---------------------------------------------------------------- 运行

def run_elf(elf, license_text, timeout):
    """把 license 喂给原始 ELF，返回 (rc, stdout, stderr)。"""
    data = (license_text.strip() + "\n").encode()
    p = subprocess.run([elf], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    return p.returncode, decode_output(p.stdout), decode_output(p.stderr)


def check_license_text(txt):
    t = txt.strip()
    if len(t) != 96 or not re.fullmatch(r"[0-9a-fA-F]{96}", t):
        raise SystemExit("[!] license 必须是 96 个十六进制字符（48 字节），"
                         "当前长度 %d" % len(t))
    return t.lower()


# ---------------------------------------------------------------- 主流程

def windows_delegate(argv):
    """Windows 下用 wsl.exe 把脚本自身以 WSL python3 重跑。"""
    args = []
    for a in argv:
        if os.path.exists(a) or _is_win_path(a):
            args.append(to_wsl_path(os.path.abspath(a)) if not _is_win_path(a)
                        else to_wsl_path(a))
        else:
            args.append(a)
    cmd = ["wsl.exe", "-e", "env", "R3_SOLVE_DELEGATED=1",
           "python3", to_wsl_path(SELF)] + args
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.write(decode_output(p.stdout))
    sys.stderr.write(decode_output(p.stderr))
    return p.returncode


def main():
    ap = argparse.ArgumentParser(
        description="Reverse3 license 校验器：原 ELF + 已知 license -> flag")
    ap.add_argument("--elf", default=None,
                    help="附件 license 的路径（默认自动查找 ./license、"
                         "附件/license，或从 附件/*.zip 解压）")
    ap.add_argument("--license", default=VALID_LICENSE,
                    help="要喂给程序的 96 位 hex license（默认用题解记录的有效值）")
    ap.add_argument("--expect-flag", default=EXPECTED_FLAG,
                    help="期望的 flag（默认 %s）" % EXPECTED_FLAG)
    ap.add_argument("--skip-tamper", action="store_true",
                    help="跳过'篡改 license 应被拒绝'的阴性对照")
    ap.add_argument("--timeout", type=float, default=120.0, help="单次运行超时（秒）")
    ap.add_argument("--keep", action="store_true", help="保留下载/解压用的临时目录")
    args = ap.parse_args()

    lic = check_license_text(args.license)

    workdir = tempfile.mkdtemp(prefix="reverse3_license_")
    try:
        print("[*] 用题解记录的 license 驱动原始 ELF，真实执行取 flag")
        print("[*] 工作目录: %s" % workdir)

        src, how = find_elf(args.elf, workdir)
        print("[*] ELF 来源 (%s): %s" % (how, src))

        size = os.path.getsize(src)
        digest = sha256_file(src)
        print("[*] 大小: %d 字节" % size)
        print("[*] SHA256: %s" % digest)
        if digest != ELF_SHA256:
            print("[!] 警告: 与题解记录的 SHA256 不一致，结果可能不可比")
        elif size != ELF_SIZE:
            print("[!] 警告: 大小与题解记录不一致: %d" % size)
        else:
            print("[+] SHA256 与题解/附件 zip 记录一致")

        if open(src, "rb").read(4) != b"\x7fELF":
            raise SystemExit("[!] 不是 ELF 文件: %s" % src)

        elf = make_runnable(src, workdir)
        print("[*] 执行: %s" % elf)
        print("[*] stdin: %s" % lic)

        rc, out, err = run_elf(elf, lic, args.timeout)
        print("[*] 退出码: %d" % rc)
        print("[*] 原始输出: %r" % (out + err).strip())

        m = FLAG_RE.search(out.encode() + b"\n" + err.encode())
        if not m:
            print("[!] 未在输出中找到 flag{}，运行环境可能有问题（静态 ELF 需要 "
                  "x86-64 Linux）")
            return 2
        flag = m.group(0).decode()
        print("[+] FLAG: %s" % flag)

        ok = True
        if args.expect_flag and flag != args.expect_flag:
            print("[!] 与题解期望 flag 不一致（期望 %s）" % args.expect_flag)
            ok = False

        # 阴性对照：篡改最后一个十六进制字符，必须被拒绝
        if not args.skip_tamper:
            bad = lic[:-1] + ("1" if lic[-1] == "0" else "0")
            rc2, out2, err2 = run_elf(elf, bad, args.timeout)
            text2 = (out2 + err2)
            has_flag = bool(FLAG_RE.search(text2.encode()))
            rejected = "Rejected" in text2
            print("[*] 对照(篡改 license): rc=%d out=%r flag=%s rejected=%s"
                  % (rc2, text2.strip(), has_flag, rejected))
            if has_flag or not rejected:
                print("[!] 阴性对照异常：篡改输入也通过了，二进制行为与题解不符")
                ok = False
            else:
                print("[+] 阴性对照通过：不同 license 被 'Rejected.'，说明是真实校验")

        print("[=] 完成: %s" % ("成功" if ok else "有异常，见上面警告"))
        print("[=] 说明: license 来自题解中的恢复结果（Feistel + M^-1·target + "
              "32 位 t 枚举），本脚本不重做该数学推导")
        return 0 if ok else 1
    finally:
        if args.keep:
            print("[*] 保留临时目录: %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    if os.name == "nt" and not os.environ.get("R3_SOLVE_DELEGATED"):
        sys.exit(windows_delegate(sys.argv[1:]))
    sys.exit(main())
