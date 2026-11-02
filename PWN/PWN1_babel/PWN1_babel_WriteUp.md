# babel（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | babel.zip（babel可执行文件、Dockerfile） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面只提供附件下载，没有额外文字描述。`babel`是OCaml编译出的自研字节码虚拟机，攻击面集中在虚拟机指令的类型检查与压缩式GC上：空串对象的长度记账错误给出1字节越界写，`setext`指令的类型检查写错给出任意地址读写。

## 2. 题目分析

### 宿主程序结构

`babel`是stripped、PIE、Full RELRO、NX的ELF，关键位置如下：

- `main`（0xd710）：先调用`dc20()`初始化运行时，再用`prctl(PR_SET_NO_NEW_PRIVS)`与`prctl(PR_SET_SECCOMP, FILTER)`装载seccomp过滤器，然后进入主循环。
- 主循环每次`read(0,4)`读4字节长度（合法范围1..0x10000），再`read(0,len)`把字节码读进0x65e40处的64KB缓冲区，最后调用`babel_dispatch()`（0xdb80）执行这段chunk。
- 每个chunk是一段独立程序，但值栈、256个寄存器、虚拟机堆等全局状态跨chunk保留，因此可以把利用拆成多次投递：先泄漏，再改内存，最后劫持控制流。
- seccomp白名单为`read write close openat exit exit_group brk rt_sigprocmask`，没有`execve`，说明预期解法是用ROP打开并读出`/flag`，而不是直接反弹shell。

### 指令分发

- 256字节分发表`map[byte] -> opcode`位于0x75f60，由0x46900处的初始化代码填充；输入字节`>= 0x40`时直接报`babel: bad opcode`。
- 64项handler表位于0x76060，由0x58840经置换`perm[i] = byte(0x46b50+i) ^ 0x5a`乱序装入。
- 合法输入字节只有29个：`0x00..0x19`、`0x20`、`0xfe`、`0xff`。

### 值编码与对象布局

虚拟机里的值是一个64位字：低位是tag，高位是堆内偏移，即`(堆偏移 << 4) | tag`。

| tag | 含义 |
| --- | --- |
| 1 | string |
| 3 | array |
| 5 | tuple |
| 7 | ref |
| 9 | buffer |
| 偶数 | 整数（OCaml风格，实际数值为`n>>1`） |

堆是1MB的mmap，基址指针存放在0x76260；对象头布局为：

```text
off+0x00  header：type（1=array，2=tuple，6=不被GC扫描）
off+0x08  size
off+0x10  count/len
off+0x14  len|0x80000000（array/tuple固定为0xffffffff）
off+0x18  data off / 首元素
```

tag-9 buffer的数据不放在上述1MB堆内，而是放在另一块4MB的data区，区指针存放在0x76270。

### 指令语义

逐条逆出的指令表（“输入字节”是chunk里实际写的字节）：

| 输入字节 | op | 语义 |
| --- | --- | --- |
| 01 | 0x0b | push imm64（压入`imm<<1`） |
| 02 | 0x31 | push字符串字面量 |
| 08 / 09 | 0x03 / 0x1d | 造array(tag3) / tuple(tag5)，`+0x14`写0xffffffff |
| 0a / 0b | 0x28 / 0x0f | get/set元素（0xe1b0处校验tag∈{2,3,4,5}） |
| 0c / 0d | 0x35 / 0x08 | 字符串按字节get/set（边界为`idx<len`且`dataOff+idx<cursor`） |
| 0e | 0x1a | 取长度 |
| 10 / 11 | 0x11 / 0x3a | 读/写256个寄存器 |
| 12 / 13 | 0x05 / 0x22 | 打印（十进制/字符串）/原始8字节输出 |
| 14 | 0x2f | 造ref(tag7)，`+0x18`写**绝对地址**`base+0x59098+8*kind` |
| 15 | 0x0c | 用tag7对象间接调用宿主函数 |
| 16 | 0x17 | alloc(size)→tag9 buffer，并置`ext[slot]={4MB区指针,len}` |
| 17 / 18 | 0x33 / 0x09 | 通过`ext[slot]`读写字节（slot<8） |
| 19 | 0x1e | 设置`ext[slot]={value>>1, 0x100000}`，要求tag==9且`+0x14==-1`、`+0x18<0x10` |
| 20 | 0x29 | 调用宿主函数（立即数为pad、fn、argc） |
| fe / ff | 0x04 / 0x38 | 结束chunk |
| 05/06/07/0f | 0x2e/0x12/0x39/0x2b | add / neg(sub) / mul /字符串拼接 |

宿主函数只有3个（`base+0x11de0`、`base+0x11ec0`、`base+0x11fa0`），都会回调OCaml的`babel_dispatch`，实测分别相当于hash、repeat与空串构造，并且**会在虚拟机堆里分配对象**，这一点在布置堆布局时必须考虑。

### 压缩式GC

GC入口在0xe710。触发条件是`cursor+size+0x10 > limit`，其中`limit = cursor+0x8000`，即剩余空间不足0x8000字节时触发。根集合有三处：

- 值栈：元素基址0x97290，元素个数在0x97288；
- 寄存器区：0x9f290；
- 临时区：0x96280。

标记阶段只遍历header type为1（array）和2（tuple）的对象，然后按标记结果把存活对象整体左移压缩，并重写根值。这里有两个可利用的性质：

1. type为6的对象不会被扫描，它指向的子对象即使还有引用也会被判成垃圾；
2. 被压缩掉的对象不会清理“还留在不扫描区域里的偏移”，于是留下陈旧偏移，压缩后的活对象可能正好落到这个陈旧偏移上。

## 3. 解题过程

### 漏洞一：空串的1字节越界写

push字符串字面量（op 0x31）在长度为0时的记账是错的：

- size只按最小对象算成0x10；
- 长度字段却被写成`1|0x80000000`，也就是“长度为1、不可变”；
- `dataOff`被设为`off+0x20`。

空串对象本身只占0x10字节，因此`off+0x20`正好落在**紧邻的下一个对象的第一个字节**上，而那个字节是下一个对象的header type。

字符串按字节写（op 0x08，即脚本里的`sset`）的边界检查是`idx < len`且`dataOff+idx < cursor`。因为长度被记成1，写`sset(0)`就合法，写入的1字节直接落在后一个对象的header type上。于是攻击者可以把一个array的type从1改成6，让GC跳过它的元素。

### 漏洞二：setext的类型检查写错

op 0x1e本来的语义是“把某个array的数据区登记进ext表”，正确的判据应该是`+0x14 == 0xffffffff`（array/tuple的特征值），实际代码却写成了`tag == 9`，同时还要求`+0x14 == -1`与`+0x18 < 0x10`。

合法tag-9对象由op 0x17的alloc产生，它的`+0x14`记录的是size，与`-1`互斥，所以正常路径下op 0x1e永远走不通。唯一入口是类型混淆：让一个tag-9的值指向一个array对象（array的`+0x14`是0xffffffff，按有符号解释就是-1；数组首元素偏移`+0x18`通常小于0x10）。

一旦走通，`ext[slot]`被写成`{value>>1, 0x100000}`：第一项是array对象的绝对地址，第二项是长度上限1MB。之后op 0x33（`extget`）与op 0x09（`extset`）就以这个地址为基址按字节读写，并且可以反复重设，等价于任意地址读写。

### 第一步：泄漏PIE基址

目标是把一个tag-7的ref对象放进GC不扫描的array元素里，压缩后该元素留下陈旧偏移，而压缩恰好让ref落到这个偏移上，再从ref的`+0x18`读出`base+0x59098+8*kind`。

chunk 1的布局与动作（偏移相对堆起点）：

| 偏移 | 对象 | 说明 |
| --- | --- | --- |
| 0x00 | `U`=array(1个元素) | 先放进寄存器0，随后丢弃引用，作为GC的垃圾 |
| 0x20 | `R`=ref(kind=1) | `+0x18`写绝对地址`base+0x590a0`，是泄漏源 |
| 0x40 | `E`=空串 | 利用3.1改写后一个对象的type |
| 0x60 | `V`=array(1个元素) | 元素0指向`U`，即“vault” |

指令序列的意图：

1. `pushraw(0); arr(1); popr(0)`造出`U`放在0x00；
2. `mkref(1); popr(1)`造出`R`放在0x20；
3. `pushstr(b''); popr(2)`造出空串`E`放在0x40，它的`dataOff=0x60`；
4. `pushr(0); arr(1); popr(3)`用`U`作元素造`V`放在0x60，于是`V`的header正好在0x60，正是`E`的dataOff；
5. `pushraw(0); popr(0)`把寄存器0改成整数0，`U`失去根；
6. `pushr(2); pushraw(6); sset(0)`用空串写`V`的header type，改成6；
7. `pushstr(b'Z'*0x7f80)`压入约32KB字符串，触发GC。

GC过程：`R`与`V`在寄存器里是根，`V`的type是6不被扫描，`U`没有根因此被压缩掉；`R`从0x20左移到0x00。压缩后`V`依然在原来的相对位置被重写，但它元素里存的值还是压缩前的`U`的偏移——正好等于`R`的新偏移0。于是第二个chunk执行`pushr(3); getf(0); getf(0); raw`：先取`V[0]`得到陈旧值（`(0<<4)|3 = 3`，一个指向`R`的array值），再对它取元素0，读到`R`的`+0x18`，即`base+0x59098+8*1 = base+0x590a0`。

脚本用`leak - 0x590a0`得到PIE基址，并用`base & 0xfff == 0`校验页对齐。

### 第二步：制造tag-9但指向array的值

思路与第一步相同，只是把要留成陈旧值的对象换成tag-9的buffer：

| 偏移 | 对象 | 说明 |
| --- | --- | --- |
| 0xC0 | `B`=alloc(0x100) | 真正的tag-9对象，最终会死掉，其偏移被元素记住 |
| 0xC0+0x20 | `T`=array(1个元素) | 元素0是小于0x10的整数，满足setext对`+0x18`的要求；压缩后落到0xC0 |
| 0xC0+0x40 | `E2`=空串 | `dataOff=0xC0+0x60`，用于改`V2`的type |
| 0xC0+0x60 | `V2`=array(1个元素) | 元素0是`B` |

具体步骤：

1. 先发一个只含`drop`的chunk，把上一步那个32KB字符串从值栈上丢掉；
2. 新chunk先`pushstr(b'S'*0x100)`：它保持存活，同时因为剩余空间不足触发GC，把上一步的32KB字符串压缩掉，堆游标回到0xC0附近；
3. `alloc(0x100); popr(4)`在0xC0造`B`；
4. `pushraw(0); arr(1); popr(5)`在0xC0+0x20造`T`；
5. `pushstr(b''); popr(6)`在0xC0+0x40造`E2`，其dataOff正好是0xC0+0x60；
6. `pushr(4); arr(1); popr(7)`在0xC0+0x60造`V2`，元素0为`B`；
7. `pushraw(0); popr(4)`丢弃`B`的引用；
8. `pushr(6); pushraw(6); sset(0)`把`V2`的type改成6；
9. `pushraw(0); popr(6)`丢弃空串的引用；
10. 再发一个`pushstr(b'Y'*0x8100)`的chunk触发GC。

这次`V2`不被扫描，`B`没有根被压缩掉，`T`存活并左移，恰好落在`B`原来的偏移0xC0上。`V2`元素里保存的仍是`B`的旧偏移，于是`getf(V2,0)`读到`(0xC0<<4)|9`：tag是9，但按偏移解引用得到的是`T`这个array对象。脚本额外检查`stale & 0xf == 9`，确认类型混淆成立。

### 第三步：任意地址读写

把这个混淆值留在寄存器7里，每次要改读写目标时执行：

```text
pushr 7 ; getf 0        # 取出混淆值（tag9，指向T）
pushraw <addr>          # 目标绝对地址
setext                  # ext[0] = {addr, 0x100000}
```

之后`extget(i)`读`addr+i`的1字节，`extset(i)`写1字节。脚本把读写成批量操作：读时一次chunk里连续发200个`extget`并把结果`raw`输出（每个字节被扩展成`n<<1`的整数，取回后再`>>1`），写时一次chunk里最多发240个`extset`。

### 第四步：泄漏libc

`babel`是Full RELRO但GOT仍可读。`read`的GOT表项在`base+0x58d30`，直接读出8字节，减去libc 2.39-0ubuntu8.9里`read`的偏移0x11bd20即得libc基址。脚本做两处校验：低12位必须为0（页对齐），并且从libc基址读4字节必须是`\x7fELF`。

### 第五步：ROP读flag

seccomp不允许`execve`，所以直接在ROP里完成“关掉stdin→打开flag→读→输出”：

```text
close(0)
open("/flag", O_RDONLY)   # fd 0 被释放，open返回0
gets(buf)                 # 从fd 0读一行到bss
puts(buf)
exit(0)
```

用`gets`而不是`read`，是因为`read`需要`rdx`作长度，而libc的`open`内部会破坏`rdx`；`gets`只依赖`rdi`。字符串、缓冲区与ROP链都写在`.bss`（`base+0x100000`起，PIE映射内可写）。

控制流劫持分三步：

1. 读取值栈元素个数`count`（`base+0x97288`），得到值栈栈顶地址`U = base+0x97290 + 8*count`；
2. 在`U`处伪造一个ucontext：`+0x88`写0x200（`uc_stack.ss_size`一类无关字段），`+0xa0`写ROP链地址（即`uc_mcontext.rsp`），`+0xa8`写`libc+L_RET`（`uc_mcontext.rip`）；
3. 把ext表里的宿主函数指针`base+0x75ec0`（fn 0）改成`libc+0x4a960+0x3d`，即`setcontext+0x3d`的`mov rsp,[rdx+0xa0]`。这里`rdx`在调用宿主函数时正好等于`&value_stack[count]`，也就是刚伪造的ucontext地址，于是栈被切到ROP链上。

最后发一个`op 0x29`、`fn=0`、`argc=0`的chunk触发，ROP依次执行`close(0)`、`open("/flag")`、`gets`、`puts`、`exit`，flag内容从stdout返回。

### 偏移与常量汇总

| 名称 | 值 | 用途 |
| --- | --- | --- |
| `ref[0x18]` | `base+0x590a0` | PIE泄漏源（`0x59098+8*1`） |
| `read@GOT` | `base+0x58d30` | libc泄漏 |
| 值栈count | `base+0x97288` | 定位栈顶 |
| 值栈基址 | `base+0x97290` | 伪造ucontext |
| ext函数指针 | `base+0x75ec0` | 劫持为`setcontext+0x3d` |
| `read` | 0x11bd20 | libc基址 |
| `setcontext` | 0x4a960 | pivot起点 |
| `pop rdi; ret` | 0x10c08d | 传参 |
| `pop rsi; ret` | 0x110b7d | 传参 |
| `ret` | 0x10c08e | 栈对齐 |
| `open` | 0x11b3f0 | 打开flag |
| `close` | 0x1169b0 | 释放fd 0 |
| `gets` | 0x87160 | 读flag |
| `puts` | 0x87cc0 | 输出 |
| `exit` | 0x47ba0 | 退出 |

libc偏移全部取自`Dockerfile`指定的`libc6=2.39-0ubuntu8.9`。

## 4. PoC

```python
#!/usr/bin/env python3
"""babel exploit

Bug 1: empty string literal is recorded with len 1 while its size is 0x10 and its
data offset is off+0x20, so one byte can be written into the header type of the
next heap object (used to hide an array from the compacting GC).
Bug 2: op 0x1e (setext) checks tag == 9 instead of the array signature
(+0x14 == 0xffffffff), so a stale tag-9 value pointing at an array turns the ext
slot table into an arbitrary byte read/write primitive -> GOT leak -> ROP.
"""
import sys, struct, socket, time
from babel import Asm, frame, extcall

BIG1 = 0x7f80
BIG2 = 0x8100

# ---- libc 2.39-0ubuntu8.9 offsets ----
L_SETCONTEXT = 0x4a960
L_PIVOT      = L_SETCONTEXT + 0x3d      # mov rsp,[rdx+0xa0] ; ...
L_POP_RDI    = 0x10c08d
L_POP_RSI    = 0x110b7d
L_RET        = 0x10c08e
L_OPEN       = 0x11b3f0
L_CLOSE      = 0x1169b0
L_GETS       = 0x87160
L_PUTS       = 0x87cc0
L_EXIT       = 0x47ba0
L_READ       = 0x11bd20

LOCAL_CMD = ['/tmp/babel/lib/ld-linux-x86-64.so.2', '--library-path', '/tmp/babel/lib',
             '/tmp/babel/babel']

class Exploit:
    def __init__(self, host=None, port=None, local=False, verbose=False):
        self.verbose = verbose
        self.sock = None
        self.proc = None
        if host:
            self.sock = socket.create_connection((host, port), timeout=15)
            self.sock.settimeout(15)
        elif local:
            import subprocess
            self.proc = subprocess.Popen(LOCAL_CMD, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         bufsize=0)
```
