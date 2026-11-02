# HESEUS（拼凑完美，掩盖瑕疵）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 容器题 |
| 附件 | 无 |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题目提示只有一句“拼凑完美，掩盖瑕疵”，无附件。服务会画出忒修斯之船，并问：找回的还是原来那艘船吗？返回的文件名`forgery`进一步提示：拼出的二进制是一份**伪造版**，真正要利用的缺陷在远端正在运行的版本中。

## 2. 题目分析

服务把每次提交的画布当作战船的图纸：画布固定64行，每行是一个块元素，正常行必须通过元素校验。校验按C字符串语义取到NUL为止，行首写NUL即被当作空元素放行；但加权和按整行原始长度逐字节累加，NUL及其后的字节照样计入：

```text
D = Σ sign8(canvas[i]) × (i + 1)
读取地址 = struct_ptr + D
```

行内字节可取-128～127，行尾换行权重为10，两种符号加微调即可精确凑出任意偏移。程序随后从`/proc/self/mem`的该地址读**1字节**，这个字节连同画布内容、请求序号一起进入ChaCha20-Poly1305派生：两段12字节nonce由画布逐字节异或而来，ChaCha20分组生成二级密钥与nonce，Poly1305标签前12字节与密文异或后，前8字节对`文件长度-切片长度+1`取模得`OFFSET`，后4字节低6位加1得`LEN`。

派生是确定函数，未知量只有那1字节。离线复现同一PRF，对0～255逐个预测`(OFFSET, LEN)`与远端返回比对，就能反推内存字节；偶有碰撞时换一条画布、换请求序号再问一次消歧。于是既得到“每请求1字节”的任意读原语，又把每次奖励的`HEX`当作`forgery`的切片：9020次请求拼出26784字节中的26772字节，缺失仅在文件头与末尾节表，代码段完整。

### 机制细节

画布的设计把“校验”与“寻址”拆成两个互不相通的口径。元素校验只信任C字符串，遇到第一个NUL即停止，因此行首或中途插入NUL都能让非法字节藏在字符串之外；加权和却按`read`到的原始长度逐字节累加，NUL、其后垃圾与结尾换行全部参与。两条口径的错位，使提交者既能通过校验，又能自由选择任意偏移。

偏移由正负权重精确拼接：第`i`行系数为`i+1`，行内每字节按最高位解释为-128～127。想加小步长，就挑一行放绝对值恰好的字节；想跨越大段距离，先在低权重行堆正数逼近目标，再用一行负数回退。实际脚本用“贪心加末位微调”，把目标偏移分解成64项之和，使误差归零。`struct_ptr`本身可从内存读回，所以读取地址不依赖猜测，是确定的一字节任意读。

切片是本题的巧思：派生把未知量压缩成那1字节，取值只有256种，离线跑同一PRF穷举即可。远端返回的`OFFSET`/`LEN`是`forgery`的一次切片，等于把秘密分摊到9020次问答里；碰撞时换画布、换序号重问，必然消歧。拼装后缺失的只有ELF头与末尾节表，不妨碍按偏移定位代码。

伪造版与运行版的差异决定利用形态：伪造版扩容时把输入写进新块，是“正确”的；运行版在`free(old)`后仍用旧指针写入，构成use-after-free，且复制长度取整行原始长度、上限1023，远大于旧块。同一份源码在两次构建里出现语义漂移——画布展示的船已换了木板，漏洞只留在真正下水的那艘上。

## 3. 解题过程

### 先取得代码与结构体地址

画布结构体本身也在可读区间。`struct+0`存代码指针（运行版`+0x1740`），减之得PIE；`struct+0x20`存画布缓冲指针，恰好指向`struct+0x30`，故`struct = 该值 - 0x30`。再读`_dl_argv`（PIE`+0x5fd8`）拿到ld.so数据指针，其`+0x90`指向初始栈辅助向量表，输入函数保存的返回地址固定在`auxv-0x268`。读回该槽低2字节与`PIE+0x15f8`相符，证明整条地址链推断正确，这是后面盲写栈的前提。

### 伪造版与运行版的差异

`forgery`的输出函数在PIE`+0x1750`，运行版在`+0x1740`，两者不是同一次构建。逐段读回运行版输入分支，扩容路径的差别是：

```c
// forgery 的效果
new = malloc(new_capacity);
memcpy(new, old, old_length);
free(old);
memcpy(new, input, input_length);

// 远端运行版的效果
new = malloc(new_capacity);
memcpy(new, old, old_length);
free(old);
memcpy(old, input, input_length);   // 继续写已释放的旧块
```

运行版在`+0x1ac5`释放旧块，`+0x1ace`又重新取回旧指针，`+0x1b54`起把输入写进旧块。触发条件同时被放宽：`!`标记的逻辑长度受48字节限制，但只要标记中含NUL，复制仍按整行原始长度进行，上限1023。所以一条241字节的`!`行既能越过容量阈值引发扩容与`free`，又能把240字节数据写进已释放的`0x100`大小类块。

### tcache定向写栈

旧缓冲区按`0xf0`申请，释放后落进`0x100`类。glibc自2.32起对tcache的`next`做异或保护，故写入值须为`target ^ (old >> 12)`。先发一条约200字节的普通行，让同类多出一个空闲块，使tcache计数足够；再发触发行，`free(old)`之后紧接的复制改写旧块的`next`。随后两条240字节`!`行：第一条把旧块取回，第二条分配即返回编码出的栈地址，负载落在保存返回地址之前。

目标槽位取`saved_ret`往前8/24/40/56且16字节对齐处。`!`行过滤器拒绝小写字母、`%`和换行，编码后的8字节必须全落在允许字符集内，所以脚本对不满足的ASLR样本重连。

### 栈上ROP与ORW

负载以NUL加填充开头，接ROP链：用ICU库里的`pop rdi; pop rbp; ret`、`pop rsi; pop rbp; ret`、`pop rdx; ret`设好`mprotect(栈页, 0x2000, 7)`的参数，再跳`mprotect@plt`（PIE`+0x1340`）把栈页改成可执行，最后转入紧随其后的shellcode。ICU基址由ld数据指针减`0x24aa58`得到，并逐个校验gadget首字节。seccomp禁止`execve`，所以代码直接`open`、`read`、`write`：先试`/flag`，失败再试当前目录的`flag`，读入`rsp-0x300`后写到fd 1。

### 复现方式

连接当前下发的地址与端口，按上述顺序完成泄露、触发与写栈。地址随实例变化，运行时替换。

### 关键机制再说明

tcache的`next`编码是写栈的第一道门槛。glibc 2.32起空闲块里存的是`next_ptr ^ (chunk_addr >> 12)`，其中`chunk_addr`为当前空闲块地址而非用户指针。因此想塞进链表的伪造目标必须写成`target ^ (old >> 12)`，`old`所在页基址由已泄露的堆地址右移12位得到，无需完整已知。改写点落在`free`之后、复制之前的那次写入：旧块已入链，覆盖内容即等于改链，且不破坏该块自身的`key`校验。

栈迁移之所以成立，是因为第二次`malloc`直接从tcache弹出被污染的`next`，返回值变成栈地址，随后的复制把240字节负载写在栈上。落点选在`auxv-0x268`保存返回地址之前8/24/40/56字节且16字节对齐处，是为了函数返回时`ret`恰好取到链首，同时避开对齐检查。`!`行过滤器拒绝小写字母、`%`与换行，等于限制了编码后8字节的取值范围，所以脚本对不满足约束的ASLR样本直接重连，用多次抽签换一个合法地址。

ORW链的约束来自seccomp：`execve`被禁，只能靠系统调用读文件。链先用ICU中的`pop rdi; pop rbp; ret`、`pop rsi; pop rbp; ret`、`pop rdx; ret`摆好`mprotect(栈页, 0x2000, 7)`参数，再跳`mprotect@plt`。选ICU而非libc，是因为PIE内缺少足够的`pop` gadget，而ICU基址可由ld数据指针减固定偏移稳定导出，并逐个校验gadget首字节以防止版本漂移。栈页可执行后跳入紧随其后的shellcode，`open("/flag")`失败则回退`open("flag")`，`read`进`rsp-0x300`，再`write`到fd 1。整条链不依赖libc具体小版本偏移，因此对远端容器的细微差异有容忍度。

## 4. PoC

```python
import re
import socket
import sys
import time

from weighted_canvas import make_row_for_delta
from fast_prf import all_outcomes
from rop_payload import choose_target, build

HOST = sys.argv[1]
PORT = int(sys.argv[2])
PATTERN = re.compile(rb'\[REWARD\] \+0x([0-9a-f]+) len=(\d+): ([0-9a-f]+)')

def prompt(sock):
    data = bytearray()
    while b'[INPUT]:\n' not in data:
        part = sock.recv(65536)
        if not part: raise EOFError('process closed before next input prompt')
        data += part
    return bytes(data)

def u64_6(data):
    return int.from_bytes(data + b'\0\0', 'little')

for attempt in range(8):
    print('ATTEMPT', attempt, flush=True)
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(30)
    prompt(sock)
    counter = 0
    struct = None

    def read_delta(delta):
        global counter
        row = make_row_for_delta(delta)
        canvas = row + b'\n'*65
        candidates = None
        observations = []
        for retry in range(4):
            counter += 1
            sock.sendall(canvas)
            response = prompt(sock)
            match = PATTERN.search(response)
            if not match: raise RuntimeError(f'no reward: {response[-120:]!r}')
            outcome = (int(match[1], 16), int(match[2]))
```
