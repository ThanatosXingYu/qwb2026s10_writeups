# license

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Reverse |
| 形态 | 附件题 |
| 附件 | license（Linux x86-64 ELF，静态链接，1,747,992字节） |
| 目标 | 无（离线附件） |

Flag：flag{9530b81c-61d0-2b62-3e96-f9a5e937f893}

题目描述：
> give me your license，and you will get everything (ps:intel x86-64)

## 2. 题目分析

附件是一个Linux x86-64 ELF。程序要求输入96个十六进制字符，将其解析为48字节license。主要难点是通过单步异常逐条解密隐藏指令，并把环境检测结果、系统调用结果和输入数据混入后续指令的解密状态。最终恢复出有效license，直接输入未修改的原程序即可得到flag。

### 附件信息与程序入口

附件基本信息：

| 项目 | 值 |
| --- | --- |
| 文件名 | `license` |
| 大小 | 1,747,992字节 |
| 格式 | ELF64 x86-64，静态链接 |
| ELF入口 | `0x402610` |
| main | `0x402f9a` |
| SHA256 | `3b90a1a0b27769cf89b9c95e29b15d1cbfe39d169be692929670d72bc749d700` |

使用objdump检查节区、符号和入口代码：

```bash
objdump -h license
objdump -t license
objdump -d -M intel --start-address=0x402f9a --stop-address=0x40302e license
objdump -d -M intel -j .dty license
```

程序保留了部分很显眼的符号，例如`chow_wb_encrypt`、`tbox_round_lookup`、`wb_verify_fold`、`wb_tt`和`wb_aesbox`。入口大致按以下顺序执行：

```text
sec_env_probe
输出输入提示
wb_read_line
chow_wb_encrypt
wb_verify_fold
0x402e5b
```

`chow_wb_encrypt`中存在大量查表运算和一个30,000,000次迭代的循环。不过，程序在`wb_verify_fold`返回后还会进入`0x402e5b`，因此不能把前面的查表比较当成全部验证逻辑。

`0x402e5b`注册了多个信号处理函数，其中SIGTRAP的处理函数位于`0x406000`。继续跟踪，输入会被解析成48字节，随后进入一段通过异常控制执行顺序的隐藏代码。

关键地址如下：

| 地址 | 作用 |
| --- | --- |
| `0x402747` | 从浮点常量表恢复一个字节 |
| `0x4029cf` | 初始化隐藏校验使用的常量和表 |
| `0x4028d6` | 准备可写代码区并启动单步执行 |
| `0x404000` | 第一份指令解密调度代码 |
| `0x406000` | SIGTRAP处理函数 |
| `0x5aa360` | 隐藏校验上下文，执行时由`r12`指向 |
| `0x5aa3c0` | 解码后的48字节输入，即上下文`+0x60` |

## 3. 解题过程

### 还原浮点编码的常量

初始化过程没有直接复制常量字节，而是反复调用`0x402747`。该函数读取单精度浮点数，调用反正弦函数，再乘以256，舍入到整数后取低8位。

浮点数组虚拟地址为`0x50d8a0`，对应文件偏移`0x10d8a0`。本题所需的常量按此公式恢复，脚本见第 4 节 PoC。

得到的S-box是一个256字节置换，可以构造逆表`inv_sbox = [sbox.index(i) for i in range(256)]`。

24字节目标值为：

```text
082f54e63c2997605d0679ba143a49d07dcdba76266c79d0
```

程序中还有对常量进行异或掩码、再恢复的步骤。求解时使用的是上述最终比较目标，不能直接把某个中间时刻的内存内容当成目标值。

### SIGTRAP驱动的指令解密

在`0x4028d6`中，对代码区域调用mprotect，然后设置EFLAGS的TF位：

```asm
pushfq
or qword ptr [rsp], 0x100
popfq
jmp 0x404000
```

TF使程序在单步执行时产生调试异常。程序借助SIGTRAP的上下文恢复机制，把控制流送到解密器和刚解密出的指令之间。

一轮执行可以概括为：

```text
解密调度器计算下一条指令的位置和密钥
    ↓
备份目标位置原来的 16 字节
    ↓
原地异或解密这 16 字节
    ↓
SIGTRAP 处理函数修改返回 RIP
    ↓
执行解密后的指令
    ↓
再次触发 SIGTRAP
    ↓
恢复原来的密文字节，选择下一份调度器
```

因此，静态顺序反汇编会混入大量无关指令；普通内存dump也不会同时包含所有明文指令。合适的提取时机是：目标已经解密、但尚未被恢复为密文的时候。

上下文中几个重要字段：

| 相对r12的偏移 | 含义 |
| --- | --- |
| `+0x00` | 调度使用的当前偏移 |
| `+0x04` | 待执行的目标偏移 |
| `+0x08` | 单步计数 |
| `+0x0a` | 滚动解密状态的一部分 |
| `+0x10` | 被临时覆盖的16字节原始代码 |
| `+0x28` | 编码的调度数据指针 |
| `+0x30` | 代码区域基址`0x404000` |
| `+0x60` | 48字节license |

解密密钥还依赖反调试、代码完整性和系统调用相关状态。直接NOP掉检测代码容易使后续地址或密钥失配。

#### 用Unicorn提取执行轨迹

使用Unicorn按ELF的PT_LOAD段装载程序，并从`0x4029cf`开始模拟隐藏校验的初始化。所需环境由hook提供：

- 将浮点常量解码函数替换为等价的Python计算。
- 为`/proc/self/status`提供`TracerPid: 0`的内容。
- 模拟涉及的文件、信号和ptrace系统调用结果。
- 为CPU厂商检查提供`GenuineIntel`。
- 在单步中断hook中实现信号处理函数的关键跳转和代码恢复行为。
- 在跳向明文指令之前，用Capstone记录地址和指令。

这里的模拟器是提取校验逻辑的工具，不是完整的Linux执行环境。模拟器

#### 模拟中需要处理的细节

第一，初始EFLAGS使用`0x202`。程序会读取与系统调用相关的标志位，如果遗漏IF位，后续混入密钥的值就不同。

第二，程序故意对无效文件描述符执行系统调用，并使用错误码参与解密。比如对`-1`执行read或close，应返回`-EBADF`，不能统一返回0。

第三，必须处理本题单步系统调用序列的实际行为。通过一个独立的Linux测试程序确认，TF下执行syscall后，下一条用户态指令执行完才进入这里需要模拟的陷阱位置。本题恰好会紧接着保存返回值：

```asm
syscall
mov word ptr [r12 + 0x56], ax
```

若模拟器在syscall后立即恢复密文并调度，就会漏掉这条保存指令。还需要更新syscall相关的RCX和R11。测试代码已并入分析流程。

### 从输入相关的解密约束恢复后半段

提取轨迹时，会遇到以下模式：

```asm
movzx eax, byte ptr [r12 + input_offset]
movzx ecx, word ptr [r12 + 0x0a]
xor cl, al
mov word ptr [r12 + 0x0a], cx
```

这意味着输入字节直接进入后续指令的解密状态。错误输入造成的现象是后续代码解密成乱码，而不只是跳到一个失败分支。

对这种单字节约束，可以保存当前寄存器、内存和栈状态，然后枚举AL，循环见第 4 节 PoC。

筛选时结合目标地址与连续指令结构，并继续执行验证。随机字节也可能解码成合法x86指令，所以“能被反汇编”本身不足以证明候选正确。

例如，输入第24字节的相关轨迹是：

```asm
0x4122b4  movzx eax, byte ptr [r12 + 0x78]
0x4122c4  movzx ecx, word ptr [r12 + 0x0a]
0x4122d8  xor cl, al
0x4122e6  mov word ptr [r12 + 0x0a], cx
0x4122f1  mov edx, eax
```

输入位于`r12+0x60`，所以`+0x78`对应`license[24]`。该位置恢复出的值为`0x00`。

下一字节在`0x4130dd`从`r12+0x79`读取；其约束恢复出`0x80`。同样处理后续位置，得到后24字节：

```text
00 80 0c c0 20 e0 01 01
60 0c 20 e0 00 80 0c a1
40 40 e0 1a 03 82 60 e0
```

十六进制形式为：

```text
00800cc020e00101600c20e000800ca14040e01a038260e0
```

这里还穿插着使用内部状态字节的解密约束。必须按数据来源区分它们与输入字节约束，不能把所有枚举结果直接拼接成license。轨迹提取阶段会把用到的地址和值整理成一份清单（gates.json），供后续矩阵与约束恢复比对。

### 前半段的Feistel与线性混合

前24字节记为X。隐藏指令把它分成两个12字节部分L和R，执行三轮Feistel：

```text
L_next = R
R_next = L XOR F_i(R)
```

每轮的F_i又按4字节分成三个独立分组。对每个分组，轮函数可以写成：

```text
F_i(x) = x XOR g_i(x)
g_i(x) = Q_i · S(P_i · x XOR k_i)
```

其中S对每个字节独立查表；P_i、Q_i是4×4的可逆二进制矩阵。矩阵作用于字节向量，系数为1时异或对应字节，并非普通整数矩阵乘法。

从轨迹恢复这些矩阵的方法是记录每条字节异或的依赖关系。例如：

```asm
movzx eax, byte ptr [r12 + 0x9c]
xor al, byte ptr [r12 + 0x9d]
xor al, byte ptr [r12 + 0x9e]
xor al, byte ptr [r12 + 0x9f]
xor al, 0xd6
add eax, 0x300
movzx eax, byte ptr [rdi + rax]
```

这一段对应S-box的一个输入：

```text
S(x0 XOR x1 XOR x2 XOR x3 XOR 0xd6)
```

查表前的异或关系给出P的一行和轮常量；查表后，各个临时字节如何异或到结果中，给出Q。

三轮Feistel结束后，程序再异或原输入：

```text
Y = Feistel3(X) XOR X
```

之后对Y进行一个24×24二进制矩阵M的线性混合。中间穿插了用于调度状态的掩码操作，还原后，前半段的比较条件是：

```text
M · Y = target
```

例如第一输出字节的关系为：

```text
out[0] = Y[3] XOR Y[5] XOR Y[7] XOR Y[8]
       XOR Y[9] XOR Y[10] XOR Y[13] XOR Y[16]
       XOR Y[17] XOR Y[18] XOR Y[23]
```

从连续的movzx、xor、mov序列提取全部24行，再做GF(2)高斯消元，得到：

```text
Y = M^-1 · target
  = 8721a19db336fdb91f3f6f5b9a2adcdc0b53034b6a8a0324
```

M会混合三个分组，但求逆后，剩下的Feistel方程又分解成三个互不依赖的问题。每个问题涉及L中的4字节和R中对应的4字节。

### 把每组八字节未知量降为四字节

直接对每组8字节输入搜索需要枚举64位。利用轮函数的可逆部分，可以把搜索变量缩减到32位。

以下只考虑一个分组，所有变量都是4字节向量。定义：

```text
U = R
V = L XOR F_1(U)
W = U XOR F_2(V)
```

三轮Feistel的输出为：

```text
L3 = W
R3 = V XOR F_3(W)
```

将该分组的已知Y分成yL、yR，则：

```text
yL = W XOR L
yR = V XOR F_3(W) XOR U
```

代入`F_i(x) = x XOR g_i(x)`，引入新的4字节变量：

```text
t = U XOR V XOR W
```

由上述等式依次得到：

```text
g_1(U) = t XOR yL
g_2(V) = t
g_3(W) = t XOR yR
```

由于P、Q和S都可逆：

```text
g_i^-1(z) = P_i^-1 · (S^-1(Q_i^-1 · z) XOR k_i)
```

所以U、V、W都能表示成t的函数：

```text
U = g_1^-1(t XOR yL)
V = g_2^-1(t)
W = g_3^-1(t XOR yR)
```

只需枚举32位t，检查：

```text
g_1^-1(t XOR yL)
XOR g_2^-1(t)
XOR g_3^-1(t XOR yR)
XOR t
== 0
```

命中后恢复原输入：

```text
R = U
L = W XOR yL
```

注意k_i在逆变换中的位置：先应用逆S-box，再异或k_i，最后乘P_i^-1。

### 查表加速枚举

设t的四个字节为a、b、c、d。由于矩阵系数都是0或1，每次逆S-box的输入都是这四个字节某个子集的异或，再异或一个常量。

用四位mask表示这个子集。例如：

```text
0001 → a
0011 → a XOR b
1101 → a XOR c XOR d
```

把相同mask的贡献合并，就能预先构造`T[16][256]`。每项保存对应查表结果对整个32位方程的贡献，包括逆矩阵、轮常量以及最后的t项。

固定a、b后，把表项按是否含c、d分组，检查式变成：

```text
A XOR B[c] XOR C[d] XOR D[c XOR d] == 0
```

因此，最内层只剩三次表访问和几次异或，内层循环见第 4 节 PoC。

这里仍是每组2^32的枚举，只是将复杂变换移到了预计算阶段。实现使用GCC `-O3 -march=native`，并用OpenMP并行处理a、b。无需在Python中执行数十亿次循环。

三组搜索得到以下t候选，按a、b、c、d的字节顺序展示：

| 分组 | t候选 |
| --- | --- |
| 0 | `dd49ccc1`、`56d7bfb2` |
| 1 | `2a0d6756`、`80ca848b`、`77f7c9b8` |
| 2 | `11d92447` |

这产生2×3×1＝6个前半段候选。前半段的数学条件不足以唯一决定完整程序的输出，因此需要把六个候选分别与已恢复的后半段拼接，送入原始ELF验证。

### 原程序验证与最终结果

六个候选中，只有以下前24字节通过完整程序验证：

```text
5b6c94d31d85e2344e666179a1d203ef02b5fdcb271d3d05
```

完整license为：

```text
5b6c94d31d85e2344e666179a1d203ef02b5fdcb271d3d0500800cc020e00101600c20e000800ca14040e01a038260e0
```

将它写入文件，在Linux中执行：

```bash
./license < valid_license.txt
```

原始程序输出：

```text
please input your license: flag{...}
```

其余五个候选均输出`Rejected.`。验证过程没有修改原始ELF，也没有修改最终比较结果。

## 4. PoC

```python
import math
import struct

raw = open('license', 'rb').read()

def decode(start, count):
    out = []
    for i in range(start, start + count):
        x = struct.unpack_from('<f', raw, 0x10d8a0 + 4*i)[0]
        out.append(round(math.asin(x) * 256) & 0xff)
    return bytes(out)

sbox = decode(0x12a, 256)
target = decode(0x22a, 24)
```
```python
for value in range(256):
    restore_snapshot()
    set_al(value)
    run_until_next_decrypted_instruction()
    inspect_destination_and_instruction()
```
```c
for (unsigned c = 0; c < 256; c++) {
    unsigned base = A ^ B[c];
    for (unsigned d = 0; d < 256; d++) {
        if ((base ^ C[d] ^ D[c ^ d]) == 0) {
            /* 保存 a、b、c、d */
        }
    }
}
```
