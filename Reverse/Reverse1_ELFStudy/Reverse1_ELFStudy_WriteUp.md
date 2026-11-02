# ELFStudy

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Reverse |
| 形态 | 附件题 |
| 附件 | elfstudy（ELF64 PIE，stripped，C++） |
| 目标 | 离线分析附件，无远程地址 |

Flag：flag{4865f2079724968a95c217e0ff4db6c6}

题面只给了附件下载链接，没有额外描述。

## 2. 题目分析

### 程序表面是一个ELF结构查看器，真正的校验函数被加密后藏在**LOAD段末页的缝隙（segment slack）**里，并用精心构造的**`Elf64_Rela`重定位+COPY重定位+`STT_GNU_IFUNC`**在`ld.so`重定位阶段执行一段自解密的加载期壳代码

1. 用`.rela.dyn`里的两条`R_X86_64_COPY`把`0x1d30`处的「假符号定义」注入dynsym；
2. 再把`0x1988`处的「隐藏38条Rela表」整块拷贝覆盖`.rela.plt`（`0x15e0`）；
3. `ld.so`继续按表遍历时，就把隐藏表当成PLT重定位执行：
   - 把隐藏表当代码常量重定位出一个0x69字节的解密stub到`0x7325`；
   - 把弱符号`_ZNSt7...10_M_disposeEv`的`st_value`变成“虚拟基址”用来生成stub；
   - 把`_ZNSt7...6appendEPKc`改造成`STT_GNU_IFUNC | SHN_ABS`，其resolver指向stub → `ld.so` **在加载期直接调用stub**；
   - stub用链式XOR解密`0x7396`处0x330字节的校验函数，改写`0x3b34`为`call 0x739a`，然后把自己清零；
   - 隐藏表里的一条COPY（idx21）再把`.rela.plt`从`0x76c6`的备份还原，运行期看起来一切正常。

`main`里原本空函数`sub_3B30`被改成`call 0x739a`，于是正常输出ELF信息后进入真正的校验函数。

### 基础信息

```bash
$ file elfstudy
elfstudy: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ readelf -hd elfstudy | head
  Type: DYN (Position-Independent Executable file)
  Entry point address: 0x2e90
  ...
  FLAGS: TEXTREL BIND_NOW
  FLAGS_1: NOW PIE
```

- PIE + **Full RELRO** + **BIND_NOW** + `TEXTREL`
- 有`__stack_chk_fail`、`__fread_chk`、`memcmp/strncpy/strlen`等
- `TEXTREL`是一个很显眼的提示：作者想让重定位去改`.text`

程序正常行为（`argv[1]`是待查看的文件，`-`表示stdin）：

```bash
$ ./elfstudy elfstudy
ELFStudy 1.4.2 — ELF structure inspector

[image] 43304 bytes loaded
[header] ... [program headers] ... [sections] ...
[symbols] summary unavailable without a section-name table in this build
```

`main`在打印完报告后会调用`0x3b30`：

```asm
; 静态时 sub_3B30
3b30: f3 0f 1e fa    endbr64
3b34: 90 90 90 90 90 90 90 90
3b3c: c3             ret
```

### 异常信号与加载期自解密

静态扫描时真正有价值的不是字符串，而是三处自相矛盾的元数据：`TEXTREL`表明作者准备在运行期改写代码段；`RELASZ`的条数比`.rela.dyn`与`.rela.plt`的总和少一条，说明重定位遍历的终点被人为挪动过；`0x7325~0x7396`整段全0，而紧随其后的`0x7396`却是高熵数据，再往后又是`.rela.plt`的一份完整副本。三者合起来只有一种解释：有一段代码在`ld.so`重定位阶段被临时拼装到`0x7325`执行，它解密`0x7396`处的数据，解密完抹掉自己，并用`0x76c6`的副本把被自己覆盖过的`.rela.plt`还原。所以“程序运行起来一切正常”与“静态看不到校验逻辑”并不矛盾——自毁发生在`_start`之前。

### `argv[1]`的双重身份

`main`对`argv[1]`做了两件互不相干的事：一是当作待检查的ELF路径去`fopen`（`-`读stdin），二是`strncpy`到`0xb1c0`（最多`0x7f`字节）留给后面的校验函数。因此校验函数的输入并不是“读到的文件内容”，而是命令行字符串本身；把flag直接当参数传进去时，`fopen`必然失败并打印一行错误，但`0xb1c0`里已经是完整的flag，校验照常进行。反过来说，传一个真正的ELF文件名永远过不了`"flag"`前缀检查——这也决定了必须从算法倒推，而不是去找某个“输入文件”。

### 入口接线：`0x3b30`补丁成`0x739a`

`main`打印完报告后调用`0x3b30`，静态看它只是`endbr64; 8×nop; ret`，反汇编器会把它当成空函数略过。补丁由stub在加载期完成，只写6个字节：

```
3b34: e8 61 38 00 00   call 0x739a
3b39: c3               ret
```

`rel32 = 0x3861`是相对**下一条指令**`0x3b39`计算的：`0x3b39 + 0x3861 = 0x739a`。补丁从`0x3b34`而不是`0x3b30`开始，是为了保留开头的`endbr64`，让开启CET/IBT的机器上该间接跳转目标仍然合法；`0x3b3a/0x3b3b`残留的两条`nop`和`0x3b3c`原来的`ret`都位于新`ret`之后，永远不会执行。写完这一笔，`0x3b30`就从“空函数”变成了“跳板”，而调用者对此一无所知。

### 作者盯上`.text`的原因

Full RELRO在重定位结束后把GOT置为只读，`BIND_NOW`又要求进入`_start`前完成全部符号绑定，于是“劫持GOT”“等延迟绑定后改函数指针”这类常规手法全部失效；但换个角度看，这也保证了所有重定位一定在程序自己的代码跑起来之前处理完毕，正好可以当作加载期壳的触发器。`TEXTREL`则说明作者主动放弃了“只改数据”的约束，选择直接往代码段写字节——因为只有代码段的改动才会在`main`调用`0x3b30`的那一刻生效，而改完之后它看起来仍是一个普普通通的函数。

## 3. 解题过程

### 静态分析：三个看不见的数据区

#### LOAD段的尾页缝隙（segment slack）

```bash
$ readelf -lW elfstudy
 LOAD 0x000000 0x000000 0x000000 0x001988 0x001988 R
 LOAD 0x002000 0x002000 0x002000 0x005325 0x005325 R E
 LOAD 0x008000 ...
```

- 第1个LOAD的`filesz = 0x1988`，但内核/`ld.so`是按**页（0x1000）**映射的：`0x1000~0x2000`整页可读，`0x1988~0x2000`的文件字节虽然超出一个LOAD段，**仍然会被映射进内存**，只是`readelf/objdump`按段/节看会认为这里“没有东西”。
- 第2个LOAD结束于`0x2000 + 0x5325 = 0x7325`，同理`0x7325~0x8000`这一页尾巴也被映射。

利用这个缝隙藏了4块数据（用`xxd`很容易看到）：

| 文件偏移 | 大小 | 用途 |
| --- | --- | --- |
| `0x1988` | `0x3a8`（实际有效38条Rela = `0x390`） | **隐藏重定位表** |
| `0x1d30` | 14字节 | **假dynsym定义块**（COPY重定位源） |
| `0x7396` | `0x330` | **加密的校验函数** |
| `0x76c6` | `0x3a8` | `.rela.plt`的副本（用于事后还原） |

同时`0x7325~0x7396`是加密函数前的空白（静态全0），实际是运行期拼装解密stub的位置；stub执行完会把自己擦成0。

#### 节表/段表与动态表的错位

```bash
$ readelf -d elfstudy | grep -E 'RELA|JMPREL|PLTREL'
 (JMPREL)  0x15e0
 (PLTRELSZ) 936            # 39 条
 (RELA)     0x1388
 (RELASZ)   1512           # 0x5e8 = 63 条
 (RELACOUNT) 7
```

- `.rela.dyn`在`0x1388`，25条（`0x258`）。
- `.rela.plt`在`0x15e0`，39条（`0x3a8`）。
- `25 + 39 = 64`，但`RELASZ = 63`条：`0x1388 + 0x5e8 = 0x1970`，**恰好差最后1条PLT重定位**。

并且`.rela.dyn`的前4条RELATIVE重定位指向了**dynsym内部**（`0x954/0x956/0x957/0x958`）——正常编译器绝不会这么干：

```bash
$ readelf -r elfstudy | head
000000000954 ... R_X86_64_RELATIVE  2600
000000000956 ... R_X86_64_RELATIVE  25f1
000000000957 ... R_X86_64_RELATIVE  25ff
000000000958 ... R_X86_64_RELATIVE  1d30
```

`0x3f8`开始是`.dynsym`，每条24字节：

- sym49 `_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2EOS4_`的`st_info/st_shndx/st_value/st_size`在`0x894/0x896/0x898/0x8a0`；
- sym55 `...6appendEPKc`在`0x920`起；
- sym57 `...10_M_disposeEv`在`0x950`起（`st_info=0x954`，`st_value=0x958`，`st_size=0x960`）。

所以上面4条重定位是在**改写sym57的符号表项**，最后把`sym57.st_value`写成`base + 0x1d30`。

再看`.rela.dyn`里两条可疑的COPY：

```bash
$ readelf -r elfstudy | grep COPY
000000000894  0000003900000005  R_X86_64_COPY  ...10_M_disposeEv
00000000015e0 0000003100000005  R_X86_64_COPY  ...C2EOS4_
```

- `r_offset = 0x894`（sym49的字段，**不是** sym57的）配合`sym = 57`；
- `r_offset = 0x15e0`（`.rela.plt`起点）配合`sym = 49`。

这就是整条链的开关。

### 加载期利用链（动态验证）

> 由于PIE，用`setarch -R`（或`personality(ADDR_NO_RANDOMIZE)`）固定`base = 0x555555554000`，再用ptrace在`_start`下断读取`/proc/pid/mem`即可对比“文件vs内存”。

实测到的关键事实：

1. `ld.so`处理`.rela.dyn`的第15条COPY时，执行了
   `memcpy(dst=base+0x894, src=base+0x1d30, n=14)`；
   随后sym49被改写成`{st_shndx=1, st_value=0x1988, st_size=0x390}`。
   （`0x1d30`处的14字节正是`00 00 01 00 88 19 00 00 00 00 00 00 90 03`）

2. 紧接着第16条COPY执行
   `memcpy(dst=base+0x15e0, src=base+0x1988, n=0x390)`：
   **把隐藏表整块覆盖到`.rela.plt`上**。

3. 由于`RELASZ=63`条，`ld.so`的RELA循环本来正好还要再走38条槽位（`0x15e0 ~ 0x1970`），现在读到的却是隐藏表——**隐藏表被当作重定位执行了**。

4. 隐藏表内容（38条，本质是`Elf64_Rela[38]`）：

| idx | r_offset | r_info含义 | r_addend | 作用 |
| --- | --- | --- | --- | --- |
| 0 | `0x958` | sym0, **type 0x21(SIZE64)** | `0x16493f2103392e07` | 写sym57.`st_value`=伪基址`S0` |
| 5 | `0x928` | RELATIVE | `0x7325` | sym55.`st_value` = `base+0x7325` |
| 16 | `0x920` | sym0, type 0x21 | `0xfff1000a00000000` | 把sym55改成`STT_GNU_IFUNC`, `SHN_ABS` |
| 18 | `0x7386` | sym55, type 1 | 0 | **触发IFUNC resolver调用（stub）** |
| 19 | `0x958` | RELATIVE | `0x76c6` | sym57.`st_value` = `base+0x76c6` |
| 20 | `0x960` | RELATIVE | `0x3a8` | sym57.`st_size` = `0x3a8` |
| 21 | `0x15e0` | sym57, **type 5(COPY)** | 0 | 把`.rela.plt`从`0x76c6`还原 |
| 其余 | `0x7325~0x738d` | sym57, type 1(64) | 各不相同 | 用`S0 + addend`拼出解密stub |

   拼装公式（逐字节吻合）：

   ```
   stub_bytes[off] = (0x16493f2103392e07 + r_addend) & (2^64-1)
   ```

   例如idx6（`r_offset=0x732d`, `add=0x31b6c0defdcc5f41`）：

   ```
   (0x16493f2103392e07 + 0x31b6c0defdcc5f41) mod 2^64
     = 0x4800000001058d48        # stub 中即 48 8d 05 01 00 00 00 48
   ```

5. 隐藏表idx18引用sym55（已被改成`IFUNC|SHN_ABS`，`st_value=base+0x7325`），`ld.so`的IFUNC分支会**调用这个resolver**，于是CPU在加载期执行`0x7325`处的stub。

6. stub执行完把自己`0x61`字节清零，所以运行到`_start`时`0x7325~0x7386`又是全0，只有`0x739a`起是解密后的校验函数——静态工具永远看不到它。

#### 解密stub（加载期，运行后自毁）

从ptrace抓到执行中的stub（`0x7325`，0x69字节）：

```asm
; rbx = 0x7325
7325: 53                      push rbx
7326: 48 8d 1d f8 ff ff ff    lea  rbx,[rip-8]          ; rbx = 0x7325
732d: 48 8d 05 01 00 00 00    lea  rax,[rip+1]          ; rax = 0x7335
7334: 48 25 00 f0 ff ff       and  rax,~0xfff           ; 页对齐 -> 0x7000
733a: 48 05 60 3d 00 00       add  rax,0x3d60           ; -> 0xad60 = DT_DEBUG 值槽
7340: 48 8b 00                mov  rax,[rax]            ; rax = r_debug*
7343: 48 85 c0                test rax,rax
7346: 74 3b                   je   erase
7348: 48 8b 48 10             mov  rcx,[rax+0x10]       ; rcx = r_debug->r_brk (_dl_debug_state)
734c: 48 85 c9                test rcx,rcx
734f: 74 32                   je   erase
7351: 80 39 cc                cmp  byte [rcx],0xcc      ; anti-debug: 下过 int3 就不解密
7354: 74 2d                   je   erase
7356: 48 8d bb 71 00 00 00    lea  rdi,[rbx+0x71]       ; rdi = 0x7396 (密文)
735d: b9 cb 00 00 00          mov  ecx,0xcb             ; 203 个 dword
7362: 31 c0                   xor  eax,eax              ; key = 0
7364: 31 04 8f                xor  dword [rdi+rcx*4],eax ; P = C ^ key
7367: 74 1a                   je   erase                 ; P==0 视为异常
7369: 03 04 8f                add  eax,[rdi+rcx*4]       ; key += P (mod 2^32)
736c: e2 f6                   loop 0x7364                ; idx: 0xcb -> 1
736e: 48 8d 83 0f c8 ff ff    lea  rax,[rbx-0x37f1]     ; rax = 0x3b34
7375: c6 00 e8                mov  byte [rax],0xe8       ; 写 call rel32
7378: c7 40 01 61 38 00 00    mov  dword [rax+1],0x3861  ; 目标 = 0x739a
737f: c6 40 05 c3             mov  byte [rax+5],0xc3     ; ret
7383: 53                      push rbx
7384: 5f                      pop  rdi                    ; rdi = 0x7325
7385: 6a 61                   push 0x61
7387: 59                      pop  rcx
7388: 31 c0                   xor  eax,eax
738a: 5b                      pop  rbx
738b: f3 aa                   rep stosb                  ; 把自身 0x61 字节清零
738d: c3                      ret
```

**解密算法（链式XOR，从高地址往低地址）**：

```
key = 0
for i = 0xcb downto 1:            # 32-bit words, 0x7396 + i*4
    P[i] = C[i] ^ key
    key = (key + P[i]) & 0xffffffff
P[0] = C[0]                        # 索引 0 未被改写
```

对应0x330字节（204 word，索引0..0xcb）的解密，索引0本来就和明文相同（`90 90 90 90`）。

### 静态提取校验函数

不用运行程序，按上面的算法直接解文件即可，得到`0x7396`处明文，脚本见第 4 节 PoC。

解密后`0x7396`起的内容与运行期内存完全一致（`0x739a`是真正的函数入口，前面4个`90`是填充），可以`objdump -D -b binary -m i386:x86-64`反汇编。

> 说明：`0x76c6`之后是`.rela.plt`的副本，不属于校验逻辑。

#### 校验函数结构（`0x739a`）

```asm
739a: endbr64
739e: push rbx / push rbp / push r12
73a5: lea  rbx,[rip-0x16]              ; rbx = 0x7396
73ac: lea  rax,[rip+1]; and rax,~0xfff; add rax,0x3d60
73bf: mov  rax,[rax]                   ; DT_DEBUG -> r_debug
      ...                              ; 反调试 1: [r_debug+0x10] 处是否为 0xcc
73e1: open("/proc/self/status", O_RDONLY)
      read(fd, buf, 0x200)
      ...                              ; 反调试 2: 查找 "TracerPid:"，要求值为 '0'
7467: ...                              ; 反调试 3: 遍历 link_map，超过 7 个对象就退出
74a2: lea rdi,[rbx+0x3e2a]             ; rdi = 0xb1c0 = main 里 strncpy 过来的 argv[1]
74b2: cmp dword [rdi],0x67616c66       ; "flag"
74be: cmp byte [rdi+4],'{'
74c8: cmp byte [rdi+0x25],'}'          ; 长度固定 0x26 = 38
74d2: cmp byte [rdi+0x26],0
      ...                              ; 把 32 个 hex 字符转成 16 字节（低位 &0x20 转小写校验）
7537: mov rax,[0x7686]; xor rax,[0x768e]   ; K0 = 常量A ^ 常量B
754a: mov rdx,[0x7696]; xor rdx,[0x769e]   ; K1 = 常量C ^ 常量D
      r8 = input_word0 ^ K0
      r9 = input_word1 ^ K1
      ; ---- 30 轮 Feistel/ARX ----
      for i = 2..31:
          r8,r9 = r9, r8 ^ G(r9, W[i])
7628: cmp r8, [0x76a6]
7634: cmp r9, [0x76ae]
      ; 相等 -> write(1,"flag accepted\n",14)
```

反调试细节：
- 用`DT_DEBUG`找到`r_debug->r_brk`（`_dl_debug_state`），若首字节是`0xcc`（被下过软件断点）就**不解密**、直接自毁返回；
- `/proc/self/status`的`TracerPid`必须是`0`；
- `link_map`数量不能超过7（挡住多余的`LD_PRELOAD`）。

#### 密钥与目标常量

从解密后的blob直接读（小端QWORD）：

| 地址 | 值 |
| --- | --- |
| `0x7686` | `0xd868187917bb2795` |
| `0x768e` | `0xc7cea69e35f49213` |
| `0x7696` | `0x939ec78e9d68b6eb` |
| `0x769e` | `0xc562921852331bb3` |
| `0x76a6` | `0x4fb335a84fa7d2d7` |
| `0x76ae` | `0x02a183e3b4f4f49f` |

于是：

```
W[0] = 0xd868187917bb2795 ^ 0xc7cea69e35f49213 = 0x1fa6bee7224fb586
W[1] = 0x939ec78e9d68b6eb ^ 0xc562921852331bb3 = 0x56fc5596cf5bad58
delta = 0x9e3779b97f4a7c15
```

#### 算法公式

```
# 密钥扩展 (i = 2..31)
W[i] = rol64(W[i-1] + W[i-2], 13) ^ ror64(W[i-2], 7) ^ (i * delta)

# 加密/校验 (i = 2..31)
G(x, k) = ( rol64(x + k, 13) ^ rol64(x, 29) ) + rol64(x, 47)
r8, r9 = input[0:8] ^ W[0], input[8:16] ^ W[1]
for i in 2..31:
    r8, r9 = r9, r8 ^ G(r9, W[i])

要求 (r8, r9) == (0x4fb335a84fa7d2d7, 0x02a183e3b4f4f49f)
```

其中`rol/ror`都是64位循环移位，加法均mod 2^64。

从指令形态可以确认这是标准Feistel结构：每轮把`(r8,r9)`整体交换，只对`r9`调用`G`，再把结果异或进`r8`，因此加密与解密共用同一套运算，只是轮序相反。`G`里三个移位量13/29/47都与64互素，循环移位必然可逆；`delta = 0x9e3779b97f4a7c15`是64位黄金比例常数，与TEA/XTEA同源，说明`W[i]`的扩展方式是“前两项自反馈+轮常数”。轮数由`i = 2..31`确定为30轮，末尾两条`cmp`分别读`0x76a6/0x76ae`，即对128位状态整体比对，没有部分匹配可利用。

#### 逆推

`r8, r9 = r9, r8 ^ G(r9, W[i])`是可逆的（给定新`r8`即可还原旧`r9`）：

```
for i = 31 downto 2:
    prev_r9 = r8
    prev_r8 = r9 ^ G(prev_r9, W[i])
    r8, r9 = prev_r8, prev_r9

word0 = r8 ^ W[0]
word1 = r9 ^ W[1]
```

#### 从目标中间值倒推

倒推的关键是把“交换”看成一次寄存器重命名：`(r8,r9) → (r9, r8⊕G(r9,W[i]))`，所以拿到新状态就能唯一确定旧状态——新`r8`就是旧`r9`，旧`r8`由新`r9`异或`G(新r8,W[i])`得到。整条链没有任何信息丢失，解唯一，不需要爆破，代价只有30次求值：

1. 取目标中间值`T = (0x4fb335a84fa7d2d7, 0x02a183e3b4f4f49f)`，即`0x76a6/0x76ae`两条QWORD；
2. 令`i`从31递减到2，执行`r8, r9 = r9 ^ G(r8, W[i]), r8`，共30次；
3. 退出时的`(r8,r9)`是白化异或之前的状态，`w0 = r8 ^ W[0]`、`w1 = r9 ^ W[1]`；
4. `W[0]/W[1]`并不是明文存储的，而是两对常量各自异或得到，必须先还原，否则后续全错；
5. 按小端把`w0`铺成flag前8字节、`w1`铺成后8字节，转hex得到32位字符串。

值得一提的是，这种结构让“比较点位置”不再重要：目标值对应的是第30轮的输出，倒推30次必然回到白化之前；即使作者把比较挪到某一轮的中间，也只是少推几轮。Feistel每轮输出都是完整128位中间状态且完全可逆，这正是不加单向压缩的对称校验的脆弱之处——运算量再大，也只能起到混淆作用，挡不住反向执行。

实算得到`w0 = 0x8a96249707f26548`、`w1 = 0xc6b64dffe017c295`，拼接即`4865f2079724968a95c217e0ff4db6c6`。

#### 正向回代验证

倒推最容易错在移位方向、轮序与`delta`上，所以必须回代：用求出的`w0/w1`重新做白化和30轮正演，检查末态是否精确等于`0x4fb335a84fa7d2d7`与`0x02a183e3b4f4f49f`。任何一处写错（把`ror(W[i-2],7)`误当成`rol`、漏掉`i*delta`、或轮数差一轮）都会让末态变成毫无关联的随机值，因此这一步同时充当算法理解的证明。正演一致之后，再把整串`flag{...}`作为`argv[1]`运行程序，输出`flag accepted`，静态推导与运行期行为就完全对上了。

#### 输入格式的硬约束

校验函数在进入运算前先把格式钉死：前4字节必须是`"flag"`，第5字节`{`，第`0x25`字节`}`，第`0x26`字节`\0`——总长恰好38字节，长一个字符、短一个字符都会被拒绝。随后把花括号之间的32个字符按十六进制解析成16字节，字母先统一折算成小写再比较，因此大小写混写都能通过，但出现`g`以上的非十六进制字符会立刻失败。这一步把解空间钉在`2^128`，暴力不可能，同时也说明作者对算法本身足够自信：唯一的出路就是逆推Feistel。

#### 常量与密文的先后依赖

所有关键常量（`0x7686~0x769e`的四对异或对、`0x76a6/0x76ae`的两个目标值）都落在解密后的blob区间`0x7396~0x76c6`内，它们在静态文件里是密文噪声，只有先完成链式XOR解密才能读到真实取值。顺序上不能跳过：不解密就没有`W[0]/W[1]`，没有目标中间值，逆推也无从开始。反过来，一旦解密成功，常量就是连续的6个QWORD，读出即可，不存在二次加密。

### 验证

```bash
$ ./elfstudy 'flag{...}'
ELFStudy 1.4.2 — ELF structure inspector
ELFStudy: cannot open 'flag{...}'
[image] 0 bytes loaded
[header] truncated: need at least 64 bytes for an ELF64 header
flag accepted
```

> 注意：程序把`argv[1]`既当“要查看的文件”又当flag（`main`里`strncpy(0xb1c0, argv[1], 0x7f)`）。
> 所以直接把flag当参数传进去：`fopen`会失败并打印错误，但校验函数仍然会跑，从而输出`flag accepted`。

## 4. PoC

```python
import struct
d = open('elfstudy','rb').read()
blob = bytearray(d[0x7396:0x76c6])            # 0x330 bytes
w = list(struct.unpack('<%dI' % (len(blob)//4), blob))
key = 0
for i in range(0xcb, 0, -1):
    p = (w[i] ^ key) & 0xffffffff
    w[i] = p
    key = (key + p) & 0xffffffff
open('checker.bin','wb').write(struct.pack('<%dI' % len(w), *w))
```
```python
M = (1 << 64) - 1
delta = 0x9e3779b97f4a7c15

def rol(x, n): n %= 64; return ((x << n) | (x >> (64 - n))) & M
def ror(x, n): n %= 64; return ((x >> n) | (x << (64 - n))) & M

K = [0xd868187917bb2795 ^ 0xc7cea69e35f49213,
     0x939ec78e9d68b6eb ^ 0xc562921852331bb3]

W = [K[0], K[1]]
for i in range(2, 32):
    W.append((rol((W[i-1] + W[i-2]) & M, 13) ^ ror(W[i-2], 7) ^ ((i * delta) & M)) & M)

def G(x, k):
    return ((rol((x + k) & M, 13) ^ rol(x, 29)) + rol(x, 47)) & M

r8 = 0x4fb335a84fa7d2d7
r9 = 0x02a183e3b4f4f49f
for i in range(31, 1, -1):
    r8, r9 = (r9 ^ G(r8, W[i])) & M, r8

a = r8 ^ W[0]
b = r9 ^ W[1]
data = a.to_bytes(8, 'little') + b.to_bytes(8, 'little')
print('flag{%s}' % data.hex())
```
```text
flag{...}
```
