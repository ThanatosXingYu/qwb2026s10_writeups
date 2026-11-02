# oldsvr

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 附件题 |
| 附件 | server、MIPS64大端uClibc 1.0.32、动态加载器 |
| 目标 | 题目提供的 nc 服务（附件可离线复现） |

Flag：flag{1ec6896ee054f9cab370a5a8473c30ee}

附件中的`server`是一个简化的MQTT服务，配套提供MIPS64大端uClibc 1.0.32和动态加载器，直接用附件里的库配合QEMU即可运行。

## 2. 题目分析

`server`是一个裁剪过的MQTT broker，只实现CONNECT、SUBSCRIBE、UNSUBSCRIBE、PUBLISH和PINGREQ，订阅表固定14个槽，每槽保存主题、payload指针和长度。报文采用定长头加剩余长度编码，主题名前带2字节长度；解析出的长度既用于`malloc`，也直接当`memcpy`的字节数，任何一次类型收窄都会变成越界。认证只在CONNECT阶段做一次，之后按报文类型分发，堆上的状态因此长期存活，可跨多条报文反复利用。附件同时给出MIPS64大端uClibc 1.0.32与`ld64-uClibc`，需配合QEMU和对应sysroot运行；大端意味着回包长度、堆块头、伪造指针都要按大端64位填写，不能照搬x86经验。

协议层面值得单独拆开看。MQTT每个报文由1字节定长头和变长剩余长度组成：定长头高4位是类型、低4位是标志（CONNECT `0x10`、PUBLISH `0x30`、SUBSCRIBE `0x82`、UNSUBSCRIBE `0xa2`、PINGREQ `0xc0`），剩余长度按7位一组编码，每字节最高位表示是否续读，最多4字节，因此单报文名义长度可达256MB，实际受堆限制。CONNECT的变长头依次是协议名长度加"MQTT"、协议级别、连接标志、Keep Alive、Client ID，本题只接受级别4、标志`0xc2`、Keep Alive `0x4321`，并在这里一次性校验Client ID、异或后的用户名和MD5密码。关键在于认证结果不随报文携带，而是写进进程全局会话状态：连接一建立，后续报文不再做任何身份校验，只要类型合法就分派到处理函数。攻击者因此能在同一TCP连接里先发一串无害的SUBSCRIBE/PING做铺垫，再把恶意PUBLISH接在后面，铺垫与攻击共享同一份堆和同一份槽表。

短消息与长消息走两条不同的释放路径，这是UAF的根源。短消息（`0 < payload_len <= 32`）处理时，`0x37d8`先按`topic_len + payload_len`申请临时块并立刻释放，再把槽里的`slot->payload`释放掉，最后仍用这个已释放的指针当源数据拼回包——回包读的是刚被free的用户区，前8字节恰好是uClibc写入的空闲链表`fd`指针，于是堆地址随响应外泄。长消息分支则把`free(slot->payload)`推到最后，块在回包期间保持存活，正好可以当作后续溢出的相邻目标。

结构体的生命周期同样不干净。每个槽由主题指针、payload指针、长度三项组成，更新不是原子的：PUBLISH先覆盖槽内容、再释放旧指针，于是回包函数执行时槽指向的块可能已经不在链上；SUBSCRIBE在14个槽全满时只`malloc`主题名，既不写表也不释放，这些块从此没有任何槽引用，只能等后续分配去"吃掉"。槽数量固定、槽内指针可被堆操作间接改写，再叠加一次能跨越块边界的拷贝，就构成了从"读到一个堆指针"走到"改写BSS里槽指针"的完整路径。

程序为PIE+NX、无Canary。`checksec`虽报Full RELRO，但`GNU_RELRO`只覆盖`0x1ffe0~0x20000`，导入函数的GOT在其后的可写段（`free@GOT = PIE+0x20220`、`malloc@GOT = PIE+0x202b0`），拿到PIE后仍可改写GOT。uClibc的堆没有tcache与safe-linking，空闲块靠双向链表管理，unlink时校验`fd->bk == P`且`bk->fd == P`；只要伪造块头让两个指针都指回同一处，就能通过检查并把任意地址写成`fd`，这是后续劫持BSS指针的原语。

## 3. 解题过程

### 通过CONNECT认证

协议版本须为`4`，CONNECT flags为`0xc2`，Keep Alive为`0x4321`；Client ID与`QWB_Client`比较，用户名逐字节异或`0x1d`后与常量比较，故为`QWB2026_Admin`。密码做MD5后由`strncmp(digest, expected, 16)`校验，预期摘要`522a00e88ca77d1f0ba2f4fd954bdaec`的第3字节是NUL，比较在此提前结束，只需找MD5前3字节为`52 2a 00`的密码。枚举十进制数得到：

```text
password = 1540124
MD5(password) = 522a005bd3a3e13a1e12905fa42a9110
```

使用上述字段发送CONNECT，服务返回`20 02 00 00`，表示认证成功。

### 短消息释放后回包泄露PIE

订阅`QWB2026_News`会置状态字节，连续6次PING使计数为6。之后向该主题PUBLISH，`0x37d8`先`malloc(topic_len + payload_len)`并立即`free`；若`0 < payload_len <= 32`再`free(slot->payload)`，然后才调用回包函数，用这个悬空指针当源数据。悬空块未被清除，前8字节仍是uClibc写入的空闲链表指针。先用另一主题布置同尺寸空闲块把该位置占住，再向News发24字节消息，块头便携带指回堆中的地址，回包前8字节因此泄露`PIE+0x22120`附近的堆指针，按`(leak - 0x22000) & ~0xfff`得PIE基址。

### slot耗尽整理堆布局

订阅表只有14个槽，`0x3e80`在槽满时仍先`malloc`主题名，却不保存也不释放，形成只增不减的小块。重复SUBSCRIBE即可消耗这些块并推移后续分配位置，让溢出目标落到预期块上；脚本把它做成可配置项，默认2000次。

### 16位截断造成堆溢出

回包构造函数`0x2610`中，主题字段长14、固定头长2，总长却存进有符号16位变量。`payload_len = 65520`时`total = (int16_t)65536 = 0`，`malloc(0)`只返回最小块，`memcpy`却照写65520字节：

```c
int16_t total = payload_len + 14 + 2;
out = malloc(total);
memcpy(out + 2 + 14, payload, payload_len);
```

先给第一个普通主题依次发73、160字节，再给第二个发160字节，制造一个`0x60`空洞及其后的活跃块；回包时的三个小分配正好吃满空洞，越界数据从相邻块头开始覆盖。偏移以复制目的地址`D`为基准，按大端64位写入：

| 偏移 | 写入值 | 用途 |
| --- | --- | --- |
| `D+0x06` | `0x21` | 保住别名块的size |
| `D+0x3e` | `T-0x18` | 伪造前驱块的`fd` |
| `D+0x46` | `T-0x10` | 伪造前驱块的`bk` |
| `D+0xce` | `0xa0` | victim的`prev_size` |
| `D+0xd6` | `0xb0` | victim的size，清除`PREV_INUSE` |
| `D+0x186` | `0x21` | 让大消息源块的后续释放进入小块链表 |
| `D+0x1a6` | `0x21` | 保持相邻块状态可通过释放检查 |

`T = PIE+0x20368`是第一个普通槽的payload指针字段。victim块头在`D+0xce`，`prev_size=0xa0`使释放时前驱算成`P=D+0x2e`，即别名消息用户区，而`*T`本就等于`P`。取消订阅victim时，uClibc要求`fd->bk == P`且`bk->fd == P`；令`fd=T-0x18`、`bk=T-0x10`，两次检查读到的都是`*T=P`，故通过，链表更新把`*T`写成`T-0x18`，槽指针由此指向前方BSS。

### 泄露libc并取flag

被改写的槽指针把「再次PUBLISH该主题」的落点搬到BSS：把80字节伪造记录写进`PIE+0x20350`，正好覆盖真实槽表的槽1、槽2。主题名统一补到8字节，远程命令为`cat /f*`（尾部补一个空格），本地为`cat flag`。记录布局如下：

| 记录偏移 | 字段 | 值 |
| --- | --- | --- |
| `+0x00` | 主题字符串 | `cat /f* ` |
| `+0x08` | 槽1 topic_ptr | `malloc@GOT` |
| `+0x10` | 槽1 topic_len | 8 |
| `+0x18` | 槽1 payload_ptr | `1` |
| `+0x20` | 槽1 payload_len | 8 |
| `+0x28` | 槽2 topic_ptr | `PIE+0x20350`（指向`cat /f* `） |
| `+0x30` | 槽2 topic_len | 8 |
| `+0x38` | 槽2 payload_ptr | `free@GOT` |
| `+0x40` | 槽2 payload_len | 80 |

槽1是泄露槽：主题指针为`malloc@GOT`、payload为地址`1`；槽2是执行槽：主题指向BSS里的命令串，payload指向`free@GOT`、长度80。

先用主题`cat /f* `发布80字节GOT补丁。此时`memcmp`还是真的，完整比较命中槽2；拷贝目的正是`free@GOT`，80字节依次覆盖：

| 补丁偏移 | 覆盖的GOT | 新值 | 作用 |
| --- | --- | --- | --- |
| `+0x00` | `free@GOT` | `PIE+0x6d40` | 程序内的`write`桩 |
| `+0x28` | `memset@GOT` | `PIE+0x30c0` | 直接`jr $ra`返回 |
| `+0x48` | `memcmp@GOT` | `PIE+0x42f4` | 主题第二字节为0即返回0 |

`PIE+0x6d40`是静态桩：取`gp-0x7ff0`处的GOT[0]（`ld64`的解析入口），携带动态符号号跳进去；解析器保留`a0~a3`与`gp`，于是`free(x)`变成`write(x, a1, a2)`，而UNSUB处理器在两次释放时恰好把`a1`、`a2`留成槽的topic指针和topic长度。

补丁落地后先排空积压的回包（溢出回包的`34 00`与之前若干UNSUBACK），再取消订阅8字节零主题。假`memcmp`只检查主题第二字节是否为0，零主题直接命中槽1；随后两次`free`变成两次`write`：第一次以`malloc@GOT`为fd（EBADF），第二次以地址`1`为fd，把`malloc@GOT`的8字节内容回写到连接：

```text
malloc@libc = 0x...ca0
libc_base   = malloc@libc - 0x5dca0
system      = libc_base + 0x65370
```

这里有意不走栈上ROP：MIPS64的`jr $ra`链需要把栈或`$sp`先控到已知地址，而泄露只有PIE与libc，溢出又落在堆上，够不到任何返回地址；即使能堆喷也拼不出可跳转的链。于是改用GOT级代码复用，一次绝对地址写入即可完成函数替换，代价远低于搭链。

拿到libc后仍在同一连接内继续。槽1已在UNSUB时被清零，下一个主题长度为8的槽是槽2；用零主题PUBLISH发送8字节`system`地址即可命中槽2。新长度8小于槽2原长度80，走「原地覆盖」分支：`memset(free@GOT, 0, 80)`因`memset`已被换成直接返回而不清空GOT，`memcpy(free@GOT, &system, 8)`把`system`写到`free@GOT`。最后再取消订阅零主题，再次命中槽2，处理器先`free(slot->topic)`，实参正是BSS里的`cat /f* `，等价于`system("cat /f* ")`，回包即带出flag。

### 各环节的作用与衔接

16位截断是整条链的入口，值得把数算清楚。`payload_len`是32位无符号，加14字节主题名和2字节固定头仍是33位内的安全值，但函数把和赋给`int16_t`：`65520 + 16 = 65536`，低16位为0，`malloc(0)`只返回一个最小块（uClibc下可用区约`0x10`字节），`memcpy`的第三参数却仍取原始`65520`。分配尺寸与拷贝尺寸就此脱钩，拷贝目的`D = out + 16`仅比最小块用户区起点晚16字节，65520字节从`D`起一路碾过后面所有块：先是相邻块头，再是后续分配出来的块和仍被槽引用的活跃块。写入内容完全由攻击者控制，所以溢出本质是"写未来"——在free发生之前，就把即将被释放、被回包的块头预先改成想要的数值，而不是去改已经用过的旧块。

slot耗尽的用途是让"写未来"有确定的落点。14个槽满后，多余的SUBSCRIBE每次只`malloc`主题名不释放，这些块像楔子一样把后续分配位置往后推；推够次数后，溢出目标的相对位置从浮动变成可预测。先给第一个普通主题发73、160字节，再给第二个发160字节，切出一个`0x60`空洞；回包时的三个小分配正好填满空洞，越界数据的第一批落点便是紧随其后的块头，偏移表因此可以按`D`硬编码：`D+0x06`写`0x21`保住别名块size，`D+0x3e`、`D+0x46`把伪造前驱块的`fd`、`bk`写成`T-0x18`、`T-0x10`，`D+0xce`、`D+0xd6`把victim的`prev_size`置`0xa0`、size置`0xb0`并清`PREV_INUSE`，`D+0x186`、`D+0x1a6`把两块size留成`0x21`以通过释放时的一致性检查。之所以要两个指针都绕回`T`，是因为uClibc的unlink会分别读`fd->bk`和`bk->fd`并与`P`比较，只要两处读到的都是`*T`原来的值，检查就必然成立，链表更新顺手把`*T`写成`T-0x18`，槽指针由此被搬到BSS前方。

接下来是两段式的GOT改写。第一段先获取libc：改写后的槽指针让再次PUBLISH把伪造槽记录写进BSS——槽1 topic指向`malloc@GOT`、payload为`1`，槽2 topic指向BSS里的命令串、payload指向`free@GOT`、长度80；随后用槽2的主题发布80字节补丁，把`free`换成程序内`write`桩、`memset`换成直接返回、`memcmp`换成剩余长度解析函数，再用8字节零主题取消订阅命中槽1，两次"释放"分别以`malloc@GOT`和`1`作`fd`调`write`，第二次便把`malloc@libc`回写到连接，减去`0x5dca0`得到libc基址。第二段换成代码执行：槽1已清零，零主题PUBLISH命中槽2，把`free@GOT`改写成`libc_base + 0x65370`（`system`）；再取消订阅零主题，`free(topic)`的实参正好指向BSS里的命令串，等价于执行`system("cat /f* ")`，回包即带出flag。两段拼接的约束是libc基址随连接变化，泄露与利用必须共用同一条连接、同一份被改写的BSS记录；这也是为什么中间不能重连。

## 4. PoC

```c
tmp = malloc(topic_len + payload_len);
free(tmp);
if (0 < payload_len && payload_len <= 32)
    free(slot->payload);
if (subscribed_news && ping_count == 6)
    send_publish("QWB2026_News", slot->payload, payload_len);
if (payload_len > 32)
    free(slot->payload);
slot->payload = NULL;
slot->payload_len = 0;
```
```c
int16_t total = payload_len + 14 + 2;
out = malloc(total);
memcpy(out + 2 + 14, payload, payload_len);
```
```bash
python3 exp.py --local
python3 exp.py --host <目标> --port <端口>
```
