# bad_puppet（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | bad_puppet.zip（二进制、启动脚本与libs/运行库） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面：当剑士Hero拿到至尊魔戒，海拉鲁的冒险似乎开始变得不太一样……可以探索地图、购买物品、管理背包，并挑战敌人。

## 2. 题目分析

### 服务形态

服务是一个塞尔达主题的C++多线程网络游戏，用纯文本协议交互，一行一条命令。进程内共有6个线程：命令解析、战斗、背包、地图、商店、交易，主世界状态由命令线程统一维护。所有线程共享同一份堆，物品对象按`0x170`字节的chunk分配（可用`0x160`字节），落在tcache的索引21。

与本题相关的命令有三组：

- 商店：`shop buy <id> <count>`、`shop sell <idx>`；
- 背包：`inv list`、`inv equip <idx>`、`inv unequip <idx>`、`inv drop <idx>`、`inv sort`；
- 主世界：`mw pickup <idx>`、`mw show`、`mw whisper <slot> <hex>`。

`mw show`会打印已装备物品的字段，其中包含`description_addr=0x...`；`mw whisper`把十六进制串解码后写进物品的名字缓冲区，长度上限127字节。这两个调试命令正是后面读写原语的入口。

### 漏洞：装备槽悬空指针

`inv drop <idx>`的实现分三步：

```text
clone = clone_item(g_inventory[idx]);   // 先按物品内容复制一份
destroy_item(g_inventory[idx]);         // 再释放原块
erase_inventory(idx);                   // 最后从背包数组里删掉
```

问题出在装备表`g_equipment`：物品被装备时，指针被登记进这张表，而`inv drop`只清理背包数组，不会把同一个指针从`g_equipment`摘除。于是丢弃一件已装备的物品后：

- 原chunk已经归还tcache；
- 背包里没有这件物品；
- 装备表里还留着指向该chunk的指针。

这就是题名里的“puppet”：装备栏看到的是一个已经不存在的物品，操作它等于操作一块已释放内存。由于`mw show`和`mw whisper`都按装备槽下标取指针，这两条命令直接变成了“读已释放chunk”和“写已释放chunk”。

释放后的`0x170`chunk头部长这样：

```text
+0x00: next   tcache链表指针, 写入时做safe-linking: (chunk_addr >> 12) ^ next
+0x08: key    tcache_perthread_struct指针, 用于双重释放检测
+0x10: 物品原有字段
```

`mw show`打印这段内容就泄露出tcache的`next`、`key`和堆地址；`mw whisper`能改写`next`，也就是能指定下一次同尺寸分配返回哪里。

### 线程模型与共享状态

服务把不同职责拆成独立线程：命令线程独占socket，逐行解析文本，再把动作封装成事件投递给战斗、地图、商店、背包线程；这些线程各自消费队列，主世界状态（背包数组、装备表`g_equipment`、掉落表、物品指针表`g_puppet`）由命令线程统一维护，但堆是所有线程共用的。

交易线程的行为与其他线程不同：它不立刻执行`equip`/`unequip`，而是把请求排进队列，稍后处理时按事件里的slot下标回查“当前占用者”并克隆，释放时却使用事件入队时捕获的旧指针。这个时间差意味着，只要队列积压，克隆源和释放目标就可能不是同一个对象，一次处理会多释放一个块。这正是把tcache计数从1抬到2的唯一入口，也是题目在多线程设计上留下的第二处缺陷。

跨线程的对象生命周期没有统一保护：某个线程`free`掉的块，仍可能被另一张全局表引用。悬空指针、计数错位、任意分配三件事因此能串成一条链，而不需要单独的堆溢出。

从攻击面看，战斗与地图线程只负责推进剧情和掉落，商店线程负责买卖与释放，真正提供原语的是“命令线程持有全局表、交易线程异步克隆”这一组合：前者让`inv drop`的清理范围小于实际引用范围，后者让释放次数可以多于克隆次数。理解这一点，才能解释为什么漏洞利用不靠溢出、不靠格式化字符串，只靠普通的背包操作就能把tcache链改到任意地址。

### 物品对象与调试命令的副作用

所有物品共用一种布局，按`0x170`字节的chunk分配：对象头部依次是引用计数、尺寸、id、类型等字段，`+0xB0`附近是名字/描述缓冲区。`mw show`遍历`g_equipment`，按槽位打印`role`、`type`和`description_addr`、`description_head`、`description_key`；`mw whisper`则把十六进制串解码后写进同一槽位对象的描述缓冲区，上限127字节。两者都只按下标取指针，既不检查对象是否还在背包里，也不检查它指向的块是否已释放，所以物品一旦被丢弃，这两条命令就分别退化为“读已释放chunk”和“写已释放chunk”。

`mw whisper`还有类型限制，只接受`RingItem`。这解释了整条链为何始终围绕至尊魔戒：只有戒指能承载后续127字节的写原语，丢弃、复制、投毒都必须以它为载体。

### 关键偏移

| 名称 | 值 |
| --- | --- |
| `main_arena`相对libc | `0x204ac0` |
| `environ`相对libc | `0x20bd58` |
| `system`相对libc | `0x58750` |
| `/bin/sh`相对libc | `0x1cc42f` |
| `pop rdi; ret`相对libc | `0x10c08d` |
| `command_loop`返回地址相对PIE | `0x5118` |
| 返回地址栈槽相对`environ` | `-0x278` |
| 物品chunk大小 | `0x170` |
| `g_puppet`指针表相对堆基址 | `0xcf0` |
| `malloc_state`相对堆基址 | `0x8a0` |
| 伪chunk大小 | `0x101` |

## 3. 解题过程

### 经济漏洞：买炸弹

商店在算钱时把单价与数量截断为32位相乘，而发货数量按64位累加。传入`0x100000001`：

```text
价格计算: (uint32)0x100000001 = 1   -> 只收 1 × 64 = 64 卢比
发货数量: (uint64)0x100000001       -> 实际到账 4294967297 个炸弹
```

于是用64卢比换到42亿个炸弹：

```text
shop buy 3 0x100000001
```

### 击杀Boss拿戒指

传送到城堡并进入战斗，用炸弹把Boss秒掉。Boss死亡后在原地掉落至尊魔戒，捡起并装备：

```text
map teleport castle
battle
use item 1 32        # 物品槽1的炸弹, 一次用32个
mw pickup 0
inv equip 2
```

戒指就是后面所有操作的载体：它既要被装备（进入`g_equipment`），又要被丢弃（触发悬空），还要能反复复制（每次`inv drop`都会先生成一份克隆）。

### 泄漏堆地址与tcache状态

装备戒指后执行`mw show`，输出里有：

```text
[1] role=Ring ... description_addr=0x55xxxxxxxxxx   # 高两位恒为0x55, 后10位随机
```

这个地址就是戒指物品chunk的地址，记作`A`。接着丢弃它：

```text
inv drop 2
```

丢弃动作把`A`放回tcache，但装备槽仍指向`A`。再次`mw show`，打印的就是`A`处的tcache头：

- `A+0x00`是`next`，由于bin里只有它自己，值为`(A>>12) ^ 0`，右移12位异或即可还原出堆页地址；
- `A+0x08`是`key`，指向tcache管理结构，能确认它确实在tcache里而不是fastbin。

这一步同时给出两个结论：`A`的地址已知，且`A`当前位于tcache索引21的表头。

### 把tcache计数做到2

只丢一次不够用。`inv drop`的执行顺序是“先克隆、后释放”，克隆本身要从同一个bin里取一块，取完再释放原块，净效果是bin里始终只有1个空闲块。要让第二次`malloc(0x170)`返回到攻击者指定的地址，必须让bin里有2个块：第一次弹出`A`，第二次弹出被污染的`next`。

办法是制造一次“克隆的是当前占用者、释放的却是事件里旧指针”的错位。交易线程会把交易请求排队，处理时按slot取当前占用者克隆，但释放用的是事件入队时捕获的指针；当这两者不是同一个物品时，就会多释放一个块而不少克隆，bin计数加1。

用`inv equip 0`与`inv unequip 0`交替400次灌满交易队列，让队列积压到处理线程跟不上，再连续丢两件物品：

```text
inv equip 0 / inv unequip 0  ×400
inv drop 0
inv drop 1
```

积压期间事件里的旧指针与slot当前占用者错开，`A`被重复计入tcache，计数变成2。判断成功的标志是随后`shop buy 0 2`能连续弹出两个块，第二次即落到被污染的`next`。

### tcache投毒与任意地址分配

计数为2后，把`A`的`next`改成目标地址`T`。由于safe-linking，写入值必须是`(A>>12) ^ T`，直接写`T`会在解码时得到错误地址。同时还要为`T`准备一个合法的chunk头，否则`malloc`在返回`T`之后、下一次取块时会因为size字段非法而崩溃。

`mw whisper`最多写127字节，把目标块选在`A+0x80`就能一次覆盖两处：

```text
T = A + 0x80
payload[0x00:0x08] = (A >> 12) ^ T      # 覆盖A的next
payload[0x08:0x10] = 0xAA...            # 填充, 破坏key即可
payload[0x78:0x80] = 0x101              # T-8处的伪chunk大小, PREV_INUSE置位
```

`T-8 = A+0x78`正好落在`payload[120]`，所以127字节足够。伪大小的低3位要满足：`PREV_INUSE=1`、`IS_MMAPPED=0`、`NON_MAIN_ARENA=0`，即`0x101`。

投毒写两遍，两个装备槽都指向同一个已释放块，保证无论命令线程先取哪个槽，写到的都是`A`：

```text
mw whisper 0 <payload>
mw whisper 1 <payload>
```

然后连续买两次同尺寸物品：

```text
shop buy 0 2
inv sort
```

第一次`malloc(0x170)`弹出`A`；第二次按`A`的`next`解码得到`T`，直接把`T`返回。物品克隆的128字节内容随之写进`T`，`T-8`的伪chunk头也已就位，于是得到“在任意地址分配一块0x170并写入127字节”的能力。

### 任意读：劫持物品指针表

全局物品指针表`g_puppet`用来给`inv list`提供条目。把`T`选成这张表的地址，克隆数据就会覆盖表项，`inv list`遍历时会把表项当成物品指针，打印其前8字节。

表地址由交易线程克隆块的地址`C1`推出：堆区按16MB对齐，`P = C1 & ~0xFFFFFF`是堆基址，`g_puppet`位于`P+0xcf0`。因此取：

```text
T = P + 0xcf0
```

为了读出地址`X`的内容，把待读地址重复填进克隆数据（每8字节一个`X`），分配落到表上后，各条目都指向`X`，`inv list`打印的条目编号就是`*(uint64_t*)X`：

```text
inv list
[*] [0] #140234...  ...
```

解析这些十进制数即可。一次读8字节，循环换`X`就能遍历任意内存；读到的值如果不像地址，说明该次分配没落在表上，重跑一次投毒即可。

### 泄漏libc：main_arena

远程靶机的堆落在`0x55...`段，也就是主arena（main arena），因此arena的`malloc_state`就在libc里。指针表所在堆区对应的`malloc_state`位于`P+0x8a0`，读它的`next`字段：

```text
leak = *(uint64_t*)(P + 0x8a0)
libc_base = leak - 0x204ac0
```

`0x204ac0`是glibc 2.39中`main_arena`相对libc基址的偏移，`next`指向arena自身的bin数组，所以减去该偏移即得基址。校验方式是回读`libc_base`前4字节，等于`\x7fELF`才继续。

### 栈地址与返回地址

拿到libc后，`environ`的地址就是`libc_base + 0x20bd58`，用同一个任意读取出它的值，得到当前环境指针所在的栈地址。

命令线程的`command_loop`在处理完一条命令后从栈上返回，它的返回地址就保存在`environ - 0x278`这个槽位，且该槽位相对`environ`的偏移固定。对应代码地址是`PIE + 0x5118`，属于`command_loop`的调用点。

### 写ROP并退出

把分配目标换成`environ - 0x278`，用同一套投毒让克隆落到该栈槽，写入三段：

```text
[environ-0x278] = libc_base + 0x10c08d   # pop rdi; ret
[environ-0x270] = libc_base + 0x1cc42f   # "/bin/sh"
[environ-0x268] = libc_base + 0x58750    # system
```

投毒时把伪chunk大小放在目标前8字节，`0x101`即可让`malloc`接受这块“栈上的chunk”。写完后向服务发送`quit`，命令线程从`command_loop`返回，栈上的返回地址被ROP链接管，执行`system("/bin/sh")`，随后在同一个连接里执行`cat /flag`取回内容。

### 两种运行方式下的堆布局差异

同一条链在直接运行附件和打远程服务时并不是完全同构的。按附件`libs/`启动时，进程先建立主线程堆，物品块常由某个工作线程首次触发分配，落地在`0x7f...`的thread arena；远程容器里连接建立较晚，`0x170`的块直接从`0x55...`主堆切出，归属main arena。

这个差别直接决定libc泄漏走哪条路。thread arena的`malloc_state`位于mmap出来的堆段，不在libc里，用`P+0x8a0`读到的`next`只是arena内部指针，减去`main_arena`偏移得不到基址，校验`\x7fELF`必然失败。远程的main arena把`malloc_state`嵌在libc数据段，`next`指向libc内的bin数组，减法才成立。若只能拿到thread arena，需要先把tcache索引21填满7个（连续`shop sell`戒指，商店线程只释放不分配，不会立刻把块取回），第8个块落入unsorted bin，其`fd`/`bk`才是arena附近地址。

堆基址推导同样依赖环境：`P = C1 & ~0xFFFFFF`成立的前提是堆段16MB对齐，`g_puppet`与`malloc_state`相对`P`的偏移是在同一构建、同一启动方式下测出的，换libc或改变线程初始化顺序都要重新确认。PIE偏移、`environ`偏移和返回地址栈槽偏移则相对稳定，可以跨环境沿用。

靶场重建后ASLR会给出新的堆、libc与栈地址，链条本身不需要改，只要每一轮都重新完成“泄漏堆地址、确认bin头、读arena、读environ”的顺序，不能复用上一轮的绝对地址。若远程恰好切换了运行库，首先失效的是`main_arena`、`environ`、`system`这几个libc偏移，堆表偏移次之。

### 时序与稳定性

整条链对命令顺序敏感，容易出错的点集中在四处。

第一是队列积压。`equip`/`unequip`必须成批快速写入，让交易线程处理速度落后于入队速度；若逐条等待回显，事件被即时消费，旧指针与当前占用者不会错开，计数仍旧是1。积压后要留足等待时间再发丢弃命令，否则丢弃事件可能插到旧事件之前。

第二是bin头。`A`必须始终是索引21的表头，中途任何一次额外的`0x170`分配（拾取、克隆）都会把链打乱，因此投毒前后的命令次序不能调换；两个装备槽写同一份payload，是为了回避命令线程取槽顺序的不确定性。

第三是伪chunk头。目标块大小必须低三位满足`PREV_INUSE=1`、`IS_MMAPPED=0`、`NON_MAIN_ARENA=0`，即`0x101`；写成`0x100`或带上其它标志位，`malloc`在取块或下一次遍历时就会中止进程。

第四是读结果判定。表项被覆盖后`inv list`打印的是十进制，数值过小说明该次分配没有落到表上，应重新做计数与投毒；`main_arena`读回后要用libc头四字节自检，`environ`的值应落在`0x7ff...`区间，栈槽写入后必须由`quit`触发返回才生效，提前断开连接只会丢掉ROP。

## 4. PoC

```python
#!/usr/bin/env python3
# bad_puppet 完整利用: 悬空装备槽 -> tcache投毒 -> g_puppet指针表任意读 -> 栈上ROP
import re
import socket
import struct
import time

HOST, PORT = "<TARGET_IP>", 0

def p64(x):
    return struct.pack("<Q", x)

class Game:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=8)
        self.s.settimeout(0.3)
        self.buf = b""
        self.read(1.5)

    def send_raw(self, data):
        self.s.sendall(data if isinstance(data, bytes) else data.encode())

    def read(self, wait=0.8, quiet=0.3):
        out = b""
        end = time.time() + wait
        last = time.time()
        while time.time() < end:
            try:
                chunk = self.s.recv(65536)
                if not chunk:
                    break
                out += chunk
                last = time.time()
            except socket.timeout:
                if out and time.time() - last > quiet:
                    break
                time.sleep(0.02)
        self.buf += out
        return out.decode("latin-1", "replace")

    def cmd(self, line, wait=0.8, quiet=0.3):
        self.send_raw(line + "\n")
        return self.read(wait, quiet)

    def close(self):
```
