# ez_qemu

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+容器） |
| 附件 | ez_qemu_39e1895599f72e453332331ab83b08eb.zip |
| 目标 | 从guest串口root shell逃逸到宿主，读取/tmp/flag_f |

Flag：flag{动态容器已脱敏}

题面只有一句“简单的qemu uaf”。容器内每来一个TCP连接就启动一个QEMU，选手直接拿到guest的串口root shell，目标是利用QEMU自定义设备的释放后使用漏洞，在宿主QEMU进程里执行命令并读出`/tmp/flag_f`。

## 2. 题目分析

### 容器与启动

附件压缩包内是`ez_qemu/attachments.zip`，解出后包含：

| 文件 | 说明 |
| --- | --- |
| `Dockerfile` | Ubuntu 22.04，硬校验glibc为`2.35-0ubuntu3.15` |
| `ctf.xinetd` | 监听10719，每个连接执行一次`run.sh` |
| `docker-entrypoint.sh` | 生成`/tmp/flag_f`（root:ctf 740），清空Flag环境变量后启动xinetd |
| `run.sh` | 每连接启动一个QEMU，600秒超时 |
| `guest/vmlinuz`、`guest/initramfs.cpio.gz` | guest内核与最小根文件系统 |
| `qemu/qemu-system-x86_64` | 题目修改过的QEMU，带`ctf-*`设备 |
| `qemu/pc-bios/` | QEMU启动所需固件 |

`run.sh`的关键参数：

```sh
timeout -k 5 600 "$QEMU" \
    -M q35 -m 512M -accel tcg -no-reboot \
    -display none -monitor none \
    -serial stdio \
    -device ctf-nic -device ctf-watchdog -device ctf-audio -device ctf-logger \
    -device ctf-msg \
    -kernel "$ROOT/vmlinuz" \
    -initrd "$ROOT/initramfs.cpio.gz" \
    -L "$ROOT/pc-bios" \
    -append "console=ttyS0 rdinit=/init quiet" \
    2>>/tmp/qemu_stderr.log
```

QEMU的stderr被单独重定向到日志，选手只能看到串口输出。README要求结束会话前在guest里执行`poweroff -f`，否则QEMU会在后台空跑到600秒超时才释放。

这个启动方式带来几个约束。每个TCP连接由xinetd fork一次`run.sh`，QEMU进程和五个`ctf-*`设备都是连接建立后才realize，PIE基址、堆布局、定时器对象地址每次连接都不同，exp不能跨连接复用地址。`-display none -monitor none`关掉了图形和QEMU monitor，选手唯一的输入输出是映射到socket的ttyS0；QEMU自身的stderr被`2>>/tmp/qemu_stderr.log`收走，`[CTF] ...`设备日志不会回显，调试只能靠guest侧打印。`-accel tcg`下只有一个vCPU线程，guest的MMIO回调都在该线程里串行执行，这一点决定了后面malloc arena的判断。容器里QEMU以ctf用户运行，而`/tmp/flag_f`是root:ctf 740，因此只要能在宿主QEMU进程里执行一条命令就能读flag，不需要再提权。

### Guest

`initramfs`里的`/init`非常短：

```sh
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

echo READY_FOR_ESC
exec /bin/sh
```

因此guest是root权限的BusyBox shell，可以读`/proc/self/pagemap`、访问`/sys/bus/pci/devices/*/resource0`，但没有编译器和完整libc。exp必须是静态、freestanding的可执行文件，通过串口base64+gzip上传。

initramfs里只有BusyBox，可用`uudecode`、`gzip -dc`、`chmod`，没有gcc、python和curl，所以exp必须在宿主编译成不依赖libc的静态ELF再送进去。串口是唯一通道，也是实际最脆弱的一环：ttyS0的输入队列很浅，一次性灌入几KB会丢字符，上传必须按行发送并留间隔。做法是宿主侧`gzip -9`压缩、base64编码，加`begin-base64`/`====`首尾写进heredoc；guest侧`uudecode`还原、`gzip -dc`解出约9KB的可执行文件，再`chmod +x`运行。exp内部只发原始syscall（`openat`、`pread`、`mmap`、`mlock`、`write`、`exit`），既不链接libc也不依赖`/bin/sh`。

QEMU二进制是stripped PIE，内部字符串仍保留了源码路径`qemu-7.0.0/hw/ctf/ctf-*.h`，可以据此确认五个自定义设备：`ctf-nic`、`ctf-watchdog`、`ctf-audio`、`ctf-logger`、`ctf-msg`。

### 利用过程

##### 建立BAR映射与guest物理页

exp先枚举四个BAR，`mmap`其`resource0`并打开bus master；然后`mmap`一页匿名内存，`mlock`住，通过`/proc/self/pagemap`取出guest物理地址：

```c
uint64_t entry;
pread(fd, &entry, 8, (ptr >> 12) * 8);
pa = ((entry & ((1ULL << 55) - 1)) << 12) | (ptr & 0xfff);
```

guest是root，因此pagemap的PFN可用。这块页既作为logger的DMA目的，也作为audio的DMA源，还存放NIC描述符。

枚举顺序不能错：`-device`的先后就是槽位，nic是03.0、watchdog是03.1、audio是03.2、logger是03.3。resource0的物理基址要读`resource`文件，不能假设固定值；配置空间`+0x04`的command要先读后写，置bit0/1/2打开MMIO与bus master，否则BAR访问会被丢弃、NIC的DMA也发不出去。guest页`mmap`后必须`mlock`，一旦被换出PFN就失效，DMA会写到别处。

##### 泄露PIE

向logger写入`{pa, 0x1010, 0x80, 1}`，触发越界拷贝；从guest页`+0x08`读出泄露指针，减去`0x4132c7`得到QEMU PIE基址，再加`0x2e2c90`得到`system@plt`。

四个寄存器要按地址、偏移、长度、触发的顺序写，最后一次写才真正发起DMA。校验低12位既容忍ASLR的页级随机，也能排除DMA失败留下的0；若失败，先查pagemap的PFN和bus master位。

##### 布置命令与回调

清空guest页，在`+0x08`写入`"/bin/cat /tmp/flag_f"`，在`+0x48`写入`system_plt`。配置audio：源地址为guest页物理地址，长度为`0x50`。这样audio commit会把命令串复制到定时器块`+0x08`、把回调复制到`+0x48`。

两个偏移不是随意挑的：`+0x08`是message起点，`+0x48`是回调指针，0x50的长度正好覆盖到块尾。命令串以`\0`结尾，`system`只拿到一个参数指针，不依赖其它寄存器；用绝对路径也避免了QEMU进程cwd和环境变量的影响。

##### NIC RX触发

在guest页`+0x100`构造描述符：

```c
d->a0 = bar[1] + 0x28;  d->l0 = 4;   // watchdog free
d->a1 = bar[2];         d->l1 = 4;   // audio alloc
d->st = bar[2] + 0x14;               // audio commit
```

把描述符物理地址写入NIC`+0x10/+0x14`，执行watchdog reset与7次tcache填充，最后写NIC`+0x1c`触发RX。RX完成后，宿主QEMU进程执行`system("/bin/cat /tmp/flag_f")`，flag通过QEMU的stdout（也就是串口socket）返回。

`l0=l1=4`是MMIO写的最小粒度：`a0`指向watchdog的`+0x28`，4字节写触发释放；`a1`指向audio的`+0x00`，4字节写触发分配；`st`指向audio的`+0x14`，RX收尾写常量1触发commit。释放、复用、覆盖三步都在RX回调内部完成，中间没有让出vCPU，所以旧定时器不会在覆盖前到期。收尾从栈上取出入口缓存的旧指针，读`+0x48`得到`system@plt`，把已变成命令串的`+0x08`当作唯一参数调用；`system`在宿主进程里fork出`/bin/sh -c`，`cat`的输出写到QEMU的stdout，也就是串口socket，flag直接回显在终端。

##### 串口上传与复现

上传脚本只做三件事：等到`READY_FOR_ESC`之后的`/ # `提示符、把base64按76列切行写进heredoc、执行解码与运行。每行之间留约25ms，避免ttyS0输入队列丢字符；heredoc的结束标记单独一行且不与payload冲突。解出后先`chmod +x`再执行，exp会打印PIE、`system@plt`和`[+] RX finished`，宿主侧据此判断是否进入收尾。

复现时用`gcc -Os -s -nostdlib -static -no-pie -ffreestanding -fno-builtin -fno-stack-protector`编译出guest侧ELF，放进与上传脚本相同的目录，连接容器后上传执行。收尾必须在guest里执行`poweroff -f`：`-no-reboot`下它会走关机路径让QEMU退出、连接立即关闭；若直接断开socket，这个QEMU会继续空跑到600秒超时，占用容器配额。

## 3. 解题过程

### 五个自定义PCI设备

按`run.sh`中的设备顺序，q35上依次得到`0000:00:03.0`到`0000:00:07.0`。exp只使用前四个：

| 索引 | 设备 | 作用 |
| --- | --- | --- |
| `pci[0]` | `ctf-nic` | 通过DMA描述符向guest物理地址写4字节，可触发其他设备的MMIO |
| `pci[1]` | `ctf-watchdog` | 分配/释放0x58字节的定时器对象，存在释放后使用 |
| `pci[2]` | `ctf-audio` | 分配/释放0x58字节缓冲区，并可从guest内存拷贝数据进去 |
| `pci[3]` | `ctf-logger` | 在MMIO回调栈上开0x1000字节缓冲，可按偏移DMA回guest，越界读可泄露PIE |
| `pci[4]` | `ctf-msg` | 对象创建/释放/调用，本链未使用 |

每个设备的BAR0都是0x1000字节。exp通过`/sys/bus/pci/devices/0000:00:03.N/resource0`做`mmap`，再向配置空间`+0x04`写`command |= 7`，打开MMIO与bus master。

五个设备共用同一套模板：realize时注册0x1000字节的BAR0、挂MMIO读写回调，厂商号都是0x1234。回调先用`addr & ~3`取寄存器偏移、再用`addr & 3`做字节选择，因此exp里每次`volatile uint32_t`写都是一次4字节寄存器写，跨设备写入也必须凑够4字节——这正是NIC描述符每段长度都填4的原因。NIC与watchdog共享同一个全局上下文：`dev+0xb10`存上下文指针，上下文第0项就是watchdog的0x58定时器对象。

### MMIO寄存器

以下偏移由反汇编`ctf-*`设备的MMIO handler核对得到，只列出利用链用到的部分。

**ctf-watchdog**

| 偏移 | 语义 |
| --- | --- |
| `+0x00` | 超时毫秒数，realize时默认`0x3e8` |
| `+0x04` / `+0x08` | 启动/重新装载定时器 |
| `+0x0c` | 停止定时器 |
| `+0x10` | reset：分配新的0x58对象，并`g_free`旧对象 |
| `+0x18` / `+0x1c` | 64位字段，写入设备对象`+0xb20` |
| `+0x20` | 设置message并触发处理 |
| `+0x24` | 确保定时器对象存在 |
| `+0x28` | 释放定时器对象，并把共享上下文里的指针置空 |

定时器对象由`g_malloc0(0x58)`分配，内部在`+0x08`放回调参数、`+0x48`放回调函数指针。reset只做“新分配+释放旧对象”，不会先停止已经装载的定时器，这是UAF的根源。

0x58对象的内部布局可从反汇编确认：`+0x00`是QEMUTimer指针，`+0x08`起是0x40字节message缓冲，`+0x48`是回调指针，`+0x50`是状态字。reset先分配新对象、再`g_free`旧对象、最后替换上下文指针，全程没有`timer_del`，已装载的QEMUTimer仍指向旧块；MMIO的`+0x20`写message时会把定时器按毫秒重新装载，`+0x28`则只释放不停表。默认超时是1000毫秒，这也是覆盖必须在一次RX回调内完成的原因。

**ctf-audio**

| 偏移 | 语义 |
| --- | --- |
| `+0x00` | `g_malloc0(0x58)`分配缓冲区 |
| `+0x04` | `g_free`缓冲区并置空 |
| `+0x08` / `+0x0c` | 64位guest物理源地址 |
| `+0x10` | 最大拷贝长度 |
| `+0x14` | commit：从guest源地址拷贝`min(len, 0x50)`字节到缓冲区 |

audio的0x58缓冲指针在设备对象`+0xb20`，`+0x00`仅在指针为空时分配，`+0x04`释放并置空。commit从guest物理地址读入缓冲，最多0x50字节，正好从块首写到块尾：正常使用时它写不越界，只有缓冲被换成别人的块时才会改到原主人的字段。

**ctf-logger**

| 偏移 | 语义 |
| --- | --- |
| `+0x00` / `+0x04` | 64位guest物理目的地址 |
| `+0x08` | 宿主缓冲区内的偏移 |
| `+0x0c` | 拷贝长度 |
| `+0x10` | 触发拷贝 |
| 读`+0x18` | 返回缓冲区大小`0x1000` |

触发路径在MMIO回调栈上开0x1000字节缓冲，`len`先截到0x10000，再用`0x1000 - off`算余量取较小值。`off`是32位无符号数，取`0x1010`时`0x1000 - off`下溢成极大值，min的结果就是`len`，于是源指针`缓冲+off`越过缓冲末尾，越界读到的宿主栈内容被DMA写回guest。

**ctf-nic**

| 偏移 | 语义 |
| --- | --- |
| `+0x00` / `+0x04` | 64位字段，写入设备对象`+0xb18` |
| `+0x10` / `+0x14` | 64位RX描述符guest物理地址 |
| `+0x1c` | RX触发 |
| `+0x24` | TX触发/掩码 |

RX描述符长0x28字节：

```c
struct desc {
    uint64_t a0; uint32_t l0; uint32_t r0;
    uint64_t a1; uint32_t l1; uint32_t r1;
    uint64_t st;
};
```

RX处理会从设备内部缓冲区`dev+0x1340`向`a0`、`a1`各写`l0`、`l1`字节（单段上限0x800），最后向`st`写4字节值`1`。由于`a0/a1/st`都是guest物理地址，写BAR区间时就会进入对应设备的MMIO handler，相当于让NIC替选手完成“跨设备写入”。

RX先把描述符读进来，再按两段做DMA，最后才处理`st`；三个目标都是guest物理地址，落在BAR区间时会被地址空间转发成MMIO访问，所以一次RX能按描述符顺序触发三次其它设备的寄存器写。`st`放在描述符末尾，天然成为整条链的最后一步。

**ctf-msg**

`+0x00`创建一个0x40字节对象，对象首8字节是回调指针、`+0x08`起是可打印字符串，`+0x04`释放，`+0x08`触发`obj->cb(obj+8)`。它的回调布局与watchdog同构，但对象只由本设备分配，也没有和audio共用大小类，本链用不到；保留它说明作者还准备了另一条“先建对象再调用”的路径。

### 共享上下文与释放后使用

所有`ctf-*`设备在realize时都会调用同一个取上下文函数，把返回的全局上下文指针存到`dev+0xb10`；上下文的第一项就是当前的watchdog定时器对象。

NIC的RX路径在入口处先把`ctx->timer`缓存到栈上（`[rbp-0x38]`），然后才做DMA。DMA结束时不重新读上下文，而是直接用缓存的指针：

```c
obj = ctx->timer;              // RX入口缓存
... DMA: 写 a0、a1、st ...
if (obj)
    ((void (*)(void *))obj->cb)(obj + 8);   // obj+0x48 处是回调
```

于是可以构造如下时序：

1. 在guest/vCPU线程里对watchdog执行`+0x10` reset，让新的0x58对象落在vCPU线程的malloc arena；
2. 用audio做7次`alloc/free`，把0x60的tcache填满；
3. NIC RX入口缓存`ctx->timer`；
4. RX描述符依次写watchdog`+0x28`（释放定时器）、audio`+0x00`（重新分配0x58）、audio`+0x14`（提交拷贝）；
5. 被释放的定时器块被audio缓冲区复用，拷贝内容覆盖`+0x08`的命令串和`+0x48`的回调指针；
6. RX收尾用缓存的旧指针调用`obj->cb(obj+8)`，回调变成`system`，参数变成命令串。

时序要求正来自RX的实现：RX入口只读一次上下文，把`ctx->timer`存到栈上`[rbp-0x38]`，之后写`a0/a1/st`、置中断都不再回读，收尾直接用缓存指针执行`call [obj+0x48]`，参数固定为`obj+8`。因此释放与复用必须发生在同一次RX回调内，且`st`必须在`a0`、`a1`之后：先`+0x28`还块，再`+0x00`让audio取到同一块，最后`+0x14`覆盖；顺序反了callback就仍指向原函数。另一风险是旧对象的QEMUTimer仍armed，若在覆盖完成前到期，回调会在已释放块上执行，表现为QEMU异常退出而不是拿到flag。

### Logger越界读泄露PIE

logger的0x1000字节缓冲是MMIO回调里的栈数组，但寄存器允许`off`和`len`任意设置。exp设置`off=0x1010`、`len=0x80`，`0x1000-off`下溢使实际长度保持0x80，源地址直接越过缓冲末尾。缓冲之后依次是栈canary、保存的rbp和返回地址，`off=0x1010`时输出开头是rbp，`+0x08`处正是返回地址。

在拷贝结果的`+0x08`处（即宿主`buffer+0x1018`）会稳定出现一个代码指针，低12位为`0x2c7`，等于`PIE+0x4132c7`，正是logger触发函数返回后那条指令的地址。exp的校验条件是：

```c
if ((ret & 0xfff) != 0x2c7 || ret < 0x1000000000ULL)
    fail;
base = ret - 0x4132c7;
system_plt = base + 0x2e2c90;
```

`0x2e2c90`是附件QEMU中`system@plt`的固定偏移，与泄露指针同属一个PIE。

### 0x60大小类与arena

watchdog定时器对象和audio缓冲区都是`g_malloc0(0x58)`，在64位glibc下落入`0x60`大小类。关键点有三个：

- 原始watchdog对象在QEMU主线程realize时分配，属于主线程arena；
- guest的PCI MMIO回调在TCG vCPU线程执行，通常使用另一个arena；
- 跨arena不能复用同一空闲块，所以必须先通过`+0x10` reset在vCPU线程重新分配一个定时器。

在glibc 2.35下，`g_malloc0`走`calloc`，而`calloc`不从tcache取块；`g_free`在tcache未满时进tcache，满了才进fastbin。因此先做7次audio`alloc/free`填满0x60的tcache，之后watchdog释放的块会进入fastbin，下一次audio`calloc`正好从fastbin取出这个块。0x58的请求加8字节头部正好落在0x60大小类，tcache每类7个槽，第8次释放必然改道fastbin，这正是“7”的唯一来源。较新的glibc即使`calloc`会碰tcache，这组操作也仍然可用，附件README记录的glibc 2.41同样是fastbin模式下走通的。

## 4. PoC

```python
#!/usr/bin/env python3
"""ez_qemu exploit uploader via guest serial shell. Python stdlib only.


Uses BusyBox uudecode and gzip, which are provided in the challenge initramfs.
Uploads the precompiled 9 KB freestanding ELF (compressed to ~1.7 KB),
executes it, prints host flag and sends `poweroff -f` to clean up the session.
"""
import base64
import gzip
import re
import socket
import sys
import time
from pathlib import Path

DEFAULT_HOST = "<TARGET_IP>"
DEFAULT_PORT = 0

def download_commands(binary: bytes) -> list[str]:
    packed = gzip.compress(binary, compresslevel=9, mtime=0)
    encoded = base64.b64encode(packed).decode("ascii")
    lines = ["begin-base64 644 /ez_qemu.gz"]
    lines.extend(encoded[i : i + 76] for i in range(0, len(encoded), 76))
    lines.append("====")
    print(f"[+] Payload: {len(binary)} bytes, gzip {len(packed)} bytes, "
          f"serial upload {sum(len(x) + 1 for x in lines)} bytes", flush=True)
    return lines

def run(host: str, port: int, binary_path: Path) -> bool:
    data = binary_path.read_bytes()
    lines = download_commands(data)
    with socket.create_connection((host, port), timeout=25) as sock:
        sock.settimeout(0.30)

        def send(line: str) -> None:
            sock.sendall(line.encode("ascii") + b"\n")

        def drain_until(marker: bytes, timeout: float = 45.0, echo: bool = True) -> bytes:
            deadline = time.monotonic() + timeout
            collected = bytearray()
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(16384)
```
