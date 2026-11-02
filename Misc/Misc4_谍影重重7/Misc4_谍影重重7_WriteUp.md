# 谍影重重7

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Misc |
| 形态 | 容器题 |
| 附件 | manager.pcap、internal.pcap、browser.keys |
| 目标 | 10.23.8.41:3389 |

Flag：flag{动态容器已脱敏}

题面：公司收到举报，员工张纪星涉嫌未经授权访问内部核心计算机并窃取机密数据；已提取涉案设备的网络流量，需要分析通信、重建访问链路、追踪文件传输过程，查明实际获取的数据内容。题面注明人物与事件均为虚构。

## 2. 题目分析

管理侧浏览器通过PVE打开Windows虚拟机OFFICE01，操作员在该虚拟机内以`CORE01\Tsuki`登录`10.23.8.41:3389`，利用RDP磁盘重定向把Restic仓库复制回本机，最后在本地用口令解锁仓库，取出并解密`core-assets.db`。

取证对象因此分成三层：PVE管理侧的控制台画面、内网RDP连接中传输的Restic仓库、以及员工机上的加密资产库。六问分别对应这三层的中间结论，最终落到`core-assets.db`的大小与哈希。

证据之间的关系是链式的：

1. `browser.keys`是浏览器会话密钥，用来解开`manager.pcap`里的TLS，从而拿到VNC WebSocket流量，还原管理控制台画面，得到虚拟机节点与分辨率，以及操作员访问的RDP目标。
2. `internal.pcap`中的RDPDR通道承载了磁盘重定向传输的Restic仓库文件；仓库本身是加密的，口令来自控制台画面上的莫尔斯码操作。
3. 仓库内最新快照含`MouseVault.exe`与`core-assets.vault`；数字键盘每次交互后换位，需要把RFB鼠标事件与画面帧对齐才能得到键盘输入序列，该序列即保险库口令。
4. 用口令走PBKDF2-HMAC-SHA256派生密钥，AES-CBC解密并校验HMAC，得到SQLite数据库，再核验完整性、大小与哈希。

## 3. 解题过程

### 解密管理侧流量并还原控制台

`manager.pcap`是浏览器与PVE之间的HTTPS流量，密钥日志`browser.keys`为NSS key log格式。把日志交给TShark后即可解密，第68条TCP流是一次WebSocket会话，升级请求路径为：

```
/api2/json/nodes/pve-lab/qemu/219/vncwebsocket
```

由此确定节点`pve-lab`与虚拟机ID`219`，这也是第1问的提交值`pve-lab|219`。随后按TCP方向重组WebSocket负载：客户端到服务端的帧是鼠标、键盘事件，服务端到客户端的帧是RFB协议数据。

服务端先完成RFB 3.8握手（版本协商、安全类型、ServerInit），ServerInit中的宽高为`1024`×`768`，据此确定第2问的前两段。之后是Tight编码的FramebufferUpdate：每个矩形带紧凑长度前缀，按压缩控制字节选择Fill、JPEG或基本压缩，并用zlib流解压。

首个包含像素的完整更新从抓包第1939帧开始，共143个像素矩形。重组时保留普通矩形里的指针像素，不另行叠加独立光标；得到完整的一帧RGB888原始字节后，对该原始像素求MD5，而不是对PNG文件求哈希，结果为`ce1f5a34c7370f7f20038d9683f1d9b3bdc6dfc51e7db1b5f8798565dac27334`，与`1024|768`拼成第2问的答案。

画面中还包含两处关键信息：远程桌面连接窗口里的地址与账户，以及记事本里的莫尔斯码操作，后者在「从控制台操作还原仓库口令」一节使用。

### 定位RDP连接与账户

`internal.pcap`是内网流量，RDP连接的服务器地址为`10.23.8.41:3389`。X.224连接请求中的`mstshash=Tsuki`给出登录名，TLS握手中服务器证书的CN为`CORE01`，两者拼出域账户`CORE01\Tsuki`。

完成第3问后可下载`rdp.keys`。将其交给TShark即可解密RDP的TLS层，之后在MCS通道`1004`上重组RDPDR消息：先解析`PAKID_CORE_DEVICE_IOREQUEST`与`PAKID_CORE_DEVICE_IOCOMPLETION`，用完成ID把创建请求与其返回的文件句柄关联起来，再按句柄和`Offset`/`Length`把写请求的负载按偏移写回文件。

重组结果是一个完整的Restic仓库目录，包含`config`、`data/`、`index/`、`keys/`、`snapshots/`。每个数据包、索引与快照文件的SHA-256都与文件名相符，说明重组无误。

### 从控制台操作还原仓库口令

口令线索出现在远程登录之前：操作员在记事本里用鼠标敲莫尔斯码。规则是画面语义而不是按键本身——在记事本正文空白处单击是点，按住标题栏拖动是划，单击外部桌面表示一个分组结束，标题栏上仅为激活窗口的单击不计符号。

按帧时间把RFB鼠标事件与当时画面对齐后，得到分组序列：

```
-. / - / ....- / ...- / .--. / ..... / -..- / ---.. / ....- / ..--- / -.. / -..
```

逐组查表得到`NT4VP5X842DD`。该口令通过Restic的`check`校验，可以解开仓库密钥文件。仓库内两份快照时间分别为`00:23:16`与`00:23:30`（UTC+8），解密`snapshots/`下的JSON后按时间取后者，其ID为`d7d68e7ed46b6f1082ceaa797b7493e4cad96e00bc45a264bc8cf8a80960b48d`，与口令拼成第4问的答案。

### 还原键盘口令并解密保险库

最新快照里有两个文件：`MouseVault.exe`与`core-assets.vault`。员工电脑的屏幕数字键盘每次交互后都会换位，所以不能直接读按键坐标，必须把RFB鼠标事件与当时的画面帧对齐，读出点击位置对应的数字；同时剔除被取消的拖动，处理退格，并保留开头的两个零。最终得到`006187393179`，即第5问答案，也是保险库口令。

从`MouseVault.exe`的.NET IL可以读出文件格式：头部为magic、盐、IV与HMAC；密钥用PBKDF2-HMAC-SHA256、200,000次迭代从口令派生64字节，前32字节用于AES-256-CBC，后32字节用于HMAC-SHA256校验。验签、解密、去PKCS#7填充后，取出内层文件名与内容，写出`core-assets.db`。

数据库通过`PRAGMA integrity_check`返回`ok`，其中含256条资产、256条部署、512条配置修订，以及1条导出清单记录。文件大小为`2424832`字节，SHA-256为`5dec31e12a4d02f09d82e254cd752f5ba64bb254472e1111234af2c0e8441419`，拼成第6问答案。

六问结论汇总：

| 问 | 提交值 |
| --- | --- |
| 1 | `pve-lab\ | 219` |
| 2 | `1024\ | 768\ | ce1f5a34c7370f7f20038d9683f1d9b3bdc6dfc51e7db1b5f8798565dac27334` |
| 3 | `10.23.8.41:3389\ | CORE01\Tsuki` |
| 4 | `NT4VP5X842DD\ | d7d68e7ed46b6f1082ceaa797b7493e4cad96e00bc45a264bc8cf8a80960b48d` |
| 5 | `006187393179` |
| 6 | `core-assets.db\ | 2424832\ | 5dec31e12a4d02f09d82e254cd752f5ba64bb254472e1111234af2c0e8441419` |

## 4. PoC

```python
import subprocess, sys
from pathlib import Path

def export(cap, keys, display, fields, out):
    cmd = ['tshark', '-nr', cap, '-o', 'tls.keylog_file:' + keys,
           '-Y', display, '-T', 'fields']
    for field in fields:
        cmd += ['-e', field]
    with open(out, 'wb') as fp:
        subprocess.run(cmd, stdout=fp, check=True)

export('manager.pcap', 'browser.keys',
       'tcp.stream==68 && websocket.payload',
       ['frame.number', 'frame.time_relative', 'tcp.srcport', 'websocket.payload'],
       'websocket.tsv')

export('internal.pcap', 'rdp.keys',
       't124.channelId==1004 && t124.userData',
       ['frame.number', 'ip.src', 't124.channelId', 't124.userData'],
       'channels.tsv')

```

```python
import hashlib, zlib
from pathlib import Path

W, H = 1024, 768
fb = bytearray(W * H * 3)

stream = bytearray()
for line in Path('websocket.tsv').read_text().splitlines():
    parts = line.split('\t')
    if len(parts) < 4 or not parts[3]:
        continue
    if int(parts[0]) < 1939 or int(parts[2]) != 5900:
        continue                      # 首帧之前、以及客户端方向都不取
    stream += bytes.fromhex(parts[3].replace(':', ''))

def put_rect(x, y, w, h, raw):
    for yy in range(h):
        base = ((y + yy) * W + x) * 3
        fb[base:base + w * 3] = raw[yy * w * 3:(yy + 1) * w * 3]

pos = 0
rects = 0
while pos + 4 <= len(stream):
    typ = stream[pos]
```
