# shadowledger

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 附件题（KVM guest内核提权） |
| 附件 | shadowledger_dcb3b5ee9fc0a77b3dfcc6934a738a99.zip |
| 目标 | 以nobody进入guest，提权到root并读取/flag |

Flag：flag{动态容器已脱敏}

题面说明：ShadowLedger是一道KVM子系统的kernel pwn。选手以`nobody`进入客户机，目标是从guest用户态提权到root并读取`/flag`。单连接最长600秒。

## 2. 题目分析

### 附件清单

`attachments.zip`包含：

| 文件 | 说明 |
| --- | --- |
| `README.md` | 题目说明、Docker/QEMU启动方式、上传方法 |
| `shadowctl_usage.md` | 账本场景与`shadowctl help/demo`说明 |
| `bzImage` | guest内核 |
| `initramfs.cpio.gz` | guest根文件系统 |
| `Dockerfile` | Ubuntu 24.04 + qemu-system-x86 + socat |
| `docker-entrypoint.sh` | `socat TCP-LISTEN:1337,fork,max-children=4 EXEC:'timeout 600 run.sh'` |
| `run.sh` | QEMU启动参数 |
| 上传协议 | 通过guest内置`upload`助手分块传入exp |

`run.sh`关键参数：

```sh
exec qemu-system-x86_64 \
  -enable-kvm -cpu host -m 256M -smp 1 \
  -kernel bzImage -initrd initramfs.cpio.gz \
  -append "console=ttyS0 quiet kaslr pti=on panic=-1" \
  -display none -vga none -no-reboot -monitor none -serial stdio -net none
```

即：guest开启KASLR与PTI，单核256MB，无网络；宿主必须支持`/dev/kvm`与嵌套虚拟化，因为guest内部还要再创建VM。

### 账本场景

`shadowctl_usage.md`把题目描述成一个“私有内存收据”的结算账本：

- 租户为某个private page发布receipt；
- 其他租户依次witness、co-sign、settle、accept、fold；
- 账本把每一步记录为entry，角色分离，单个租户无法独立完成转账；
- 窗口包括publish、certify、co-sign、settle、accept、fold、renew、revoke；
- guest内提供`/dev/kvm`与`/usr/bin/shadowctl`；
- `shadowctl demo`只走一遍普通审计路径，按设计会命中角色门禁，不会提权。

### 传输约束

guest没有网络也没有编译器，payload必须是静态二进制。guest内置`upload`助手：

```text
upload
# 粘贴 base64(gzip(exp))，每行最多512字符，以单独一行 EOF 结束
/tmp/exp
```

上传客户端按这个协议工作：等待`Launching shell as nobody`与`$ `，发送`upload`，每512字符一行分块发送，最后`EOF`，再执行`/tmp/exp`。

### guest运行态与可观测性

- 附件没有提供guest内核的`config`、`vmlinux`、`System.map`，也没有KVM的补丁源码，符号与结构体偏移只能从exp的硬编码常量和运行时泄露反推。
- 启动参数带`kaslr`与`pti=on`：内核基址随机化，用户态页表不映射内核，不能靠固定地址取符号；`nobody`也读不到`/proc/kallsyms`。
- `-m 256M -smp 1`：单核减少了并发干扰，堆布局相对确定；256MB限制了页表与slab的规模，同时也限制了大规模堆喷射，只能做小对象精确复用。
- `-net none`：guest无法外联，不能下载payload或反弹shell；`initramfs`里没有编译器、python，exp必须是静态ELF。
- `panic=-1`与`quiet`：一旦触发oops/panic，guest直接终止，串口断开，且大部分内核日志被抑制，选手看不到KASAN报告和崩溃栈。因此利用必须一次完成泄露、写原语与提权，失败只能换新guest重试。

### 上传协议与体积预算

`upload`不是文件服务，而是读串口的helper：识别单独一行`upload`后进入接收态，按行读base64文本，单行上限512字符，读到单独一行`EOF`后解码、gunzip、写入`/tmp/exp`并加执行位，最后打印`ready:`回到shell。

exp为869112字节的静态ELF，gzip -9后base64长495932字符，按512分块为969行。脚本每16行插入30ms间隔（合计约1.8秒），避免串口与行缓冲在高速写入时丢字符；上传完成后等待`ready:`，再执行`/tmp/exp; echo __SHADOW_DONE__$?`。在600秒预算里上传只占几秒，主要时间留给32次布局重试和512次slide探测。若`ready:`不出现，说明base64被截断或行协议出错，只能换连接重来。

### 账本接口与漏洞定位

##### 脚本实际使用的ioctl

附件没有内核源码或补丁diff，无法给出函数级根因。以下接口表来自对静态exp二进制的反汇编，以及脚本打印的阶段名；自定义账本ioctl的语义按调用顺序推断。

| ioctl | 来源 | 作用 |
| --- | --- | --- |
| `0xae01` | 标准KVM | `KVM_CREATE_VM` |
| `0xaee0` | 账本自定义 | 初始化账本/VM上下文 |
| `0xc040aed4` | 标准KVM | `KVM_CREATE_GUEST_MEMFD` |
| `0x40a0ae49` | 标准KVM | `KVM_SET_USER_MEMORY_REGION2` |
| `0x4020aed2` | 标准KVM | `KVM_SET_MEMORY_ATTRIBUTES` |
| `0x4040ae79` | 标准KVM | `KVM_IOEVENTFD` |
| `0xc070aee1` | 账本自定义 | publish，提交回执 |
| `0xc070aee2` | 账本自定义 | certify，认证回执 |
| `0x4070aee3` | 账本自定义 | co-sign |
| `0x4070aee4` | 账本自定义 | accept |
| `0xc050aee5` | 账本自定义 | settle |
| `0x4050aee6` | 账本自定义 | renew/其他状态迁移 |
| `0xc020aee7` | 账本自定义 | peek，读取回执字段 |
| `0x4088aeea` | 账本自定义 | 带MAC的状态检查/oracle |
| `0xaeeb` | 账本自定义 | fold/运行触发器 |
| `0xc0c0aeee` | 账本自定义 | fold准备，写入折叠记录 |

所有账本ioctl都直接作用在KVM VM fd上，说明题目是在KVM内部加了一层“收据/账本”状态机，而不是另建字符设备。

###### ioctl编码里的结构体线索

`_IOC`把方向、type、nr、size打包进32位请求号。例如`0xc040aed4`拆开是dir=3（读写）、type=0xae、nr=0xd4、size=0x40=64；`0xc070aee1`是size=0x70=112的双向请求；`0xc050aee5`与`0x4050aee6`都是size=0x50=80；`0x4088aeea`是size=0x88=136的只写请求；`0xc0c0aeee`则是size=0xc0=192。size非零意味着每条账本命令都用一个定长结构体整体进出内核，字段按固定偏移排列——这正是后面能在`0x260`、`0x2a8`位置读出key材料的原因。方向位则区分纯输出（peek）、纯输入（co-sign/accept）和双向（publish/settle/fold准备）。

自定义nr集中在`0xe0`到`0xee`，与KVM原生的`0xae01`、`0xaed4`等同属type `0xae`，说明账本复用了KVM的ioctl入口，在VM fd上按nr二次分派，没有注册新设备。这也解释了利用顺序：必须先`KVM_CREATE_VM`，再初始化账本，后续回执操作全部通过同一个VM fd完成；一旦关闭fd，账本上下文与所有回执一起销毁。

##### 漏洞：回执失效不完整导致UAF

从exp的利用原语与阶段名可以还原出漏洞轮廓：

1. 账本为每个receipt/token维护角色、nonce、key与private page引用；
2. `renew`/`revoke`只把回执标记为失效，没有撤销其他角色（peek列表、accept队列）手里持有的引用；
3. 已经失效并释放的回执仍可被`peek`或`accept`解引用，形成UAF读；
4. 回执底层与`guest_memfd`的slot/btree节点共用分配路径，释放后的slot0可以被同尺寸对象复用；
5. 复用对象里的nonce/key/函数指针可被读出，用来伪造MAC；
6. 伪造的折叠记录写回slot0后，`fold`按记录里的地址执行内核写，最终改到`commit_creds`路径。

需要强调：**具体是哪个ioctl在哪个错误分支提前free，附件材料不足以确认**。本文只描述脚本确实执行的原语与顺序，不虚构内核函数名或补丁细节。

##### 回执对象、slot与复用路径

账本至少维护三类对象：回执（角色、nonce、key、状态、指向private page的引用）、折叠记录（目标地址、写值、长度、MAC）以及由`guest_memfd`管理的slot。publish创建回执并分配slot，certify与co-sign在回执间传递引用，settle做结算，accept把回执挂入待fold队列，fold读取折叠记录并落到内核写。角色分离的目的就是让单条回执无法走完全程。

失效逻辑的缺口在于“标记”与“撤销”不是一回事：`renew`/`revoke`把回执标成失效并从活跃链表摘除，却没有清空peek缓存、accept队列以及其他回执里保存的指针。对象随后被释放回slab，但旧句柄仍可通过peek/accept进入内核，形成UAF读；当同尺寸对象（eventfd上下文、guest_memfd的slot或btree节点）复用这块内存时，旧句柄读到的已是新对象内容。利用因此分成两段：先用UAF读泄露key/nonce并确认槽可复用，再用UAF写覆盖slot0里的折叠记录，让fold按攻击者给的地址和值执行写。

##### 可用回执判据的作用

publish/certify之后脚本并不立刻peek，而是先检查`KVM_SET_USER_MEMORY_REGION2`返回结构里的flags与计数字段。该结构与账本slot共用同一段内核内存布局：只有回执落在预期slot、且region字段与账本初始化写入的值一致时，后续peek的固定偏移才指向目标字段；否则读到的是相邻对象，泄露不可用。脚本把“region字段符合预期”当成布局正确的旁证，不满足就关闭fd重建，最多32次。这不是漏洞本身，而是把slab随机化造成的不可控布局过滤成可预测布局的重试策略。

##### slide oracle的构造

`0x4088aeea`接收一个0x88字节结构体，按脚本用法包含候选slide、用泄露key算出的MAC以及期望状态。账本用自己的key对候选地址重算tag，只有tag匹配才返回“通过”状态字节。于是它等价于一个1比特判定器：`candidate = i << 21`，`i`取0到511正好覆盖x86-64默认1GB的KASLR窗口，512次ioctl即可唯一确定slide。MAC带密钥，错误候选不会因为地址碰巧可映射而误判；脚本再用`MODE2 MAC`独立复算一次，排除单比特偶然碰撞。

## 3. 解题过程

静态exp是869112字节的静态ELF（BuildID `acb9088d…`），内嵌在Python脚本里，运行时解压并上传到guest。`main()`的分支与打印字符串把整条链切成了清晰的阶段。

### 初始化与可用回执 oracle

脚本先打开`/dev/kvm`，然后最多重试32次：

1. `KVM_CREATE_VM`创建VM；
2. 账本初始化；
3. publish/certify一组回执；
4. 检查`KVM_SET_USER_MEMORY_REGION2`返回结构里的标志位与计数字段；
5. 不满足条件就关闭fd重来。

对应字符串`No usable receipt after 32 attempts`。这一步同时完成堆布局的初步筛选：只有回执落在期望slot状态时，后续`peek`才能稳定读出目标字段。

展开看，初始化阶段实际建立了两层上下文：外层是KVM的VM与`guest_memfd`，用`KVM_SET_MEMORY_ATTRIBUTES`把页标成private，再用`KVM_SET_USER_MEMORY_REGION2`把memfd映射进guest地址空间；内层是账本，用`0xaee0`建立回执表并把slot与private page绑定。publish A与certify B既产生初始回执，也顺带把账本状态推进到可settle的位置。region2返回结构被当作布局探针：单核下slab的随机化只体现在对象落在哪个页、与哪个空闲对象相邻，重建VM能重新抽一次布局，32次足以命中一个peek偏移稳定的组合。

### 泄露阶段

脚本按以下顺序读取回执内容：

```text
PUBLISH A
CERTIFY B
COSIGN F
SETTLE C
PEEK C SECRET
PEEK OLD NONCE
PEEK CRED
SHAPE
PUBLISH C PROBE
SHAPE FREE
SHAPE REFILL
eventfd
KVM_IOEVENTFD C
ACCEPT C
RENEW C
E6
PEEK KEY260
PEEK KEY2A8
```

- `PEEK C SECRET`/`PEEK OLD NONCE`/`PEEK CRED`读取回执里本应隔离的secret、旧nonce与cred字段；
- `SHAPE FREE`/`SHAPE REFILL`把回执释放后用同尺寸对象占位，验证UAF槽确实可复用；
- `eventfd` + `KVM_IOEVENTFD C`把一个eventfd挂到账本的IO事件上，用内核对象填充被释放的回执槽；
- `ACCEPT C`/`RENEW C`在槽被占位后继续推进状态，读取`KEY260`、`KEY2A8`两个偏移的key材料。

这些key/nonce既用于通过账本的MAC校验，也为后面的KASLR oracle提供输入。

`PEEK CRED`读到的cred字段是判断当前进程凭证对象位置的旁证，也提供一个可对照的堆指针；`SHAPE FREE`/`SHAPE REFILL`则是显式的UAF验证：释放回执后立刻用同尺寸对象占位，再peek看内容是否变化。若占位后仍能读到旧字段，说明旧引用没有被撤销；若读到eventfd的标记值，说明复用路径与预期cache一致。`KVM_IOEVENTFD C`把eventfd绑到账本的IO事件上，使内核分配一个可识别的eventfd上下文填充空槽，比纯用户态喷射更可控。最后的`ACCEPT C`/`RENEW C`是在槽已被占位的情况下继续推进状态机，验证失效回执仍能驱动accept与renew，并读出`0x260`、`0x2a8`两处key材料。

### KASLR slide oracle

字符串`AEEA slide`、`KASLR slide=%#lx`对应一个512候选的暴力搜索：

- x86-64 KASLR的slide按2MB对齐，脚本用`candidate = i << 21`枚举`i = 0..511`；
- 对每个候选计算一个带密钥的MAC，调用`0x4088aeea`；
- 只有slide正确时，账本返回的状态字节才与预期一致；
- 找到后打印`KASLR slide=0x...`。

随后用`SCRATCH MODE2`、`FOLD PREP MODE2`、`MODE2 MAC`再验证一次；错误候选会打印`MODE2 WRONG MAC`，避免把偶然碰撞当成slide。

这里的开销可以忽略：512次ioctl、每次只拷贝0x88字节结构体，在600秒预算里不到一秒。真正的约束是候选空间必须完整覆盖。x86-64的`CONFIG_RANDOMIZE_BASE`默认在1GB窗口内以2MB为粒度取偏移，`i << 21`与这一粒度一致；如果内核编译时缩小了`RANDOMIZE_MEMORY`范围，512仍然覆盖，不会漏解。MAC校验还要求泄露的key完整，这也是前一段必须先拿到`KEY260`/`KEY2A8`的原因：key缺字节时所有候选都会失败，表现为512次全部不通过，而不是错误命中。

### 任意写与提权

拿到slide后：

```text
SHAPE SLOT0 FREE
SHAPE SLOT0 REFILL
ACCEPT C SECOND
PATCH COMMIT_CREDS
FOLD C ROOT
uid=0
open /flag
read /flag
flag: %s
```

- `SHAPE SLOT0 FREE/REFILL`把slot0释放并用受控记录重新占位；
- `ACCEPT C SECOND`让账本接受第二条回执，使slot0记录进入fold路径；
- `PATCH COMMIT_CREDS`把计算出的内核地址与补丁值写进伪造记录；
- `FOLD C ROOT`触发账本fold，内核按伪造记录执行写操作，进程cred被改成root；
- `geteuid()`返回0后打印`uid=0`，打开`/flag`、读取并打印`flag: ...`。

`main()`末尾还会再发一次`0xaeeb`并检查`geteuid()==0`，确认提权不是偶然的返回值。

任意写的形态取决于折叠记录：记录里带目标地址、写值和长度，fold在账本上下文里按记录执行写，等价于“把受控值写到slide换算后的任意内核地址”。脚本先把`commit_creds`的运行时地址算出，再把补丁值写入对应位置；具体补丁字节（改函数前言、改调用点，还是改cred字段）附件不足以确认，但阶段名`PATCH COMMIT_CREDS`与最终的`geteuid()==0`表明写目标就是凭证提交路径。`SHAPE SLOT0 FREE/REFILL`保证slot0的旧回执被释放后由伪造记录精确占位，`ACCEPT C SECOND`让这条记录进入待fold链表，`FOLD C ROOT`才真正触发写入。写成功后不再需要第二次UAF，直接读flag即可。

### 失败模式与重试

整条链的确定性依赖三件事：布局命中、key完整、slide唯一。布局失败表现为初始化阶段32次都不满足region判据，exp自身退出；key缺失表现为`AEEA slide`全部候选不通过；slide误判则会打印`MODE2 WRONG MAC`。三种情况都不会破坏guest，换一条TCP连接就是全新内核与全新布局。相反，一旦fold执行了错误地址的写，guest通常立即panic，`panic=-1`让连接直接断开，只能重连。因此脚本把重试放在连接层，而不是在guest内循环。

## 4. PoC

```python
EXP = gzip.decompress(base64.b64decode('H4sIAAAAAAAC/...'))
blob = base64.b64encode(gzip.compress(EXP, 9))
lines = [blob[i:i + 512] for i in range(0, len(blob), 512)]
```
```python
until(s, b"token>", 20)
s.sendall(token.encode() + b"\n")
until(s, b"Launching shell as nobody", 120)
s.sendall(b"upload\n")
for i, ln in enumerate(lines):
    s.sendall(ln + b"\n")
    if i % 16 == 15:
        time.sleep(0.03)
s.sendall(b"EOF\n")
until(s, b"ready:", 120)
s.sendall(b"/tmp/exp; echo __SHADOW_DONE__$?\n")
```
```python
DONE = re.compile(rb"__SHADOW_DONE__(\d+)")
FLAG = re.compile(rb"flag:[ \t]*([^\r\n]+)")
SLIDE = re.compile(rb"KASLR slide=[^\r\n]+")
```
```text
CREATE_VM -> INIT -> KVM_SET_MEMORY_ATTRIBUTES
PUBLISH A -> CERTIFY B -> COSIGN F -> SETTLE C
PEEK C SECRET / OLD NONCE / CRED
SHAPE -> PUBLISH C PROBE -> SHAPE FREE -> SHAPE REFILL
eventfd -> KVM_IOEVENTFD C -> ACCEPT C -> RENEW C
PEEK KEY260 / KEY2A8
SCRATCH E8 -> FOLD PREP E9 -> AEEA slide MAC
KASLR slide
SCRATCH MODE2 -> FOLD PREP MODE2 -> MODE2 MAC
SHAPE SLOT0 FREE -> SHAPE SLOT0 REFILL -> ACCEPT C SECOND
PATCH COMMIT_CREDS -> FOLD C ROOT
uid=0 -> open /flag -> read /flag -> flag: ...
```
