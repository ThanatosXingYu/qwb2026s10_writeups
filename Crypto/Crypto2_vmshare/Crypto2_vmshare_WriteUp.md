# vmshare

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Crypto |
| 形态 | 附件题 |
| 附件 | vmshare_6d3416fb746f85cad8020e41571f8b7b.zip，内含encryptor与cipher.bin |
| 目标 | 无（离线附件） |

Flag：flag{3174812_31af718}

附件两个文件：
题目是一个自定义ARX分组密码：16条`uint16`lane、每段8轮、两段28 bit密钥。目标是逆推`cipher.bin`对应的原始输入。

## 2. 题目分析

`main`位于`0x1eb0`，整体流程是“读入并校验→解析两段整数→两轮分组加密→输出32字节”。

### encryptor的整体结构

`encryptor`只是一层很薄的命令行包装：把输入的flag文本切成两段十六进制数，调用同一套核心例程完成两轮分组加密，再`write`出32字节。程序里没有网络、没有随机数、也不读取时间，因此`cipher.bin`是一个确定性的函数值。这一点决定了整道题的本质是“求一个公开函数的原像”，而不是猜测某个隐藏状态或外部密钥。

反汇编中编译器把单条lane的运算全部展开成256 bit向量指令（`vpsllw`/`vpsrlw`/`vpaddw`/`vpxor`），一次处理16条`uint16`。这不是虚拟化或解释器，而是刻意让题目看起来像一台小型SIMD机器：

| 设计点 | 具体取值 | 作用 |
| --- | --- | --- |
| 分组长度 | 16 lane × 16 bit = 256 bit | 与一个AVX2寄存器等宽 |
| 轮数 | 每段8轮，共16轮 | 短到可以手工跟踪 |
| 密钥 | 两段各28 bit，实际各24 bit | 单段穷举可行 |
| 每轮结构 | 循环移位+模加+两次异或右移 | 全部可逆 |

“两段28 bit密钥”来自flag文本里两段7位十六进制；但密钥扩展第一行就写了`v & 0xffffff`，真正进入运算的只有24 bit。这个截断既是出题人留的“可解”口子，也是后面flag多解性的根源。

### 输入校验

从`argv[1]`或`flag.txt`读取输入，并检查：

- 总长度为`0x15`（21字符）；
- 以`flag{`开头，`flag[20] == '}'`；
- `flag[12] == '_'`；
- `flag[5..11]`和`flag[13..19]`都是十六进制字符，且大小写均可。

### 密钥扩展

将下划线两侧的7个字符分别交给`strtoul(s, 0, 16)`，得到两段28 bit整数，再对每段调用`sub_1c60(v, seed)`生成8个16-bit轮密钥。两段使用的seed分别是：

- 第一段：`0x31415926`
- 第二段：`0x27182818`

密钥扩展的核心代码：

```c
h = (v & 0xffffff) ^ seed;                  // 只保留低 24 bit
h ^= h >> 13;
h *= 0x45d9f3b;
h ^= h >> 16;                               // murmur3 finalizer

for (i = 0; i < 8; i++) {
    h  = h + i * 0x7f4a7c15 + 0x9e3779b9;
    h2 = h;
    h2 ^= h2 >> 13;
    h2 *= 0x85ebca6b;
    h2 ^= h2 >> 16;
    key[i] = (h2 ^ (h2 >> 16)) & 0xffff;
    h = h2;
}
```

这里有两个细节值得记住：

- `v & 0xffffff`把每段输入截成24 bit，所以7位十六进制的最高4 bit对轮密钥没有任何影响；
- 第`i`轮先把常数`i*0x7f4a7c15 + 0x9e3779b9`加进状态，再做一次murmur3 finalizer（乘`0x85ebca6b`），取低16位作为轮密钥；下一轮的起点是本次的`h2`，因此8个轮密钥彼此串联。

### 轮函数与整体结构

加密状态初始化为`0xa80`处的32字节常量：

```text
SIMD_TINY_BLOCK_IS_A_NIGHTMARE!!
```

这32字节被解释为16条小端`uint16`lane：

```text
0x4953 0x444d 0x545f 0x4e49 0x5f59 0x4c42 0x434f 0x5f4b
0x5349 0x415f 0x4e5f 0x4749 0x5448 0x414d 0x4552 0x2121
```

紧挨着状态常量之前（偏移`0xa60`）还有一张32字节的lane常量表，按小端解释为16个`uint16`：

```text
0x1357 0x2468 0x369c 0x48ad 0x5be1 0x6cf2 0x7d03 0x8e14
0x9f25 0xa036 0xb147 0xc258 0xd369 0xe47a 0xf58b 0x069c
```

随后执行两次`sub_1cc0`，分别使用X、Y两段的密钥。每轮中16条lane相互独立，单条lane的变换为：

```text
x ^= x >> 5                         // 每次调用 sub_1cc0 时先执行一次
b = rol16(x, 3)
y = (key[i] + C_lane + b) mod 2^16
y ^= y >> 7
y = rol16(y, 9)
y ^= y >> 5                         // 第 8 轮省略
x = y
```

因此整体加密过程可以表示为：

```text
C = R(K(Y), R(K(X), S))
```

其中`S`是初始状态，`X`、`Y`是两段输入解析出的整数，`K(·)`是密钥扩展，`R(·)`是8轮变换。两次调用各自都带开头那次`x ^= x >> 5`。把上面这套结构与`cipher.bin`对照，用已知明文`flag{...}`跑一遍即可逐字节复现密文`e717f224...537527`，说明反汇编得到的常量与运算顺序都是对的。

### 三个可利用的结构性质

把轮函数放在一起看，可以得到三条互相独立的结论，第3节的整条攻击链都建立在这三条上：

1. **lane之间完全解耦。**轮函数里唯一与lane下标相关的是常量`C_j`，它是按位置固定的，不含数据依赖。因此16条lane等价于16个互不通信的16 bit小密码，共享同一组轮密钥。
2. **每段加密是双射。**单轮由`rol3`、模加、`y ^= y >> 7`、`rol9`、`y ^= y >> 5`组成，五个操作都是`GF(2)^16`上的可逆映射，复合后仍是双射。加上开头那次`x ^= x >> 5`，`R(K, ·)`整体可逆，逆函数存在且唯一，这正是反向枚举Y段的前提。
3. **密钥空间被压到`2^24`。**因为`& 0xffffff`，X、Y各自只有`2^24`种可能的轮密钥序列，且映射`v → K(v)`可以被完整枚举。

顺带得到一个推论：由于`K(·)`只依赖低24 bit，密文对7位十六进制数的最高半字节完全不敏感，所以解出的X、Y只能确定到低24 bit，flag写法天然不唯一。这一点会在「flag的等价写法」一节量化。

## 3. 解题过程

### 单lane可逆

由于各lane相互独立，给定密钥后，单lane的每一轮都可以逆运算：

- `y ^= y >> n`可以通过连续异或`y >> n, y >> 2n, ...`还原（右移后高位补0，迭代`16/n+1`次即收敛）；
- 循环左移对应循环右移；
- 模加对应模减。

于是正向一轮可以写成

\[
z=(\mathrm{rol}_3(x)+k_i+C)\bmod 2^{16},\quad
w=z\oplus(z\gg 7),\quad
y=\mathrm{rol}_9(w),
\]

最后一轮之外再补一步`y ^= y >> 5`。反向只需按相反顺序做“去末尾异或→右旋9→去异或7→减密钥与常量→右旋3”。

去异或右移之所以能用迭代收敛，是因为`x ^ (x >> n)`是一个上三角线性变换：最高的`n`个bit保持不变，随后每一位只依赖比它更高的位。因此`unxor_r(y, n)`从`x = y`出发，每迭代一次就多修正`n`个bit，`16/n + 1`次后必然稳定（`n=5`时4次，`n=7`时3次）。这保证反向过程是精确的，不涉及任何近似或暴力猜测。

另一个有用的观察是：由于lane独立，正向和反向都不必算完全部16条lane。给定密钥后，第`j`条lane的演化只用到`key[i]`和`C_j`，与其他lane的中间值无关。这为下文的“部分指纹匹配”提供了合法性——截取前3条lane不是启发式剪枝，而是严格无损的局部计算，只要这段局部结果匹配，整段密钥就必然被唯一确定（至多差一个待排除的碰撞）。

### 3-lane meet-in-the-middle

密钥只有24 bit有效位，所以正向空间是`2^24`；反向从密文出发的空间同样只有`2^24`。直接枚举`2^48`不可行，但lane之间互不影响，可以只比较前3条lane组成的48 bit指纹：

1. 正向枚举`2^24`个X，计算`R(K(X), S)`的前3条lane，拼成48-bit指纹并排序；
2. 反向枚举`2^24`个Y，从密文计算`R⁻¹(K(Y), C)`的前3条lane，拼成同样的指纹；
3. 在正向表中二分查找对应指纹。

随机假匹配的期望数量为

\[
\frac{2^{24}\cdot 2^{24}}{2^{48}}=1,
\]

所以前3条lane足够定位唯一解；命中后再用完整的16条lane重新加密一次做最终确认。总代价从`2^48`降到`2^25`量级的计算，用`numpy`分块向量化后在普通单机上几分钟内即可跑完。

工作量可以再具体一点：单次lane计算约8轮、每轮5个基本操作，正向总共`2^24`次；把候选按20 bit一块向量化后，每块`2^20`个候选只需几百毫秒。正向表用`2^24`个`uint64`存48 bit指纹，约128 MiB，内存完全可控；排序`O(2^24 log 2^24)`是整个流程最贵的一步，但仍能在一分钟内结束。反向侧不必存表，可以流式生成指纹后立刻`searchsorted`，额外内存接近零。

随机碰撞的处理也需要交代清楚：期望值1意味着实际可能得到0个、1个或少数几个候选。脚本对每个命中都做一次完整16 lane重加密，只有32字节全部相等才接受，因此多出来的碰撞会被自动淘汰，不需要人为去挑“看起来最合理”的那一个。若某次运行命中0个，说明正向表或反向式的某个细节（比如第8轮是否省略末尾异或）与实际二进制不一致，应回到2.3节逐项核对，而不是扩大枚举范围。

### 恢复结果

脚本给出的唯一命中：

```text
X = 0x174812
Y = 0x1AF718
```

用这组值重新加密初始状态，得到的32字节与`cipher.bin`逐字节相同（脚本最后会打印`cipher-ok=True`）。

校验建议分三层做，任何一层不过都说明复现有偏差：先重算两段的8个轮密钥，与手工跟踪密钥扩展的结果对比，确认`h`的串联方式没写错；再把初始常量按小端`uint16`读成16条lane，完整跑完两段共16轮，逐字节比对`cipher.bin`；最后用`encryptor`本身接收候选flag文本，确认输出文件的MD5仍是`03243ad1d8942819f4beaa67c188a578`。三层都通过，才能说明常量表、轮顺序、“第8轮省略末尾异或”这些容易出错的细节全部正确。

### flag的等价写法

密钥扩展中的`v & 0xffffff`只保留每段输入的低24 bit，因此7位十六进制数的最高4 bit不会影响轮密钥，也不会影响密文。同时，输入校验和`strtoul`都接受大小写。

所有形如下面的字符串都会得到完全相同的`cipher.bin`：

```text
flag{...}
```

其中`<h1>`、`<h2>`可以是任意十六进制字符。按7位补零写法得到`flag{0174812_01af718}`；平台侧的答案是`flag{...}`，它的低24 bit同样是`0x174812`与`0x1af718`，因此与密文完全自洽。差值只出现在被`& 0xffffff`截掉的最高半字节上：

```text
flag{0174812_01af718}  ->  X=0x174812 Y=0x1af718  == cipher.bin
flag{...}  ->  X=0x174812 Y=0x1af718  == cipher.bin（最终 flag）
flag{0174813_01af718}  ->  X=0x174813            != cipher.bin
```

把等价类数清楚会更放心。每段的低24 bit固定，最高半字节可取16种值，而校验与`strtoul`都接受大小写，所以每段共有`16 + 6 = 22`种文本形式（10个数字各1种，6个字母各2种）。此外低24 bit内部若含字母，同一数值还会因大小写再翻倍：`0x174812`与`0x1af718`的固定部分里共有`a`、`f`两个字母，每个字母两写法，合计4种组合。于是等价flag总数为`22 × 22 × 4 = 1936`个，密文对这1936个字符串完全一致，单靠`cipher.bin`无法区分，只能由平台给出“官方写法”来选定。官方取值是`h1 = h2 = '3'`、字母全小写，即`flag{...}`，其低24 bit恰好等于`0x174812`与`0x1af718`，与密文自洽。

## 4. PoC

```python
        y = (y - keys[i][:, None] - c[None, :]) & np.uint64(0xFFFF)
        y = ror(y, 3)
    return unxor_r(y, 5)

def fingerprint(lanes):
    return (lanes[:, 0] | (lanes[:, 1] << np.uint64(16))
            | (lanes[:, 2] << np.uint64(32)))

def encrypt(block, vx, vy):
    st = np.frombuffer(block, dtype='<u2').astype(np.uint64)
    for k in (schedule(vx, SEED_X), schedule(vy, SEED_Y)):
        keys = [np.full(1, t, dtype=np.uint64) for t in k]
        st = forward(st[None, :], keys, LANE_C)[0]
    return st.astype('<u2').tobytes()

def main():
    block = open('cipher.bin', 'rb').read()
    state = np.frombuffer(INIT, dtype='<u2').astype(np.uint64)
    ct = np.frombuffer(block, dtype='<u2').astype(np.uint64)

    step = 1 << 20
    fwd = np.empty(1 << 24, dtype=np.uint64)
    for base in range(0, 1 << 24, step):
        v = np.arange(base, base + step, dtype=np.uint64)
        keys = schedule_vec(v, SEED_X)
        lanes = np.broadcast_to(state[:LANES], (step, LANES)).copy()
        fwd[base:base + step] = fingerprint(forward(lanes, keys, LANE_C[:LANES]))
        print('forward', base + step, flush=True)

    order = np.argsort(fwd)
    sfwd = fwd[order]

    for base in range(0, 1 << 24, step):
        v = np.arange(base, base + step, dtype=np.uint64)
        keys = schedule_vec(v, SEED_Y)
        lanes = np.broadcast_to(ct[:LANES], (step, LANES)).copy()
        fp = fingerprint(backward(lanes, keys, LANE_C[:LANES]))
        pos = np.searchsorted(sfwd, fp)
        pos[pos >= len(sfwd)] = 0
        hit = sfwd[pos] == fp
        for idx in np.nonzero(hit)[0][:4]:
            x, y = int(order[pos[idx]]), base + int(idx)
            print('candidate X=%#x Y=%#x cipher-ok=%s'
                  % (x, y, encrypt(INIT, x, y) == block), flush=True)
            print('flag form: flag{%07x_%07x}' % (x, y), flush=True)
```
