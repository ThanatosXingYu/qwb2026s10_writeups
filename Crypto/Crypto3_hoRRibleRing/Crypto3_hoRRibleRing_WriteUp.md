# hoRRibleRing

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Crypto |
| 形态 | 附件题 |
| 附件 | hoRRibleRing_387f520883f218a707f3a963fc9aa014.zip，内含task.sage（9869字节）与samples.txt（3.7 MB） |
| 目标 | 无（离线附件） |

Flag：flag{a5c0e489-a8e6-4532-b03a-f875461165cd}

## 2. 题目分析

### 样本生成本身就是一位一题

`task.sage`的核心只有几行：

```python
p = 0x3ac01f87                      # 985669511，素数
f = x^512 + 885977155*x^511 + ... + 309893591*x + 500564413   # 512 次首一多项式
n = f.degree()                      # 512

def F0():                                    # bit = 0
    s = PR([D() for _ in range(n)])           # 离散高斯，sigma=3.371
    e = PR([D() for _ in range(n)])
    a = PR([randbelow(p) for _ in range(n)])  # 均匀
    b = (a*s + e) % f
    return [a.list(), b.list()]

def F1():                                    # bit = 1
    a = PR([randbelow(p) for _ in range(n)])
    b = PR([randbelow(p) for _ in range(n)])
    return [a.list(), b.list()]

s.write("output =" + str([F0() if i == "0" else F1()
                          for i in bin(bytes_to_long(flag))[2:].zfill(len(flag)*8)]))
```

flag的每一位对应一个样本：

| bit | 样本 |
| --- | --- |
| `0` | 一条Ring-LWE样本`b = a·s + e (mod f)`，`s, e`都是σ=3.371的离散高斯 |
| `1` | `(a, b)`完全均匀随机 |

样本顺序就是flag的大端bit串，每8个样本拼一个字节。

**把环摊平成512维。**代码里`s`、`e`、`a`、`b`都是`R_p = F_p[x]/(f)`的元素，而`f`的次数是512，所以`R_p`作为`F_p`-向量空间的维数就是512，基取`1, x, ..., x^511`，一个元素等价于一个512维系数向量。乘法不是逐坐标的：先做多项式乘法，再把次数≥512的部分按`x^512 = -(f_0 + ... + f_511 x^511)`折回。但把`a`固定成常数之后，映射`s ↦ a·s mod f`是`F_p`-线性的，幂基下就是一个512×512矩阵`M_a`：第一列是`a`本身，之后每一列都是前一列“乘`x`再折回”，结构接近循环矩阵，折回系数由`f`决定。只要`gcd(a,f)=1`（`f`无重因子、`a`随机，概率约`1-1/p`），`M_a`就可逆，于是`b`与`a`之间不存在“能不能表示”的差别，能携带信息的只剩“表示系数有多小”。

### 参数核对

先做最基础的核对，这些数字后面全都用得上：

| 项 | 值 |
| --- | --- |
| `p` | `985669511 = 2^29.88` |
| `n = deg f` | `512` |
| `σ` | `3.371`（系数几乎都落在`[-15,15]`） |
| 样本数 | `336`→336 bit = `42`字节 |
| `p/σ` | `2^28.1` |

42字节正好是`flag{`+36字符UUID+`}`的长度，用这个一致性可以确认“每个bit一个样本、按大端bit序”的解读没错：

```python
>>> bits = ''.join(format(c,'08b') for c in b"flag{...}")
>>> bits[:40]   -> 0110011001101100011000010110011101111011  == b"flag{"
>>> bits[-8:]   -> 01111101                                   == "}"
>>> bits.count('0'), bits.count('1') -> 181, 155
```

即336个样本里预期有181个是F0、155个是F1，与最终读出的flag自洽。

### 判定问题归约成search-LWE

一个样本`(a, b)`满足什么？

- 若bit = 0：存在小的`s, e`（`||s||∞, ||e||∞ ≲ 15`）使`b = a·s + e mod f`；
- 若bit = 1：不存在这样的`s`。

因为`a`在`R_p = F_p[x]/(f)`中几乎必然可逆，任意`b`都能写成`a·s' + e'`（取`s' = a^{-1}(b-e')`），所以“能否线性表示”这件事本身不含信息；唯一的信息是`(s, e)`能同时很小。这正是一个标准的search-LWE：给定`(a, b)`，找小向量`(s, e)`。

**两个分布只差在一个“小”字。**严格按照分布写，`F0`输出`(a, a·s+e)`，其中`(s,e)`服从`Z^{2n}`上的离散高斯`D_{Z^{2n},σ}`；`F1`输出`(a, u)`，`u`在`R_p`上均匀。这两个分布在计算上不可区分，正是Ring-LWE的判定版本（decisional Ring-LWE）。方向上也很清楚：能区分就能在`a·Z^n`这个格上解“带噪最近向量”从而恢复`s`；反过来有了`s`就能算出`e`并检查它小不小。所以本题不是求一个全局结论，而是把同一个判定问题独立实例化336次，逐条回答0/1——每条样本的答案互不影响。

于是判定规则很干净：

> 能在格`Λ = {(p z + M_a s, s)}`里找到长度~10²的向量，当且仅当bit = 0。

其中`M_a`是“乘`a`再模`f`”这个线性映射在幂基下的512×512整数矩阵。注意这里是整数格：系数先按模`p`的中心代表元取`[-p/2, p/2]`，`p·z`负责消去`p`的倍数。

### 格建

`mult_matrix(a, f)`逐列生成`a·x^j mod f`。因为`f`首一，有

\[
x^{512}=-(f_0+f_1x+\cdots+f_{511}x^{511}),
\]

所以从`a·x^j`右移一位得到`a·x^{j+1}`时，最高位系数`top`要按上式折回低位：

```python
nxt[0] = (-top * f[0]) % p
nxt[i] = (cur[i-1] - top * f[i]) % p      # i = 1..511
```

于是`a·s mod f = Σ_j s_j · cols[j]`，`cols[j]`正好是`M_a`的第j列。取格子

```text
        ┌ p·I_n   0    0 ┐        Λ ∋ (p·z + M_a·s , s , 0)
    B = │  M_a    I_n   0 │        det Λ = p^n
        └   b      0    K ┘        Λ ∋ (b - M_a·s - p·z , -s , K) = (e, -s, K)
```

最后一行是Kannan embedding：把目标`(b,0)`塞进去。取`K=1`，并令`z`由`b - M_a s - e ≡ 0 (mod p)`逐坐标给出，则目标向量`(e,-s,K)`本身就是格里的一个向量。格的秩是`2n+1 = 1025`，行列式是`p^n`，与`s`无关，因此每个样本的格结构完全一致，只有最后一行随`b`变化。

**几处容易忽略的细节。**一是`det`怎么来：按`n + n + 1`分块，左上角`[[p·I, 0], [M_a, I]]`是下三角分块矩阵，对角块行列式相乘得`p^n·1`，末行只动最后一个坐标，所以`det B = p^n`与`a`、`b`都无关——这也是336个格“难度相同”的原因。二是`p·I`只占前`n`列：`z`的作用就是把`M_a·s`与`b`的差补齐成`p`的整数倍，让`e`落在居中代表元`[-p/2, p/2]`上；若不做居中，`e`会被写成接近`p`的正数，长度立刻变成`~p√n`，短向量根本不存在。三是最后一列只有末行有`K`：任何用到末行的整数组合末坐标都是`±K`，否则恒为0，于是`row[2n]=±1`就是“这行是Kannan行”的指纹，而`row[n:2n]`正好是被嵌入的`±s`。四是`K`取1：它只负责标记“带`b`的组合”，取大了反而拉长目标向量、削弱它与普通短向量的差距。

### gap大小与可解性

```text
dim Λ       = 2n+1 = 1025
det Λ       = p^512
det^(1/d)   = 31080
Gaussian heuristic = det^(1/d)·sqrt(d/2πe) ≈ 2.4×10^5
目标向量    ||(e,-s)|| ≈ sqrt(2n)·σ ≈ 108
gap         ≈ 2232×
```

`Λ`里“普通”的短向量长度是~2.4e5，而目标只有108，比格里的其它向量短2200倍，是一个非常极端的uSVP（unique-SVP）实例。这种“gap巨大”的实例正是BKZ最擅长的情况：不需要把格约化到很好，只要能把这一个异常向量“顶”到基里就行。

**uSVP、BKZ与“判1”的本质。** uSVP指的是`λ_2/λ_1`很大的格：这里`λ_1 ≤ ||(e,-s,1)|| ≈ 108`，其余向量的长度都在Gaussian heuristic`2.4×10^5`附近，unique gap≈2200。BKZ-β的根Hermite因子是`δ_β`，能把基中最短向量压到约`δ_β^{d}·det^{1/d}`；要让它低于`2.4×10^5`、也就是把异常向量从背景里挤出来，需要`δ_β^{1025} ≲ 2200`，即`δ_β ≲ 1.0075`，对应`β`一百以上——这就是下表`β≈120`的来源。作为对照，LLL的`δ≈1.0219`给出`1.0219^{1025} ≈ 4×10^9`，差了六个数量级，所以LLL在这里毫无希望，必须上BKZ。反过来，对bit=1的样本，格中最短向量就是约`2.4×10^5`的普通向量，`β`再大也只能把它约到`δ_β^{d}·det^{1/d}`，永远碰不到`10^2`量级；“找不到”本身就是答案，只是它只能以“约化后最短行长什么样”这种统计证据出现，必须配合复算与边界`BOUND`，而不能看到“最短行不太长”就判0。

### 环的可分解性

`f`看起来像随机多项式，其实在`F_p`上是完全可约的：用distinct-degree加equal-degree分解可以得到261个不可约因子，次数分布为

```text
deg 1: 140   deg 2: 56   deg 3: 28   deg 4: 19   deg 5: 8   deg 6: 10
```

随机512次多项式期望只有~1个线性因子，这里有140个，说明`f`是刻意构造成“光滑”的。于是

\[
R_p=\mathbb F_p[x]/(f)\cong\prod_{i=1}^{261}\mathbb F_{p^{d_i}},\qquad d_i\le 6 .
\]

直觉上会想：既然能CRT拆成261个6次以内的小域，那就在每个分量里解LWE。这条路走不通，因为误差在分量里不再小：

```text
e 的系数：        max|e_j| = 10 ~ 13                 （极小）
e mod g（deg 1）：max|centered| = 4.3e8, 2.9e8, 1.3e8  （完全均匀）
e mod g（deg 6）：max|centered| = 4.7e8, 4.4e8, 4.5e8  （p/2 = 4.9e8）
```

`e`是次数511、系数≤13的多项式，除以6次因子`g`后商的系数是~p量级的随机数，`e - q·g`把小系数彻底搅匀。所以“小”这个性质只存在于系数基（幂基）下，CRT分量里既没有小误差也没有小秘密；何况每个分量只有d个方程、2d个未知数。

结论：`f`光滑是硬化而不是软化，本题唯一有效的攻击就是整格上的uSVP。标题里的“Ring”三个R，指的就是这个“环不是域”的事实。

## 3. 解题过程

### 解析参数与样本

`f`的513个系数要从`task.sage`里抽出来，最容易出错的是`x^1`项和常数项（它们没有`*x^k`的写法）。脚本按项解析：从`f =`截到`f.degree()`，按`+/-`切成项，含`x`的取指数，其余当常数项，最后校验`x^512`的系数为1。

`samples.txt`是`output = [[[...],[...]], ...]`的形式，去掉前缀后用`ast.literal_eval`一次性读入，得到336个`(a, b)`，每个是长度512的整数列表。

这里有两个坑。第一，`bin(bytes_to_long(flag))[2:]`会丢掉flag最高字节的前导零，而`zfill(len(flag)*8)`把长度补回`8·len(flag)`，所以样本总数必然是8的倍数；336/8=42正好是`flag{`+36字符UUID+`}`，这也反向确认了解析出的样本数没多没少。第二，`b`的系数读进来已是模`p`的代表元，不需要再约化；但还原`e`时必须先`% p`再居中到`[-p/2, p/2]`，否则`b - a·s`的负值会被写成大正数，长度判断直接失效。

### 构造格子

对每个样本先算`cols = mult_matrix(a)`（512次多项式移位，每次512次乘加，纯Python约0.1秒），再按前文给出的方式拼出`1025×1025`的整数矩阵：

- 前512行是`p·I`；
- 接着512行是`M_a`的列加单位向量；
- 最后一行是`b`、零向量、`K=1`。

### BKZ约化与复算校验

约化完把每一行拿去验证，不做“看起来短就算”的判断，而是真的把`a·s + e`复算一遍：

- 只接受带`K=±1`的Kannan行；
- `s`的符号未知，`row[n:2*n]`与取负两个方向都试；
- 要求`max|s_i| ≤ BOUND`且复算出的`e = b - a·s mod f`居中后也`≤ BOUND`；
- 两向都不满足才判bit = 1。

`BOUND=40`是`12σ`，误判概率可忽略：随机行恰好让512个系数全落在`[-40,40]`里的概率是`(81/p)^512`。

注意这个校验是单边的：判0有构造性证据（真的给出了`s`，代回去误差确实小），判1只有“约化后没有任何一行通过”这个否定证据。因此流程上总是先按较低的`β`跑，通过就立刻停；只有跑完仍不通过才判1。若某样本在`β=80`下判1、在`β=120`下判0，说明是`β`不够而不是样本随机，这也正是要用更高`β`复核所有判1样本的原因。

### 复杂度：本题horrible的地方

单样本的uSVP gap决定所需BKZ block size。用标准估计条件

\[
\sigma\sqrt{\beta}\le \delta_\beta^{2\beta-d-1}\cdot p^{m/d},
\qquad m=n=512,\ d=1025
\]

得到：

| β | δ_β | RHS | LHS = σ√β | 够用 |
| --- | --- | --- | --- | --- |
| 40 | 1.01254 | 0.24 | 21.3 | 否 |
| 60 | 1.01145 | 1.03 | 26.1 | 否 |
| 80 | 1.01026 | 4.49 | 30.2 | 否 |
| 100 | 1.00926 | 15.4 | 33.7 | 否 |
| 120 | 1.00844 | 42.2 | 36.9 | 是 |
| 140 | 1.00775 | 97.7 | 39.9 | 是 |
| 200 | 1.00628 | 616 | 47.7 | 是 |

即估计器给出`β ≈ 120`。这类估计对中等`β`偏保守，实测常从60~80起，不成功再往上加。维度1025、β~100的BKZ，用`fpylll`是“几十分钟/样本”量级，用G6K（sieving BKZ）可以压到分钟级。

而题目要判336个样本：其中181个是F0，必须真的解出`s`才能判成0；另外155个无论`β`多大都找不到短向量，只能靠“跑完约化、什么也没找到”来排除。没有一个能省掉。工程上的做法是：

1. 分片：`--start/--end`把336个样本摊到多台机器/多个进程上，互不依赖；
2. 用`BKZ.Param(block_size=β, max_loops=4, flags=BKZ.AUTO_ABORT)`让它在收敛后自动提前退出；
3. 用已知明文校准`β`：`flag{`给出bit 0–39的40个已知标签、`}`给出bit 328–335的8个，先在这48个样本上跑一遍，确认“0能还原出s、1还原不出”，再放开全量；
4. 一旦某行通过复算就立即判0并停止加`β`；只有始终找不到才判1，判1时通常还要把`β`抬高再跑一遍以降低误判。

### 拼位得到flag

336个bit按样本顺序拼成字符串，每8位按大端还原一个字节：

```python
bitstr = "".join(str(bits[i]) for i in range(336))
flag   = bytes(int(bitstr[i:i+8], 2) for i in range(0, 336, 8)).decode()
```

得到`flag{...}`，其中`flag{`与结尾的`}`恰好落在第0–39位和第328–335位，与用于校准的已知明文完全一致。

拼位时有两个方向都不能错：位序按样本下标从小到大（`task.sage`的列表推导按bit串从左到右生成，即flag的大端bit序），组字节时每个字节内部高位在前（`int(bitstr[i:i+8], 2)`等价于按`<<7, <<6, ..., <<0`加权）。任一处反过来，得到的字节串长度仍是42但会是乱码；用前40位必须等于`b"flag{"`、末8位必须等于`}`这48个已知位做双向校验，可以在拼装阶段就发现位序错误，而不必回头重跑336次约化。同理，若某一位的判定存疑，它的影响仅限于对应字节，可单独复跑该样本，不必重做整批。

## 4. PoC

```python
    A = IntegerMatrix.from_matrix(build_basis(cols, b))
    LLL.reduction(A)
    BKZ.reduction(A, BKZ.Param(block_size=BETA, max_loops=4,
                                flags=BKZ.AUTO_ABORT))
    for i in range(2 * N + 1):
        if try_row([int(v) for v in A[i]], b, cols):
            return 0
    return 1

def _init(sage_path, beta):
    global F, P, BETA
    P = load_p(sage_path)
    F = load_f(sage_path)
    BETA = beta

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sage', default='task.sage')
    ap.add_argument('--samples', default='samples.txt')
    ap.add_argument('--bkz', type=int, default=80)
    ap.add_argument('--jobs', type=int, default=1)
    ap.add_argument('--start', type=int, default=0)
    ap.add_argument('--end', type=int, default=0)
    ap.add_argument('--out', default='bits.json')
    args = ap.parse_args()

    samples = load_samples(args.samples)
    end = args.end or len(samples)
    todo = list(range(args.start, end))
    bits = {i: None for i in range(len(samples))}

    if args.jobs <= 1:
        _init(args.sage, args.bkz)
        for i in todo:
            bits[i] = decide(samples[i])
            print('sample %d -> %d' % (i, bits[i]), flush=True)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs, initializer=_init,
                                 initargs=(args.sage, args.bkz)) as pool:
            for i, bit in zip(todo, pool.map(decide, [samples[i] for i in todo])):
                bits[i] = bit
                print('sample %d -> %d' % (i, bit), flush=True)

    Path(args.out).write_text(json.dumps(bits), encoding='utf-8')
    if all(v is not None for v in bits.values()):
```
