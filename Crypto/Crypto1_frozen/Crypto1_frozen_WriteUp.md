# frozen

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Crypto |
| 形态 | 混合题（附件+容器） |
| 附件 | frozen_02136a685ccd425e537aa0735795019f.zip，解压得task.py |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

官方题面只给出附件下载链接，没有任何文字提示，所有信息都要从`task.py`与服务输出里读。

## 2. 题目分析

### 服务端流程

`task.py`先跑一遍NTRU/Falcon风格的密钥生成，再用密钥的“自相关多项式”`D`派生对称密钥，把真实flag加密后输出。核心步骤：

1. `keygen(N=128, q=12289, sigma=19.16)`采样高斯多项式`f, g`（系数标准差19.16），用塔式扩展欧几里得解出`F, G`，满足

   \[
   fG-gF=q ,
   \]

   再做Babai约化控制`F, G`的范数，最后算出公钥

   \[
   h=g\cdot f^{-1}\bmod q .
   \]

2. 真正的秘密量是

   \[
   D=f\cdot\mathrm{adj}(f)+g\cdot\mathrm{adj}(g),
   \]

   其中`adj`是负循环伴随（`adj(a) = [a0, -a_{N-1}, ..., -a_1]`），所以`D`就是`f`与`g`的负循环自相关之和，系数为整数且很小。

3. `D`按十进制、逗号连接后取`fk = sha256(b"frozen:" + canon)`，密钥流为`sha256(fk || counter)`逐块拼接，异或flag得到`flag`字段。

4. 打印`pubkey`（含`h`与`rho_hint`）、`memory`（泄露的双精度浮点块）、`flag`（密文）。

：只要能还原整数多项式`D`，就能算出`fk`、解出flag，完全不需要求`f, g`。

把四个多项式都看成商环`R_q = Z_q[x]/(x^N+1)`里的元素，这套记号会更清楚：负循环乘法中`x^N = -1`、`x^{-1} = -x^{N-1}`，所以`adj(a)`正是`a`在环内的共轭（把`x`换成`x^{-1}`），于是

\[
D=a\cdot\overline{a}+b\cdot\overline{b}
\]

就是`f`与`g`的负循环自相关之和，而不是别的什么“派生量”。再看密钥关系：矩阵`[[g,-f],[G,-F]]`的行列式恰为`q`，它把`(f,g)`送到`(q,0)`，因此公钥`h=g/f`只是这个矩阵一行信息的投影，128个模`q`系数里没有`D`的直接痕迹；`D`只活在整数域。其系数量级为`sqrt(N)·sigma² ≈ 4.3×10³`，而`D[0]=|f|²+|g|² ≈ 2N sigma² ≈ 9.4×10⁴`，全都远在`2^53`以内，双精度可以逐个精确表示——这既是“取整即得”的前提，也是后面用叶子中位数估计绝对尺度的依据。

### Falcon树的中间量

`expanded_doubles()`先算四个谱`fh, gh, Fh, Gh`，再构造Falcon的LDL树：

```python
G00 = gh*conj(gh) + fh*conj(fh)
G01 = gh*conj(Gh) + fh*conj(Fh)
G11 = Gh*conj(Gh) + Fh*conj(Fh)
Ltop = G01 / G00
Dright = G11 - Ltop*conj(Ltop)*G00
return [Ltop, _T(G00), _T(Dright)]
```

`_T(E)`递归做“折半+归一化”：

```python
Ee, Eo = splitfft(E)          # Ee=(E[:h]+E[h:])/2, Eo=(E[:h]-E[h:])/(2*rho)
L = conj(Eo) / Ee
return [L, _T(Ee), _T(Ee - L*conj(L)*Ee)]
```

关键性质：

- `G00`就是`D`在2N次单位根上的取值（`G00(ζ) = D(ζ)`），所以`D`是`G00`的逆NTT；
- `Dright`由Falcon关系满足`Dright = q² / G00`，因此两个子树其实是同一个`D`的两种镜像表示；
- 树的每个内部节点只存一个`L`，它编码了两个孩子谱的比值，本身不含量纲；绝对尺度由叶子给出。

### `G00`与`D`的关系

设`ζ`是2N次本原单位根，`fh(ζ)=Σ_j f_j ζ^j`。因为`ζ^N = -1`，有

\[
\overline{fh(\zeta)}=\sum_j f_j\zeta^{-j}=\sum_j f_j \zeta^{N-j}=\mathrm{adj}(f)(\zeta),
\]

于是

\[
G_{00}(\zeta)=|fh(\zeta)|^2+|gh(\zeta)|^2
=f(\zeta)\mathrm{adj}(f)(\zeta)+g(\zeta)\mathrm{adj}(g)(\zeta)=D(\zeta).
\]

`G00`在`ζ^k (k=0..N-1)`上的N个取值正好是`D`的N点NTT，所以做一次逆变换就能取回`D`的整数系数。

再看`Dright`。令

\[
S=\begin{pmatrix}g&-f\\G&-F\end{pmatrix},
\]

由`fG-gF=q`得`det S = q`，于是Gram矩阵

\[
SS^{\mathsf T}=\begin{pmatrix}G_{00}&G_{01}\\G_{01}&G_{11}\end{pmatrix}
\]

的行列式为`q²`。因此

\[
G_{00}G_{11}-G_{01}^2=q^2
\quad\Longrightarrow\quad
D_{\text{right}}=G_{11}-\frac{G_{01}^2}{G_{00}}=\frac{q^2}{G_{00}}.
\]

这条恒等式把左右两棵子树绑定在一起：左树给出`G00`，右树给出`q²/G00`，两者是同一组未知量的两次独立观测。拟合时把右树的模型写成`2·log q - z`（`z`是左树`log G00`的参数），等价于同时使用两份数据。

### 序列化布局与被删掉的头

`expanded_doubles()`的写入顺序是：`fh`、`gh`、`Fh`、`Gh`（每个2N个double）→先序遍历的内部节点→叶子（实部标量）。

但服务端在输出前砍掉了头部：

```python
head = 8 * 128
cblob = cblob_full[head * 8:]
```

即丢掉前`8*N = 1024`个double，正好是四个谱（4×2N=8N）。剩下的`memory`布局为：

| 段 | double数 | 说明 |
| --- | --- | --- |
| `Ltop` | `2N = 256` | 根节点，N个复数（实部、虚部交错） |
| 左树内部节点 | `N*log2(N) = 896` | 先序，每层节点存`h`个复数 |
| 右树内部节点 | `896` | 同上 |
| 左树叶子 | `N = 128` | 实标量 |
| 右树叶子 | `N = 128` | 实标量 |
| 合计 | `2304` | 18432字节 |

所以按下面的方式切分就能还原出两棵树的观测：

```python
internal = n * (n.bit_length() - 1)
obs   = np.r_[mem[2*n:2*n+internal],  mem[-2*n:-n]]        # 左树内部 + 左叶子
right = np.r_[mem[2*n+internal:2*n+2*internal], mem[-n:]]  # 右树内部 + 右叶子
```

### 节点`L`的编码内容

一次`splitfft`把长度`m`的谱`E`拆成偶数位与奇数位两组，`h=m/2`，`rho_j = exp(iπ(2j+1)/m)`。记两个孩子谱为`a=Ee`、`b=Eo`，`_T`里存的节点值是

\[
L=t\cdot\rho,\qquad t=\frac{a-b}{a+b}.
\]

因为`|ρ|=1`，从`L`立刻得到`t = L\cdot\bar\rho`，进而

\[
\frac{b}{a}=\frac{1-t}{1+t}.
\]

`L`只描述“右子与左子的比值”，不携带任何绝对大小；把80个内部节点全部读完，也只能确定谱的相对形状，最后必须靠叶子（`E`的实部标量）定标。这正是拟合时“内部节点权重0.25、叶子权重取叶子中位数”的原因。

### 噪声模型：位翻转而不是加性高斯

`corrupt_blob()`对每个double的bit 0..55以及bit 63做翻转：

```python
flipbits = list(range(56)) + [63]
# 当前位为 1 时以 rho10=0.01 翻成 0；为 0 时以 rho01=0.001 翻成 1
```

这带来两类误差：

- bit 0..55：只动尾数低位，相对误差极小（`~2^-56`量级），属于“几乎无损”的抖动；
- bit 63：符号位翻转，数值直接变成相反数，属于粗大误差（gross outlier）。

粗差在`L`上有一个可检测的特征：正常的`|t| ≤ 1`，而`|ρ|=1`，所以物理上必须`|L| ≤ 1`；一旦符号被翻，`L`变成`-L`，模长仍小于1却指向反方向，或者与`|L|>1`的数值一起出现。拟合时把`|L|>1.01`和非有限值直接屏蔽，再用`soft_l1`损失压制残余的离谱点，就能把翻转样本的影响压到可忽略。

冗余还来自树本身：深度`d`的节点有`2^d`个，每个节点在同一个下标`j`上都存了一份`L`，同一位置的比值被重复测量了`2^d`次；再加上右树的镜像观测，总共2304个double全部进入拟合。

不过“只动尾数低位”说的是最常见的情形：`bit48`~`bit55`落在尾数高位甚至指数区，一位翻转就能把该double抬高或压低几倍，概率虽低，量级上却与符号翻转同属粗差。所以噪声整体是重尾的，既不是干净的高斯，也不是单纯的全有全无，鲁棒损失加掩码这两手必须同时具备。

### 自由度与冗余度

未知量只有`n/2 = 64`个实数（`G00`的共轭对称把128个谱点砍半），观测却有`2304`个double。256个double给出根节点与下一层的`L`，越往深层节点越短但数量越多，每个下标上的同一比值都有`2^d`份副本；再叠加右树的`q²/G00`镜像，等于同一组未知量被独立测量了两遍，整体冗余度约`2304/64 = 36`。冗余带来两个好处：任何单个double被毁（非有限、符号翻转、高位翻转）都不致命，去掉它仍有大量同位置副本可用；拟合残差因而能被压到`1e-10`量级，让`rint`的余量远小于`0.05`的判据。

## 3. 解题过程

### 把整棵树参数化成`n/2`维

不要逐层手工合并，而是把`log`域的谱值`z`（`n/2 = 64`维）当作未知量，用树的结构正向生成全部观测。因为`G00`是实多项式`D`在单位根上的取值，它满足共轭对称`E(ζ^{N-j}) = conj(E(ζ^j))`，所以只需要64个自由度：

```python
idx = np.minimum(np.arange(n), n-1-np.arange(n))
E   = np.exp(z[idx])            # 把 64 维参数镜像成 n 维谱
```

给定父谱`E`，两个孩子由`splitfft`决定。反过来，若已知孩子`a, b`，则

```python
A = (a+b)/2;  t = (a-b)/(a+b);  L = t*rho
B = A*(1 - t*t)
```

即：只要给出`n/2`个谱值，整棵树（所有层的`L`与所有叶子）都能确定。于是“恢复`D`”变成一个只有64个未知量、2304个观测的非线性最小二乘问题。

选`log`域而不是直接拟合谱值，原因有三：谱值恒正且动态范围有`1e5`量级，取对数后各分量才在差不多的尺度上，优化器的步长不必为最亮的点和最暗的点分别妥协；`exp`保证参数化后的谱永不越过零点，避免`t=(a-b)/(a+b)`在`a+b→0`处爆炸；而单调变换不改变极小点，`z`到每个观测的雅可比仍可由链式法则解析写出，不必退回数值差分。

### 稳健最小二乘

残差按段加权：内部节点的误差尺度取0.25（`L`的量级就是1，0.25已经是宽松上界），叶子的尺度取叶子观测的中位数（叶子是绝对量，量级差很多）。同时屏蔽非有限值与非物理值（`|L| > 1.01`）。

权重要与掩码严格同步：同一个`mask`必须同时作用在观测、尺度和雅可比的行上，否则残差向量与雅可比的行数会对不上。`bounds`把`z`限制在`log(scale0) ± 8`，即谱值允许在两个数量级内浮动：下界防止某个分量被粗差推到0附近（`log`发散），上界防止个别点吞掉全部能量；初值取全`log(scale0)`，等于先假设谱是平的，让优化器自己长出不均匀性。

右树用镜像模型`2*log(q) - z`，对`z`的雅可比取负号：

```python
rv, rj = tree_model(2*np.log(q) - z)
v = np.r_[v, rv]; j = np.r_[j, -rj]
```

这样一次调用就同时拟合了左树与右树。

求解器用`scipy.optimize.least_squares`配`loss='soft_l1'`，`f_scale`从`1e-2`逐步收紧到`1e-10`：

```python
for fs in [1e-2, 1e-4, 1e-6, 1e-8, 1e-10]:
    sol = least_squares(..., loss='soft_l1', f_scale=fs, max_nfev=150, ...)
    z = sol.x
```

为什么要分级？`soft_l1`在大`f_scale`下近似L1损失，对符号位翻转造成的整段误差不敏感，先把解拉到正确盆地；随后逐步减小`f_scale`，损失趋近L2，用剩余的干净样本把解精修到1e-10量级。若一上来就用L2，几个`-L`的粗差足以把解拖偏。

雅可比是手工推导而非数值差分：对`A=(a+b)/2`、`t=(a-b)/(a+b)`、`B=A(1-t²)`三式求导，得

\[
J_A=\frac{j_a+j_b}{2},\quad
J_t=\frac{(j_a-j_b)-t\,(j_a+j_b)}{a+b},\quad
J_B=J_A(1-t^2)-2At\,J_t,
\]

再乘上`rho`的对角项与`exp(z[idx])`的对角项，就得到每个观测对64个参数的偏导。右树把`q²/G00`写成`2log q - z`后，链式法则只多一个负号，`J`整体取反即可，两份数据的雅可比在同一轮里拼起来，避免了两次独立求解可能落到不同局部极小。

### 逆变换与取整

收敛后把`z`镜像成`spec = exp(z[...])`，再做逆NTT。注意`G00`是在`ζ^k`（2N次根）上采样、而`D`是负循环多项式，所以逆变换要带一个半格相位因子：

```python
D = np.fft.fft(spec) / n * np.exp(-1j*np.pi*np.arange(n)/n)
```

那个相位因子不是凑出来的：`G00`采样在`zeta_j = exp(iπ(2j+1)/N)`上，也就是2N次本原根只取奇数次幂，而还原`D`需要偶数次幂的均匀网格。`zeta_j^{-k}`里多出的`exp(-iπk/N)`正好补上这半个格子的偏移，所以写成`exp(-1j*pi*arange(n)/n)`；若直接调用普通的逆NTT，结果会整体错位半格，每个系数都偏一点，自相关结构也随之破坏。

理论上`D`的系数是整数，实测虚部与小数部分都在1e-10量级，直接`np.rint(D.real)`即可。为了不把错误结果当答案，脚本做两道保险：

1. 取整误差`max|raw - rint(raw)| < 0.05`，否则拒绝解密；
2. 自伴随校验`D[n/2]=0`且`D[i] = -D[n-i]`，这是`D = f·adj(f) + g·adj(g)`必然具备的对称性。

### 从`D`到flag

```python
canon = ','.join(map(str, D)).encode()
fk = sha256(b'frozen:' + canon).digest()
pt = bytes(a ^ b for a, b in zip(ct, keystream(fk, len(ct))))
```

这里必须注意三点，任何一处不同都会解出乱码：

- `D`必须是整数且按`str(int)`、逗号无空格连接；
- 前缀固定为`b'frozen:'`；
- 计数器是4字节大端。

密钥流的生成为

\[
\mathrm{ks}_i=\mathrm{SHA256}(\mathrm{fk}\parallel i_{32,\text{BE}}),\quad i=0,1,\dots
\]

拼接后截断到密文长度。

密文字段是十六进制，长度即明文长度；每32字节一个块，最后一块按需截断，块内不再做任何填充。解密结果应当是可打印ASCII且以`flag{`开头，这个检查比任何概率判据都直接：只要`D`错了一个系数，`fk`就完全不同，输出会整体变成随机字节。反过来，一旦看到`flag{`，基本可以断定`D`的128个整数全部正确——SHA-256把任何一位错误都放大成了全文不可读。

### 用公钥独立复核

若不想只依赖“取整误差小”这一条判据，还可以从`h`独立地把密钥捞回来做交叉验证。构造`2N×2N`的NTRU格基

```text
[ I  H ]
[ 0 qI ]
```

其中`H`是`h`的负循环卷积矩阵。这个格子里同时含有`(f, g)`及其全部旋转，该行范数约`sqrt(2N)·sigma ≈ 217`，与`q=12289`相比小得多，LLL就能把它直接拉出来。对候选行做系数居中（映到`[-q/2, q/2]`），检查`h·f ≡ g (mod q)`且最大系数在合理范围内，再用`D = f·adj(f) + g·adj(g)`重算一遍。两条完全独立的路径给出同一个`D`，才说明整条反演链没有踩到数值巧合；N=128时LLL只需几秒，BKZ仅在极端实例上才有必要。

## 4. PoC

```python
# 关键代码：Falcon树模型与最小二乘恢复
def tree_model(z, jac=False):
    """Preorder serialization of the Falcon LDL tree for a spectrum exp(z)."""
    n = 2 * len(z)
    idx = np.minimum(np.arange(n), n - 1 - np.arange(n))
    E = np.exp(z[idx])
    J = E[:, None] * np.eye(n // 2)[idx]
    vals, deriv, leaves, dl = [], [], [], []

    def rec(E, J):
        m = len(E)
        if m == 1:
            leaves.append(E)
            dl.append(J)
            return
        h = m // 2
        a, b = E[:h], E[h:]
        ja, jb = J[:h], J[h:]
        A = (a + b) / 2
        JA = (ja + jb) / 2
        t = (a - b) / (a + b)
        JT = ((ja - jb) - t[:, None] * (ja + jb)) / (a + b)[:, None]
        rho = np.exp(1j * np.pi * (2 * np.arange(h) + 1) / m)
        L = t * rho
        vals.extend([L.real, L.imag])
        deriv.extend([JT * rho.real[:, None], JT * rho.imag[:, None]])
        B = A * (1 - t * t)
        JB = JA * (1 - t * t)[:, None] - 2 * (A * t)[:, None] * JT
        rec(A, JA)
        rec(B, JB)

    rec(E, J)
    return np.concatenate(vals + leaves), np.concatenate(deriv + dl)

def recover(obs, n=128, verbose=False, right=None, q=12289):
    # Internal nodes encode spectral ratios; leaves determine absolute scale.
    scale0 = np.median(obs[-n:][(obs[-n:] > 100) & (obs[-n:] < 1e8)])
    if not np.isfinite(scale0):
        raise ValueError('No usable leaves')
    scales = np.r_[np.full(len(obs) - n, .25), np.full(n, scale0)]
    limits = np.r_[np.full(len(obs) - n, 1.01), np.full(n, scale0 * 100)]
    if right is not None:
        rscale = np.median(right[-n:][(right[-n:] > 0) & (right[-n:] < 1e8)])
        scales = np.r_[scales, np.full(len(right) - n, .25), np.full(n, rscale)]
        limits = np.r_[limits, np.full(len(right) - n, 1.01), np.full(n, rscale * 100)]
```
