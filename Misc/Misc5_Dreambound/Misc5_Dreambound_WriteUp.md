# Dreambound

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Misc |
| 形态 | 混合题 |
| 附件 | model.py、checkpoint.pt（4,245,557 B）、requirements.txt |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

题面：**Dreambound** — "Try to dream hallucinate."

## 2. 题目分析

### 思路概要

附件直接给了一个**完整的世界模型和权重**：服务端接收48步离散动作（每步5选1），用模型"想象"（`imagine`）未来48步的奖励并求和作为分数，分数过阈值就给flag。所以这题不是盲打，而是**离线把模型当白盒，搜一条让reward head输出爆炸的动作序列**，再在线提交。

最终这条序列把GRU隐状态推到分布外，单步reward最大冲到**564**，48步合计1290。

### 附件分析

```text
dreambound/
├── checkpoint.pt    4,245,557 B   torch.save({"config": {}, "state_dict": ...})
├── model.py         1,715 B       模型定义 + imagine() + load_checkpoint()
└── requirements.txt               torch>=2.0, numpy>=1.24
```

`model.py`核心：

```python
OBS_DIM, ACT_DIM, H_DIM = 4, 5, 384

class WorldModel(nn.Module):
    def __init__(self, obs_dim=4, act_dim=5, h_dim=384):
        self.gru           = nn.GRUCell(act_dim, h_dim)          # 5 -> 384
        self.decoder       = Sequential(Linear(384,256), ReLU(), Linear(256,4))
        self.reward_head   = Sequential(Linear(384,512), ReLU(),
                                        Linear(512,512), ReLU(), Linear(512,1))
        self.continue_head = Sequential(Linear(384,128), ReLU(), Linear(128,1))

    def step(self, h, a_onehot):  return self.gru(a_onehot, h)
    def predict_reward(self, h):  return self.reward_head(h).squeeze(-1)
    def decode(self, h):          return self.decoder(h)

@torch.no_grad()
def imagine(model, actions):          # actions: (B, T) 的 long
    h = model.initial(actions.shape[0], actions.device)
    rewards = []
    for t in range(actions.shape[1]):
        a = F.one_hot(actions[:, t], model.act_dim).float()
        h = model.step(h, a)
        rewards.append(model.predict_reward(h))
    return torch.stack(rewards, dim=1)   # (B, T)
```

`checkpoint.pt`用`torch.load(..., weights_only=False)`直接可读，只有`config`（空字典）和`state_dict`两个键。加载后统计：

| 项 | 值 |
| --- | --- |
| 总参数量 | **1,059,718** |
| GRU `weight_ih` | `[1152, 5]`（3×384门） |
| GRU `weight_hh` | `[1152, 384]` |
| 隐状态维度 | 384 |
| 动作维度 | 5（0–4） |
| 序列长度 | 48（服务端错误信息给出） |

解码头`decode`和`continue_head`在这题里没被服务用到，真正参与打分的只有**GRU + reward_head**。

### 模型的想象结果

`WorldModel`是一个隐空间世界模型：它不预测画面，而是把历史压进384维隐状态`h`，再用三个头分别解码观测、奖励和终止信号。`gru`是`GRUCell(5, 384)`，每步只吃一个5维one-hot动作：

```text
r_t = σ(W_r a_t + U_r h_{t-1} + b_r)
z_t = σ(W_z a_t + U_z h_{t-1} + b_z)
n_t = tanh(W_n a_t + U_n (r_t ⊙ h_{t-1}) + b_n)
h_t = (1 - z_t) ⊙ n_t + z_t ⊙ h_{t-1}
```

三个门各384维，所以`weight_ih`是`[1152, 5]`、`weight_hh`是`[1152, 384]`。输入只有5维，携带的信息极少，`h_t`主要由`h_{t-1}`和固定偏置决定，动作序列的作用更像"沿着一条轨迹持续轻推"；真正把`h`推远的不是某一步的神来之笔，而是几十步同向累积。

`reward_head`是`384→512→512→1`的MLP，中间ReLU、末端线性。ReLU让它在`h`上分段线性，末端无激活意味着**输出没有上界**：只要`h`落进某个"高奖励扇形"，单步reward可以任意大。`decoder`（`384→256→4`）和`continue_head`（`384→128→1`）分别是观测重建与终止预测，属于训练世界模型时的辅助头，打分时完全不参与。

`imagine()`就是"在隐空间里做梦"：从零状态出发喂48个动作，逐步取reward，全程不回真实环境。所以分数衡量的不是"这条策略真能拿多少分"，而是"模型相信它能拿多少分"——题面"Try to dream hallucinate"说的正是这件事。

### 动作空间与搜索规模

服务端要求恰好48个`[0,5)`整数，组合数`5^48 ≈ 2.8×10^33`，穷举无望；但单条评估极便宜：48次384维`GRUCell`加48次小MLP，CPU上批量算上百条也在毫秒级。这种"维度中等、评估廉价、目标确定"的结构适合基于邻域的启发式搜索。每步只有5种取值，邻域也规整：固定其余47步、枚举某一步的另外4种，一次全扫描正好`48×4=192`条，可以一个batch前向算完，这直接决定了后面的坐标下降方案。

### 白盒给

附件把模型定义和`state_dict`一起给出，等于把评分函数原样交出：可以离线复现分数、看任意时刻的`h`、对输入求梯度、无限次批量评估而不受服务端限速。黑盒只能一次次提交换回一个标量，既慢又看不到中间量。所以本题难点不在"猜打分逻辑"，而在"对一个已知函数做组合优化"。

同时这也暴露了设计缺陷：服务端直接对48个reward求和，**不clip单步奖励、不约束隐状态范数、也不检查动作是否落在训练分布内**，模型在分布外给出的荒谬高奖励会被照单全收。

### 阈值的大致位置

常量策略已经给了参照：全0是7.15、全1是-63.12、全3是24.80、全4是170.51。全4是常量里最好的却仍不返flag，说明阈值明显高于170；按此类题的常见设置，大概率是1000这样的整数。必须找到比最好的常量策略还高数倍的序列，"稍微调一调"到不了，只能真正把隐状态推到模型没见过的区域。

### 从防御视角看

这题本质是**奖励模型被对抗性策略利用**：

- 世界模型/奖励模型在训练分布内很准，但对分布外的隐状态会输出荒谬的高奖励；
- 如果这是真实的RL训练/评估系统，攻击者可以构造动作序列骗过reward model，得到虚高的评估分（reward hacking）；
- 缓解思路：奖励模型集成/不确定性估计、隐状态范数约束、动作序列分布约束（KL/支持集限制）、对抗训练、以及把"想象评估"和"真实环境评估"交叉验证。

## 3. 解题过程

### 服务侦察：它不是HTTP

#### 第一反应：nc / socket

```text
$ nc * *
（无 banner，等 60 秒也没有任何输出）
```

用Python连上后发送`\n`、`0\n`、`hello\n`再半关闭，全部**没有任何响应**；连接会被静默关闭。

#### 误以为HTTP

用`curl`发GET：

```bash
curl -v http://*:*/
```

结果非常怪：

```text
* Received HTTP/0.9 when not allowed
< {"ok": false, "error": "bad submission: want {\"actions\": [48 ints in [0,5)]}"}
```

- 服务**没有回状态行/响应头**（HTTP/0.9风格），只吐了一个JSON body；
- 但这个body把期望的格式写得明明白白：`{"actions": [48 ints in [0,5)]}`。

于是按它说的发：

```bash
curl -s -X POST http://*:*/ \
     -H 'Content-Type: application/json' \
     -d '{"actions":[0,0,...,0]}'
```

依旧`bad submission`。换成`compact`写法、`text/plain`、少一个元素、全4、GET query……**全部都是同一条错误**。

#### 真正的协议：裸TCP上的一行JSON

把JSON **不带头**直接写到socket上：

```python
s = socket.create_connection(("*", *))
s.sendall(b'{"actions":[0,0,...,0]}\n')
print(s.recv(4096))
```

```json
{"ok": true, "score": 7.1452}
```

成了。

#### 协议实验汇总

| 发送方式 | 结果 |
| --- | --- |
| HTTP `POST /` + body `test` | `bad submission` |
| HTTP `POST /`+合法JSON body（带请求头） | `bad submission` |
| JSON放在请求行里`POST {json} HTTP/1.0` | `bad submission` |
| JSON当作header `X-Actions: {json}` | `bad submission` |
| `GET /?actions=[...]` | `bad submission` |
| 裸socket发JSON，**不带换行**后半关闭 | 空响应（服务端按行读，没读到完整行） |
| 裸socket发JSON + `\n` | `{"ok": true, "score": ...}` ✅ |
| 裸socket发JSON + `\r\n\r\n` | 同上 ✅ |

结论：服务端是**按行读取**的极简实现，拿到一整行后`json.loads`；带HTTP请求头时第一行是`POST / HTTP/1.1`，解析必然失败，于是统一回`bad submission`。

### 逆向打分函数

#### 先猜：`sum(imagine(...))`

`imagine()`返回`(B, T)`的reward。服务只回一个`score`，最自然的是`sum`。

用**全1**序列做指纹最干净（数值小、特征明显），代码见第 4 节 PoC。

服务端：

```json
{"ok": true, "score": -63.1219}
```

**完全对上了**（四位小数）。打分函数确认：

```text
score(a) = Σ_{t=1..48} reward_head( GRU(one_hot(a_t), h_{t-1}) )
```

#### 常量动作基线

| 序列 | 离线`sum` | 服务端`score` |
| --- | --- | --- |
| 全0 | 7.146025 | 7.1452 |
| 全1 | **-63.121872** | **-63.1219** |
| 全2 | -208.885254 | — |
| 全3 | 24.797272 | — |
| 全4 | 170.508408 | 170.5086 |

（离线值与服务端有~1e-3的尾差，来自torch版本/浮点累加差异，不影响判断。）

全4已经能到170.5，但服务**不返flag**——说明阈值明显更高。

#### 排除均值、最大值与折扣

只对上了一个数还不够，要排除"服务端算的是均值或最大值"。均值假设可以直接否掉：全4的均值只有3.55，服务端却返回170.5086；最大值假设也不成立，全1与全4的稳态单步reward不会差出233。所以只能是求和。若还想确认有没有折扣因子，可做前缀截断：把同一序列截到前24步、前12步分别提交，若返回值和离线对应前缀的累加一致，就说明没有`γ`——有折扣时截断后的比值会随长度漂移。

### 问题形式化

```text
maximize  f(a) = Σ_{t=0}^{47} reward_head(h_t)
s.t.      a_t ∈ {0,1,2,3,4},  h_t = GRU(one_hot(a_t), h_{t-1}),  h_{-1} = 0
```

- 搜索空间`5^48 ≈ 2.8×10^33`，暴力不可能；
- 但模型完全已知、推理极快（48步GRU，384维）；
- 目标是**单目标最大化**，可以用"批量评估+局部搜索"。

先看解的形态：`reward_head`最后一层是线性的，GRU隐状态被`tanh`限幅在`[-1,1]`，但384维全饱和时，线性层输出仍然可以很大。**只要把隐状态推到某个极端区域，单步reward就能爆**。这正是题目名"dream hallucinate" —— 让世界模型"梦见"不真实的高奖励。

把48步的单步reward单独拆开看，地形比总分更说明问题：常量策略很快进入稳态，全4大约每步3.55，全2则是负的-4.35；而最优序列前12步只在-6.37到31.86之间小幅波动，第36、37步却突然冒出526和564，同时全程有17步是负的。高总分并不是"每步都好"，而是**先铺垫、后引爆**——前面几十步负责把`h`送进奖励头的极端扇区，一旦进入，单步输出就脱离正常量级。这种"少数步贡献绝大部分分数"的形态意味着目标高度多峰、峰很窄，也就排除了任何依赖平滑性的优化器。

### 方法一：梯度法（行不通）

既然模型可导，直觉是先做连续松弛：把`48×5`的logits当参数，用Gumbel-softmax采样软动作，前向换成one-hot、反向把梯度灌回soft值，即straight-through估计。温度`τ`从2.0线性退火到0.3，前期软、后期硬，指望logits逐渐逼近one-hot分布。实现见第 4 节 PoC。

纸面上这条路很顺：`GRUCell`和两层MLP都可导，48步展开就是一张现成计算图，`total`对`logits`的梯度能一路反传。但实际跑600步、多个随机种子，最好的离散结果只有：

```text
best = 28.26
```

比全4（170.5）还差。

**原因**：

1. GRU是逐时间步递推的，soft输入（5维概率向量）和one-hot输入产生的轨迹差异很大，梯度指向的"软最优"在argmax后不成立；
2. reward对输入非常敏感（「这条序列的分布外」一节的单点扰动数据改一个动作分数能从1290掉到200），软松弛把这种尖锐性抹平了；
3. 目标不是平滑函数，局部梯度几乎无意义。

还有一层更本质的问题：即使梯度方向是对的，离散动作也没有"步长"可调。logits动一点，argmax可能纹丝不动，也可能整步翻转，梯度给的是局部斜率而不是可执行的离散更新；再加上48步递推中每步雅可比连乘，长程依赖上的梯度要么消失要么被放大，指向的方向在argmax之后往往并不成立。白盒梯度能告诉你"往哪边软一点会更好"，却回答不了"把哪一步改成哪个整数"。

结论：**这题适合离散搜索，不适合梯度**。

### 方法二：批量离散搜索（成功）

#### 批量评估

一次前向评估B条序列，充分利用CPU向量化，批量打分函数见第 4 节 PoC。

单条评估约0.1 ms量级，一次评估192条邻域毫无压力。

#### 坐标下降

固定其余47个动作，枚举第t个动作的5种取值，取最优，实现见第 4 节 PoC。

一次完整扫描评估`48×4 = 192`条，几轮就收敛到局部最优。

#### 随机扰动跳出局部最优

坐标下降只能到局部最优，所以外层加"踢两脚"，外层循环见第 4 节 PoC。

#### 实际收敛过程

从全4出发，记录每一轮的最优值：

```text
start   : 170.5084        # 全 4
round 0 : 741.1721        # 第一轮坐标下降就翻了 4 倍多
round 1 : 759.4033
round 5 : 778.4235
round 8 : 780.0279
round 9 : 1054.5375       # 突破 1000
round 10: 1183.2273
round 12: 1239.5614
round 14: 1290.2621       # 收敛
round 15–29: 1290.2621    # 不再提升
```

耗时在分钟级（纯CPU，torch 2.10.0+cpu）。

#### 最优序列

```python
BEST = [2,1,2,2,1,0,0,0,3,4,0,0,2,0,2,4,1,0,0,4,2,3,0,3,
        0,2,0,3,3,4,3,2,3,3,3,3,2,2,0,0,0,0,0,0,1,0,0,3]
```

离线`sum`：

| 指标 | 值 |
| --- | --- |
| 总和 | **1290.2621** |
| 单步最小 | -29.09 |
| 单步最大 | **564.45** |
| 单步均值 | 26.88 |
| >2的步数 | 29 / 48 |
| <0的步数 | 17 / 48 |

单步reward轨迹（前12 /后12）：

```text
前 12:  -6.37, 1.25, -8.36, 4.02, 4.22, -3.28, 0.55, 5.41, 9.44, 6.76, 15.59, 31.86
后 12: 526.26, 564.45, -3.74, -9.93, -11.30, -1.38, 18.28, 33.64, 14.72, 43.82, 31.43, 12.79
```

第36、37步reward直接冲到500+——**隐状态被推到了奖励头的极端区域**，这就是"幻觉"。整条序列并不是全程高奖励，而是先铺垫隐状态，再在末尾引爆。

#### 坐标下降在这里有效的原因

严格说目标并不可分：改第t步会改变`h_t`之后的所有隐状态，单步reward之间强耦合，坐标下降没有理论上的收敛保证。但它实践上奏效有两个原因：一是靠前动作的边际影响常被后面的稳态"吸收"，多数单点替换只造成有限扰动，少数替换能把轨迹整体推进新的扇区；二是每轮全扫描192条候选并取全局最优，等价于在48维超立方体网格上做一次"最陡离散下降"，只要存在单点改进就会被接受，不会停在单点平台上。再配合"随机改两个位置后重新下降"的踢动，就能从一个窄峰跳到另一个窄峰。

收敛曲线的形状也印证了这一点：第一轮从170.5跳到741.2，说明全4附近有大量单点改进方向；780附近徘徊几轮，是局部最优之间的平台；第9轮突破1054，是某次踢动把轨迹送进了新扇区；最后稳定在1290.26，连续十几轮踢动都无改进，可以认为在当前邻域结构下已经到顶。

#### 这条序列的分布外

对照常量策略能看得很清楚：常量策略下`h`很快收敛到不动点，48步reward基本是同一个数重复；而这条序列动作分布极不均匀，且有成段重复，第36步前后把`h`推到了使`reward_head`输出500+的位置，这在任何常规策略下都不会出现。世界模型只在有限的策略分布上训练过，`reward_head`只在见过的`h`附近可信；一旦`h`离开支撑集，三层MLP就退化为纯线性外推，没有任何校准，输出可以任意大。这正是reward hacking的典型形态——不是策略变好了，而是评分器被绕过了。

### 提交拿flag

用最优序列拼成一行JSON提交，代码见第 4 节 PoC。

```json
{"ok": true, "score": 1290.2773, "flag": "flag{...}"}
```

- 服务端`1290.2773` vs离线`1290.2621`，差0.015，是torch版本/浮点差异；
- 对照：全4只有`170.5086`，**不返flag**，所以阈值在`(170.5, 1290.3]`之间（大概率是1000这种整数）。

从返回体可以直接读出判定逻辑：`ok`恒为true，`score`总是回，只有`score`越过阈值时才附带`flag`字段。所以整条搜索是"要么过线、要么零分"，900分和7分没有区别；而本题没有任何随机性，同一序列重复提交结果完全一致，这也让"离线算好一条、在线提交一次"成为最优路径。反过来说，只要离线`sum`稳定超过疑似阈值，就可以直接提交，不必反复试探服务端——试探一次就够，剩下的交给确定性的打分函数。

### 解的敏感性

对最优序列做**单点修改**（只改一个动作），重新评估，得到的分数分布：

| 单点修改后的分数 | 说明 |
| --- | --- |
| 1133.66 | 最好的一步替换，仍掉156 |
| 1041.65 | — |
| 535.43 | — |
| 509.37 | — |
| 229.90 | — |
| 200.10 | — |

最优解非常"尖"：任何一个动作改错，分数就从1290掉到几百甚至200。这也解释了为什么梯度/软松弛不work——reward对离散输入的响应是阶跃式的。

## 4. PoC

```python
import json, socket
payload = json.dumps({"actions": BEST}, separators=(",", ":"))
s = socket.create_connection(("*", *))
s.sendall((payload + "\n").encode())
print(s.recv(4096).decode())

```

```python
a = torch.tensor([[1]*48])
r = imagine(model, a)
r.sum()   # tensor(-63.12187194824219)

```

```python
logits = torch.zeros(T, A, requires_grad=True)
opt = torch.optim.Adam([logits], lr=0.15)

for it in range(600):
    tau = max(0.3, 2.0 * (1 - it / 600))
    soft = F.gumbel_softmax(logits, tau=tau, hard=False, dim=-1)
    idx  = soft.argmax(-1)
    hard = F.one_hot(idx, A).float()
    st   = hard + soft - soft.detach()          # 前向 one-hot，反向走 soft

    h, total = model.initial(1), 0.0
    for t in range(T):
        h = model.step(h, st[t].unsqueeze(0))
        total = total + model.predict_reward(h)

    (-total).backward(); opt.step(); opt.zero_grad()

```

```python
@torch.no_grad()
def batch_score(seqs):                 # seqs: (B, 48) long
    B = seqs.shape[0]
    h = torch.zeros(B, 384)
    total = torch.zeros(B)
    for t in range(48):
        h = model.gru(F.one_hot(seqs[:, t], 5).float(), h)
        total += model.reward_head(h).squeeze(-1)
    return total                        # (B,)

def coordinate_descent(start):
    cur = list(start)
    cur_s = score1(cur)
    improved = True
    while improved:
        improved = False
        cand = []
        for t in range(48):
```
