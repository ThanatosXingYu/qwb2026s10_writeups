# Hexachord 现场复现包

本包按“收集现场记录 → 结算开碑”分成两段。先读 [案卷](notes/field_notes.md)，再运行脚本；每次 `capture` 都从头建立一条连接，残章不能跨轮混用。

## 目录

```text
hexachord_lab/transport.py   字节级菜单收发与原始记录
hexachord_lab/planning.py    魔方目标搜索与咒文编码选择
hexachord_lab/session.py     逐章执行和结算保存
hexachord_lab/recovery.py    份额插值及 GCM 开碑
hexachord_lab/geometry/     魔方状态、搜索器和预计算表
hexachord_lab/exploit/      栈迁移与两段祷文
artifacts/gift.elf           礼物程序样本
```

## 运行

在 Kali Linux 中使用 Python 3.14；建表前至少预留约 6 GiB 可用内存。

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m hexachord_lab check
.venv/bin/python -m hexachord_lab capture \
  --host 47.95.113.113 --port 20549 --out runs/attempt_01
```

`capture` 写入 `chapters.jsonl`、`transcript.bin`、`received.bin`、`sent.bin` 和结算时的 `final_response.bin`。重新尝试时换一个空的 `--out` 目录。已有同一轮的完整记录可单独开碑：

```bash
.venv/bin/python -m hexachord_lab open \
  --records runs/attempt_01/chapters.jsonl \
  --final runs/attempt_01/final_response.bin
```

脚本检查是否至少有 18 份已计分残章；GCM 标签不通过时会打印 `SEAL_INVALID`。此时先对照该轮原始收发记录检查残章与结算的归属和字节完整性。

服务地址可能随比赛实例变化；运行时以题面给出的地址为准。
