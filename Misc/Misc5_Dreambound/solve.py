"""Dreambound：白盒搜索 48 步动作序列，让 reward head 输出"幻觉"高分。

用法:
    python solve.py --model-dir ./dreambound --checkpoint checkpoint.pt
    python solve.py --model-dir ./dreambound --checkpoint checkpoint.pt --host H --port P

搜索部分是批量评估 + 坐标下降 + 随机扰动；给 --host/--port 时把最优序列提交给服务端。
"""
import argparse
import importlib.util
import json
import random
import socket
from pathlib import Path

import torch
import torch.nn.functional as F

T, A, H = 48, 5, 384

# 题解中收敛到的序列（离线 sum = 1290.2621）
BEST = [2, 1, 2, 2, 1, 0, 0, 0, 3, 4, 0, 0, 2, 0, 2, 4, 1, 0, 0, 4, 2, 3, 0, 3,
        0, 2, 0, 3, 3, 4, 3, 2, 3, 3, 3, 3, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3]

model = None


def load_world_model(model_py, checkpoint):
    spec = importlib.util.spec_from_file_location("dreambound_model", model_py)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    state = torch.load(checkpoint, map_location="cpu", weights_only=False)
    state_dict = state.get("state_dict", state) if isinstance(state, dict) else state
    config = state.get("config") if isinstance(state, dict) else None
    net = module.WorldModel(**config) if config else module.WorldModel()
    net.load_state_dict(state_dict)
    net.eval()
    return module, net


@torch.no_grad()
def batch_score(seqs):                 # seqs: (B, 48) long
    B = seqs.shape[0]
    h = torch.zeros(B, 384)
    total = torch.zeros(B)
    for t in range(48):
        h = model.gru(F.one_hot(seqs[:, t], 5).float(), h)
        total += model.reward_head(h).squeeze(-1)
    return total                        # (B,)


def score1(seq):
    return float(batch_score(torch.tensor([seq], dtype=torch.long))[0])


def coordinate_descent(start):
    cur = list(start)
    cur_s = score1(cur)
    improved = True
    while improved:
        improved = False
        cand = []
        for t in range(48):
            for v in range(A):
                if v == cur[t]:
                    continue
                seq = list(cur)
                seq[t] = v
                cand.append((t, v, seq))
        if not cand:
            break
        scores = batch_score(torch.tensor([c[2] for c in cand], dtype=torch.long))
        best_i = int(torch.argmax(scores))
        best_s = float(scores[best_i])
        if best_s > cur_s + 1e-6:
            t, v, seq = cand[best_i]
            cur, cur_s = seq, best_s
            improved = True
    return cur, cur_s


def kick(seq, rng):
    out = list(seq)
    for _ in range(2):
        out[rng.randrange(T)] = rng.randrange(A)
    return out


def submit(host, port, actions):
    payload = json.dumps({"actions": actions}, separators=(",", ":"))
    s = socket.create_connection((host, port))
    s.sendall((payload + "\n").encode())
    data = s.recv(4096).decode()
    s.close()
    return data


def main():
    global model
    parser = argparse.ArgumentParser(description="Dreambound 动作序列搜索")
    parser.add_argument("--model-dir", default=".", help="model.py 所在目录")
    parser.add_argument("--checkpoint", default="checkpoint.pt")
    parser.add_argument("--rounds", type=int, default=30, help="扰动轮数")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="best_actions.json")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    model_py = Path(args.model_dir) / "model.py"
    _module, model = load_world_model(str(model_py), args.checkpoint)

    print(f"[*] sum of BEST = {score1(BEST):.4f}")

    rng = random.Random(args.seed)
    cur, cur_s = coordinate_descent([4] * T)
    print(f"start   : {score1([4] * T):.4f}")
    print(f"round 0 : {cur_s:.4f}")

    best, best_s = cur, cur_s
    for rnd in range(1, args.rounds + 1):
        cand, cand_s = coordinate_descent(kick(best, rng))
        if cand_s > best_s:
            best, best_s = cand, cand_s
            print(f"round {rnd:<2}: {best_s:.4f}")
        else:
            print(f"round {rnd:<2}: {cand_s:.4f} (no improvement)")

    print(f"[*] best score = {best_s:.4f}")
    print(f"[*] best actions = {best}")

    with open(args.out, "w", encoding="utf-8") as fp:
        json.dump({"actions": best, "score": best_s}, fp)

    if args.host and args.port:
        print(submit(args.host, args.port, best))


if __name__ == "__main__":
    main()
