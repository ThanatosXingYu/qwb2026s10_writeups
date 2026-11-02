"""Dreambound 的梯度法基线：Gumbel-softmax + straight-through，题解中确认行不通。

用法:
    python solve.py --model-dir ./dreambound --checkpoint checkpoint.pt

多次运行、多种子下最好的离散结果仅约 28.26，低于全 4 常量策略的 170.51，
因此它只作为对照，真正可用的是 coordinate descent。
"""
import argparse
import importlib.util
from pathlib import Path

import torch
import torch.nn.functional as F

T, A = 48, 5


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


def main():
    parser = argparse.ArgumentParser(description="Dreambound 梯度法基线")
    parser.add_argument("--model-dir", default=".")
    parser.add_argument("--checkpoint", default="checkpoint.pt")
    parser.add_argument("--steps", type=int, default=600)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    _module, model = load_world_model(str(Path(args.model_dir) / "model.py"),
                                      args.checkpoint)

    logits = torch.zeros(T, A, requires_grad=True)
    opt = torch.optim.Adam([logits], lr=0.15)

    best = None
    for it in range(args.steps):
        tau = max(0.3, 2.0 * (1 - it / 600))
        soft = F.gumbel_softmax(logits, tau=tau, hard=False, dim=-1)
        idx = soft.argmax(-1)
        hard = F.one_hot(idx, A).float()
        st = hard + soft - soft.detach()          # 前向 one-hot，反向走 soft

        h, total = model.initial(1), 0.0
        for t in range(T):
            h = model.step(h, st[t].unsqueeze(0))
            total = total + model.predict_reward(h)

        (-total).backward()
        opt.step()
        opt.zero_grad()

        if best is None or float(total) > best[0]:
            best = (float(total), idx.tolist())

    print(f"[*] best soft score = {best[0]:.2f}")
    print(f"[*] best discrete   = {best[1]}")


if __name__ == "__main__":
    main()
