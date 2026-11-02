"""恢复 NeuronShuffle 的权重种子与置换，并推导 flag。

用法:
    python solve.py model_A.npz
"""
import argparse
import hashlib
from datetime import date, timedelta

import numpy as np

V = "cf8303ef7e9fc6f51baf27b6e2c8763bd199a0a24c5294bcdaca3ddef6e47864"
START = date(2026, 10, 1)
DAYS = 92
POOL = 974
LAYERS = (48, 40, 32)


def load_pool_hint(path):
    with np.load(path, allow_pickle=False) as model:
        row = model["k5"][0].copy()
        values = np.unique(np.concatenate([model[n].ravel() for n in model.files]))
    return row, values


def find_seed(row, values):
    for offset in range(DAYS):
        day = START + timedelta(days=offset)
        seed = int(day.strftime("%Y%m%d"))
        samples = np.random.default_rng(seed).normal(0, 0.6, POOL)
        if np.array_equal(row, samples[:32]) and np.setdiff1d(values, samples).size == 0:
            return day
    raise SystemExit("seed not found")


def main():
    parser = argparse.ArgumentParser(description="NeuronShuffle solver")
    parser.add_argument("model", help="model_A.npz 路径")
    parser.add_argument("--out", default="answer.txt", help="规范化答案串输出文件")
    args = parser.parse_args()

    row, values = load_pool_hint(args.model)
    print(f"[*] unique floats = {values.size}, fingerprint len = {row.size}")

    day = find_seed(row, values)
    print(f"[*] weight seed = {day:%Y%m%d}")

    for shift in (-1, 0, 1):
        perm_day = day + timedelta(days=shift)
        rng = np.random.default_rng(int(perm_day.strftime("%Y%m%d")))
        answer = ";".join(",".join(map(str, rng.permutation(n))) for n in LAYERS)
        body = hashlib.sha256(answer.encode()).hexdigest()[:32]
        if hashlib.sha256(("ns::" + body).encode()).hexdigest() == V:
            print(f"[*] perm  seed = {perm_day:%Y%m%d}")
            print(f"[*] answer({len(answer)}) = {answer}")
            print(f"[+] flag = flag{{{body}}}")
            with open(args.out, "w", encoding="utf-8") as fp:
                fp.write(answer + "\n")
            print(f"[*] answer saved to {args.out}")
            return
    raise SystemExit("permutation seed not found")


if __name__ == "__main__":
    main()
