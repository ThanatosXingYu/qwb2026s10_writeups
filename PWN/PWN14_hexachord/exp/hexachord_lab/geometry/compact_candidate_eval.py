"""Numba evaluation of full-cube states at compressed projection meets."""

from __future__ import annotations

import numpy as np
from numba import njit


@njit(cache=True)
def evaluate_base(back_indices, forward_indices, back_parents, forward_parents,
                  cp0, urul0, ubdf0, fr0, parity0,
                  cp_move, urul_move, ubdf_move, fr_move, parity_move,
                  merge, cp_prun, ep_prun, budget,
                  out_paths, out_cost, out_h2, out_cp, out_ep,
                  out_fr, out_parity):
    """Write candidates; each path is target-to-solved inverse quarter turns."""
    count = 0
    path = np.empty(32, dtype=np.uint8)
    back = np.empty(16, dtype=np.uint8)
    for meet in range(len(back_indices)):
        index = int(back_indices[meet])
        back_len = 0
        while index:
            packed = int(back_parents[index])
            back[back_len] = packed & 7
            back_len += 1
            index = packed >> 3
        length = 0
        for i in range(back_len-1, -1, -1):
            path[length] = back[i]
            length += 1
        index = int(forward_indices[meet])
        while index:
            packed = int(forward_parents[index])
            path[length] = packed & 7
            length += 1
            index = packed >> 3
        if length > budget:
            continue
        cp, urul, ubdf, fr, parity = cp0, urul0, ubdf0, fr0, parity0
        for i in range(length):
            m = int(path[i]) * 3 + 2
            cp = int(cp_move[cp, m])
            urul = int(urul_move[urul, m])
            ubdf = int(ubdf_move[ubdf, m])
            fr = int(fr_move[fr, m])
            parity = int(parity_move[parity, m])
        if fr >= 24 or urul >= 336 or ubdf >= 336:
            continue
        ep = int(merge[urul, ubdf])
        if ep < 0:
            continue
        cph = int(cp_prun[(cp * 24 + fr) * 2 + parity])
        eph = int(ep_prun[(ep * 24 + fr) * 2 + parity])
        h2 = max(cph, eph)
        if length + h2 > budget:
            continue
        if count >= len(out_cost):
            break
        for i in range(length):
            out_paths[count, i] = path[i]
        out_cost[count] = length
        out_h2[count] = h2
        out_cp[count] = cp
        out_ep[count] = ep
        out_fr[count] = fr
        out_parity[count] = parity
        count += 1
    return count


def arrays(capacity: int = 1000000):
    return (
        np.empty((capacity, 32), dtype=np.uint8),
        np.empty(capacity, dtype=np.uint8),
        np.empty(capacity, dtype=np.uint8),
        np.empty(capacity, dtype=np.uint16),
        np.empty(capacity, dtype=np.uint16),
        np.empty(capacity, dtype=np.uint8),
        np.empty(capacity, dtype=np.uint8),
    )
