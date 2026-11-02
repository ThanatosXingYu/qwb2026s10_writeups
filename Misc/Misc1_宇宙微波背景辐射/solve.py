"""从MKV还原六段文字并拼出flag。

用法:
    python solve.py challenge.mkv [--out recovered]

输出:
    recovered/part0..part5.png, recovered/recovered_parts.png, recovered/flag.txt
"""
import argparse
import re
import subprocess
import tarfile
from pathlib import Path

import cv2
import numpy as np

THRESH = 125          # 二值化阈值
SIGMA = 2.0           # 高斯平滑半径
BASE = 0.49           # 相关性基线
GAIN = 2200.0         # 对比度拉伸系数
COUNT = 200           # 每段帧数
TAIL_SECONDS = 8      # 主视频结尾雪花时长
ORDER = [0, 1, 4, 3, 2, 5]   # part 存放顺序 -> 语义顺序

IMAGE_SUFFIXES = (".bmp", ".png")


def run(cmd, cwd=None):
    subprocess.run(cmd, check=True, cwd=cwd)


def video_meta(path):
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise SystemExit(f"[-] cannot open {path}")
    fps = cap.get(cv2.CAP_PROP_FPS)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    cap.release()
    return fps, total


def read_video(path, start=0, count=COUNT):
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise SystemExit(f"[-] cannot open {path}")
    if start:
        cap.set(cv2.CAP_PROP_POS_FRAMES, start)
    frames = []
    while len(frames) < count:
        ok, frame = cap.read()
        if not ok:
            break
        frames.append(frame)
    cap.release()
    return frames


def read_image_sequence(directory):
    files = sorted(p for p in Path(directory).rglob("*")
                   if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES)
    frames = []
    for f in files:
        img = cv2.imread(str(f), cv2.IMREAD_COLOR)
        if img is None:
            raise SystemExit(f"[-] cannot read image {f}")
        frames.append(img)
    return frames


def read_srt_frames(path):
    """SRT 每块正文是一条被换行拆开的十六进制 PNG，按块顺序还原成帧。"""
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    frames = []
    for block in re.split(r"\n\s*\n", text.strip()):
        lines = [ln.strip() for ln in block.strip().splitlines() if ln.strip()]
        if len(lines) < 3:
            continue
        body = "".join(ln for ln in lines[2:] if "-->" not in ln)
        hexstr = re.sub(r"[^0-9a-fA-F]", "", body)
        if len(hexstr) % 2 or not hexstr.lower().startswith("89504e47"):
            continue
        buf = np.frombuffer(bytes.fromhex(hexstr), np.uint8)
        img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        if img is None:
            continue
        frames.append(img)
    return frames


def correlate(frames):
    """逐像素统计相邻帧二值图相同的比例，再平滑与拉伸。"""
    if len(frames) < 2:
        raise SystemExit("[-] need at least 2 frames")
    prev = frames[0] > THRESH
    score = np.zeros(prev.shape, dtype=np.float64)
    for frame in frames[1:]:
        cur = frame > THRESH
        score += (cur == prev)
        prev = cur
    score /= (len(frames) - 1)
    smooth = cv2.GaussianBlur(score, (0, 0), SIGMA)
    return np.clip((smooth - BASE) * GAIN, 0, 255).astype(np.uint8)


def stitch(images):
    height = min(img.shape[0] for img in images)
    cropped = [img[:height] for img in images]
    return np.hstack(cropped)


def main():
    parser = argparse.ArgumentParser(description="宇宙微波背景辐射 solver")
    parser.add_argument("mkv", help="challenge.mkv 路径")
    parser.add_argument("--out", default="recovered", help="输出目录")
    args = parser.parse_args()

    src = Path(args.mkv).resolve()
    if not src.exists():
        raise SystemExit(f"[-] no such file: {src}")
    work = src.parent / "analysis"
    out = Path(args.out)
    if not out.is_absolute():
        out = src.parent / out
    work.mkdir(exist_ok=True)
    out.mkdir(exist_ok=True)

    # ---------- 1. 拆轨与拆附件 ----------
    run(["ffmpeg", "-y", "-i", str(src), "-map", "0:1", "-c", "copy",
         str(work / "hidden.mkv")])
    run(["ffmpeg", "-y", "-i", str(src), "-map", "0:s:0", str(work / "hidden.srt")])
    run(["ffmpeg", "-y", "-dump_attachment:t", "", "-i", str(src)], cwd=work)

    for name in ("g2", "g4"):
        with tarfile.open(work / f"{name}.tar") as tf:
            tf.extractall(work / name)

    # ---------- 2. 取帧 ----------
    hidden = read_video(work / "hidden.mkv", 0, COUNT * 2)
    if len(hidden) < COUNT * 2:
        print(f"[!] hidden track has only {len(hidden)} frames, slicing anyway")
    part0_frames = hidden[:COUNT]
    part2_frames = hidden[COUNT:COUNT * 2]

    part1_frames = read_image_sequence(work / "g2")
    part3_frames = read_image_sequence(work / "g4")
    part4_frames = read_srt_frames(work / "hidden.srt")

    fps, total = video_meta(src)
    start = max(total - round(fps * TAIL_SECONDS), 0)
    part5_frames = read_video(src, start, COUNT)

    # ---------- 3. 时间相关性成像 ----------
    groups = [part0_frames, part1_frames, part2_frames,
              part3_frames, part4_frames, part5_frames]
    images = []
    for idx, frames in enumerate(groups):
        if not frames:
            raise SystemExit(f"[-] part{idx} has no frames")
        img = correlate(frames)
        cv2.imwrite(str(out / f"part{idx}.png"), img)
        images.append(img)
        print(f"[*] part{idx}: {len(frames)} frames -> {out / f'part{idx}.png'}")

    # ---------- 4. 按语义顺序拼接 ----------
    ordered = [images[i] for i in ORDER]
    cv2.imwrite(str(out / "recovered_parts.png"), stitch(ordered))

    note = out / "flag.txt"
    note.write_text(
        "已按语义顺序 [0,1,4,3,2,5] 把六段图像横向拼接到 recovered_parts.png。\n"
        "依次读出六段文字即为 flag（首段写作 f1ag{，提交时把前缀改回 flag{）。\n"
        "逐段核对时看 part0..part5.png。\n",
        encoding="utf-8",
    )
    print(f"[*] stitched -> {out / 'recovered_parts.png'}")
    print(f"[*] note      -> {note}")


if __name__ == "__main__":
    main()
